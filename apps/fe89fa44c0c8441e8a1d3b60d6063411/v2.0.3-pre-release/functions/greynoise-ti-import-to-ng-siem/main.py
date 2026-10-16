import csv
import gc
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Dict

from crowdstrike.foundry.function import APIError, Function, Request, Response
from falconpy import NGSIEM
from greynoise.api import APIConfig, GreyNoise

func = Function.instance()

INTEGRATION_NAME = "CrowdStrike Foundry v3.0.0"
EXCLUDE_FIELDS = "destination_asns,destination_cities,destination_countries,destination_country_codes,tags.details"

# Define file name and csv headers
FILE_NAME = "greynoise_indicators"
FILE_HEADERS = [
    "source.ip",
    "source.ip.greynoise.is.actor",
    "source.ip.greynoise.is.classification",
    "source.ip.greynoise.is.last_seen_timestamp",
    "source.ip.greynoise.is.asn",
    "source.ip.greynoise.is.source_country_code",
    "source.ip.greynoise.is.spoofable",
    "source.ip.greynoise.is.tags",
    "source.ip.greynoise.is.tor",
    "source.ip.greynoise.is.vpn",
    "source.ip.greynoise.is.vpn_service",
    "source.ip.greynoise.bs.trust_level",
    "source.ip.greynoise.bs.category",
    "source.ip.greynoise.bs.name",
]

CALLBACK_FEED_FILE_NAME = "greynoise_callback_indicators"
CALLBACK_FEED_HEADERS = [
    "source.ip",
    "source.ip.greynoise.callback.is_stage2",
    "source.ip.greynoise.callback.is_stage1",
    "source.ip.greynoise.callback.is_riot",
    "source.ip.greynoise.callback.riot_trust_level",
    "source.ip.greynoise.callback.first_seen",
    "source.ip.greynoise.callback.last_seen",
    "source.ip.greynoise.callback.scanner_count",
    "source.ip.greynoise.callback.file_count",
    "source.ip.greynoise.callback.source_country_code",
]


def validate_api_key(logger, api_client):
    """Validate if a provided API key is valid."""
    try:
        api_client.test_connection()
        return True
    except Exception as e:
        logger.debug(f"Connection to GreyNoise API failed - {str(e)}")
        return False

def _normalize_csv_or_list(value):
    """Normalize an API field that may be a comma-separated string or a list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip().lower() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(part).strip().lower() for part in value if str(part).strip()]
    return [str(value).strip().lower()]


def validate_entitlements(logger, api_client):
    """Validate if the provided API key has the necessary entitlements to access the callback feed."""
    try:
        entitled = api_client.test_connection()
        modules = _normalize_csv_or_list(entitled.get("modules"))
        plans = _normalize_csv_or_list(entitled.get("plans") or entitled.get("plan"))
        logger.debug(f"Modules: {modules}")
        logger.debug(f"Plans: {plans}")
        if (
            any("c2" in module or "callback" in module for module in modules)
            or any("greynoise internal" in plan for plan in plans)
        ):
            logger.info("Callback feed is entitled, including in output")
            return True
        logger.warning("Callback feed is not entitled, skipping in output")
        return False
    except Exception as e:
        logger.warning(f"Validation of entitlements failed - {str(e)}")
        return False


def get_ip_tag_names(tags: list) -> str:
    """Get tag names from tags list.

    :type tags: ``list``
    :param tags: list of tags.

    :return: string of tag names.
    :rtype: ``str``
    """
    # Use list comprehension for better performance
    return ";".join(
        f"{tag.get('name', '')} ({tag.get('intention', '')} - {tag.get('category', '')})"
        for tag in tags[:10]
    )


def process_record(item, record_num, logger):
    """Process a single GreyNoise record into a CSV row."""
    try:
        # Cache nested dictionary lookups to avoid repeated access
        is_intel = item.get("internet_scanner_intelligence", {})
        bs_intel = item.get("business_service_intelligence", {})
        metadata = is_intel.get("metadata", {})

        # Handle actor field
        actor = is_intel.get("actor", "")
        if actor == "unknown":
            actor = ""

        row = [
            item.get("ip", ""),
            actor,
            is_intel.get("classification", ""),
            is_intel.get("last_seen_timestamp", ""),
            metadata.get("asn", ""),
            metadata.get("source_country_code", ""),
            "1" if is_intel.get("spoofable", False) else "0",
            get_ip_tag_names(is_intel.get("tags", [])),
            "1" if is_intel.get("tor", False) else "0",
            "1" if is_intel.get("vpn", False) else "0",
            is_intel.get("vpn_service", ""),
            bs_intel.get("trust_level", ""),
            bs_intel.get("category", ""),
            bs_intel.get("name", ""),
        ]
        return row
    except KeyError as e:
        logger.warning(f"Missing key in record {record_num}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error processing record {record_num}: {str(e)}")
        return None


def process_callback_record(item, record_num, logger):
    """Process a single GreyNoise callback record into a CSV row."""
    try:
        return [
            item.get("ip", ""),
            "1" if item.get("is_stage_2", False) else "0",
            "1" if item.get("is_stage_1", False) else "0",
            "1" if item.get("is_riot", False) else "0",
            item.get("riot_trust_level", "") or "",
            item.get("first_seen", "") or "",
            item.get("last_seen", "") or "",
            item.get("scanner_count", ""),
            item.get("file_count", ""),
            item.get("source_country_code", "") or "",
        ]
    except Exception as e:
        logger.error(f"Error processing callback record {record_num}: {str(e)}")
        return None


def process_callback_feed(logger, temp_dir, gn) -> str:
    """Fetch callback IPs last seen in the past 7 days and write them to CSV."""
    output_filename = f"ti_{CALLBACK_FEED_FILE_NAME}.csv"
    output_path = os.path.join(temp_dir, output_filename)
    logger.info(f"Creating CSV file for callback feed: {output_path}")

    last_seen_after = (datetime.now(timezone.utc) - timedelta(days=7)).strftime(
        "%Y-%m-%d"
    )
    page = 0
    page_size = 1000
    processed_count = 0

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(CALLBACK_FEED_HEADERS)

        while True:
            logger.debug(
                f"Querying GreyNoise callback_list (page {page}, "
                f"last_seen_after={last_seen_after})"
            )
            response = gn.callback_list(
                last_seen_after=last_seen_after,
                page=page,
                page_size=page_size,
            )

            if isinstance(response, dict) and response.get("message"):
                raise Exception(f"Callback list error: {response.get('message')}")

            items = response.get("items", []) if isinstance(response, dict) else []
            total = response.get("total", 0) if isinstance(response, dict) else 0

            if page == 0:
                logger.info(f"GreyNoise Callback Indicator Count: {total}")

            if not items:
                break

            rows_to_write = []
            for i, item in enumerate(items):
                row = process_callback_record(item, processed_count + i + 1, logger)
                if row is not None:
                    rows_to_write.append(row)
                    processed_count += 1

            if rows_to_write:
                writer.writerows(rows_to_write)

            logger.debug(f"Processed {processed_count} callback records so far")

            if len(items) < page_size or (page + 1) * page_size >= total:
                break

            page += 1
            if page % 3 == 0:
                gc.collect()

    if not os.path.exists(output_path):
        raise FileNotFoundError("Callback CSV file was not created")

    file_size = os.path.getsize(output_path)
    logger.info(
        f"Callback CSV created successfully with {processed_count} records. "
        f"Size: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)"
    )
    return output_path


def process_main_feed(logger, temp_dir, gn, query, max_indicator_count) -> str:
    """Process the main GreyNoise indicator feed and write it to CSV."""
    output_filename = f"ti_{FILE_NAME}.csv"
    output_path = os.path.join(temp_dir, output_filename)
    logger.info(f"Creating CSV file for streaming write for main feed: {output_path}")

    processed_count = 0
    total_records = 0
    file_size = 0

    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        # Write header
        writer.writerow(FILE_HEADERS)

        if max_indicator_count < 5000:
            size = max_indicator_count
        else:
            size = 5000

        # Query GreyNoise API - first page
        logger.debug(f"Querying GreyNoise API with query: '{query}'")
        response = gn.query(
            query=query, exclude_raw=True, size=size, exclude_fields=EXCLUDE_FIELDS
        )

        # Cache metadata to avoid repeated dictionary access
        request_metadata = response.get("request_metadata", {})
        logger.info(
            f"GreyNoise Query Indicator Count: {request_metadata.get('count', 0)}"
        )

        scroll = request_metadata.get("scroll", None)
        complete = request_metadata.get("complete", True)

        # Process first batch
        if "data" in response:
            batch_data = response["data"]
            logger.debug(f"Processing first batch of {len(batch_data)} records")

            # Batch process records for better performance
            rows_to_write = []
            for i, item in enumerate(batch_data):
                if processed_count >= max_indicator_count:
                    break

                row = process_record(item, total_records + i + 1, logger)
                if row is not None:
                    rows_to_write.append(row)
                    processed_count += 1

            # Write all rows at once for better I/O performance
            if rows_to_write:
                writer.writerows(rows_to_write)

            total_records += len(batch_data)
            logger.debug(f"Processed {processed_count} records so far")
            file_size = os.path.getsize(output_path)
            logger.debug(
                f"CSV file size: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)"
            )

            # Clear the batch data to free memory
            del batch_data, rows_to_write
        else:
            logger.error("No data found in GreyNoise API response")
            raise Exception("No data found in the response")

        # Clear the response to free memory
        del response
        # Only force garbage collection if processing large batches
        if size >= 5000:
            gc.collect()

        # Continue with pagination if needed
        batch_num = 1
        while not complete and processed_count < max_indicator_count:
            logger.debug(f"Getting next page of results (batch {batch_num})")
            try:
                response = gn.query(
                    query=query,
                    exclude_raw=True,
                    size=size,
                    scroll=scroll,
                    exclude_fields=EXCLUDE_FIELDS,
                )

                if "data" in response:
                    batch_data = response["data"]
                    logger.debug(f"Processing batch of {len(batch_data)} records")

                    # Batch process records for better performance
                    rows_to_write = []
                    for i, item in enumerate(batch_data):
                        if processed_count >= max_indicator_count:
                            break

                        row = process_record(item, total_records + i + 1, logger)
                        if row is not None:
                            rows_to_write.append(row)
                            processed_count += 1

                    # Write all rows at once for better I/O performance
                    if rows_to_write:
                        writer.writerows(rows_to_write)

                    total_records += len(batch_data)
                    logger.debug(f"Processed {processed_count} records so far")

                    # Only check file size every 5 batches to reduce I/O overhead
                    if batch_num % 5 == 0:
                        file_size = os.path.getsize(output_path)
                        logger.debug(
                            f"CSV file size: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)"
                        )

                    # Clear batch data to free memory
                    del batch_data, rows_to_write

                    # if file_size > 47000000:
                    #    logger.warning("File size is greater than 47MB, stopping processing")
                    #     break
                else:
                    logger.error("No data found in GreyNoise API response")
                    break

                # Cache metadata to avoid repeated dictionary access
                request_metadata = response.get("request_metadata", {})
                scroll = request_metadata.get("scroll", None)
                complete = request_metadata.get("complete", True)

                # Clear response to free memory
                del response
                # Only force garbage collection every few batches or for large batches
                if batch_num % 3 == 0 or size >= 5000:
                    gc.collect()

                batch_num += 1

            except Exception as e:
                logger.error(f"Error during pagination: {str(e)}")
                break

    logger.info(f"Successfully processed {processed_count} records total")

    # Verify file was created
    if os.path.exists(output_path):
        file_size = os.path.getsize(output_path)
        logger.info(
            f"CSV file created successfully. Size: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)"
        )
    else:
        logger.error("CSV file was not created")
        raise FileNotFoundError("CSV file was not created")

    return output_path


def process_file(logger, temp_dir, api_key, query, max_indicator_count, include_callback_feed):
    """Process GreyNoise feeds independently so one failure does not block the other."""
    logger.info(f"Starting to process file: {FILE_NAME}")

    # Initialize GreyNoise API
    logger.info("Initializing GreyNoise API client")
    api_config = APIConfig(api_key=api_key, integration_name=INTEGRATION_NAME)
    gn = GreyNoise(api_config)

    # Check if API key is valid
    logger.info("Validating API key")
    if not validate_api_key(logger, gn):
        raise Exception("Invalid API key")

    output_files = []
    errors = []

    try:
        logger.info("Processing main feed")
        output_path = process_main_feed(
            logger, temp_dir, gn, query, max_indicator_count
        )
        output_files.append(
            {"path": output_path, "file": f"ti_{FILE_NAME}.csv"}
        )
    except Exception as e:
        logger.error(f"Error processing {FILE_NAME}: {str(e)}", exc_info=True)
        errors.append(
            {
                "file": f"ti_{FILE_NAME}.csv",
                "status": "error",
                "message": str(e),
            }
        )

    if include_callback_feed:
        callback_filename = f"ti_{CALLBACK_FEED_FILE_NAME}.csv"
        logger.info("Processing callback feed")
        try:
            if validate_entitlements(logger, gn):
                callback_path = process_callback_feed(logger, temp_dir, gn)
                output_files.append(
                    {
                        "path": callback_path,
                        "file": callback_filename,
                    }
                )
            else:
                logger.warning("Skipping callback feed due to missing entitlements")
                errors.append(
                    {
                        "file": callback_filename,
                        "status": "error",
                        "message": "Callback feed is not entitled",
                    }
                )
        except Exception as e:
            logger.error(
                f"Error processing {CALLBACK_FEED_FILE_NAME}: {str(e)}",
                exc_info=True,
            )
            errors.append(
                {
                    "file": callback_filename,
                    "status": "error",
                    "message": str(e),
                }
            )
    else:
        logger.info("Callback feed not included.")

    if not output_files and errors:
        raise Exception("; ".join(error["message"] for error in errors))

    return {"files": output_files, "errors": errors}


# Handler greynoise-ti-import-bulk
@func.handler(method="POST", path="/greynoise-ti-import-bulk")
def on_post(request: Request, config: Dict[str, object] | None, logger) -> Response:
    logger.info("Starting NGSIEM CSV import process")

    try:
        # Get parameters
        repository = request.body.get("repository", "search-all").strip()
        api_key = request.body.get("api_key", "").strip()
        query = request.body.get("query", "last_seen:1d -classification:unknown").strip()

        max_indicator_count = request.body.get("max_indicator_count", "100000").strip()
        if max_indicator_count.isdigit():
            max_indicator_count = int(max_indicator_count)
        else:
            max_indicator_count = 100000

        include_callback_feed = request.body.get("include_callback_feed", False)

        # Initialize NGSIEM client
        logger.info("Initializing NGSIEM client")
        ngsiem = NGSIEM()

        # Create temporary directory
        logger.info("Creating temporary directory for file processing")
        with tempfile.TemporaryDirectory() as temp_dir:
            logger.debug(f"Temporary directory created: {temp_dir}")
            results = []

            # Process
            logger.info(f"Processing file: {FILE_NAME}")
            try:
                process_result = process_file(
                    logger, temp_dir, api_key, query, max_indicator_count, include_callback_feed
                )
                output_files = process_result.get("files", [])
                results.extend(process_result.get("errors", []))

                for output in output_files:
                    output_path = output["path"]
                    output_filename = output["file"]

                    if not os.path.exists(output_path):
                        logger.error(f"File does not exist: {output_path}")
                        results.append(
                            {
                                "file": output_filename,
                                "status": "error",
                                "message": "File does not exist",
                            }
                        )
                        continue

                    logger.info(f"Uploading file to NGSIEM: {output_path}")
                    response = ngsiem.upload_file(
                        lookup_file=output_path, repository=repository
                    )

                    if 400 <= response["status_code"] < 500:
                        error_message = response.get("error", {}).get(
                            "message", "Unknown error"
                        )
                        logger.error(
                            f"NGSIEM upload error for {output_filename}: {error_message}"
                        )
                        logger.debug(f"API response: {response}")
                        results.append(
                            {
                                "file": output_filename,
                                "status": "error",
                                "message": f"NGSIEM upload error: {error_message}",
                            }
                        )
                        continue

                    logger.info(
                        f"File {output_filename} uploaded successfully to repository: {repository}"
                    )
                    results.append(
                        {
                            "file": output_filename,
                            "status": "success",
                            "message": "File processed and uploaded successfully",
                        }
                    )
            except Exception as e:
                logger.error(
                    f"Error processing file {FILE_NAME}: {str(e)}", exc_info=True
                )
                results.append(
                    {
                        "file": f"ti_{FILE_NAME}.csv",
                        "status": "error",
                        "message": str(e),
                    }
                )

        logger.info("NGSIEM CSV import process completed")
        return Response(body={"results": results}, code=200)

    except Exception as e:
        logger.error(f"Fatal error in NGSIEM CSV import: {str(e)}", exc_info=True)
        return Response(errors=[APIError(code=500, message=str(e))], code=500)


if __name__ == "__main__":
    func.run()
