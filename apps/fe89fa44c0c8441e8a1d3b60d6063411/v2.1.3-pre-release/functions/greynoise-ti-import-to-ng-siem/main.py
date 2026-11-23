import csv
import os
import shutil
import tempfile
import time
from functools import partial
from typing import Dict

from crowdstrike.foundry.function import FDKException, Function, Request, Response
from falconpy import NGSIEM
from greynoise.api import APIConfig, FileResult, GreyNoise
from greynoise.exceptions import RequestFailure

func = Function.instance()

VERSION = "3.1.0"
INTEGRATION = f"crowdstrike-ngsiem/{VERSION}"
INTEGRATION_NAME = f"CrowdStrike Foundry v{VERSION}"
DEFAULT_QUERY = "last_seen:1d -classification:unknown"
GNQL_FILE = "ti_greynoise_indicators.csv"
CALLBACK_FILE = "ti_greynoise_callback_indicators.csv"
CALLBACK_HEADERS = [
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
TIMEOUT = (10, 300)
# Leaves room inside the function's 900 s limit to download and upload once the
# feed is built.
PROVISION_TIMEOUT = 600
DEFAULT_RETRY_AFTER = 60


def import_feeds(body: Dict[str, object], ngsiem, logger) -> list:
    """Download the GreyNoise lookup files and overwrite the NG-SIEM lookups."""
    api_key = str(body.get("api_key") or "").strip()
    if not api_key:
        logger.error("api_key is required")
        raise FDKException(400, "api_key is required")
    repository = str(body.get("repository") or "search-all").strip()
    query = str(body.get("query") or DEFAULT_QUERY).strip()
    raw_limit = str(body.get("max_indicator_count") or "").strip()
    limit = int(raw_limit) if raw_limit.isdigit() and int(raw_limit) > 0 else None
    include_callback = str(body.get("include_callback_feed")).lower() == "true"
    if raw_limit and limit is None:
        logger.debug(
            f"Ignoring max_indicator_count {raw_limit!r}; it is not a positive integer"
        )

    logger.info(
        f"Importing GreyNoise lookups into repository {repository!r} "
        f"with query {query!r} and limit {limit if limit is not None else 'unset'}"
    )
    logger.debug(
        f"Integration {INTEGRATION}; client timeout {TIMEOUT}; "
        f"provision budget {PROVISION_TIMEOUT}s"
    )

    logger.info("Initializing GreyNoise API client")
    gn = GreyNoise(
        APIConfig(
            api_key=api_key,
            integration_name=INTEGRATION_NAME,
            timeout=TIMEOUT,
        )
    )
    feeds = [
        (
            GNQL_FILE,
            partial(gn.gnql_file_metadata, query, limit=limit),
            partial(gn.gnql_file, query, limit=limit),
        )
    ]
    if include_callback:
        logger.info("Callback feed included")
        feeds.append((CALLBACK_FILE, gn.callback_file_metadata, gn.callback_file))
    else:
        logger.info("Callback feed disabled; an empty lookup CSV will be uploaded")

    logger.info(f"Feeds to import: {GNQL_FILE}, {CALLBACK_FILE}")
    deadline = time.monotonic() + PROVISION_TIMEOUT
    results, failures = [], []
    for filename, metadata, download in feeds:
        run_feed(
            filename,
            lambda filename=filename, metadata=metadata, download=download: fetch_feed(
                filename, metadata, download, repository, ngsiem, deadline, logger
            ),
            results,
            failures,
            logger,
        )
    if not include_callback:
        run_feed(
            CALLBACK_FILE,
            lambda: upload_header_only(
                CALLBACK_FILE, CALLBACK_HEADERS, repository, ngsiem, logger
            ),
            results,
            failures,
            logger,
        )
    if failures:
        logger.error(
            f"Import finished with {len(failures)} failure(s) "
            f"and {len(results)} successful upload(s)"
        )
        raise FDKException(
            max(e.code for e in failures), "; ".join(e.message for e in failures)
        )
    logger.info(f"Import finished: {len(results)} feed(s) uploaded")
    return results


def run_feed(filename, action, results, failures, logger) -> None:
    """Run one feed upload and record a failure without stopping the other feed."""
    logger.info(f"{filename}: starting")
    try:
        results.append(action())
    except FDKException as e:
        logger.error(f"{filename}: failed with HTTP {e.code}: {e.message}")
        failures.append(e)
    except Exception as e:
        logger.error(f"{filename}: unexpected failure: {e}", exc_info=True)
        failures.append(FDKException(500, f"{filename}: {e}"))


def fetch_feed(filename, metadata, download, repository, ngsiem, deadline, logger) -> dict:
    """Wait for one feed, download it, and overwrite its NG-SIEM lookup file."""
    work_dir = tempfile.mkdtemp()
    logger.debug(f"{filename}: using temporary directory {work_dir}")
    phase = "checking feed metadata"
    try:
        logger.info(f"{filename}: {phase}")
        wait_until_built(filename, metadata, deadline, logger)

        phase = "downloading the feed"
        path = os.path.join(work_dir, filename)
        logger.info(f"{filename}: {phase}")
        result = download(path, integration=INTEGRATION)
        logger.debug(
            f"{filename}: download status={result.status} "
            f"generated_at={result.generated_at} rows={result.row_count} "
            f"total={result.total_count} truncated={result.truncated} "
            f"feed_status={result.feed_status}"
        )
        if result.status != FileResult.STATUS_OK:
            raise FDKException(
                502,
                f"{filename}: GreyNoise returned {result.status} after reporting the feed built",
            )

        file_size = os.path.getsize(path)
        logger.info(
            f"{filename}: downloaded {file_size} bytes "
            f"({file_size / 1024 / 1024:.2f} MB, {freshness(result)})"
        )

        phase = f"uploading to NG-SIEM repository {repository}"
        upload_lookup(filename, path, repository, ngsiem, logger)

        message = f"Imported into {repository} ({freshness(result)})"
        logger.info(f"{filename}: {message}")
        return {"file": filename, "status": "success", "message": message}
    except RequestFailure as e:
        status, body = (e.args + (0, None))[:2]
        detail = (
            body.get("error") or body.get("message") if isinstance(body, dict) else body
        ) or "request failed"
        logger.debug(f"{filename}: GreyNoise error during {phase}: HTTP {status}: {detail}")
        raise FDKException(
            status if isinstance(status, int) and 400 <= status < 600 else 502,
            f"{filename}: GreyNoise API returned {status}: {detail}",
        ) from e
    finally:
        logger.debug(f"{filename}: removing temporary directory {work_dir}")
        shutil.rmtree(work_dir, ignore_errors=True)


def write_empty_lookup(path, headers) -> None:
    """Write a lookup CSV NG-SIEM will accept when there are no indicators.

    A header row alone is rejected with HTTP 400. One blank data row keeps the
    columns and matches no indicators.
    """
    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(headers)
        writer.writerow([""] * len(headers))


def upload_header_only(filename, headers, repository, ngsiem, logger) -> dict:
    """Upload a CSV that contains the lookup columns and no indicator values."""
    work_dir = tempfile.mkdtemp()
    logger.debug(f"{filename}: using temporary directory {work_dir}")
    try:
        path = os.path.join(work_dir, filename)
        logger.info(f"{filename}: writing an empty lookup CSV")
        write_empty_lookup(path, headers)
        file_size = os.path.getsize(path)
        logger.info(f"{filename}: wrote empty lookup CSV ({file_size} bytes)")
        upload_lookup(filename, path, repository, ngsiem, logger)
        message = f"Imported into {repository} (no indicators, callback feed disabled)"
        logger.info(f"{filename}: {message}")
        return {"file": filename, "status": "success", "message": message}
    finally:
        logger.debug(f"{filename}: removing temporary directory {work_dir}")
        shutil.rmtree(work_dir, ignore_errors=True)


def upload_lookup(filename, path, repository, ngsiem, logger) -> None:
    """Overwrite one NG-SIEM lookup file."""
    logger.info(f"{filename}: uploading to NG-SIEM repository {repository}")
    upload = ngsiem.upload_file(lookup_file=path, repository=repository)
    status_code = upload["status_code"]
    logger.debug(f"{filename}: NGSIEM upload returned status {status_code}")
    if not 200 <= status_code < 300:
        message = upload_error_detail(upload)
        logger.error(f"{filename}: NGSIEM upload returned {status_code}: {message}")
        raise FDKException(
            502,
            f"{filename}: NGSIEM upload returned {status_code}: {message}",
        )


def upload_error_detail(upload) -> str:
    """Return the NG-SIEM error text from an upload response."""
    body = upload.get("body")
    if isinstance(body, dict):
        errors = body.get("errors") or []
        if errors:
            first = errors[0]
            if isinstance(first, dict):
                for key in ("message", "detail", "title", "description"):
                    if first.get(key):
                        return str(first[key])
                return str(first)
            return str(first)
    if body:
        text = str(body)
        return text if len(text) <= 500 else text[:500] + "..."
    return "unknown error"


def wait_until_built(filename, metadata, deadline, logger) -> None:
    """Poll file metadata until GreyNoise reports the feed is built."""
    attempt = 0
    while True:
        attempt += 1
        remaining = deadline - time.monotonic()
        logger.debug(
            f"{filename}: requesting feed metadata "
            f"(attempt {attempt}, {remaining:.0f}s left in the provision budget)"
        )
        built = metadata(integration=INTEGRATION)
        logger.debug(
            f"{filename}: metadata status={built.status} "
            f"generated_at={built.generated_at} rows={built.row_count} "
            f"total={built.total_count} truncated={built.truncated} "
            f"feed_status={built.feed_status} retry_after={built.retry_after}"
        )
        if built.status == FileResult.STATUS_OK:
            logger.info(f"{filename}: feed is built ({freshness(built)})")
            return
        wait = max(built.retry_after or DEFAULT_RETRY_AFTER, 1)
        if time.monotonic() + wait > deadline:
            logger.error(
                f"{filename}: still {built.status} with {remaining:.0f}s left; "
                f"not enough time to wait {wait}s"
            )
            raise FDKException(
                504,
                f"{filename}: GreyNoise is still building the feed after {PROVISION_TIMEOUT} s",
            )
        logger.info(
            f"{filename}: GreyNoise is building the feed; checking again in {wait} s"
        )
        time.sleep(wait)


def freshness(result: FileResult) -> str:
    """Describe when the downloaded file was generated."""
    parts = [f"generated at {result.generated_at or 'unknown'}"]
    if result.row_count is not None:
        parts.append(f"{result.row_count} rows")
    if result.truncated:
        parts.append("truncated")
    return ", ".join(parts)


@func.handler(method="POST", path="/greynoise-ti-import-bulk")
def on_post(request: Request, config: Dict[str, object] | None, logger) -> Response:
    logger.info("Starting NGSIEM lookup import")
    logger.debug("Initializing NGSIEM client")
    results = import_feeds(request.body or {}, NGSIEM(), logger)
    logger.info(f"NGSIEM lookup import completed with {len(results)} feed(s)")
    return Response(body={"results": results}, code=200)


if __name__ == "__main__":
    func.run()
