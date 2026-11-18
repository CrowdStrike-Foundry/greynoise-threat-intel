![GreyNoise](greynoise2.png)

# GreyNoise Threat Intel Import to NG-SIEM
This app has a Python function that downloads GreyNoise threat intelligence via the GreyNoise API.

## Requirements:
- A GreyNoise Subscription
- A GreyNoise [API Key](https://viz.greynoise.io/account/api-key)
- (Optional) GreyNoise Callback / C2 Intelligence entitlement, required only if enabling the Callback Indicator feed

## Function Details
- The function downloads GreyNoise's pre-built NG-SIEM lookup files with the GreyNoise Python SDK (`greynoise` 3.2.0). It does not page GNQL results or build the CSV itself.
- For the GNQL feed, it requests the file for the provided query (default: `last_seen:1d -classification:unknown`). When `max_indicator_count` is set, that value is sent as the row limit. When it is omitted, GreyNoise applies its own cap.
- If GreyNoise is still building a file, the function waits and checks again until the file is ready or 10 minutes have passed.
- Every run downloads the file and overwrites `ti_greynoise_indicators.csv` in the specified NG-SIEM repository (default: `search-all`). The lookup file uses this format:
  - source.ip
  - source.ip.greynoise.is.actor
  - source.ip.greynoise.is.classification
  - source.ip.greynoise.is.last_seen_timestamp
  - source.ip.greynoise.is.asn
  - source.ip.greynoise.is.source_country_code
  - source.ip.greynoise.is.spoofable
  - source.ip.greynoise.is.tags
  - source.ip.greynoise.is.tor
  - source.ip.greynoise.is.vpn
  - source.ip.greynoise.is.vpn_service
  - source.ip.greynoise.bs.trust_level
  - source.ip.greynoise.bs.category
  - source.ip.greynoise.bs.name
- Every run also overwrites `ti_greynoise_callback_indicators.csv`. When `include_callback_feed` is `true`, that file is the pre-built callback feed for the last 7 days. A key without the Callback / C2 Intelligence entitlement fails the run. When the flag is `false`, the lookup is overwritten with the column headers and one blank row, so NG-SIEM keeps the file and it matches no indicators. The columns are:
  - source.ip
  - source.ip.greynoise.callback.is_stage2
  - source.ip.greynoise.callback.is_stage1
  - source.ip.greynoise.callback.is_riot
  - source.ip.greynoise.callback.riot_trust_level
  - source.ip.greynoise.callback.first_seen
  - source.ip.greynoise.callback.last_seen
  - source.ip.greynoise.callback.scanner_count
  - source.ip.greynoise.callback.file_count
  - source.ip.greynoise.callback.source_country_code
- Both feeds are attempted before the function reports failure. A GreyNoise or NG-SIEM error fails the run and includes the API's message. A feed that already uploaded is left in place.

### Example queries:
The function requires a GreyNoise Query using GNQL, which returns the indicators to import into NG-SIEM.

The default query included is: `last_seen:1d -classification:unknown`

The default query will pull all indicators from GreyNoise with observed scanning in the last day, except for those classified as unknown.

Some additional queries that may be useful:
- All recently malicious IPs: `last_seen:1d last_seen_malicious:1d classification:malicious`
- All observed IPs from the last day: `last_seen:1d`
- IPs observed with Vendor (replace VENDOR with vendor name) attack tags in the last day: `last_seen_malicious:1d AND classification:malicious AND spoofable:false AND tags:VENDOR`

After installing this app, you can find its workflow in **Fusion SOAR** > **Workflows**. This workflow:

- Runs automatically every hour, at the top of the hour, Eastern Time (America/New_York)
- Skips a new run when the previous run is still in progress
- Can also be triggered manually through the CrowdStrike platform

For assistance, please reach out to [support@greynoise.io](support@greynoise.io).
