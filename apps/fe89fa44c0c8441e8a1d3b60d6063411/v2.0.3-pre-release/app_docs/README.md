![GreyNoise](greynoise2.png)

# GreyNoise Threat Intel Import to NG-SIEM
This app has a Python function that downloads GreyNoise threat intelligence via the GreyNoise API.

## Requirements:
- A GreyNoise Subscription
- A GreyNoise [API Key](https://viz.greynoise.io/account/api-key)
- (Optional) GreyNoise Callback / C2 Intelligence entitlement, required only if enabling the Callback Indicator feed

## Function Details
- The function downloads indicators from the GreyNoise v3 GNQL Metadata API based on the provided query (default: `last_seen:1d -classification:unknown`)
- The function then converts this data to a CSV file (`ti_greynoise_indicators.csv`) with the following format:
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
- Optionally, when `include_callback_feed` is set to `true` and the API key is entitled for Callback / C2 Intelligence, the function also downloads Callback Indicator IPs observed in the last 7 days via the GreyNoise Callback API and writes a second CSV (`ti_greynoise_callback_indicators.csv`) with the following format:
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
- The main indicator feed and optional Callback feed are processed independently. If one feed fails, any successfully generated feed is still uploaded.
- Finally, it uploads lookup files to NG-SIEM using FalconPy:
  - Uploads CSVs to the specified NG-SIEM repository (default: "search-all").
  - Returns status information for each uploaded feed.

### Example queries:
The function requires a GreyNoise Query using GNQL, which returns the indicators to import into NG-SIEM.

The default query included is: `last_seen:1d -classification:unknown`

The default query will pull all indicators from GreyNoise with observed scanning in the last day, except for those classified as unknown.

Some additional queries that may be useful:
- All recently malicious IPs: `last_seen:1d last_seen_malicious:1d classification:malicious`
- All observed IPs from the last day: `last_seen:1d`
- IPs observed with Vendor (replace VENDOR with vendor name) attack tags in the last day: `last_seen_malicious:1d AND classification:malicious AND spoofable:false AND tags:VENDOR`

After installing this app, you can find its workflow in **Fusion SOAR** > **Workflows**. This workflow:

- Runs automatically at 3:00 AM Eastern Time (America/New_York) every day
- Can also be triggered manually through the CrowdStrike platform

For assistance, please reach out to [support@greynoise.io](support@greynoise.io).
