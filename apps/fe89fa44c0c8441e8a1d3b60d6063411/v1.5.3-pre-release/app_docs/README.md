![GreyNoise](greynoise2.png)

# GreyNoise Threat Intel Import to NG-SIEM
This app has a Python function that downloads GreyNoise threat intelligence via the GreyNoise API.

## Requirements:
- A GreyNoise Subscription
- A GreyNoise [API Key](https://viz.greynoise.io/account/api-key)

## Function Details
- The function downloads indicators from the GreyNoise v3 GNQL Metadata API based on the provided query (default: `last_seen:1d -classification:unknown`)
- The function then converts this data to a CSV file with the following format:
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
- Finally, it uploads lookup files to NG-SIEM using FalconPy:
  - Uploads CSVs to the specified NG-SIEM repository (default: "search-all").
  - Returns status information.

### Example queries:
The function requires a GreyNoise Query using GNQL, which returns the indicators to import into NG-SIEM.

The default query included is: `last_seen:1d -classification:unknown`

The default query will pull all indicators from GreyNoise with observed scanning in the last day, except for those classified as unknown.

Some additional queries that may be useful:
- All recently malicious IPs: `last_seen:1d last_seen_malicious:1d classification:malicious`
- All observed IPs from the last day: `last_seen:1d`
- IPs observed with Vendor (repalace VENDOR with vendor name) attack tags in the last day: `last_seen_malicious:1d AND classification:malicious AND spoofable:false AND tags:VENDOR`

After installing this app, you can find its workflow in **Fusion SOAR** > **Workflows**. This workflow:

- Runs automatically at 3:00 AM Eastern Time (America/New_York) every day
- Can also be triggered manually through the CrowdStrike platform

The source code for this app can be found on GitHub: [https://github.com/GreyNoise-Intelligence/greynoise-crowdstrike-foundry](https://github.com/GreyNoise-Intelligence/greynoise-crowdstrike-foundry)] 


