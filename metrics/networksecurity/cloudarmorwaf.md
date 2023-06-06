# ❗**Update:**

- I stopped this project as I eventually ran into [this issue](https://cloud.google.com/logging/docs/logs-based-metrics/troubleshooting#too-many-time-series). 
- The cardinality problem is a label combination limit..  `count(label_A) * count(label_B) * ... * count(label_N)` must be under 30000 (`<=299991`), otherwise data points start getting lost and not recorded.
- This is not possible with a WAF due to high cardinality fields concatenated from things such as `serverIP` and `remoteIP`
- If it's done with custom log metrics, the better pattern is probably to use the Metrics dashboard to track the incidents at a macro level `(by type)` and then use the Logs Explorer to drill down and filter the low level data... and for example use those `remoteIP` sidebar breakdowns and similar to find the contributors.
- A way around this would be to edit the filter example below for logging query and reduce the # of labels from the metrics, but would not provide sufficient data in my opinion to present in a dashboard
- I was able to see the `metrics.label` populate when editing dashboard panes, but simply no data was displayed
- Within the dashboard panes when attempting to configure custom graphs, I also had to amend the `fetch` nested `metric` value from CloudArmor WAF default `'| metric networksecurity.googleapis.com/https/request_count'` to `| metric 'logging.googleapis.com/user/<metric-name>` for these fields to populate from my custom metric

- Look's like this is not possible and would recommend a SIEM or log aggregation tool to achieve this

# Prior Work:

## Summary of pulling stats into GCS Monitoring Dashboards via Metrics:

In this example, I use the GCS Network Security Policy resource for CloudArmor WAF

- Default metrics are not billed in GCS
- Custom Metrics (which can be built from the Log Explorer) are billed based on ingestion - See [sku](https://cloud.google.com/skus/sku-groups/cloud-monitoring) and [here](https://cloud.google.com/skus/?currency=USD&filter=A924-09D0-8854)
  - See the following links which define what is exactly "pulled through" as a default metric for GCS resources
<br>

- [`tag_global`](https://cloud.google.com/monitoring/api/resources#tag_global)
- [`metrics_gcp`](https://cloud.google.com/monitoring/api/metrics_gcp)
- [`metrics_gcp/gcp-networksecurity`](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-networksecurity)

<br>

- An example of searching for "Security" we can see [networksecurity](https://cloud.google.com/monitoring/api/metrics_gcp#gcp-networksecurity) subset with many sub-HTML links:

<br>

![image](https://github.com/GangGreenTemperTatum/gcp-log-explorer/assets/104169244/9301eb2a-6aa6-427d-9c07-c8147a61268f)

- Problem here, is that the default metric's do not pull in what we are looking for specifically

## Creating the Base Logging Query to Build From:

- Therefore, this determines that metadata (via `labels`) only included by default are mainly related to `request_count`
- We want to dig further and provide metrics and dashboards to give us insight
- Using the [Log Metric Syntax doc](https://cloud.google.com/logging/docs/view/logging-query-language) we can build an advanced query to pull in the specific data we want to monitor:

```
resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(<security-policy-name>)

-- httpRequest --
-- Filter anything not RFC1918 CIDR ranges for remoteIP
NOT (ip_in_net(httpRequest.remoteIp,"10.0.0.0/8") OR ip_in_net(httpRequest.remoteIp,"192.168.0.0/16") OR ip_in_net(httpRequest.remoteIp,"80.76.0.0/16"))
-- Filter RFC1918 CIDR ranges for serverIP
(ip_in_net(httpRequest.serverIp,"10.0.0.0/8") OR ip_in_net(httpRequest.serverIp,"192.168.0.0/16") OR ip_in_net(httpRequest.serverIp,"80.76.0.0/16"))
-- Include all Requested URLs, not the
httpRequest.requestUrl=~".*"
-- Filter Success, Client Errors and Server Errors
httpRequest.status=200 OR httpRequest.status>=400 AND httpRequest.status<=599
-- Include all User Agents
httpRequest.userAgent=~".*"

-- enforcedSecurityPolicy --
-- Include the security policy enforced action configured and outcome
jsonPayload.enforcedSecurityPolicy.configuredAction=~".*" -- Configured action of traffic as per matching rule
jsonPayload.enforcedSecurityPolicy.outcome=~".*" -- Actual representation of traffic outcome
jsonPayload.enforcedSecurityPolicy.name=~".*" -- Matching Security Policy name, not matching Rule description
jsonPayload.enforcedSecurityPolicy.priority>=1 AND jsonPayload.enforcedSecurityPolicy.priority<=2147483647 -- Actual matching Rule ID

-- previewSecurityPolicy --
-- Include the PREVIEW security policy which would have been enforced and outcome
jsonPayload.previewSecurityPolicy.configuredAction=~".*" -- Configured action for rule in PREVIEW=true mode
jsonPayload.previewSecurityPolicy.priority>=1 AND jsonPayload.previewSecurityPolicy.priority<=2147483647 -- Hypothetical matching Rule ID of traffic for rule in PREVIEW=true mode
jsonPayload.previewSecurityPolicy.outcome=~".*" -- Hypothetical outcome of traffic for rule in PREVIEW=true mode
jsonPayload.previewSecurityPolicy.matchedFieldValue=~".*" -- What ARGUMENT triggered this rule
jsonPayload.previewSecurityPolicy.preconfiguredExprIds=~".*" -- What syntax or CRS rule within the rule forced the match of this traffic

-- Use a timestamp if needed to gather historic logs
-- timestamp>="2023-07-01T00:00:01Z" AND timestamp<="2023-07-01T23:59:00Z"
```

This means, through a metric we can now pull these metadata endpoints into a dashboard

![image](https://github.com/GangGreenTemperTatum/gcp-log-explorer/assets/104169244/acc9c2a5-b8d1-4989-b96e-ad7a23301211)

- Be as specific as possible to reduce ingestion costs here
  - Define exactly what you look to monitor/report and alert on 
  - Filter for only specific metrics you want to ingest
  - Where you do want to ingest, be as specific as possible (I.E: filter srcip/dstip ranges, status code ranges) etc.


## Creating the Metric from the Logging Query

- Either [creating a Logging Metric with Terraform](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/logging_metric) or from the Log Explorer sub-link.
- Here is an example using the above logging query in `MQL` syntax

```
METRIC SYNTAX INSERT HERE
```

<SNIP!>

- GCP supports both [MQL](https://cloud.google.com/monitoring/mql/examples) as well as [PromQL](https://cloud.google.com/monitoring/promql) query language for metrics

## Creating the Dashboard from the Metric

- Then in Metrics Explorer or Dashboards or any other system that refers to metrics, you should be able to search by the "name" you get. The metrics for log-based metrics aren't instant (they can take awhile to appear and to backfill old data) so turn off the "show only active resources" as needed

![image](https://github.com/GangGreenTemperTatum/gcp-log-explorer/assets/104169244/fe6f9cc8-d009-41a5-8b9d-93441efed9fc)

- You can refer to it directly in the MQL box like this:

```
fetch l7_lb_rule
| metric 'logging.googleapis.com/user/ethan-test-log-metric-02jun2023'
| align rate(1m)
| every 1m
| group_by [], [value_jun2023_mean: mean(value.jun2023)]
| group_by 1m, [value_jun2023_mean_mean: mean(value_jun2023_mean)]
| every 1m
```

- And then refer to your custom labels using the `metric.your-label-name` syntax. auto-complete suggestions work and are smart enough for this
- In this case the Log-based Metric is smart enough to know it's based on a Load Balancer event (in my case) and also automatically makes the l7_lb_rule indexes available as well using the resource. prefix.

![image](https://github.com/GangGreenTemperTatum/gcp-log-explorer/assets/104169244/c9684950-9e0a-4750-a8ad-b1b330801b18)
