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

![image](https://github.com/GangGreenTemperTatum/gcp-log-explorer/assets/104169244/acc9c2a5-b8d1-4989-b96e-ad7a23301211)

## Creating the Base Logging Query to Build From:

- Therefore, this determines that metadata (via `labels`) only included by default are mainly related to `request_count`
- We want to dig further and provide metrics and dashboards to give us insight
- Using the [Log Metric Syntax doc](https://cloud.google.com/logging/docs/view/logging-query-language) we can build an advanced query to pull in the specific data we want to monitor:

```
LOGGING QUERY INSERT HERE
```

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
