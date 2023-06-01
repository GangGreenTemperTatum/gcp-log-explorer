# Log Ingestion Monitoring (Metrics)

- Log ingestion, meaning "volume/amount" of logs per-"X" (`metric = day/week/month hour/minute/second`)

- When using the GCP native default ["Logs-based Metrics"](https://cloud.google.com/monitoring/api/metrics_gcp) (not for buckets), **the metric is a delta and the measure is a rate, so it won't show cumulative**

![image](https://github.com/GangGreenTemperTatum/gcp-log-explorer/assets/104169244/91568b72-4cac-4864-8ae1-abdd08be0e0b)

- - To remediate this:

1. Go into the `CODE EDITOR` pane and use the query language

![image](https://github.com/GangGreenTemperTatum/gcp-log-explorer/assets/104169244/6072417d-1964-4f16-8c0e-7b4b7353d62a)

```
fetch global
| metric 'logging.googleapis.com/billing/bytes_ingested'
| group_by 1d, [value_bytes_ingested_aggregate: aggregate(value.bytes_ingested)]
| every 1d
| group_by [resource.project_id],
    [value_bytes_ingested_aggregate_aggregate:
       aggregate(value_bytes_ingested_aggregate)]
```

- The aggregate operator doesn't seem to be exposed in the GUI query builder. that's the key to convert incremental to cumulative
- `MQL` is google's timeseries query language, the `CODE EDITOR` also supports `PromQL` syntax if you prefer (not 100% equivalent but either one is sufficient for most use cases)

![image](https://github.com/GangGreenTemperTatum/gcp-log-explorer/assets/104169244/9914eb7e-e923-4e0c-8488-27fc6dff0bc9)

# Log Ingestion Monitoring (Metrics) - Drill-Down

- What if we want to drill-down further and identify services, resources hogging high amounts of logs? 

## **Additional Resources**:

- [List metric and resource types](https://cloud.google.com/monitoring/custom-metrics/browsing-metrics)
- [REST API Docs - `REST Resource: projects.metricDescriptors`](https://cloud.google.com/monitoring/api/ref_v3/rest/v3/projects.metricDescriptors) 
- [Sample MQL Queries](https://cloud.google.com/monitoring/mql/examples)

- We can add additional `group_by` values such as `metric.resource_type`

```
fetch global
| metric 'logging.googleapis.com/billing/bytes_ingested'
| group_by 1d, [value_bytes_ingested_aggregate: aggregate(value.bytes_ingested)]
| every 1d
| group_by [resource.project_id : metric.resource_type],
    [value_bytes_ingested_aggregate_aggregate:
       aggregate(value_bytes_ingested_aggregate)]
```

- I personally like the numerical chart to display this example as drilling-down by GCE Service enabled (I.E `metric.resource_type`)

![image](https://github.com/GangGreenTemperTatum/gcp-log-explorer/assets/104169244/d99768a8-130c-49aa-a251-a232b510b9cf)
