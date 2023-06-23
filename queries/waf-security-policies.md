- [Log Explorer Overview](https://cloud.google.com/logging/docs/view/logs-explorer-interface)
- [Logging Query Language](https://cloud.google.com/logging/docs/view/logging-query-language)

* Default summary fields for `resource.type:(http_load_balancer)`:
  - `httpRequest.status`
  - `httpRequest.requestMethod`
  - `httpRequest.latency`
  - `httpRequest.userAgent`
  - `httpRequest.responseSize`

* Recommended [Summary Field](https://cloud.google.com/logging/docs/view/logs-explorer-interface#add_summary_fields) additions for detecting high interest log patterns: (persisted in saved queries)
  - `jsonPayload.remoteIp`
  - `httpRequest.requestUrl`
  - `jsonPayload.enforcedSecurityPolicy.name`
  - `jsonPayload.enforcedSecurityPolicy.priority`
  - `jsonPayload.enforcedSecurityPolicy.outcome`
  - `jsonPayload.previewSecurityPolicy.preconfiguredExprIds`

# View errors (I.E `400-4XX,500-5xx` HTTP error codes):

```
severity>=WARNING
```

# Generic Load Balancer Query:

```
resource.type:(http_load_balancer)
```

# Generic WAF Security Policy Query:

```
resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(<NAME>)
```

# HTTP Load Balancer 5xx errors:

```
resource.type="http_load_balancer" AND
httpRequest.status>=500
```

# HTTP Load Balancer requests to PHPMyAdmin:

```
resource.type="http_load_balancer" AND
httpRequest.request_url:"phpmyadmin"
```

# Security Policies Denied by CloudArmor:

```
resource.type="http_load_balancer"
jsonPayload.statusDetails="denied_by_security_policy"
```

# Example - Blocked Countries (502) Security Policies Actively Blocking:

```
resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(<security-policy-name>)
jsonPayload.enforcedSecurityPolicy.priority="<security-policy-id>"
timestamp>="2023-05-25T00:00:00Z" AND timestamp<="2023-07-01T00:02:00Z"
httpRequest.status="502"
```

- - Follow-up verify the "`remoteIP`" within the payload is geo-situated correctly within GCP's threat intel

`whois <ipv4|ipv6> | grep country`

# Security Policies Preview (Would be Denied by CloudArmor):

* The `jsonPayload.previewSecurityPolicy` field provides details on the rule priority, which tells you the rule and the outcome if the rule was not in preview.

```
resource.type="http_load_balancer"
jsonPayload.previewSecurityPolicy.outcome="DENY"
```

# Security Policies Preview (Would be Denied by CloudArmor) for Rate Limiting:

```
resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(<security-policy-name>)
-- Look for rules with ID's #4000, through #4010
jsonPayload.previewSecurityPolicy.priority="4000" --&& jsonPayload.previewSecurityPolicy.priority<="4010"

-- Match traffic not under the `allow` conform which means its within acceptable deemed limits per the rule config
-- -jsonPayload.previewSecurityPolicy.rateLimitAction.outcome="RATE_LIMIT_THRESHOLD_CONFORM"
-- Or, include matching traffic for the exceed_action as a positive match
jsonPayload.previewSecurityPolicy.rateLimitAction.outcome="RATE_LIMIT_THRESHOLD_EXCEED"

timestamp>="2023-06-10T00:00:00Z" AND timestamp<="2023-06-24T00:02:00Z"

-- Reduce logs for traffic matching the intentional endpoints as per the security policy rule, to ensure no other endpoints are being consumed as a false positive
-httpRequest.requestUrl=~"x" OR httpRequest.requestUrl=~"y" OR httpRequest.requestUrl=~"z"
```

# Security Policy Rule Outcomes Matching "`.wp`" URL's requested (I.E, potential scrapers or crawlers looking for `.wp` file extension (WordPress))

- [Tips and tricks for using new RegEx support in Cloud Logging](https://cloud.google.com/blog/products/management-tools/cloud-logging-gets-regular-expression-support)

```
resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(<security-policy-name>)
-jsonPayload.previewSecurityPolicy.priority="201"
httpRequest.requestUrl =~ "\.wp$"
timestamp>="2023-06-12T00:00:00Z" -- AND timestamp<="2023-06-12T00:00:00Z"
--httpRequest.status!="404" || httpRequest.status!="400" || httpRequest.status!="415"
```

- Example from [my repo](https://github.com/GangGreenTemperTatum/gcp-cloud-armor-lab/blob/940b71c2703f92e50c5a1111a6c1ca52bc7dc0b8/variables.tf#L87) of ensuring rate-limiting policies would only capturing the specific intentionally matched endpoints for rate-limiting clients and as such can be moved to `preview = false` once confident

```
resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(<security-policy-name>)
-- Look for rules with ID's #4000, through #4010
jsonPayload.previewSecurityPolicy.priority="4000" --&& jsonPayload.previewSecurityPolicy.priority<="4010"

-- Match traffic not under the `allow` conform which means its within acceptable deemed limits per the rule config
-- -jsonPayload.previewSecurityPolicy.rateLimitAction.outcome="RATE_LIMIT_THRESHOLD_CONFORM"
-- Or, include matching traffic for the exceed_action as a positive match
-- jsonPayload.previewSecurityPolicy.rateLimitAction.outcome="RATE_LIMIT_THRESHOLD_EXCEED"

timestamp>="2023-06-08T00:00:00Z" AND timestamp<="2023-06-22T00:02:00Z"

-- Reduce logs for traffic matching the intentional endpoints as per the security policy rule, to ensure no other endpoints are being consumed as a false positive
-httpRequest.requestUrl=~"RegisterWithEmail" OR httpRequest.requestUrl=~"InviteUser" OR httpRequest.requestUrl=~"RequestPasswordReset"
```

# [Detect Log4Shell Security Exploits](https://cloud.google.com/logging/docs/log4j2-vulnerability):

```
${jndi:
$%7Bjndi:
%24%7Bjndi:
${jNdI:ldAp
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}:
${${lower:j}${lower:n}${lower:d}i:
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}:
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}
```

```
resource.type="http_load_balancer"
httpRequest.requestUrl=~"(?i)(\$|\%24)(\{|\%7b).*j.*n.*d.*i.*(\:|\%3a)" OR
httpRequest.userAgent=~"(?i)(\$|\%24)(\{|\%7b).*j.*n.*d.*i.*(\:|\%3a)" OR
httpRequest.referer=~"(?i)(\$|\%24)(\{|\%7b).*j.*n.*d.*i.*(\:|\%3a)"

# You can use the previous query to scan request logs in other services by changing the value of resource.type.
```

# CloudArmor WAF Rule Summary Except Explicit Allow:

```
resource.type:(http_load_balancer) AND jsonPayload.enforcedSecurityPolicy.name:(<name>)
--resource.labels.policy_name="<name>"

-- remove policy priority matching logs (example, explicit allow rule)
-jsonPayload.enforcedSecurityPolicy.priority="2147483646" AND -jsonPayload.enforcedSecurityPolicy.priority="2147483647"

-- remove permitted policy outcome value
--jsonPayload.enforcedSecurityPolicy.outcome="DENY"

timestamp >= "2023-04-13T08:00:00Z" AND timestamp <= "2023-04-15"
--limit 50

-- Observe potential data exfiltration
-- httpRequest.responseSize>="10000"
```

# :

```
code
```

# :

```
code
```
