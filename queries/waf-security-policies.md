- [Log Explorer Overview](https://cloud.google.com/logging/docs/view/logs-explorer-interface)
- [Logging Query Language](https://cloud.google.com/logging/docs/view/logging-query-language)

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

# Security Policies Preview (Would be Denied by CloudArmor):

* The `jsonPayload.previewSecurityPolicy` field provides details on the rule priority, which tells you the rule and the outcome if the rule was not in preview.

```
resource.type="http_load_balancer"
jsonPayload.previewSecurityPolicy.outcome="DENY"
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

# :

```
code
```

# :

```
code
```

# :

```
code
```
