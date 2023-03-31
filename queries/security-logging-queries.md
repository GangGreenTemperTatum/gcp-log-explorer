- [Log Explorer Overview](https://cloud.google.com/logging/docs/view/logs-explorer-interface)
- [Logging Query Language](https://cloud.google.com/logging/docs/view/logging-query-language)

# Audit logs—all:

```
logName:"cloudaudit.googleapis.com"
```

# Audit logs- Access Transparency (AXT):

```
log_id("cloudaudit.googleapis.com/access_transparency")
```

# Audit logs- Admin Activity:

```
log_id("cloudaudit.googleapis.com/activity")
```

# Audit logs- Data Access:

```
log_id("cloudaudit.googleapis.com/data_access")
```

# Audit logs- System Event:

```
log_id("cloudaudit.googleapis.com/system_event")
```

# Firewall Logs - All:

```
resource.type="gce_subnetwork" AND
log_id("compute.googleapis.com/firewall")
```

# Firewall Logs - Country:

```
resource.type="gce_subnetwork" AND
log_id("compute.googleapis.com/firewall") AND
jsonPayload.remote_location.country=COUNTRY_ISO_ALPHA_3
```

# Firewall Logs - VM:

```
resource.type="gce_subnetwork" AND
log_id("compute.googleapis.com/firewall") AND
jsonPayload.instance.vm_name="INSTANCE_NAME"
```

# Firewall Logs - Subnet:

```
resource.type="gce_subnetwork" AND
log_id("compute.googleapis.com/firewall") AND
resource.labels.subnetwork_name="SUBNET_NAME"
```

# (Intra-VLAN routing) - Compute Engine subnetwork traffic logs to a subnet:

```
resource.type="gce_subnetwork" AND
ip_in_net(jsonPayload.connection.dest_ip, "SUBNET_IP")
```

# VPN gateway logs:

```
resource.type="vpn_gateway" AND
resource.labels.gateway_id="GATEWAY_ID"
```