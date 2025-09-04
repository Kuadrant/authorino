# Custom Metric Labels for Authorino

This document describes how to configure custom metric labels in Authorino using CEL expressions to extract dynamic values from the authorization context.

## Overview

Authorino supports custom metric labels that allow users to add dynamic labels to Prometheus metrics based on values extracted from the authorization pipeline using CEL (Common Expression Language) expressions. This feature enables more granular monitoring and alerting by adding contextual information such as user IDs, API versions, request methods, and other metadata to metrics.

## Configuration

Custom metric labels are configured via a YAML file that maps label names to CEL expressions. The CEL expressions are evaluated against the authorization JSON context during each request.

### Configuration File Format

```yaml
label_name_1: cel_expression_1
label_name_2: cel_expression_2
label_name_3: cel_expression_3
```

### Example Configuration

```yaml
# examples/custom-metric-labels.yaml
user_id: auth.identity.sub
api_version: request.headers.api_version
user_org: auth.identity.org_id
request_method: request.method
request_path: request.path
client_id: auth.identity.client_id
host: request.host
```

## Command Line Usage

Use the `--custom-metric-labels-file` flag to specify the path to your custom labels configuration file:

```bash
./authorino server \
  --custom-metric-labels-file=/path/to/custom-metric-labels.yaml \
  --other-flags...
```

You can also set the configuration file path using the environment variable:

```bash
export CUSTOM_METRIC_LABELS_FILE=/path/to/custom-metric-labels.yaml
./authorino server
```

## Available CEL Context

The CEL expressions have access to the full authorization JSON context, which includes:

- `request.*` - Request context (HTTP headers, method, path, etc.)
- `auth.identity.*` - Identity information from authentication
- `auth.authorization.*` - Authorization results
- `auth.metadata.*` - Metadata from evaluators
- `source.*` - Source information
- `destination.*` - Destination information

### Common CEL Expression Examples

```yaml
# User information
user_id: auth.identity.sub
username: auth.identity.preferred_username
user_email: auth.identity.email
organization: auth.identity.org_id

# Request information  
http_method: request.http.method
request_path: request.http.path
user_agent: request.http.headers.user_agent

# API versioning
api_version: request.http.headers['x-api-version']
api_version_alt: request.http.headers.get('api-version', 'v1')

# Custom headers
client_id: request.http.headers.get('x-client-id', 'unknown')
trace_id: request.http.headers.get('x-trace-id', '')

# Complex expressions
is_admin: auth.identity.groups.exists(g, g == 'admin') ? 'true' : 'false'
request_size_category: size(request.http.body) > 1024 ? 'large' : 'small'
```

## Impact on Metrics

When custom metric labels are configured, all Authorino metrics will include the additional labels:

### Evaluator Metrics
- `auth_server_evaluator_total{namespace, authconfig, evaluator_type, evaluator_name, <custom_labels>}`
- `auth_server_evaluator_cancelled{namespace, authconfig, evaluator_type, evaluator_name, <custom_labels>}`
- `auth_server_evaluator_ignored{namespace, authconfig, evaluator_type, evaluator_name, <custom_labels>}`
- `auth_server_evaluator_denied{namespace, authconfig, evaluator_type, evaluator_name, <custom_labels>}`
- `auth_server_evaluator_duration_seconds{namespace, authconfig, evaluator_type, evaluator_name, <custom_labels>}`

### AuthConfig Metrics
- `auth_server_authconfig_total{namespace, authconfig, <custom_labels>}`
- `auth_server_authconfig_response_status{namespace, authconfig, status, <custom_labels>}`
- `auth_server_authconfig_duration_seconds{namespace, authconfig, <custom_labels>}`

### Example Metric with Custom Labels

Without custom labels:
```
auth_server_authconfig_total{namespace="default", authconfig="my-api"} 1
```

With custom labels:
```
auth_server_authconfig_total{namespace="default", authconfig="my-api", user_id="user123", request_method="GET", api_version="v2"} 1
```

## Error Handling

- If a CEL expression fails to evaluate, an empty string value is used for that label
- If the custom labels configuration file is invalid, Authorino will fail to start with an error message
- Invalid CEL expressions in the configuration file will cause startup failure

## Performance Considerations

- CEL expressions are compiled once at startup for optimal runtime performance
- Each request evaluates the CEL expressions against the authorization JSON
- Complex CEL expressions may have minimal impact on request latency
- Consider the cardinality impact of custom labels on Prometheus storage and query performance

## Kubernetes Deployment

When deploying in Kubernetes, you can use a ConfigMap to provide the custom labels configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: authorino-custom-metrics
data:
  custom-labels.yaml: |
    user_id: auth.identity.sub
    api_version: request.headers.api_version
    user_org: auth.identity.org_id
    request_method: request.method
    request_path: request.path
    client_id: auth.identity.client_id
    host: request.host
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authorino
spec:
  template:
    spec:
      containers:
      - name: authorino
        image: quay.io/kuadrant/authorino:latest
        args:
        - server
        - --custom-metric-labels-file=/etc/authorino/custom-labels.yaml
        volumeMounts:
        - name: custom-metrics-config
          mountPath: /etc/authorino
      volumes:
      - name: custom-metrics-config
        configMap:
          name: authorino-custom-metrics
```

## Limitations

- Custom labels are applied to all metrics; there's no way to selectively apply them to specific metrics
- Label values are always converted to strings
- The total number of unique label combinations affects Prometheus performance and storage
- Labels with high cardinality (many unique values) should be used carefully to avoid overwhelming Prometheus

## Troubleshooting

### Check Configuration
```bash
# Validate YAML syntax
cat custom-metric-labels.yaml | yaml-validate

# Test CEL expressions using a CEL evaluator tool
```

### Monitor Logs
Look for error messages in Authorino logs related to custom metric labels:
```
Failed to load custom metric labels configuration
Failed to initialize custom metric labels
```

### Verify Metrics
Use Prometheus query to verify custom labels are present:
```promql
auth_server_authconfig_total{your_custom_label="expected_value"}
```
