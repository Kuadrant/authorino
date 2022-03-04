# Observability

Authorino exports metrics in 2 endpoints:

<table>
  <tr>
    <td><strong>/metrics</strong></td>
    <td>Metrics of the controller-runtime about reconciliation (caching) of AuthConfigs and API key Secrets</td>
  </tr>
  <tr>
    <td><strong>/server-metrics</strong></td>
    <td>Metrics of the external authorization gRPC and OIDC/Festival Writband validation built-in HTTP servers</td>
  </tr>
</table>

The [Authorino Operator](https://github.com/kuadrant/authorino-operator) creates a Service named `<authorino-cr-name>-controller-metrics` that exposes the endpoints on port 8080. The Authorino instance allows to modify the port number of the metrics endpoints, by setting the `metrics-addr` command-line argument (default: `:8080`).

## Main metrics exported by endpoint

<table>
  <thead>
    <tr>
      <td colspan="4"><strong>/metrics</strong></td>
    </tr>
    <tr>
      <th>Metric name</th>
      <th>Description&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</th>
      <th>Labels</th>
      <th>Type</th>
    <tr>
  </thead>
  <tbody>
    <tr>
      <td>controller_runtime_reconcile_total</td>
      <td>Total number of reconciliations per controller</td>
      <td><code>controller=authconfig|secret</code>, <code>result=success|error|requeue</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>controller_runtime_reconcile_errors_total</td>
      <td>Total number of reconciliation errors per controller</td>
      <td><code>controller=authconfig|secret</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>controller_runtime_reconcile_time_seconds</td>
      <td>Length of time per reconciliation per controller</td>
      <td><code>controller=authconfig|secret</code></td>
      <td>histogram</td>
    </tr>
    <tr>
      <td>controller_runtime_max_concurrent_reconciles</td>
      <td>Maximum number of concurrent reconciles per controller</td>
      <td><code>controller=authconfig|secret</code></td>
      <td>gauge</td>
    </tr>
    <tr>
      <td>workqueue_adds_total</td>
      <td>Total number of adds handled by workqueue</td>
      <td><code>name=authconfig|secret</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>workqueue_depth</td>
      <td>Current depth of workqueue</td>
      <td><code>name=authconfig|secret</code></td>
      <td>gauge</td>
    </tr>
    <tr>
      <td>workqueue_queue_duration_seconds</td>
      <td>How long in seconds an item stays in workqueue before being requested</td>
      <td><code>name=authconfig|secret</code></td>
      <td>histogram</td>
    </tr>
    <tr>
      <td>workqueue_longest_running_processor_seconds</td>
      <td>How many seconds has the longest running processor for workqueue been running.</td>
      <td><code>name=authconfig|secret</code></td>
      <td>gauge</td>
    </tr>
    <tr>
      <td>workqueue_retries_total</td>
      <td>Total number of retries handled by workqueue</td>
      <td><code>name=authconfig|secret</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>workqueue_unfinished_work_seconds</td>
      <td>How many seconds of work has been done that is in progress and hasn't been observed by work_duration.</td>
      <td><code>name=authconfig|secret</code></td>
      <td>gauge</td>
    </tr>
    <tr>
      <td>workqueue_work_duration_seconds</td>
      <td>How long in seconds processing an item from workqueue takes.</td>
      <td><code>name=authconfig|secret</code></td>
      <td>histogram</td>
    </tr>
    <tr>
      <td>rest_client_requests_total</td>
      <td>Number of HTTP requests, partitioned by status code, method, and host.</td>
      <td><code>code=200|404</code>, <code>method=GET|PUT|POST</code></td>
      <td>counter</td>
    </tr>
  </tbody>
  <thead>
    <tr>
      <td colspan="4"><br/><br/><strong>/server-metrics</strong></td>
    </tr>
    <tr>
      <th>Metric name</th>
      <th>Description</th>
      <th>Labels</th>
      <th>Type</th>
    <tr>
  </thead>
  <tbody>
    <tr>
      <td>auth_server_evaluator_total(*)</td>
      <td>Total number of evaluations of individual authconfig rule performed by the auth server.</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>evaluator_type</code>, <code>evaluator_name</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_evaluator_cancelled(*)</td>
      <td>Number of evaluations of individual authconfig rule cancelled by the auth server.</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>evaluator_type</code>, <code>evaluator_name</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_evaluator_ignored(*)</td>
      <td>Number of evaluations of individual authconfig rule ignored by the auth server.</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>evaluator_type</code>, <code>evaluator_name</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_evaluator_denied(*)</td>
      <td>Number of denials from individual authconfig rule evaluated by the auth server.</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>evaluator_type</code>, <code>evaluator_name</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_evaluator_duration_seconds(*)</td>
      <td>Response latency of individual authconfig rule evaluated by the auth server (in seconds).</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>evaluator_type</code>, <code>evaluator_name</code></td>
      <td>histogram</td>
    </tr>
    <tr>
      <td>auth_server_authconfig_total</td>
      <td>Total number of authconfigs enforced by the auth server, partitioned by authconfig.</td>
      <td><code>namespace</code>, <code>authconfig</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_authconfig_response_status</td>
      <td>Response status of authconfigs sent by the auth server, partitioned by authconfig.</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>status=OK|UNAUTHENTICATED,PERMISSION_DENIED</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_authconfig_duration_seconds</td>
      <td>Response latency of authconfig enforced by the auth server (in seconds).</td>
      <td><code>namespace</code>, <code>authconfig</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_response_status</td>
      <td>Response status of authconfigs sent by the auth server.</td>
      <td><code>status=OK|UNAUTHENTICATED,PERMISSION_DENIED|NOT_FOUND</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>grpc_server_handled_total</td>
      <td>Total number of RPCs completed on the server, regardless of success or failure.</td>
      <td><code>grpc_code=OK|Aborted|Canceled|DeadlineExceeded|Internal|ResourceExhausted|Unknown</code>, <code>grpc_method=Check</code>, <code>grpc_service=envoy.service.auth.v3.Authorization</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>grpc_server_handling_seconds</td>
      <td>Response latency (seconds) of gRPC that had been application-level handled by the server.</td>
      <td><code>grpc_method=Check</code>, <code>grpc_service=envoy.service.auth.v3.Authorization</code></td>
      <td>histogram</td>
    </tr>
    <tr>
      <td>grpc_server_msg_received_total</td>
      <td>Total number of RPC stream messages received on the server.</td>
      <td><code>grpc_method=Check</code>, <code>grpc_service=envoy.service.auth.v3.Authorization</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>grpc_server_msg_sent_total</td>
      <td>Total number of gRPC stream messages sent by the server.</td>
      <td><code>grpc_method=Check</code>, <code>grpc_service=envoy.service.auth.v3.Authorization</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>grpc_server_started_total</td>
      <td>Total number of RPCs started on the server.</td>
      <td><code>grpc_method=Check</code>, <code>grpc_service=envoy.service.auth.v3.Authorization</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>oidc_server_requests_total</td>
      <td>Number of get requests received on the OIDC (Festival Wristband) server.</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>wristband</code>, <code>path=oidc-config|jwks</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>oidc_server_response_status</td>
      <td>Status of HTTP response sent by the OIDC (Festival Wristband) server.</td>
      <td><code>status=200|404</code></td>
      <td>counter</td>
    </tr>
  </tbody>
</table>

Both endpoints also export metrics about the Go runtime, such as number of goroutines (go_goroutines) and threads (go_threads), usage of CPU, memory and GC stats.

<small><strong>(\*) Opt-in metrics:</strong> <code>auth_server_evaluator_*</code> metrics require <code>authconfig.spec.(identity|metadata|authorization|response).metrics: true</code> (default: <code>false</code>). This can be enforced for the entire instance (all AuthConfigs and evaluators), by setting the <code>DEEP_METRICS_ENABLED=true</code> environment variable in the Authorino deployment.<small>

## Examples

### /metrics

```ini
# HELP controller_runtime_active_workers Number of currently used workers per controller
# TYPE controller_runtime_active_workers gauge
controller_runtime_active_workers{controller="authconfig"} 0
controller_runtime_active_workers{controller="secret"} 0
# HELP controller_runtime_max_concurrent_reconciles Maximum number of concurrent reconciles per controller
# TYPE controller_runtime_max_concurrent_reconciles gauge
controller_runtime_max_concurrent_reconciles{controller="authconfig"} 1
controller_runtime_max_concurrent_reconciles{controller="secret"} 1
# HELP controller_runtime_reconcile_errors_total Total number of reconciliation errors per controller
# TYPE controller_runtime_reconcile_errors_total counter
controller_runtime_reconcile_errors_total{controller="authconfig"} 12
controller_runtime_reconcile_errors_total{controller="secret"} 0
# HELP controller_runtime_reconcile_time_seconds Length of time per reconciliation per controller
# TYPE controller_runtime_reconcile_time_seconds histogram
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.005"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.01"} 11
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.025"} 17
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.05"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.1"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.15"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.2"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.25"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.3"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.35"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.4"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.45"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.5"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.6"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.7"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.8"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="0.9"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="1"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="1.25"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="1.5"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="1.75"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="2"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="2.5"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="3"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="3.5"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="4"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="4.5"} 18
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="5"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="6"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="7"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="8"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="9"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="10"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="15"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="20"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="25"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="30"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="40"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="50"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="60"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="authconfig",le="+Inf"} 19
controller_runtime_reconcile_time_seconds_sum{controller="authconfig"} 5.171108321999999
controller_runtime_reconcile_time_seconds_count{controller="authconfig"} 19
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.005"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.01"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.025"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.05"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.1"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.15"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.2"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.25"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.3"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.35"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.4"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.45"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.5"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.6"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.7"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.8"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="0.9"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="1"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="1.25"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="1.5"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="1.75"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="2"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="2.5"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="3"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="3.5"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="4"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="4.5"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="5"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="6"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="7"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="8"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="9"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="10"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="15"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="20"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="25"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="30"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="40"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="50"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="60"} 1
controller_runtime_reconcile_time_seconds_bucket{controller="secret",le="+Inf"} 1
controller_runtime_reconcile_time_seconds_sum{controller="secret"} 0.000138025
controller_runtime_reconcile_time_seconds_count{controller="secret"} 1
# HELP controller_runtime_reconcile_total Total number of reconciliations per controller
# TYPE controller_runtime_reconcile_total counter
controller_runtime_reconcile_total{controller="authconfig",result="error"} 12
controller_runtime_reconcile_total{controller="authconfig",result="requeue"} 0
controller_runtime_reconcile_total{controller="authconfig",result="requeue_after"} 0
controller_runtime_reconcile_total{controller="authconfig",result="success"} 7
controller_runtime_reconcile_total{controller="secret",result="error"} 0
controller_runtime_reconcile_total{controller="secret",result="requeue"} 0
controller_runtime_reconcile_total{controller="secret",result="requeue_after"} 0
controller_runtime_reconcile_total{controller="secret",result="success"} 1
# HELP go_gc_cycles_automatic_gc_cycles_total Count of completed GC cycles generated by the Go runtime.
# TYPE go_gc_cycles_automatic_gc_cycles_total counter
go_gc_cycles_automatic_gc_cycles_total 13
# HELP go_gc_cycles_forced_gc_cycles_total Count of completed GC cycles forced by the application.
# TYPE go_gc_cycles_forced_gc_cycles_total counter
go_gc_cycles_forced_gc_cycles_total 0
# HELP go_gc_cycles_total_gc_cycles_total Count of all completed GC cycles.
# TYPE go_gc_cycles_total_gc_cycles_total counter
go_gc_cycles_total_gc_cycles_total 13
# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 4.5971e-05
go_gc_duration_seconds{quantile="0.25"} 5.69e-05
go_gc_duration_seconds{quantile="0.5"} 0.000140699
go_gc_duration_seconds{quantile="0.75"} 0.000313162
go_gc_duration_seconds{quantile="1"} 0.001692423
go_gc_duration_seconds_sum 0.003671076
go_gc_duration_seconds_count 13
# HELP go_gc_heap_allocs_by_size_bytes_total Distribution of heap allocations by approximate size. Note that this does not include tiny objects as defined by /gc/heap/tiny/allocs:objects, only tiny blocks.
# TYPE go_gc_heap_allocs_by_size_bytes_total histogram
go_gc_heap_allocs_by_size_bytes_total_bucket{le="8.999999999999998"} 6357
go_gc_heap_allocs_by_size_bytes_total_bucket{le="16.999999999999996"} 45065
[...]
go_gc_heap_allocs_by_size_bytes_total_bucket{le="32768.99999999999"} 128306
go_gc_heap_allocs_by_size_bytes_total_bucket{le="+Inf"} 128327
go_gc_heap_allocs_by_size_bytes_total_sum 1.5021512e+07
go_gc_heap_allocs_by_size_bytes_total_count 128327
# HELP go_gc_heap_allocs_bytes_total Cumulative sum of memory allocated to the heap by the application.
# TYPE go_gc_heap_allocs_bytes_total counter
go_gc_heap_allocs_bytes_total 1.5021512e+07
# HELP go_gc_heap_allocs_objects_total Cumulative count of heap allocations triggered by the application. Note that this does not include tiny objects as defined by /gc/heap/tiny/allocs:objects, only tiny blocks.
# TYPE go_gc_heap_allocs_objects_total counter
go_gc_heap_allocs_objects_total 128327
# HELP go_gc_heap_frees_by_size_bytes_total Distribution of freed heap allocations by approximate size. Note that this does not include tiny objects as defined by /gc/heap/tiny/allocs:objects, only tiny blocks.
# TYPE go_gc_heap_frees_by_size_bytes_total histogram
go_gc_heap_frees_by_size_bytes_total_bucket{le="8.999999999999998"} 3885
go_gc_heap_frees_by_size_bytes_total_bucket{le="16.999999999999996"} 33418
[...]
go_gc_heap_frees_by_size_bytes_total_bucket{le="32768.99999999999"} 96417
go_gc_heap_frees_by_size_bytes_total_bucket{le="+Inf"} 96425
go_gc_heap_frees_by_size_bytes_total_sum 9.880944e+06
go_gc_heap_frees_by_size_bytes_total_count 96425
# HELP go_gc_heap_frees_bytes_total Cumulative sum of heap memory freed by the garbage collector.
# TYPE go_gc_heap_frees_bytes_total counter
go_gc_heap_frees_bytes_total 9.880944e+06
# HELP go_gc_heap_frees_objects_total Cumulative count of heap allocations whose storage was freed by the garbage collector. Note that this does not include tiny objects as defined by /gc/heap/tiny/allocs:objects, only tiny blocks.
# TYPE go_gc_heap_frees_objects_total counter
go_gc_heap_frees_objects_total 96425
# HELP go_gc_heap_goal_bytes Heap size target for the end of the GC cycle.
# TYPE go_gc_heap_goal_bytes gauge
go_gc_heap_goal_bytes 9.356624e+06
# HELP go_gc_heap_objects_objects Number of objects, live or unswept, occupying heap memory.
# TYPE go_gc_heap_objects_objects gauge
go_gc_heap_objects_objects 31902
# HELP go_gc_heap_tiny_allocs_objects_total Count of small allocations that are packed together into blocks. These allocations are counted separately from other allocations because each individual allocation is not tracked by the runtime, only their block. Each block is already accounted for in allocs-by-size and frees-by-size.
# TYPE go_gc_heap_tiny_allocs_objects_total counter
go_gc_heap_tiny_allocs_objects_total 11750
# HELP go_gc_pauses_seconds_total Distribution individual GC-related stop-the-world pause latencies.
# TYPE go_gc_pauses_seconds_total histogram
go_gc_pauses_seconds_total_bucket{le="9.999999999999999e-10"} 0
go_gc_pauses_seconds_total_bucket{le="1.9999999999999997e-09"} 0
[...]
go_gc_pauses_seconds_total_bucket{le="206708.18602188796"} 26
go_gc_pauses_seconds_total_bucket{le="+Inf"} 26
go_gc_pauses_seconds_total_sum 0.003151488
go_gc_pauses_seconds_total_count 26
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 80
# HELP go_info Information about the Go environment.
# TYPE go_info gauge
go_info{version="go1.17.7"} 1
# HELP go_memory_classes_heap_free_bytes Memory that is completely free and eligible to be returned to the underlying system, but has not been. This metric is the runtime's estimate of free address space that is backed by physical memory.
# TYPE go_memory_classes_heap_free_bytes gauge
go_memory_classes_heap_free_bytes 589824
# HELP go_memory_classes_heap_objects_bytes Memory occupied by live objects and dead objects that have not yet been marked free by the garbage collector.
# TYPE go_memory_classes_heap_objects_bytes gauge
go_memory_classes_heap_objects_bytes 5.140568e+06
# HELP go_memory_classes_heap_released_bytes Memory that is completely free and has been returned to the underlying system. This metric is the runtime's estimate of free address space that is still mapped into the process, but is not backed by physical memory.
# TYPE go_memory_classes_heap_released_bytes gauge
go_memory_classes_heap_released_bytes 4.005888e+06
# HELP go_memory_classes_heap_stacks_bytes Memory allocated from the heap that is reserved for stack space, whether or not it is currently in-use.
# TYPE go_memory_classes_heap_stacks_bytes gauge
go_memory_classes_heap_stacks_bytes 786432
# HELP go_memory_classes_heap_unused_bytes Memory that is reserved for heap objects but is not currently used to hold heap objects.
# TYPE go_memory_classes_heap_unused_bytes gauge
go_memory_classes_heap_unused_bytes 2.0602e+06
# HELP go_memory_classes_metadata_mcache_free_bytes Memory that is reserved for runtime mcache structures, but not in-use.
# TYPE go_memory_classes_metadata_mcache_free_bytes gauge
go_memory_classes_metadata_mcache_free_bytes 13984
# HELP go_memory_classes_metadata_mcache_inuse_bytes Memory that is occupied by runtime mcache structures that are currently being used.
# TYPE go_memory_classes_metadata_mcache_inuse_bytes gauge
go_memory_classes_metadata_mcache_inuse_bytes 2400
# HELP go_memory_classes_metadata_mspan_free_bytes Memory that is reserved for runtime mspan structures, but not in-use.
# TYPE go_memory_classes_metadata_mspan_free_bytes gauge
go_memory_classes_metadata_mspan_free_bytes 17104
# HELP go_memory_classes_metadata_mspan_inuse_bytes Memory that is occupied by runtime mspan structures that are currently being used.
# TYPE go_memory_classes_metadata_mspan_inuse_bytes gauge
go_memory_classes_metadata_mspan_inuse_bytes 113968
# HELP go_memory_classes_metadata_other_bytes Memory that is reserved for or used to hold runtime metadata.
# TYPE go_memory_classes_metadata_other_bytes gauge
go_memory_classes_metadata_other_bytes 5.544408e+06
# HELP go_memory_classes_os_stacks_bytes Stack memory allocated by the underlying operating system.
# TYPE go_memory_classes_os_stacks_bytes gauge
go_memory_classes_os_stacks_bytes 0
# HELP go_memory_classes_other_bytes Memory used by execution trace buffers, structures for debugging the runtime, finalizer and profiler specials, and more.
# TYPE go_memory_classes_other_bytes gauge
go_memory_classes_other_bytes 537777
# HELP go_memory_classes_profiling_buckets_bytes Memory that is used by the stack trace hash map used for profiling.
# TYPE go_memory_classes_profiling_buckets_bytes gauge
go_memory_classes_profiling_buckets_bytes 1.455487e+06
# HELP go_memory_classes_total_bytes All memory mapped by the Go runtime into the current process as read-write. Note that this does not include memory mapped by code called via cgo or via the syscall package. Sum of all metrics in /memory/classes.
# TYPE go_memory_classes_total_bytes gauge
go_memory_classes_total_bytes 2.026804e+07
# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.
# TYPE go_memstats_alloc_bytes gauge
go_memstats_alloc_bytes 5.140568e+06
# HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.
# TYPE go_memstats_alloc_bytes_total counter
go_memstats_alloc_bytes_total 1.5021512e+07
# HELP go_memstats_buck_hash_sys_bytes Number of bytes used by the profiling bucket hash table.
# TYPE go_memstats_buck_hash_sys_bytes gauge
go_memstats_buck_hash_sys_bytes 1.455487e+06
# HELP go_memstats_frees_total Total number of frees.
# TYPE go_memstats_frees_total counter
go_memstats_frees_total 108175
# HELP go_memstats_gc_cpu_fraction The fraction of this program's available CPU time used by the GC since the program started.
# TYPE go_memstats_gc_cpu_fraction gauge
go_memstats_gc_cpu_fraction 0
# HELP go_memstats_gc_sys_bytes Number of bytes used for garbage collection system metadata.
# TYPE go_memstats_gc_sys_bytes gauge
go_memstats_gc_sys_bytes 5.544408e+06
# HELP go_memstats_heap_alloc_bytes Number of heap bytes allocated and still in use.
# TYPE go_memstats_heap_alloc_bytes gauge
go_memstats_heap_alloc_bytes 5.140568e+06
# HELP go_memstats_heap_idle_bytes Number of heap bytes waiting to be used.
# TYPE go_memstats_heap_idle_bytes gauge
go_memstats_heap_idle_bytes 4.595712e+06
# HELP go_memstats_heap_inuse_bytes Number of heap bytes that are in use.
# TYPE go_memstats_heap_inuse_bytes gauge
go_memstats_heap_inuse_bytes 7.200768e+06
# HELP go_memstats_heap_objects Number of allocated objects.
# TYPE go_memstats_heap_objects gauge
go_memstats_heap_objects 31902
# HELP go_memstats_heap_released_bytes Number of heap bytes released to OS.
# TYPE go_memstats_heap_released_bytes gauge
go_memstats_heap_released_bytes 4.005888e+06
# HELP go_memstats_heap_sys_bytes Number of heap bytes obtained from system.
# TYPE go_memstats_heap_sys_bytes gauge
go_memstats_heap_sys_bytes 1.179648e+07
# HELP go_memstats_last_gc_time_seconds Number of seconds since 1970 of last garbage collection.
# TYPE go_memstats_last_gc_time_seconds gauge
go_memstats_last_gc_time_seconds 1.6461572121033354e+09
# HELP go_memstats_lookups_total Total number of pointer lookups.
# TYPE go_memstats_lookups_total counter
go_memstats_lookups_total 0
# HELP go_memstats_mallocs_total Total number of mallocs.
# TYPE go_memstats_mallocs_total counter
go_memstats_mallocs_total 140077
# HELP go_memstats_mcache_inuse_bytes Number of bytes in use by mcache structures.
# TYPE go_memstats_mcache_inuse_bytes gauge
go_memstats_mcache_inuse_bytes 2400
# HELP go_memstats_mcache_sys_bytes Number of bytes used for mcache structures obtained from system.
# TYPE go_memstats_mcache_sys_bytes gauge
go_memstats_mcache_sys_bytes 16384
# HELP go_memstats_mspan_inuse_bytes Number of bytes in use by mspan structures.
# TYPE go_memstats_mspan_inuse_bytes gauge
go_memstats_mspan_inuse_bytes 113968
# HELP go_memstats_mspan_sys_bytes Number of bytes used for mspan structures obtained from system.
# TYPE go_memstats_mspan_sys_bytes gauge
go_memstats_mspan_sys_bytes 131072
# HELP go_memstats_next_gc_bytes Number of heap bytes when next garbage collection will take place.
# TYPE go_memstats_next_gc_bytes gauge
go_memstats_next_gc_bytes 9.356624e+06
# HELP go_memstats_other_sys_bytes Number of bytes used for other system allocations.
# TYPE go_memstats_other_sys_bytes gauge
go_memstats_other_sys_bytes 537777
# HELP go_memstats_stack_inuse_bytes Number of bytes in use by the stack allocator.
# TYPE go_memstats_stack_inuse_bytes gauge
go_memstats_stack_inuse_bytes 786432
# HELP go_memstats_stack_sys_bytes Number of bytes obtained from system for stack allocator.
# TYPE go_memstats_stack_sys_bytes gauge
go_memstats_stack_sys_bytes 786432
# HELP go_memstats_sys_bytes Number of bytes obtained from system.
# TYPE go_memstats_sys_bytes gauge
go_memstats_sys_bytes 2.026804e+07
# HELP go_sched_goroutines_goroutines Count of live goroutines.
# TYPE go_sched_goroutines_goroutines gauge
go_sched_goroutines_goroutines 80
# HELP go_sched_latencies_seconds Distribution of the time goroutines have spent in the scheduler in a runnable state before actually running.
# TYPE go_sched_latencies_seconds histogram
go_sched_latencies_seconds_bucket{le="9.999999999999999e-10"} 244
go_sched_latencies_seconds_bucket{le="1.9999999999999997e-09"} 244
[...]
go_sched_latencies_seconds_bucket{le="206708.18602188796"} 2336
go_sched_latencies_seconds_bucket{le="+Inf"} 2336
go_sched_latencies_seconds_sum 0.18509832400000004
go_sched_latencies_seconds_count 2336
# HELP go_threads Number of OS threads created.
# TYPE go_threads gauge
go_threads 8
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 1.84
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 1.048576e+06
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 14
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 4.3728896e+07
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.64615612779e+09
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 7.65362176e+08
# HELP process_virtual_memory_max_bytes Maximum amount of virtual memory available in bytes.
# TYPE process_virtual_memory_max_bytes gauge
process_virtual_memory_max_bytes 1.8446744073709552e+19
# HELP rest_client_requests_total Number of HTTP requests, partitioned by status code, method, and host.
# TYPE rest_client_requests_total counter
rest_client_requests_total{code="200",host="10.96.0.1:443",method="GET"} 114
rest_client_requests_total{code="200",host="10.96.0.1:443",method="PUT"} 4
# HELP workqueue_adds_total Total number of adds handled by workqueue
# TYPE workqueue_adds_total counter
workqueue_adds_total{name="authconfig"} 19
workqueue_adds_total{name="secret"} 1
# HELP workqueue_depth Current depth of workqueue
# TYPE workqueue_depth gauge
workqueue_depth{name="authconfig"} 0
workqueue_depth{name="secret"} 0
# HELP workqueue_longest_running_processor_seconds How many seconds has the longest running processor for workqueue been running.
# TYPE workqueue_longest_running_processor_seconds gauge
workqueue_longest_running_processor_seconds{name="authconfig"} 0
workqueue_longest_running_processor_seconds{name="secret"} 0
# HELP workqueue_queue_duration_seconds How long in seconds an item stays in workqueue before being requested
# TYPE workqueue_queue_duration_seconds histogram
workqueue_queue_duration_seconds_bucket{name="authconfig",le="1e-08"} 0
workqueue_queue_duration_seconds_bucket{name="authconfig",le="1e-07"} 0
workqueue_queue_duration_seconds_bucket{name="authconfig",le="1e-06"} 0
workqueue_queue_duration_seconds_bucket{name="authconfig",le="9.999999999999999e-06"} 8
workqueue_queue_duration_seconds_bucket{name="authconfig",le="9.999999999999999e-05"} 17
workqueue_queue_duration_seconds_bucket{name="authconfig",le="0.001"} 17
workqueue_queue_duration_seconds_bucket{name="authconfig",le="0.01"} 17
workqueue_queue_duration_seconds_bucket{name="authconfig",le="0.1"} 18
workqueue_queue_duration_seconds_bucket{name="authconfig",le="1"} 18
workqueue_queue_duration_seconds_bucket{name="authconfig",le="10"} 19
workqueue_queue_duration_seconds_bucket{name="authconfig",le="+Inf"} 19
workqueue_queue_duration_seconds_sum{name="authconfig"} 4.969016371
workqueue_queue_duration_seconds_count{name="authconfig"} 19
workqueue_queue_duration_seconds_bucket{name="secret",le="1e-08"} 0
workqueue_queue_duration_seconds_bucket{name="secret",le="1e-07"} 0
workqueue_queue_duration_seconds_bucket{name="secret",le="1e-06"} 0
workqueue_queue_duration_seconds_bucket{name="secret",le="9.999999999999999e-06"} 1
workqueue_queue_duration_seconds_bucket{name="secret",le="9.999999999999999e-05"} 1
workqueue_queue_duration_seconds_bucket{name="secret",le="0.001"} 1
workqueue_queue_duration_seconds_bucket{name="secret",le="0.01"} 1
workqueue_queue_duration_seconds_bucket{name="secret",le="0.1"} 1
workqueue_queue_duration_seconds_bucket{name="secret",le="1"} 1
workqueue_queue_duration_seconds_bucket{name="secret",le="10"} 1
workqueue_queue_duration_seconds_bucket{name="secret",le="+Inf"} 1
workqueue_queue_duration_seconds_sum{name="secret"} 4.67e-06
workqueue_queue_duration_seconds_count{name="secret"} 1
# HELP workqueue_retries_total Total number of retries handled by workqueue
# TYPE workqueue_retries_total counter
workqueue_retries_total{name="authconfig"} 12
workqueue_retries_total{name="secret"} 0
# HELP workqueue_unfinished_work_seconds How many seconds of work has been done that is in progress and hasn't been observed by work_duration. Large values indicate stuck threads. One can deduce the number of stuck threads by observing the rate at which this increases.
# TYPE workqueue_unfinished_work_seconds gauge
workqueue_unfinished_work_seconds{name="authconfig"} 0
workqueue_unfinished_work_seconds{name="secret"} 0
# HELP workqueue_work_duration_seconds How long in seconds processing an item from workqueue takes.
# TYPE workqueue_work_duration_seconds histogram
workqueue_work_duration_seconds_bucket{name="authconfig",le="1e-08"} 0
workqueue_work_duration_seconds_bucket{name="authconfig",le="1e-07"} 0
workqueue_work_duration_seconds_bucket{name="authconfig",le="1e-06"} 0
workqueue_work_duration_seconds_bucket{name="authconfig",le="9.999999999999999e-06"} 0
workqueue_work_duration_seconds_bucket{name="authconfig",le="9.999999999999999e-05"} 0
workqueue_work_duration_seconds_bucket{name="authconfig",le="0.001"} 0
workqueue_work_duration_seconds_bucket{name="authconfig",le="0.01"} 11
workqueue_work_duration_seconds_bucket{name="authconfig",le="0.1"} 18
workqueue_work_duration_seconds_bucket{name="authconfig",le="1"} 18
workqueue_work_duration_seconds_bucket{name="authconfig",le="10"} 19
workqueue_work_duration_seconds_bucket{name="authconfig",le="+Inf"} 19
workqueue_work_duration_seconds_sum{name="authconfig"} 5.171738079000001
workqueue_work_duration_seconds_count{name="authconfig"} 19
workqueue_work_duration_seconds_bucket{name="secret",le="1e-08"} 0
workqueue_work_duration_seconds_bucket{name="secret",le="1e-07"} 0
workqueue_work_duration_seconds_bucket{name="secret",le="1e-06"} 0
workqueue_work_duration_seconds_bucket{name="secret",le="9.999999999999999e-06"} 0
workqueue_work_duration_seconds_bucket{name="secret",le="9.999999999999999e-05"} 0
workqueue_work_duration_seconds_bucket{name="secret",le="0.001"} 1
workqueue_work_duration_seconds_bucket{name="secret",le="0.01"} 1
workqueue_work_duration_seconds_bucket{name="secret",le="0.1"} 1
workqueue_work_duration_seconds_bucket{name="secret",le="1"} 1
workqueue_work_duration_seconds_bucket{name="secret",le="10"} 1
workqueue_work_duration_seconds_bucket{name="secret",le="+Inf"} 1
workqueue_work_duration_seconds_sum{name="secret"} 0.000150956
workqueue_work_duration_seconds_count{name="secret"} 1
```

### /server-metrics

```ini
# HELP auth_server_authconfig_duration_seconds Response latency of authconfig enforced by the auth server (in seconds).
# TYPE auth_server_authconfig_duration_seconds histogram
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.001"} 0
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.051000000000000004"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.101"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.15100000000000002"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.201"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.251"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.301"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.351"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.40099999999999997"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.45099999999999996"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.501"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.551"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.6010000000000001"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.6510000000000001"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.7010000000000002"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.7510000000000002"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.8010000000000003"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.8510000000000003"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.9010000000000004"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="0.9510000000000004"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="edge-auth",namespace="authorino",le="+Inf"} 1
auth_server_authconfig_duration_seconds_sum{authconfig="edge-auth",namespace="authorino"} 0.001701795
auth_server_authconfig_duration_seconds_count{authconfig="edge-auth",namespace="authorino"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.001"} 1
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.051000000000000004"} 4
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.101"} 4
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.15100000000000002"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.201"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.251"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.301"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.351"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.40099999999999997"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.45099999999999996"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.501"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.551"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.6010000000000001"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.6510000000000001"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.7010000000000002"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.7510000000000002"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.8010000000000003"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.8510000000000003"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.9010000000000004"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="0.9510000000000004"} 5
auth_server_authconfig_duration_seconds_bucket{authconfig="talker-api-protection",namespace="authorino",le="+Inf"} 5
auth_server_authconfig_duration_seconds_sum{authconfig="talker-api-protection",namespace="authorino"} 0.26967658299999997
auth_server_authconfig_duration_seconds_count{authconfig="talker-api-protection",namespace="authorino"} 5
# HELP auth_server_authconfig_response_status Response status of authconfigs sent by the auth server, partitioned by authconfig.
# TYPE auth_server_authconfig_response_status counter
auth_server_authconfig_response_status{authconfig="edge-auth",namespace="authorino",status="OK"} 1
auth_server_authconfig_response_status{authconfig="talker-api-protection",namespace="authorino",status="OK"} 2
auth_server_authconfig_response_status{authconfig="talker-api-protection",namespace="authorino",status="PERMISSION_DENIED"} 2
auth_server_authconfig_response_status{authconfig="talker-api-protection",namespace="authorino",status="UNAUTHENTICATED"} 1
# HELP auth_server_authconfig_total Total number of authconfigs enforced by the auth server, partitioned by authconfig.
# TYPE auth_server_authconfig_total counter
auth_server_authconfig_total{authconfig="edge-auth",namespace="authorino"} 1
auth_server_authconfig_total{authconfig="talker-api-protection",namespace="authorino"} 5
# HELP auth_server_evaluator_duration_seconds Response latency of individual authconfig rule evaluated by the auth server (in seconds).
# TYPE auth_server_evaluator_duration_seconds histogram
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.001"} 0
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.051000000000000004"} 3
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.101"} 3
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.15100000000000002"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.201"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.251"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.301"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.351"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.40099999999999997"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.45099999999999996"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.501"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.551"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.6010000000000001"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.6510000000000001"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.7010000000000002"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.7510000000000002"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.8010000000000003"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.8510000000000003"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.9010000000000004"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="0.9510000000000004"} 4
auth_server_evaluator_duration_seconds_bucket{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino",le="+Inf"} 4
auth_server_evaluator_duration_seconds_sum{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino"} 0.25800055
auth_server_evaluator_duration_seconds_count{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino"} 4
# HELP auth_server_evaluator_total Total number of evaluations of individual authconfig rule performed by the auth server.
# TYPE auth_server_evaluator_total counter
auth_server_evaluator_total{authconfig="talker-api-protection",evaluator_name="geo",evaluator_type="METADATA_GENERIC_HTTP",namespace="authorino"} 4
# HELP auth_server_response_status Response status of authconfigs sent by the auth server.
# TYPE auth_server_response_status counter
auth_server_response_status{status="NOT_FOUND"} 1
auth_server_response_status{status="OK"} 3
auth_server_response_status{status="PERMISSION_DENIED"} 2
auth_server_response_status{status="UNAUTHENTICATED"} 1
# HELP go_gc_cycles_automatic_gc_cycles_total Count of completed GC cycles generated by the Go runtime.
# TYPE go_gc_cycles_automatic_gc_cycles_total counter
go_gc_cycles_automatic_gc_cycles_total 11
# HELP go_gc_cycles_forced_gc_cycles_total Count of completed GC cycles forced by the application.
# TYPE go_gc_cycles_forced_gc_cycles_total counter
go_gc_cycles_forced_gc_cycles_total 0
# HELP go_gc_cycles_total_gc_cycles_total Count of all completed GC cycles.
# TYPE go_gc_cycles_total_gc_cycles_total counter
go_gc_cycles_total_gc_cycles_total 11
# HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
# TYPE go_gc_duration_seconds summary
go_gc_duration_seconds{quantile="0"} 4.5971e-05
go_gc_duration_seconds{quantile="0.25"} 5.69e-05
go_gc_duration_seconds{quantile="0.5"} 0.000158594
go_gc_duration_seconds{quantile="0.75"} 0.000324091
go_gc_duration_seconds{quantile="1"} 0.001692423
go_gc_duration_seconds_sum 0.003546711
go_gc_duration_seconds_count 11
# HELP go_gc_heap_allocs_by_size_bytes_total Distribution of heap allocations by approximate size. Note that this does not include tiny objects as defined by /gc/heap/tiny/allocs:objects, only tiny blocks.
# TYPE go_gc_heap_allocs_by_size_bytes_total histogram
go_gc_heap_allocs_by_size_bytes_total_bucket{le="8.999999999999998"} 6261
go_gc_heap_allocs_by_size_bytes_total_bucket{le="16.999999999999996"} 42477
[...]
go_gc_heap_allocs_by_size_bytes_total_bucket{le="32768.99999999999"} 122133
go_gc_heap_allocs_by_size_bytes_total_bucket{le="+Inf"} 122154
go_gc_heap_allocs_by_size_bytes_total_sum 1.455944e+07
go_gc_heap_allocs_by_size_bytes_total_count 122154
# HELP go_gc_heap_allocs_bytes_total Cumulative sum of memory allocated to the heap by the application.
# TYPE go_gc_heap_allocs_bytes_total counter
go_gc_heap_allocs_bytes_total 1.455944e+07
# HELP go_gc_heap_allocs_objects_total Cumulative count of heap allocations triggered by the application. Note that this does not include tiny objects as defined by /gc/heap/tiny/allocs:objects, only tiny blocks.
# TYPE go_gc_heap_allocs_objects_total counter
go_gc_heap_allocs_objects_total 122154
# HELP go_gc_heap_frees_by_size_bytes_total Distribution of freed heap allocations by approximate size. Note that this does not include tiny objects as defined by /gc/heap/tiny/allocs:objects, only tiny blocks.
# TYPE go_gc_heap_frees_by_size_bytes_total histogram
go_gc_heap_frees_by_size_bytes_total_bucket{le="8.999999999999998"} 3789
go_gc_heap_frees_by_size_bytes_total_bucket{le="16.999999999999996"} 31067
[...]
go_gc_heap_frees_by_size_bytes_total_bucket{le="32768.99999999999"} 91013
go_gc_heap_frees_by_size_bytes_total_bucket{le="+Inf"} 91021
go_gc_heap_frees_by_size_bytes_total_sum 9.399936e+06
go_gc_heap_frees_by_size_bytes_total_count 91021
# HELP go_gc_heap_frees_bytes_total Cumulative sum of heap memory freed by the garbage collector.
# TYPE go_gc_heap_frees_bytes_total counter
go_gc_heap_frees_bytes_total 9.399936e+06
# HELP go_gc_heap_frees_objects_total Cumulative count of heap allocations whose storage was freed by the garbage collector. Note that this does not include tiny objects as defined by /gc/heap/tiny/allocs:objects, only tiny blocks.
# TYPE go_gc_heap_frees_objects_total counter
go_gc_heap_frees_objects_total 91021
# HELP go_gc_heap_goal_bytes Heap size target for the end of the GC cycle.
# TYPE go_gc_heap_goal_bytes gauge
go_gc_heap_goal_bytes 9.601744e+06
# HELP go_gc_heap_objects_objects Number of objects, live or unswept, occupying heap memory.
# TYPE go_gc_heap_objects_objects gauge
go_gc_heap_objects_objects 31133
# HELP go_gc_heap_tiny_allocs_objects_total Count of small allocations that are packed together into blocks. These allocations are counted separately from other allocations because each individual allocation is not tracked by the runtime, only their block. Each block is already accounted for in allocs-by-size and frees-by-size.
# TYPE go_gc_heap_tiny_allocs_objects_total counter
go_gc_heap_tiny_allocs_objects_total 9866
# HELP go_gc_pauses_seconds_total Distribution individual GC-related stop-the-world pause latencies.
# TYPE go_gc_pauses_seconds_total histogram
go_gc_pauses_seconds_total_bucket{le="9.999999999999999e-10"} 0
go_gc_pauses_seconds_total_bucket{le="1.9999999999999997e-09"} 0
[...]
go_gc_pauses_seconds_total_bucket{le="206708.18602188796"} 22
go_gc_pauses_seconds_total_bucket{le="+Inf"} 22
go_gc_pauses_seconds_total_sum 0.0030393599999999996
go_gc_pauses_seconds_total_count 22
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 79
# HELP go_info Information about the Go environment.
# TYPE go_info gauge
go_info{version="go1.17.7"} 1
# HELP go_memory_classes_heap_free_bytes Memory that is completely free and eligible to be returned to the underlying system, but has not been. This metric is the runtime's estimate of free address space that is backed by physical memory.
# TYPE go_memory_classes_heap_free_bytes gauge
go_memory_classes_heap_free_bytes 630784
# HELP go_memory_classes_heap_objects_bytes Memory occupied by live objects and dead objects that have not yet been marked free by the garbage collector.
# TYPE go_memory_classes_heap_objects_bytes gauge
go_memory_classes_heap_objects_bytes 5.159504e+06
# HELP go_memory_classes_heap_released_bytes Memory that is completely free and has been returned to the underlying system. This metric is the runtime's estimate of free address space that is still mapped into the process, but is not backed by physical memory.
# TYPE go_memory_classes_heap_released_bytes gauge
go_memory_classes_heap_released_bytes 3.858432e+06
# HELP go_memory_classes_heap_stacks_bytes Memory allocated from the heap that is reserved for stack space, whether or not it is currently in-use.
# TYPE go_memory_classes_heap_stacks_bytes gauge
go_memory_classes_heap_stacks_bytes 786432
# HELP go_memory_classes_heap_unused_bytes Memory that is reserved for heap objects but is not currently used to hold heap objects.
# TYPE go_memory_classes_heap_unused_bytes gauge
go_memory_classes_heap_unused_bytes 2.14776e+06
# HELP go_memory_classes_metadata_mcache_free_bytes Memory that is reserved for runtime mcache structures, but not in-use.
# TYPE go_memory_classes_metadata_mcache_free_bytes gauge
go_memory_classes_metadata_mcache_free_bytes 13984
# HELP go_memory_classes_metadata_mcache_inuse_bytes Memory that is occupied by runtime mcache structures that are currently being used.
# TYPE go_memory_classes_metadata_mcache_inuse_bytes gauge
go_memory_classes_metadata_mcache_inuse_bytes 2400
# HELP go_memory_classes_metadata_mspan_free_bytes Memory that is reserved for runtime mspan structures, but not in-use.
# TYPE go_memory_classes_metadata_mspan_free_bytes gauge
go_memory_classes_metadata_mspan_free_bytes 16696
# HELP go_memory_classes_metadata_mspan_inuse_bytes Memory that is occupied by runtime mspan structures that are currently being used.
# TYPE go_memory_classes_metadata_mspan_inuse_bytes gauge
go_memory_classes_metadata_mspan_inuse_bytes 114376
# HELP go_memory_classes_metadata_other_bytes Memory that is reserved for or used to hold runtime metadata.
# TYPE go_memory_classes_metadata_other_bytes gauge
go_memory_classes_metadata_other_bytes 5.544408e+06
# HELP go_memory_classes_os_stacks_bytes Stack memory allocated by the underlying operating system.
# TYPE go_memory_classes_os_stacks_bytes gauge
go_memory_classes_os_stacks_bytes 0
# HELP go_memory_classes_other_bytes Memory used by execution trace buffers, structures for debugging the runtime, finalizer and profiler specials, and more.
# TYPE go_memory_classes_other_bytes gauge
go_memory_classes_other_bytes 537777
# HELP go_memory_classes_profiling_buckets_bytes Memory that is used by the stack trace hash map used for profiling.
# TYPE go_memory_classes_profiling_buckets_bytes gauge
go_memory_classes_profiling_buckets_bytes 1.455487e+06
# HELP go_memory_classes_total_bytes All memory mapped by the Go runtime into the current process as read-write. Note that this does not include memory mapped by code called via cgo or via the syscall package. Sum of all metrics in /memory/classes.
# TYPE go_memory_classes_total_bytes gauge
go_memory_classes_total_bytes 2.026804e+07
# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.
# TYPE go_memstats_alloc_bytes gauge
go_memstats_alloc_bytes 5.159504e+06
# HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.
# TYPE go_memstats_alloc_bytes_total counter
go_memstats_alloc_bytes_total 1.455944e+07
# HELP go_memstats_buck_hash_sys_bytes Number of bytes used by the profiling bucket hash table.
# TYPE go_memstats_buck_hash_sys_bytes gauge
go_memstats_buck_hash_sys_bytes 1.455487e+06
# HELP go_memstats_frees_total Total number of frees.
# TYPE go_memstats_frees_total counter
go_memstats_frees_total 100887
# HELP go_memstats_gc_cpu_fraction The fraction of this program's available CPU time used by the GC since the program started.
# TYPE go_memstats_gc_cpu_fraction gauge
go_memstats_gc_cpu_fraction 0
# HELP go_memstats_gc_sys_bytes Number of bytes used for garbage collection system metadata.
# TYPE go_memstats_gc_sys_bytes gauge
go_memstats_gc_sys_bytes 5.544408e+06
# HELP go_memstats_heap_alloc_bytes Number of heap bytes allocated and still in use.
# TYPE go_memstats_heap_alloc_bytes gauge
go_memstats_heap_alloc_bytes 5.159504e+06
# HELP go_memstats_heap_idle_bytes Number of heap bytes waiting to be used.
# TYPE go_memstats_heap_idle_bytes gauge
go_memstats_heap_idle_bytes 4.489216e+06
# HELP go_memstats_heap_inuse_bytes Number of heap bytes that are in use.
# TYPE go_memstats_heap_inuse_bytes gauge
go_memstats_heap_inuse_bytes 7.307264e+06
# HELP go_memstats_heap_objects Number of allocated objects.
# TYPE go_memstats_heap_objects gauge
go_memstats_heap_objects 31133
# HELP go_memstats_heap_released_bytes Number of heap bytes released to OS.
# TYPE go_memstats_heap_released_bytes gauge
go_memstats_heap_released_bytes 3.858432e+06
# HELP go_memstats_heap_sys_bytes Number of heap bytes obtained from system.
# TYPE go_memstats_heap_sys_bytes gauge
go_memstats_heap_sys_bytes 1.179648e+07
# HELP go_memstats_last_gc_time_seconds Number of seconds since 1970 of last garbage collection.
# TYPE go_memstats_last_gc_time_seconds gauge
go_memstats_last_gc_time_seconds 1.6461569717723043e+09
# HELP go_memstats_lookups_total Total number of pointer lookups.
# TYPE go_memstats_lookups_total counter
go_memstats_lookups_total 0
# HELP go_memstats_mallocs_total Total number of mallocs.
# TYPE go_memstats_mallocs_total counter
go_memstats_mallocs_total 132020
# HELP go_memstats_mcache_inuse_bytes Number of bytes in use by mcache structures.
# TYPE go_memstats_mcache_inuse_bytes gauge
go_memstats_mcache_inuse_bytes 2400
# HELP go_memstats_mcache_sys_bytes Number of bytes used for mcache structures obtained from system.
# TYPE go_memstats_mcache_sys_bytes gauge
go_memstats_mcache_sys_bytes 16384
# HELP go_memstats_mspan_inuse_bytes Number of bytes in use by mspan structures.
# TYPE go_memstats_mspan_inuse_bytes gauge
go_memstats_mspan_inuse_bytes 114376
# HELP go_memstats_mspan_sys_bytes Number of bytes used for mspan structures obtained from system.
# TYPE go_memstats_mspan_sys_bytes gauge
go_memstats_mspan_sys_bytes 131072
# HELP go_memstats_next_gc_bytes Number of heap bytes when next garbage collection will take place.
# TYPE go_memstats_next_gc_bytes gauge
go_memstats_next_gc_bytes 9.601744e+06
# HELP go_memstats_other_sys_bytes Number of bytes used for other system allocations.
# TYPE go_memstats_other_sys_bytes gauge
go_memstats_other_sys_bytes 537777
# HELP go_memstats_stack_inuse_bytes Number of bytes in use by the stack allocator.
# TYPE go_memstats_stack_inuse_bytes gauge
go_memstats_stack_inuse_bytes 786432
# HELP go_memstats_stack_sys_bytes Number of bytes obtained from system for stack allocator.
# TYPE go_memstats_stack_sys_bytes gauge
go_memstats_stack_sys_bytes 786432
# HELP go_memstats_sys_bytes Number of bytes obtained from system.
# TYPE go_memstats_sys_bytes gauge
go_memstats_sys_bytes 2.026804e+07
# HELP go_sched_goroutines_goroutines Count of live goroutines.
# TYPE go_sched_goroutines_goroutines gauge
go_sched_goroutines_goroutines 79
# HELP go_sched_latencies_seconds Distribution of the time goroutines have spent in the scheduler in a runnable state before actually running.
# TYPE go_sched_latencies_seconds histogram
go_sched_latencies_seconds_bucket{le="9.999999999999999e-10"} 225
go_sched_latencies_seconds_bucket{le="1.9999999999999997e-09"} 225
[...]
go_sched_latencies_seconds_bucket{le="206708.18602188796"} 1916
go_sched_latencies_seconds_bucket{le="+Inf"} 1916
go_sched_latencies_seconds_sum 0.18081453600000003
go_sched_latencies_seconds_count 1916
# HELP go_threads Number of OS threads created.
# TYPE go_threads gauge
go_threads 8
# HELP grpc_server_handled_total Total number of RPCs completed on the server, regardless of success or failure.
# TYPE grpc_server_handled_total counter
grpc_server_handled_total{grpc_code="Aborted",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Aborted",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Aborted",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="AlreadyExists",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="AlreadyExists",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="AlreadyExists",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="Canceled",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Canceled",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Canceled",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="DataLoss",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="DataLoss",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="DataLoss",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="DeadlineExceeded",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="DeadlineExceeded",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="DeadlineExceeded",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="FailedPrecondition",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="FailedPrecondition",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="FailedPrecondition",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="Internal",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Internal",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Internal",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="InvalidArgument",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="InvalidArgument",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="InvalidArgument",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="NotFound",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="NotFound",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="NotFound",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="OK",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 7
grpc_server_handled_total{grpc_code="OK",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="OK",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="OutOfRange",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="OutOfRange",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="OutOfRange",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="PermissionDenied",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="PermissionDenied",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="PermissionDenied",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="ResourceExhausted",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="ResourceExhausted",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="ResourceExhausted",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="Unauthenticated",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Unauthenticated",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Unauthenticated",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="Unavailable",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Unavailable",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Unavailable",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="Unimplemented",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Unimplemented",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Unimplemented",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
grpc_server_handled_total{grpc_code="Unknown",grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Unknown",grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_handled_total{grpc_code="Unknown",grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
# HELP grpc_server_handling_seconds Histogram of response latency (seconds) of gRPC that had been application-level handled by the server.
# TYPE grpc_server_handling_seconds histogram
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="0.005"} 3
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="0.01"} 3
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="0.025"} 3
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="0.05"} 6
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="0.1"} 6
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="0.25"} 7
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="0.5"} 7
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="1"} 7
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="2.5"} 7
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="5"} 7
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="10"} 7
grpc_server_handling_seconds_bucket{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary",le="+Inf"} 7
grpc_server_handling_seconds_sum{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 0.277605516
grpc_server_handling_seconds_count{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 7
# HELP grpc_server_msg_received_total Total number of RPC stream messages received on the server.
# TYPE grpc_server_msg_received_total counter
grpc_server_msg_received_total{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 7
grpc_server_msg_received_total{grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_msg_received_total{grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
# HELP grpc_server_msg_sent_total Total number of gRPC stream messages sent by the server.
# TYPE grpc_server_msg_sent_total counter
grpc_server_msg_sent_total{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 7
grpc_server_msg_sent_total{grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_msg_sent_total{grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
# HELP grpc_server_started_total Total number of RPCs started on the server.
# TYPE grpc_server_started_total counter
grpc_server_started_total{grpc_method="Check",grpc_service="envoy.service.auth.v3.Authorization",grpc_type="unary"} 7
grpc_server_started_total{grpc_method="Check",grpc_service="grpc.health.v1.Health",grpc_type="unary"} 0
grpc_server_started_total{grpc_method="Watch",grpc_service="grpc.health.v1.Health",grpc_type="server_stream"} 0
# HELP oidc_server_requests_total Number of get requests received on the OIDC (Festival Wristband) server.
# TYPE oidc_server_requests_total counter
oidc_server_requests_total{authconfig="edge-auth",namespace="authorino",path="/.well-known/openid-configuration",wristband="wristband"} 1
oidc_server_requests_total{authconfig="edge-auth",namespace="authorino",path="/.well-known/openid-connect/certs",wristband="wristband"} 1
# HELP oidc_server_response_status Status of HTTP response sent by the OIDC (Festival Wristband) server.
# TYPE oidc_server_response_status counter
oidc_server_response_status{status="200"} 2
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 1.42
# HELP process_max_fds Maximum number of open file descriptors.
# TYPE process_max_fds gauge
process_max_fds 1.048576e+06
# HELP process_open_fds Number of open file descriptors.
# TYPE process_open_fds gauge
process_open_fds 14
# HELP process_resident_memory_bytes Resident memory size in bytes.
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 4.370432e+07
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.64615612779e+09
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 7.65362176e+08
# HELP process_virtual_memory_max_bytes Maximum amount of virtual memory available in bytes.
# TYPE process_virtual_memory_max_bytes gauge
process_virtual_memory_max_bytes 1.8446744073709552e+19
# HELP promhttp_metric_handler_requests_in_flight Current number of scrapes being served.
# TYPE promhttp_metric_handler_requests_in_flight gauge
promhttp_metric_handler_requests_in_flight 1
# HELP promhttp_metric_handler_requests_total Total number of scrapes by HTTP status code.
# TYPE promhttp_metric_handler_requests_total counter
promhttp_metric_handler_requests_total{code="200"} 1
promhttp_metric_handler_requests_total{code="500"} 0
promhttp_metric_handler_requests_total{code="503"} 0
```
