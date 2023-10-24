# Observability

## Metrics

Authorino exports metrics at 2 endpoints:

<table>
  <tr>
    <td><strong>/metrics</strong></td>
    <td>Metrics of the controller-runtime about reconciliation (caching) of AuthConfigs and API key Secrets</td>
  </tr>
  <tr>
    <td><strong>/server-metrics</strong></td>
    <td>Metrics of the external authorization gRPC and OIDC/Festival Wristband validation built-in HTTP servers</td>
  </tr>
</table>

The [Authorino Operator](https://github.com/kuadrant/authorino-operator) creates a Kubernetes `Service` named `<authorino-cr-name>-controller-metrics` that exposes the endpoints on port 8080. The Authorino instance allows to modify the port number of the metrics endpoints, by setting the `--metrics-addr` command-line flag (default: `:8080`).

**Main metrics exported by endpoint<sup>1</sup>:**

<table>
  <thead>
    <tr>
      <td colspan="4"><br/><strong>Endpoint: <code>/metrics</code></strong><br/><br/></td>
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
      <td colspan="4"><br/><br/><strong>Endpoint: <code>/server-metrics</code></strong><br/><br/></td>
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
      <td>auth_server_evaluator_total<sup>2</sup></td>
      <td>Total number of evaluations of individual authconfig rule performed by the auth server.</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>evaluator_type</code>, <code>evaluator_name</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_evaluator_cancelled<sup>2</sup></td>
      <td>Number of evaluations of individual authconfig rule cancelled by the auth server.</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>evaluator_type</code>, <code>evaluator_name</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_evaluator_ignored<sup>2</sup></td>
      <td>Number of evaluations of individual authconfig rule ignored by the auth server.</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>evaluator_type</code>, <code>evaluator_name</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_evaluator_denied<sup>2</sup></td>
      <td>Number of denials from individual authconfig rule evaluated by the auth server.</td>
      <td><code>namespace</code>, <code>authconfig</code>, <code>evaluator_type</code>, <code>evaluator_name</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>auth_server_evaluator_duration_seconds<sup>2</sup></td>
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
      <td>histogram</td>
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
      <td>http_server_handled_total</td>
      <td>Total number of calls completed on the raw HTTP authorization server, regardless of success or failure.</td>
      <td><code>http_code</code></td>
      <td>counter</td>
    </tr>
    <tr>
      <td>http_server_handling_seconds</td>
      <td>Response latency (seconds) of raw HTTP authorization request that had been application-level handled by the server.</td>
      <td></td>
      <td>histogram</td>
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

<sup>1</sup> Both endpoints export metrics about the Go runtime, such as number of goroutines (go_goroutines) and threads (go_threads), usage of CPU, memory and GC stats.

<sup>2</sup> Opt-in metrics: <code>auth_server_evaluator_*</code> metrics require <code>authconfig.spec.(identity|metadata|authorization|response).metrics: true</code> (default: <code>false</code>). This can be enforced for the entire instance (all AuthConfigs and evaluators), by setting the <code>--deep-metrics-enabled</code> command-line flag in the Authorino deployment.

<details>
  <summary><b>Example of metrics exported at the <code>/metrics</code> endpoint</b></summary>

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
  go_info{version="go1.18.7"} 1
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
</details>

<details>
  <summary><b>Example of metrics exported at the <code>/server-metrics</code> endpoint</b></summary>

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
  go_info{version="go1.18.7"} 1
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
</details>

## Readiness check

Authorino exposes two main endpoints for health and readiness check of the AuthConfig controller:
- `/healthz`: Health probe (ping) – reports "ok" if the controller is healthy.
- `/readyz`: Readiness probe – reports "ok" if the controller is ready to reconcile AuthConfig-related events.

In general, the endpoints return either `200` ("ok", i.e. all checks have passed) or `500` (when one or more checks failed).

The default binding network address is `:8081`, which can be changed by setting the command-line flag `--health-probe-addr`.

The following additional subpath is available and its corresponding check can be aggregated into the response from the main readiness probe:
- `/readyz/authconfigs`: Aggregated readiness status of the AuthConfigs – reports "ok" if all AuthConfigs watched by the reconciler have been marked as ready.

<table>
  <tbody>
    <tr>
      <td><b><i>Important!</i></b><br/>The AuthConfig readiness check within the scope of the aggregated readiness probe endpoint is deactivated by default – i.e. this check is an opt-in check. Sending a request to the <code>/readyz</code> endpoint without explicitly opting-in for the AuthConfigs check, by using the <code>include</code> parameter, will result in a response message that disregards the actual status of the watched AuthConfigs, possibly an "ok" message. To read the aggregated status of the watched AuthConfigs, either use the specific endpoint <code>/readyz/authconfigs</code> or opt-in for the check in the aggregated endpoint by sending a request to <code>/readyz?include=authconfigs</code></td>
    </tr>
  </tbody>
</table>

Apart from `include` to add the aggregated status of the AuthConfigs, the following additional query string parameters are available:
- `verbose=true|false` - provides more verbose response messages;
- `exclude=(check name)` – to exclude a particular readiness check (for future usage).

## Logging

Authorino provides structured log messages ("production") or more log messages output to stdout in a more user-friendly format ("development" mode) and different level of logging.

### Log levels and log modes

Authorino outputs 3 levels of log messages: (from lowest to highest level)
1. `debug`
2. `info` (default)
3. `error`

`info` logging is restricted to high-level information of the gRPC and HTTP authorization services, limiting messages to incoming request and respective outgoing response logs, with reduced details about the corresponding objects (request payload and authorization result), and without any further detailed logs of the steps in between, except for errors.

Only `debug` logging will include processing details of each [Auth Pipeline](../architecture.md#the-auth-pipeline-aka-enforcing-protection-in-request-time), such as intermediary requests to validate identities with external auth servers, requests to external sources of auth metadata or authorization policies.

To configure the desired log level, set the `spec.logLevel` field of the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) custom resource (or `--log-level` command-line flag in the Authorino deployment), to one of the supported values listed above. Default log level is `info`.

Apart from log level, Authorino can output messages to the logs in 2 different formats:
- `production` (default): each line is a parseable JSON object with properties `{"level":string, "ts":int, "msg":string, "logger":string, extra values...}`
- `development`: more human-readable outputs, extra stack traces and logging info, plus extra values output as JSON, in the format: `<timestamp-iso-8601>\t<log-level>\t<logger>\t<message>\t{extra-values-as-json}`

To configure the desired log mode, set the `spec.logMode` field of the [`Authorino`](https://github.com/Kuadrant/authorino-operator/blob/main/config/crd/bases/operator.authorino.kuadrant.io_authorinos.yaml) custom resource (or `--log-mode` command-line flag in the Authorino deployment), to one of the supported values listed above. Default log level is `production`.

Example of `Authorino` custom resource with log level `debug` and log mode `production`:

```yaml
apiVersion: operator.authorino.kuadrant.io/v1beta1
kind: Authorino
metadata:
  name: authorino
spec:
  logLevel: debug
  logMode: production
  listener:
    tls:
      enabled: false
  oidcServer:
    tls:
      enabled: false
```

### Sensitive data output to the logs

Authorino will never output HTTP headers and query string parameters to `info` log messages, as such values usually include sensitive data (e.g. access tokens, API keys and Authorino Festival Wristbands). However, `debug` log messages may include such sensitive information and those are not redacted.

Therefore, **DO NOT USE `debug` LOG LEVEL IN PRODUCTION**! Instead, use either `info` or `error`.

### Log messages printed by Authorino

Some log messages printed by Authorino and corresponding extra values included:

| logger                                                                     | level   | message                                                                                    | extra values                                                                                                                                                                                                                                                                                                                                                                              |
|----------------------------------------------------------------------------|---------|--------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `authorino`                                                                | `info`  | "setting instance base logger"                                                             | `min level=info\|debug`, `mode=production\|development`                                                                                                                                                                                                                                                                                                                                   |
| `authorino`                                                                | `info`  | "booting up authorino"                                                                     | `version`                                                                                                                                                                                                                                                                                                                                                                                 |
| `authorino`                                                                | `debug` | "setting up with options"                                                                  | `auth-config-label-selector`, `deep-metrics-enabled`, `enable-leader-election`, `evaluator-cache-size`, `ext-auth-grpc-port`, `ext-auth-http-port`, `health-probe-addr`, `log-level`, `log-mode`, `max-http-request-body-size`, `metrics-addr`, `oidc-http-port`, `oidc-tls-cert`, `oidc-tls-cert-key`, `secret-label-selector`, `timeout`, `tls-cert`, `tls-cert-key`, `watch-namespace` |
| `authorino`                                                                | `info`  | "attempting to acquire leader lease &lt;namespace&gt;/cb88a58a.authorino.kuadrant.io...\n" |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `info`  | "successfully acquired lease &lt;namespace&gt;/cb88a58a.authorino.kuadrant.io\n"           |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `info`  | "disabling grpc auth service"                                                              |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `info`  | "starting grpc auth service"                                                               | `port`, `tls`                                                                                                                                                                                                                                                                                                                                                                             |
| `authorino`                                                                | `error` | "failed to obtain port for the grpc auth service"                                          |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `error` | "failed to load tls cert for the grpc auth"                                                |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `error` | "failed to start grpc auth service"                                                        |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `info`  | "disabling http auth service"                                                              |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `info`  | "starting http auth service"                                                               | `port`, `tls`                                                                                                                                                                                                                                                                                                                                                                             |
| `authorino`                                                                | `error` | "failed to obtain port for the http auth service"                                          |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `error` | "failed to start http auth service"                                                        |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `info`  | "disabling http oidc service"                                                              |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `info`  | "starting http oidc service"                                                               | `port`, `tls`                                                                                                                                                                                                                                                                                                                                                                             |
| `authorino`                                                                | `error` | "failed to obtain port for the http oidc service"                                          |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `error` | "failed to start http oidc service"                                                        |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `info`  | "starting manager"                                                                         |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `error` | "unable to start manager"                                                                  |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `error` | "unable to create controller"                                                              | `controller=authconfig\|secret\|authconfigstatusupdate`                                                                                                                                                                                                                                                                                                                                   |
| `authorino`                                                                | `error` | "problem running manager"                                                                  |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `info`  | "starting status update manager"                                                           |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `error` | "unable to start status update manager"                                                    |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino`                                                                | `error` | "problem running status update manager"                                                    |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino.controller-runtime.metrics`                                     | `info`  | "metrics server is starting to listen"                                                     | `addr`                                                                                                                                                                                                                                                                                                                                                                                    |
| `authorino.controller-runtime.manager`                                     | `info`  | "starting metrics server"                                                                  | `path`                                                                                                                                                                                                                                                                                                                                                                                    |
| `authorino.controller-runtime.manager.events`                              | `debug` | "Normal"                                                                                   | `object={kind=ConfigMap, apiVersion=v1}`, `reauthorino.ason=LeaderElection`, `message="authorino-controller-manager-* became leader"`                                                                                                                                                                                                                                                     |
| `authorino.controller-runtime.manager.events`                              | `debug` | "Normal"                                                                                   | `object={kind=Lease, apiVersion=coordination.k8s.io/v1}`, `reauthorino.ason=LeaderElection`, `message="authorino-controller-manager-* became leader"`                                                                                                                                                                                                                                     |
| `authorino.controller-runtime.manager.controller.authconfig`               | `info`  | "resource reconciled"                                                                      | `authconfig`                                                                                                                                                                                                                                                                                                                                                                              |
| `authorino.controller-runtime.manager.controller.authconfig`               | `info`  | "host already taken"                                                                       | `authconfig`, `host`                                                                                                                                                                                                                                                                                                                                                                      |
| `authorino.controller-runtime.manager.controller.authconfig.statusupdater` | `debug` | "resource status did not change"                                                           | `authconfig`                                                                                                                                                                                                                                                                                                                                                                              |
| `authorino.controller-runtime.manager.controller.authconfig.statusupdater` | `debug` | "resource status changed"                                                                  | `authconfig`, `authconfig/status`                                                                                                                                                                                                                                                                                                                                                         |
| `authorino.controller-runtime.manager.controller.authconfig.statusupdater` | `error` | "failed to update the resource"                                                            | `authconfig`                                                                                                                                                                                                                                                                                                                                                                              |
| `authorino.controller-runtime.manager.controller.authconfig.statusupdater` | `info`  | "resource status updated"                                                                  | `authconfig`                                                                                                                                                                                                                                                                                                                                                                              |
| `authorino.controller-runtime.manager.controller.secret`                   | `info`  | "resource reconciled"                                                                      |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino.controller-runtime.manager.controller.secret`                   | `info`  | "could not reconcile authconfigs using api key authorino.authentication"                   |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino.service.oidc`                                                   | `info`  | "request received"                                                                         | `request id`, `url`, `realm`, `config`, `path`                                                                                                                                                                                                                                                                                                                                            |
| `authorino.service.oidc`                                                   | `info`  | "response sent"                                                                            | `request id`                                                                                                                                                                                                                                                                                                                                                                              |
| `authorino.service.oidc`                                                   | `error` | "failed to serve oidc request"                                                             |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino.service.auth`                                                   | `info`  | "incoming authorization request"                                                           | `request id`, `object`                                                                                                                                                                                                                                                                                                                                                                    |
| `authorino.service.auth`                                                   | `debug` | "incoming authorization request"                                                           | `request id`, `object`                                                                                                                                                                                                                                                                                                                                                                    |
| `authorino.service.auth`                                                   | `info`  | "outgoing authorization response"                                                          | `request id`, `authorized`, `response`, `object`                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth`                                                   | `debug` | "outgoing authorization response"                                                          | `request id`, `authorized`, `response`, `object`                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth`                                                   | `error` | "failed to create dynamic metadata"                                                        | `request id`, `object`                                                                                                                                                                                                                                                                                                                                                                    |
| `authorino.service.auth.authpipeline`                                      | `debug` | "skipping config"                                                                          | `request id`, `config`, `reason`                                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth.authpipeline.identity`                             | `debug` | "identity validated"                                                                       | `request id`, `config`, `object`                                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth.authpipeline.identity`                             | `debug` | "cannot validate identity"                                                                 | `request id`, `config`, `reason`                                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth.authpipeline.identity`                             | `error` | "failed to extend identity object"                                                         | `request id`, `config`, `object`                                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth.authpipeline.identity.oidc`                        | `error` | "failed to discovery openid connect configuration"                                         | `endpoint`                                                                                                                                                                                                                                                                                                                                                                                |
| `authorino.service.auth.authpipeline.identity.oidc`                        | `debug` | "auto-refresh of openid connect configuration disabled"                                    | `endpoint`, `reason`                                                                                                                                                                                                                                                                                                                                                                      |
| `authorino.service.auth.authpipeline.identity.oidc`                        | `debug` | "openid connect configuration updated"                                                     | `endpoint`                                                                                                                                                                                                                                                                                                                                                                                |
| `authorino.service.auth.authpipeline.identity.oauth2`                      | `debug` | "sending token introspection request"                                                      | `request id`, `url`, `data`                                                                                                                                                                                                                                                                                                                                                               |
| `authorino.service.auth.authpipeline.identity.kubernetesauth`              | `debug` | "calling kubernetes token review api"                                                      | `request id`, `tokenreview`                                                                                                                                                                                                                                                                                                                                                               |
| `authorino.service.auth.authpipeline.identity.apikey`                      | `error` | "Something went wrong fetching the authorized credentials"                                 |                                                                                                                                                                                                                                                                                                                                                                                           |
| `authorino.service.auth.authpipeline.metadata`                             | `debug` | "fetched auth metadata"                                                                    | `request id`, `config`, `object`                                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth.authpipeline.metadata`                             | `debug` | "cannot fetch metadata"                                                                    | `request id`, `config`, `reason`                                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth.authpipeline.metadata.http`                        | `debug` | "sending request"                                                                          | `request id`, `method`, `url`, `headers`                                                                                                                                                                                                                                                                                                                                                  |
| `authorino.service.auth.authpipeline.metadata.userinfo`                    | `debug` | "fetching user info"                                                                       | `request id`, `endpoint`                                                                                                                                                                                                                                                                                                                                                                  |
| `authorino.service.auth.authpipeline.metadata.uma`                         | `debug` | "requesting pat"                                                                           | `request id`, `url`, `data`, `headers`                                                                                                                                                                                                                                                                                                                                                    |
| `authorino.service.auth.authpipeline.metadata.uma`                         | `debug` | "querying resources by uri"                                                                | `request id`, `url`                                                                                                                                                                                                                                                                                                                                                                       |
| `authorino.service.auth.authpipeline.metadata.uma`                         | `debug` | "getting resource data"                                                                    | `request id`, `url`                                                                                                                                                                                                                                                                                                                                                                       |
| `authorino.service.auth.authpipeline.authorization`                        | `debug` | "evaluating for input"                                                                     | `request id`, `input`                                                                                                                                                                                                                                                                                                                                                                     |
| `authorino.service.auth.authpipeline.authorization`                        | `debug` | "access granted"                                                                           | `request id`, `config`, `object`                                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth.authpipeline.authorization`                        | `debug` | "access denied"                                                                            | `request id`, `config`, `reason`                                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth.authpipeline.authorization.opa`                    | `error` | "invalid response from policy evaluation"                                                  | `policy`                                                                                                                                                                                                                                                                                                                                                                                  |
| `authorino.service.auth.authpipeline.authorization.opa`                    | `error` | "failed to precompile policy"                                                              | `policy`                                                                                                                                                                                                                                                                                                                                                                                  |
| `authorino.service.auth.authpipeline.authorization.opa`                    | `error` | "failed to download policy from external registry"                                         | `policy`, `endpoint`                                                                                                                                                                                                                                                                                                                                                                      |
| `authorino.service.auth.authpipeline.authorization.opa`                    | `error` | "failed to refresh policy from external registry"                                          | `policy`, `endpoint`                                                                                                                                                                                                                                                                                                                                                                      |
| `authorino.service.auth.authpipeline.authorization.opa`                    | `debug` | "external policy unchanged"                                                                | `policy`, `endpoint`                                                                                                                                                                                                                                                                                                                                                                      |
| `authorino.service.auth.authpipeline.authorization.opa`                    | `debug` | "auto-refresh  of external policy disabled"                                                | `policy`, `endpoint`, `reason`                                                                                                                                                                                                                                                                                                                                                            |
| `authorino.service.auth.authpipeline.authorization.opa`                    | `info`  | "policy updated from external registry"                                                    | `policy`, `endpoint`                                                                                                                                                                                                                                                                                                                                                                      |
| `authorino.service.auth.authpipeline.authorization.kubernetesauthz`        | `debug` | "calling kubernetes subject access review api"                                             | `request id`, `subjectaccessreview`                                                                                                                                                                                                                                                                                                                                                       |
| `authorino.service.auth.authpipeline.response`                             | `debug` | "dynamic response built"                                                                   | `request id`, `config`, `object`                                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth.authpipeline.response`                             | `debug` | "cannot build dynamic response"                                                            | `request id`, `config`, `reason`                                                                                                                                                                                                                                                                                                                                                          |
| `authorino.service.auth.http`                                              | `debug` | "bad request"                                                                              | `request id`                                                                                                                                                                                                                                                                                                                                                                              |
| `authorino.service.auth.http`                                              | `debug` | "not found"                                                                                | `request id`                                                                                                                                                                                                                                                                                                                                                                              |
| `authorino.service.auth.http`                                              | `debug` | "request body too large"                                                                   | `request id`                                                                                                                                                                                                                                                                                                                                                                              |
| `authorino.service.auth.http`                                              | `debug` | "service unavailable"                                                                      | `request id`                                                                                                                                                                                                                                                                                                                                                                              |

#### Examples

The examples below are all with `--log-level=debug` and `--log-mode=production`.

<details>
  <summary>Booting up the service</summary>

  ```jsonc
  {"level":"info","ts":1669220526.929678,"logger":"authorino","msg":"setting instance base logger","min level":"debug","mode":"production"}
  {"level":"info","ts":1669220526.929718,"logger":"authorino","msg":"booting up authorino","version":"7688cfa32317a49f0461414e741c980e9c05dba3"}
  {"level":"debug","ts":1669220526.9297278,"logger":"authorino","msg":"setting up with options","auth-config-label-selector":"","deep-metrics-enabled":"false","enable-leader-election":"false","evaluator-cache-size":"1","ext-auth-grpc-port":"50051","ext-auth-http-port":"5001","health-probe-addr":":8081","log-level":"debug","log-mode":"production","max-http-request-body-size":"8192","metrics-addr":":8080","oidc-http-port":"8083","oidc-tls-cert":"/etc/ssl/certs/oidc.crt","oidc-tls-cert-key":"/etc/ssl/private/oidc.key","secret-label-selector":"authorino.kuadrant.io/managed-by=authorino","timeout":"0","tls-cert":"/etc/ssl/certs/tls.crt","tls-cert-key":"/etc/ssl/private/tls.key","watch-namespace":"default"}
  {"level":"info","ts":1669220527.9816976,"logger":"authorino.controller-runtime.metrics","msg":"Metrics server is starting to listen","addr":":8080"}
  {"level":"info","ts":1669220527.9823213,"logger":"authorino","msg":"starting grpc auth service","port":50051,"tls":true}
  {"level":"info","ts":1669220527.9823658,"logger":"authorino","msg":"starting http auth service","port":5001,"tls":true}
  {"level":"info","ts":1669220527.9824295,"logger":"authorino","msg":"starting http oidc service","port":8083,"tls":true}
  {"level":"info","ts":1669220527.9825335,"logger":"authorino","msg":"starting manager"}
  {"level":"info","ts":1669220527.982721,"logger":"authorino","msg":"Starting server","path":"/metrics","kind":"metrics","addr":"[::]:8080"}
  {"level":"info","ts":1669220527.982766,"logger":"authorino","msg":"Starting server","kind":"health probe","addr":"[::]:8081"}
  {"level":"info","ts":1669220527.9829438,"logger":"authorino.controller.secret","msg":"Starting EventSource","reconciler group":"","reconciler kind":"Secret","source":"kind source: *v1.Secret"}
  {"level":"info","ts":1669220527.9829693,"logger":"authorino.controller.secret","msg":"Starting Controller","reconciler group":"","reconciler kind":"Secret"}
  {"level":"info","ts":1669220527.9829714,"logger":"authorino.controller.authconfig","msg":"Starting EventSource","reconciler group":"authorino.kuadrant.io","reconciler kind":"AuthConfig","source":"kind source: *v1beta1.AuthConfig"}
  {"level":"info","ts":1669220527.9830208,"logger":"authorino.controller.authconfig","msg":"Starting Controller","reconciler group":"authorino.kuadrant.io","reconciler kind":"AuthConfig"}
  {"level":"info","ts":1669220528.0834699,"logger":"authorino.controller.authconfig","msg":"Starting workers","reconciler group":"authorino.kuadrant.io","reconciler kind":"AuthConfig","worker count":1}
  {"level":"info","ts":1669220528.0836608,"logger":"authorino.controller.secret","msg":"Starting workers","reconciler group":"","reconciler kind":"Secret","worker count":1}
  {"level":"info","ts":1669220529.041266,"logger":"authorino","msg":"starting status update manager"}
  {"level":"info","ts":1669220529.0418258,"logger":"authorino.controller.authconfig","msg":"Starting EventSource","reconciler group":"authorino.kuadrant.io","reconciler kind":"AuthConfig","source":"kind source: *v1beta1.AuthConfig"}
  {"level":"info","ts":1669220529.0418813,"logger":"authorino.controller.authconfig","msg":"Starting Controller","reconciler group":"authorino.kuadrant.io","reconciler kind":"AuthConfig"}
  {"level":"info","ts":1669220529.1432905,"logger":"authorino.controller.authconfig","msg":"Starting workers","reconciler group":"authorino.kuadrant.io","reconciler kind":"AuthConfig","worker count":1}
  ```
</details>

<details>
  <summary>Reconciling an AuthConfig and 2 related API key secrets</summary>

  ```jsonc
  {"level":"debug","ts":1669221208.7473805,"logger":"authorino.controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status changed","authconfig":"default/talker-api-protection","authconfig/status":{"conditions":[{"type":"Available","status":"False","lastTransitionTime":"2022-11-23T16:33:28Z","reason":"HostsNotLinked","message":"No hosts linked to the resource"},{"type":"Ready","status":"False","lastTransitionTime":"2022-11-23T16:33:28Z","reason":"Unknown"}],"summary":{"ready":false,"hostsReady":[],"numHostsReady":"0/1","numIdentitySources":1,"numMetadataSources":0,"numAuthorizationPolicies":0,"numResponseItems":0,"festivalWristbandEnabled":false}}}
  {"level":"info","ts":1669221208.7496614,"logger":"authorino.controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"default/talker-api-protection"}
  {"level":"info","ts":1669221208.7532616,"logger":"authorino.controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"default/talker-api-protection"}
  {"level":"debug","ts":1669221208.7535005,"logger":"authorino.controller.secret","msg":"adding k8s secret to the index","reconciler group":"","reconciler kind":"Secret","name":"api-key-1","namespace":"default","authconfig":"default/talker-api-protection","config":"friends"}
  {"level":"debug","ts":1669221208.7535596,"logger":"authorino.controller.secret.apikey","msg":"api key added","reconciler group":"","reconciler kind":"Secret","name":"api-key-1","namespace":"default"}
  {"level":"info","ts":1669221208.7536132,"logger":"authorino.controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"default/api-key-1"}
  {"level":"info","ts":1669221208.753772,"logger":"authorino.controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status updated","authconfig":"default/talker-api-protection"}
  {"level":"debug","ts":1669221208.753835,"logger":"authorino.controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status changed","authconfig":"default/talker-api-protection","authconfig/status":{"conditions":[{"type":"Available","status":"True","lastTransitionTime":"2022-11-23T16:33:28Z","reason":"HostsLinked"},{"type":"Ready","status":"True","lastTransitionTime":"2022-11-23T16:33:28Z","reason":"Reconciled"}],"summary":{"ready":true,"hostsReady":["talker-api.127.0.0.1.nip.io"],"numHostsReady":"1/1","numIdentitySources":1,"numMetadataSources":0,"numAuthorizationPolicies":0,"numResponseItems":0,"festivalWristbandEnabled":false}}}
  {"level":"info","ts":1669221208.7571108,"logger":"authorino.controller-runtime.manager.controller.authconfig","msg":"resource reconciled","authconfig":"default/talker-api-protection"}
  {"level":"info","ts":1669221208.7573664,"logger":"authorino.controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status updated","authconfig":"default/talker-api-protection"}
  {"level":"debug","ts":1669221208.757429,"logger":"authorino.controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status did not change","authconfig":"default/talker-api-protection"}
  {"level":"debug","ts":1669221208.7586699,"logger":"authorino.controller.secret","msg":"adding k8s secret to the index","reconciler group":"","reconciler kind":"Secret","name":"api-key-2","namespace":"default","authconfig":"default/talker-api-protection","config":"friends"}
  {"level":"debug","ts":1669221208.7586884,"logger":"authorino.controller.secret.apikey","msg":"api key added","reconciler group":"","reconciler kind":"Secret","name":"api-key-2","namespace":"default"}
  {"level":"info","ts":1669221208.7586913,"logger":"authorino.controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"default/api-key-2"}
  {"level":"debug","ts":1669221208.7597604,"logger":"authorino.controller-runtime.manager.controller.authconfig.statusupdater","msg":"resource status did not change","authconfig":"default/talker-api-protection"}
  ```
</details>

<details>
  <summary>Enforcing an AuthConfig with authentication based on Kubernetes tokens:</summary>

  <br/>

  - identity: k8s-auth, oidc, oauth2, apikey
  - metadata: http, oidc userinfo
  - authorization: opa, k8s-authz
  - response: wristband

  ```jsonc
  {"level":"info","ts":1634830460.1486168,"logger":"authorino.service.auth","msg":"incoming authorization request","request id":"8157480586935853928","object":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":53144}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"http":{"id":"8157480586935853928","method":"GET","path":"/hello","host":"talker-api","scheme":"http"}}}}
  {"level":"debug","ts":1634830460.1491194,"logger":"authorino.service.auth","msg":"incoming authorization request","request id":"8157480586935853928","object":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":53144}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"time":{"seconds":1634830460,"nanos":147259000},"http":{"id":"8157480586935853928","method":"GET","headers":{":authority":"talker-api",":method":"GET",":path":"/hello",":scheme":"http","accept":"*/*","authorization":"Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkRsVWJZMENyVy1sZ0tFMVRMd19pcTFUWGtTYUl6T0hyWks0VHhKYnpEZUUifQ.eyJhdWQiOlsidGFsa2VyLWFwaSJdLCJleHAiOjE2MzQ4MzEwNTEsImlhdCI6MTYzNDgzMDQ1MSwiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXItMSIsInVpZCI6ImI0MGY1MzFjLWVjYWItNGYzMS1hNDk2LTJlYmM3MmFkZDEyMSJ9fSwibmJmIjoxNjM0ODMwNDUxLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YXV0aG9yaW5vOmFwaS1jb25zdW1lci0xIn0.PaP0vqdl5DPfErr84KfVhPdlsGAPgsw0NkDaA9rne1zXjzcO7KPPbXhFwZC-oIjSGG1HfRMSoQeCXbQz24PSATmX8l1T52a9IFeXgP7sQmXZIDbiPfTm3X09kIIlfPKHhK_f-jQwRIpMRqNgLntlZ-xXX3P1fOBBUYR8obTPAQ6NDDaLHxw2SAmHFTQWjM_DInPDemXX0mEm7nCPKifsNxHaQH4wx4CD3LCLGbCI9FHNf2Crid8mmGJXf4wzcH1VuKkpUlsmnlUgTG2bfT2lbhSF2lBmrrhTJyYk6_aA09DwL4Bf4kvG-JtCq0Bkd_XynViIsOtOnAhgmdSPkfr-oA","user-agent":"curl/7.65.3","x-envoy-internal":"true","x-forwarded-for":"10.244.0.11","x-forwarded-proto":"http","x-request-id":"4c5d5c97-e15b-46a3-877a-d8188e09e08f"},"path":"/hello","host":"talker-api","scheme":"http","protocol":"HTTP/1.1"}},"context_extensions":{"virtual_host":"local_service"},"metadata_context":{}}}
  {"level":"debug","ts":1634830460.150506,"logger":"authorino.service.auth.authpipeline.identity.kubernetesauth","msg":"calling kubernetes token review api","request id":"8157480586935853928","tokenreview":{"metadata":{"creationTimestamp":null},"spec":{"token":"eyJhbGciOiJSUzI1NiIsImtpZCI6IkRsVWJZMENyVy1sZ0tFMVRMd19pcTFUWGtTYUl6T0hyWks0VHhKYnpEZUUifQ.eyJhdWQiOlsidGFsa2VyLWFwaSJdLCJleHAiOjE2MzQ4MzEwNTEsImlhdCI6MTYzNDgzMDQ1MSwiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXItMSIsInVpZCI6ImI0MGY1MzFjLWVjYWItNGYzMS1hNDk2LTJlYmM3MmFkZDEyMSJ9fSwibmJmIjoxNjM0ODMwNDUxLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YXV0aG9yaW5vOmFwaS1jb25zdW1lci0xIn0.PaP0vqdl5DPfErr84KfVhPdlsGAPgsw0NkDaA9rne1zXjzcO7KPPbXhFwZC-oIjSGG1HfRMSoQeCXbQz24PSATmX8l1T52a9IFeXgP7sQmXZIDbiPfTm3X09kIIlfPKHhK_f-jQwRIpMRqNgLntlZ-xXX3P1fOBBUYR8obTPAQ6NDDaLHxw2SAmHFTQWjM_DInPDemXX0mEm7nCPKifsNxHaQH4wx4CD3LCLGbCI9FHNf2Crid8mmGJXf4wzcH1VuKkpUlsmnlUgTG2bfT2lbhSF2lBmrrhTJyYk6_aA09DwL4Bf4kvG-JtCq0Bkd_XynViIsOtOnAhgmdSPkfr-oA","audiences":["talker-api"]},"status":{"user":{}}}}
  {"level":"debug","ts":1634830460.1509938,"logger":"authorino.service.auth.authpipeline.identity","msg":"cannot validate identity","request id":"8157480586935853928","config":{"Name":"api-keys","ExtendedProperties":[{"Name":"sub","Value":{"Static":null,"Pattern":"auth.identity.metadata.annotations.userid"}}],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":{"AuthCredentials":{"KeySelector":"APIKEY","In":"authorization_header"},"Name":"api-keys","LabelSelectors":{"audience":"talker-api","authorino.kuadrant.io/managed-by":"authorino"}},"KubernetesAuth":null},"reason":"credential not found"}
  {"level":"debug","ts":1634830460.1517606,"logger":"authorino.service.auth.authpipeline.identity.oauth2","msg":"sending token introspection request","request id":"8157480586935853928","url":"http://talker-api:523b92b6-625d-4e1e-a313-77e7a8ae4e88@keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token/introspect","data":"token=eyJhbGciOiJSUzI1NiIsImtpZCI6IkRsVWJZMENyVy1sZ0tFMVRMd19pcTFUWGtTYUl6T0hyWks0VHhKYnpEZUUifQ.eyJhdWQiOlsidGFsa2VyLWFwaSJdLCJleHAiOjE2MzQ4MzEwNTEsImlhdCI6MTYzNDgzMDQ1MSwiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXItMSIsInVpZCI6ImI0MGY1MzFjLWVjYWItNGYzMS1hNDk2LTJlYmM3MmFkZDEyMSJ9fSwibmJmIjoxNjM0ODMwNDUxLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YXV0aG9yaW5vOmFwaS1jb25zdW1lci0xIn0.PaP0vqdl5DPfErr84KfVhPdlsGAPgsw0NkDaA9rne1zXjzcO7KPPbXhFwZC-oIjSGG1HfRMSoQeCXbQz24PSATmX8l1T52a9IFeXgP7sQmXZIDbiPfTm3X09kIIlfPKHhK_f-jQwRIpMRqNgLntlZ-xXX3P1fOBBUYR8obTPAQ6NDDaLHxw2SAmHFTQWjM_DInPDemXX0mEm7nCPKifsNxHaQH4wx4CD3LCLGbCI9FHNf2Crid8mmGJXf4wzcH1VuKkpUlsmnlUgTG2bfT2lbhSF2lBmrrhTJyYk6_aA09DwL4Bf4kvG-JtCq0Bkd_XynViIsOtOnAhgmdSPkfr-oA&token_type_hint=requesting_party_token"}
  {"level":"debug","ts":1634830460.1620777,"logger":"authorino.service.auth.authpipeline.identity","msg":"identity validated","request id":"8157480586935853928","config":{"Name":"k8s-service-accounts","ExtendedProperties":[],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"object":{"aud":["talker-api"],"exp":1634831051,"iat":1634830451,"iss":"https://kubernetes.default.svc.cluster.local","kubernetes.io":{"namespace":"authorino","serviceaccount":{"name":"api-consumer-1","uid":"b40f531c-ecab-4f31-a496-2ebc72add121"}},"nbf":1634830451,"sub":"system:serviceaccount:authorino:api-consumer-1"}}
  {"level":"debug","ts":1634830460.1622565,"logger":"authorino.service.auth.authpipeline.metadata.uma","msg":"requesting pat","request id":"8157480586935853928","url":"http://talker-api:523b92b6-625d-4e1e-a313-77e7a8ae4e88@keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token","data":"grant_type=client_credentials","headers":{"Content-Type":["application/x-www-form-urlencoded"]}}
  {"level":"debug","ts":1634830460.1670353,"logger":"authorino.service.auth.authpipeline.metadata.http","msg":"sending request","request id":"8157480586935853928","method":"GET","url":"http://talker-api.default.svc.cluster.local:3000/metadata?encoding=text/plain&original_path=/hello","headers":{"Content-Type":["text/plain"]}}
  {"level":"debug","ts":1634830460.169326,"logger":"authorino.service.auth.authpipeline.metadata","msg":"cannot fetch metadata","request id":"8157480586935853928","config":{"Name":"oidc-userinfo","UserInfo":{"OIDC":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"Endpoint":"http://keycloak:8080/auth/realms/kuadrant"}},"UMA":null,"GenericHTTP":null},"reason":"Missing identity for OIDC issuer http://keycloak:8080/auth/realms/kuadrant. Skipping related UserInfo metadata."}
  {"level":"debug","ts":1634830460.1753876,"logger":"authorino.service.auth.authpipeline.metadata","msg":"fetched auth metadata","request id":"8157480586935853928","config":{"Name":"http-metadata","UserInfo":null,"UMA":null,"GenericHTTP":{"Endpoint":"http://talker-api.default.svc.cluster.local:3000/metadata?encoding=text/plain&original_path={context.request.http.path}","Method":"GET","Parameters":[],"ContentType":"application/x-www-form-urlencoded","SharedSecret":"","AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"object":{"body":"","headers":{"Accept-Encoding":"gzip","Content-Type":"text/plain","Host":"talker-api.default.svc.cluster.local:3000","User-Agent":"Go-http-client/1.1","Version":"HTTP/1.1"},"method":"GET","path":"/metadata","query_string":"encoding=text/plain&original_path=/hello","uuid":"1aa6ac66-3179-4351-b1a7-7f6a761d5b61"}}
  {"level":"debug","ts":1634830460.2331996,"logger":"authorino.service.auth.authpipeline.metadata.uma","msg":"querying resources by uri","request id":"8157480586935853928","url":"http://keycloak:8080/auth/realms/kuadrant/authz/protection/resource_set?uri=/hello"}
  {"level":"debug","ts":1634830460.2495668,"logger":"authorino.service.auth.authpipeline.metadata.uma","msg":"getting resource data","request id":"8157480586935853928","url":"http://keycloak:8080/auth/realms/kuadrant/authz/protection/resource_set/e20d194c-274c-4845-8c02-0ca413c9bf18"}
  {"level":"debug","ts":1634830460.2927864,"logger":"authorino.service.auth.authpipeline.metadata","msg":"fetched auth metadata","request id":"8157480586935853928","config":{"Name":"uma-resource-registry","UserInfo":null,"UMA":{"Endpoint":"http://keycloak:8080/auth/realms/kuadrant","ClientID":"talker-api","ClientSecret":"523b92b6-625d-4e1e-a313-77e7a8ae4e88"},"GenericHTTP":null},"object":[{"_id":"e20d194c-274c-4845-8c02-0ca413c9bf18","attributes":{},"displayName":"hello","name":"hello","owner":{"id":"57a645a5-fb67-438b-8be5-dfb971666dbc"},"ownerManagedAccess":false,"resource_scopes":[],"uris":["/hi","/hello"]}]}
  {"level":"debug","ts":1634830460.2930083,"logger":"authorino.service.auth.authpipeline.authorization","msg":"evaluating for input","request id":"8157480586935853928","input":{"context":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":53144}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"time":{"seconds":1634830460,"nanos":147259000},"http":{"id":"8157480586935853928","method":"GET","headers":{":authority":"talker-api",":method":"GET",":path":"/hello",":scheme":"http","accept":"*/*","authorization":"Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkRsVWJZMENyVy1sZ0tFMVRMd19pcTFUWGtTYUl6T0hyWks0VHhKYnpEZUUifQ.eyJhdWQiOlsidGFsa2VyLWFwaSJdLCJleHAiOjE2MzQ4MzEwNTEsImlhdCI6MTYzNDgzMDQ1MSwiaXNzIjoiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrdWJlcm5ldGVzLmlvIjp7Im5hbWVzcGFjZSI6ImF1dGhvcmlubyIsInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJhcGktY29uc3VtZXItMSIsInVpZCI6ImI0MGY1MzFjLWVjYWItNGYzMS1hNDk2LTJlYmM3MmFkZDEyMSJ9fSwibmJmIjoxNjM0ODMwNDUxLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6YXV0aG9yaW5vOmFwaS1jb25zdW1lci0xIn0.PaP0vqdl5DPfErr84KfVhPdlsGAPgsw0NkDaA9rne1zXjzcO7KPPbXhFwZC-oIjSGG1HfRMSoQeCXbQz24PSATmX8l1T52a9IFeXgP7sQmXZIDbiPfTm3X09kIIlfPKHhK_f-jQwRIpMRqNgLntlZ-xXX3P1fOBBUYR8obTPAQ6NDDaLHxw2SAmHFTQWjM_DInPDemXX0mEm7nCPKifsNxHaQH4wx4CD3LCLGbCI9FHNf2Crid8mmGJXf4wzcH1VuKkpUlsmnlUgTG2bfT2lbhSF2lBmrrhTJyYk6_aA09DwL4Bf4kvG-JtCq0Bkd_XynViIsOtOnAhgmdSPkfr-oA","user-agent":"curl/7.65.3","x-envoy-internal":"true","x-forwarded-for":"10.244.0.11","x-forwarded-proto":"http","x-request-id":"4c5d5c97-e15b-46a3-877a-d8188e09e08f"},"path":"/hello","host":"talker-api","scheme":"http","protocol":"HTTP/1.1"}},"context_extensions":{"virtual_host":"local_service"},"metadata_context":{}},"auth":{"identity":{"aud":["talker-api"],"exp":1634831051,"iat":1634830451,"iss":"https://kubernetes.default.svc.cluster.local","kubernetes.io":{"namespace":"authorino","serviceaccount":{"name":"api-consumer-1","uid":"b40f531c-ecab-4f31-a496-2ebc72add121"}},"nbf":1634830451,"sub":"system:serviceaccount:authorino:api-consumer-1"},"metadata":{"http-metadata":{"body":"","headers":{"Accept-Encoding":"gzip","Content-Type":"text/plain","Host":"talker-api.default.svc.cluster.local:3000","User-Agent":"Go-http-client/1.1","Version":"HTTP/1.1"},"method":"GET","path":"/metadata","query_string":"encoding=text/plain&original_path=/hello","uuid":"1aa6ac66-3179-4351-b1a7-7f6a761d5b61"},"uma-resource-registry":[{"_id":"e20d194c-274c-4845-8c02-0ca413c9bf18","attributes":{},"displayName":"hello","name":"hello","owner":{"id":"57a645a5-fb67-438b-8be5-dfb971666dbc"},"ownerManagedAccess":false,"resource_scopes":[],"uris":["/hi","/hello"]}]}}}}
  {"level":"debug","ts":1634830460.2955465,"logger":"authorino.service.auth.authpipeline.authorization.kubernetesauthz","msg":"calling kubernetes subject access review api","request id":"8157480586935853928","subjectaccessreview":{"metadata":{"creationTimestamp":null},"spec":{"nonResourceAttributes":{"path":"/hello","verb":"get"},"user":"system:serviceaccount:authorino:api-consumer-1"},"status":{"allowed":false}}}
  {"level":"debug","ts":1634830460.2986183,"logger":"authorino.service.auth.authpipeline.authorization","msg":"access granted","request id":"8157480586935853928","config":{"Name":"my-policy","OPA":{"Rego":"fail := input.context.request.http.headers[\"x-ext-auth-mock\"] == \"FAIL\"\nallow { not fail }\n","OPAExternalSource":{"Endpoint":"","SharedSecret":"","AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"JSON":null,"KubernetesAuthz":null},"object":true}
  {"level":"debug","ts":1634830460.3044975,"logger":"authorino.service.auth.authpipeline.authorization","msg":"access granted","request id":"8157480586935853928","config":{"Name":"kubernetes-rbac","OPA":null,"JSON":null,"KubernetesAuthz":{"Conditions":[],"User":{"Static":"","Pattern":"auth.identity.user.username"},"Groups":null,"ResourceAttributes":null}},"object":true}
  {"level":"debug","ts":1634830460.3052874,"logger":"authorino.service.auth.authpipeline.response","msg":"dynamic response built","request id":"8157480586935853928","config":{"Name":"wristband","Wrapper":"httpHeader","WrapperKey":"x-ext-auth-wristband","Wristband":{"Issuer":"https://authorino-oidc.default.svc:8083/default/talker-api-protection/wristband","CustomClaims":[],"TokenDuration":300,"SigningKeys":[{"use":"sig","kty":"EC","kid":"wristband-signing-key","crv":"P-256","alg":"ES256","x":"TJf5NLVKplSYp95TOfhVPqvxvEibRyjrUZwwtpDuQZw","y":"SSg8rKBsJ3J1LxyLtt0oFvhHvZcUpmRoTuHk3UHisTA","d":"Me-5_zWBWVYajSGZcZMCcD8dXEa4fy85zv_yN7BxW-o"}]},"DynamicJSON":null},"object":"eyJhbGciOiJFUzI1NiIsImtpZCI6IndyaXN0YmFuZC1zaWduaW5nLWtleSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzQ4MzA3NjAsImlhdCI6MTYzNDgzMDQ2MCwiaXNzIjoiaHR0cHM6Ly9hdXRob3Jpbm8tb2lkYy5hdXRob3Jpbm8uc3ZjOjgwODMvYXV0aG9yaW5vL3RhbGtlci1hcGktcHJvdGVjdGlvbi93cmlzdGJhbmQiLCJzdWIiOiI4NDliMDk0ZDA4MzU0ZjM0MjA4ZGI3MjBmYWZmODlmNmM3NmYyOGY3MTcxOWI4NTQ3ZDk5NWNlNzAwMjU2ZGY4In0.Jn-VB5Q_0EX1ed1ji4KvhO4DlMqZeIl5H0qlukbTyYkp-Pgb4SnPGSbYWp5_uvG8xllsFAA5nuyBIXeba-dbkw"}
  {"level":"info","ts":1634830460.3054585,"logger":"authorino.service.auth","msg":"outgoing authorization response","request id":"8157480586935853928","authorized":true,"response":"OK"}
  {"level":"debug","ts":1634830460.305476,"logger":"authorino.service.auth","msg":"outgoing authorization response","request id":"8157480586935853928","authorized":true,"response":"OK"}
  ```
</details>

<details>
  <summary>Enforcing an AuthConfig with authentication based on API keys</summary>

  <br/>

  - identity: k8s-auth, oidc, oauth2, apikey
  - metadata: http, oidc userinfo
  - authorization: opa, k8s-authz
  - response: wristband

  ```jsonc
  {"level":"info","ts":1634830413.2425854,"logger":"authorino.service.auth","msg":"incoming authorization request","request id":"7199257136822741594","object":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":52702}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"http":{"id":"7199257136822741594","method":"GET","path":"/hello","host":"talker-api","scheme":"http"}}}}
  {"level":"debug","ts":1634830413.2426975,"logger":"authorino.service.auth","msg":"incoming authorization request","request id":"7199257136822741594","object":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":52702}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"time":{"seconds":1634830413,"nanos":240094000},"http":{"id":"7199257136822741594","method":"GET","headers":{":authority":"talker-api",":method":"GET",":path":"/hello",":scheme":"http","accept":"*/*","authorization":"APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx","user-agent":"curl/7.65.3","x-envoy-internal":"true","x-forwarded-for":"10.244.0.11","x-forwarded-proto":"http","x-request-id":"d38f5e66-bd72-4733-95d1-3179315cdd60"},"path":"/hello","host":"talker-api","scheme":"http","protocol":"HTTP/1.1"}},"context_extensions":{"virtual_host":"local_service"},"metadata_context":{}}}
  {"level":"debug","ts":1634830413.2428744,"logger":"authorino.service.auth.authpipeline.identity","msg":"cannot validate identity","request id":"7199257136822741594","config":{"Name":"k8s-service-accounts","ExtendedProperties":[],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"reason":"credential not found"}
  {"level":"debug","ts":1634830413.2434332,"logger":"authorino.service.auth.authpipeline","msg":"skipping config","request id":"7199257136822741594","config":{"Name":"keycloak-jwts","ExtendedProperties":[],"OAuth2":null,"OIDC":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"Endpoint":"http://keycloak:8080/auth/realms/kuadrant"},"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":null},"reason":"context canceled"}
  {"level":"debug","ts":1634830413.2479305,"logger":"authorino.service.auth.authpipeline.identity","msg":"identity validated","request id":"7199257136822741594","config":{"Name":"api-keys","ExtendedProperties":[{"Name":"sub","Value":{"Static":null,"Pattern":"auth.identity.metadata.annotations.userid"}}],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":{"AuthCredentials":{"KeySelector":"APIKEY","In":"authorization_header"},"Name":"api-keys","LabelSelectors":{"audience":"talker-api","authorino.kuadrant.io/managed-by":"authorino"}},"KubernetesAuth":null},"object":{"apiVersion":"v1","data":{"api_key":"bmR5QnpyZVV6RjR6cURRc3FTUE1Ia1JocmlFT3RjUng="},"kind":"Secret","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"annotations\":{\"userid\":\"john\"},\"labels\":{\"audience\":\"talker-api\",\"authorino.kuadrant.io/managed-by\":\"authorino\"},\"name\":\"api-key-1\",\"namespace\":\"authorino\"},\"stringData\":{\"api_key\":\"ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx\"},\"type\":\"Opaque\"}\n","userid":"john"},"creationTimestamp":"2021-10-21T14:45:54Z","labels":{"audience":"talker-api","authorino.kuadrant.io/managed-by":"authorino"},"managedFields":[{"apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:data":{".":{},"f:api_key":{}},"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{},"f:userid":{}},"f:labels":{".":{},"f:audience":{},"f:authorino.kuadrant.io/managed-by":{}}},"f:type":{}},"manager":"kubectl-client-side-apply","operation":"Update","time":"2021-10-21T14:45:54Z"}],"name":"api-key-1","namespace":"authorino","resourceVersion":"8979","uid":"c369852a-7e1a-43bd-94ca-e2b3f617052e"},"sub":"john","type":"Opaque"}}
  {"level":"debug","ts":1634830413.248768,"logger":"authorino.service.auth.authpipeline.metadata.http","msg":"sending request","request id":"7199257136822741594","method":"GET","url":"http://talker-api.default.svc.cluster.local:3000/metadata?encoding=text/plain&original_path=/hello","headers":{"Content-Type":["text/plain"]}}
  {"level":"debug","ts":1634830413.2496722,"logger":"authorino.service.auth.authpipeline.metadata","msg":"cannot fetch metadata","request id":"7199257136822741594","config":{"Name":"oidc-userinfo","UserInfo":{"OIDC":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"Endpoint":"http://keycloak:8080/auth/realms/kuadrant"}},"UMA":null,"GenericHTTP":null},"reason":"Missing identity for OIDC issuer http://keycloak:8080/auth/realms/kuadrant. Skipping related UserInfo metadata."}
  {"level":"debug","ts":1634830413.2497928,"logger":"authorino.service.auth.authpipeline.metadata.uma","msg":"requesting pat","request id":"7199257136822741594","url":"http://talker-api:523b92b6-625d-4e1e-a313-77e7a8ae4e88@keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token","data":"grant_type=client_credentials","headers":{"Content-Type":["application/x-www-form-urlencoded"]}}
  {"level":"debug","ts":1634830413.258932,"logger":"authorino.service.auth.authpipeline.metadata","msg":"fetched auth metadata","request id":"7199257136822741594","config":{"Name":"http-metadata","UserInfo":null,"UMA":null,"GenericHTTP":{"Endpoint":"http://talker-api.default.svc.cluster.local:3000/metadata?encoding=text/plain&original_path={context.request.http.path}","Method":"GET","Parameters":[],"ContentType":"application/x-www-form-urlencoded","SharedSecret":"","AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"object":{"body":"","headers":{"Accept-Encoding":"gzip","Content-Type":"text/plain","Host":"talker-api.default.svc.cluster.local:3000","User-Agent":"Go-http-client/1.1","Version":"HTTP/1.1"},"method":"GET","path":"/metadata","query_string":"encoding=text/plain&original_path=/hello","uuid":"97529f8c-587b-4121-a4db-cd90c63871fd"}}
  {"level":"debug","ts":1634830413.2945344,"logger":"authorino.service.auth.authpipeline.metadata.uma","msg":"querying resources by uri","request id":"7199257136822741594","url":"http://keycloak:8080/auth/realms/kuadrant/authz/protection/resource_set?uri=/hello"}
  {"level":"debug","ts":1634830413.3123596,"logger":"authorino.service.auth.authpipeline.metadata.uma","msg":"getting resource data","request id":"7199257136822741594","url":"http://keycloak:8080/auth/realms/kuadrant/authz/protection/resource_set/e20d194c-274c-4845-8c02-0ca413c9bf18"}
  {"level":"debug","ts":1634830413.3340268,"logger":"authorino.service.auth.authpipeline.metadata","msg":"fetched auth metadata","request id":"7199257136822741594","config":{"Name":"uma-resource-registry","UserInfo":null,"UMA":{"Endpoint":"http://keycloak:8080/auth/realms/kuadrant","ClientID":"talker-api","ClientSecret":"523b92b6-625d-4e1e-a313-77e7a8ae4e88"},"GenericHTTP":null},"object":[{"_id":"e20d194c-274c-4845-8c02-0ca413c9bf18","attributes":{},"displayName":"hello","name":"hello","owner":{"id":"57a645a5-fb67-438b-8be5-dfb971666dbc"},"ownerManagedAccess":false,"resource_scopes":[],"uris":["/hi","/hello"]}]}
  {"level":"debug","ts":1634830413.3367748,"logger":"authorino.service.auth.authpipeline.authorization","msg":"evaluating for input","request id":"7199257136822741594","input":{"context":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":52702}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"time":{"seconds":1634830413,"nanos":240094000},"http":{"id":"7199257136822741594","method":"GET","headers":{":authority":"talker-api",":method":"GET",":path":"/hello",":scheme":"http","accept":"*/*","authorization":"APIKEY ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx","user-agent":"curl/7.65.3","x-envoy-internal":"true","x-forwarded-for":"10.244.0.11","x-forwarded-proto":"http","x-request-id":"d38f5e66-bd72-4733-95d1-3179315cdd60"},"path":"/hello","host":"talker-api","scheme":"http","protocol":"HTTP/1.1"}},"context_extensions":{"virtual_host":"local_service"},"metadata_context":{}},"auth":{"identity":{"apiVersion":"v1","data":{"api_key":"bmR5QnpyZVV6RjR6cURRc3FTUE1Ia1JocmlFT3RjUng="},"kind":"Secret","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"annotations\":{\"userid\":\"john\"},\"labels\":{\"audience\":\"talker-api\",\"authorino.kuadrant.io/managed-by\":\"authorino\"},\"name\":\"api-key-1\",\"namespace\":\"authorino\"},\"stringData\":{\"api_key\":\"ndyBzreUzF4zqDQsqSPMHkRhriEOtcRx\"},\"type\":\"Opaque\"}\n","userid":"john"},"creationTimestamp":"2021-10-21T14:45:54Z","labels":{"audience":"talker-api","authorino.kuadrant.io/managed-by":"authorino"},"managedFields":[{"apiVersion":"v1","fieldsType":"FieldsV1","fieldsV1":{"f:data":{".":{},"f:api_key":{}},"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{},"f:userid":{}},"f:labels":{".":{},"f:audience":{},"f:authorino.kuadrant.io/managed-by":{}}},"f:type":{}},"manager":"kubectl-client-side-apply","operation":"Update","time":"2021-10-21T14:45:54Z"}],"name":"api-key-1","namespace":"authorino","resourceVersion":"8979","uid":"c369852a-7e1a-43bd-94ca-e2b3f617052e"},"sub":"john","type":"Opaque"},"metadata":{"http-metadata":{"body":"","headers":{"Accept-Encoding":"gzip","Content-Type":"text/plain","Host":"talker-api.default.svc.cluster.local:3000","User-Agent":"Go-http-client/1.1","Version":"HTTP/1.1"},"method":"GET","path":"/metadata","query_string":"encoding=text/plain&original_path=/hello","uuid":"97529f8c-587b-4121-a4db-cd90c63871fd"},"uma-resource-registry":[{"_id":"e20d194c-274c-4845-8c02-0ca413c9bf18","attributes":{},"displayName":"hello","name":"hello","owner":{"id":"57a645a5-fb67-438b-8be5-dfb971666dbc"},"ownerManagedAccess":false,"resource_scopes":[],"uris":["/hi","/hello"]}]}}}}
  {"level":"debug","ts":1634830413.339894,"logger":"authorino.service.auth.authpipeline.authorization","msg":"access granted","request id":"7199257136822741594","config":{"Name":"my-policy","OPA":{"Rego":"fail := input.context.request.http.headers[\"x-ext-auth-mock\"] == \"FAIL\"\nallow { not fail }\n","OPAExternalSource":{"Endpoint":"","SharedSecret":"","AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"JSON":null,"KubernetesAuthz":null},"object":true}
  {"level":"debug","ts":1634830413.3444238,"logger":"authorino.service.auth.authpipeline.authorization.kubernetesauthz","msg":"calling kubernetes subject access review api","request id":"7199257136822741594","subjectaccessreview":{"metadata":{"creationTimestamp":null},"spec":{"nonResourceAttributes":{"path":"/hello","verb":"get"},"user":"john"},"status":{"allowed":false}}}
  {"level":"debug","ts":1634830413.3547812,"logger":"authorino.service.auth.authpipeline.authorization","msg":"access granted","request id":"7199257136822741594","config":{"Name":"kubernetes-rbac","OPA":null,"JSON":null,"KubernetesAuthz":{"Conditions":[],"User":{"Static":"","Pattern":"auth.identity.user.username"},"Groups":null,"ResourceAttributes":null}},"object":true}
  {"level":"debug","ts":1634830413.3558292,"logger":"authorino.service.auth.authpipeline.response","msg":"dynamic response built","request id":"7199257136822741594","config":{"Name":"wristband","Wrapper":"httpHeader","WrapperKey":"x-ext-auth-wristband","Wristband":{"Issuer":"https://authorino-oidc.default.svc:8083/default/talker-api-protection/wristband","CustomClaims":[],"TokenDuration":300,"SigningKeys":[{"use":"sig","kty":"EC","kid":"wristband-signing-key","crv":"P-256","alg":"ES256","x":"TJf5NLVKplSYp95TOfhVPqvxvEibRyjrUZwwtpDuQZw","y":"SSg8rKBsJ3J1LxyLtt0oFvhHvZcUpmRoTuHk3UHisTA","d":"Me-5_zWBWVYajSGZcZMCcD8dXEa4fy85zv_yN7BxW-o"}]},"DynamicJSON":null},"object":"eyJhbGciOiJFUzI1NiIsImtpZCI6IndyaXN0YmFuZC1zaWduaW5nLWtleSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MzQ4MzA3MTMsImlhdCI6MTYzNDgzMDQxMywiaXNzIjoiaHR0cHM6Ly9hdXRob3Jpbm8tb2lkYy5hdXRob3Jpbm8uc3ZjOjgwODMvYXV0aG9yaW5vL3RhbGtlci1hcGktcHJvdGVjdGlvbi93cmlzdGJhbmQiLCJzdWIiOiI5NjhiZjViZjk3MDM3NWRiNjE0ZDFhMDgzZTg2NTBhYTVhMGVhMzAyOTdiYmJjMTBlNWVlMWZmYTkxYTYwZmY4In0.7G440sWgi2TIaxrGJf5KWR9UOFpNTjwVYeaJXFLzsLhVNICoMLbYzBAEo4M3ym1jipxxTVeE7anm4qDDc7cnVQ"}
  {"level":"info","ts":1634830413.3569078,"logger":"authorino.service.auth","msg":"outgoing authorization response","request id":"7199257136822741594","authorized":true,"response":"OK"}
  {"level":"debug","ts":1634830413.3569596,"logger":"authorino.service.auth","msg":"outgoing authorization response","request id":"7199257136822741594","authorized":true,"response":"OK"}
  ```
</details>

<details>
  <summary>Enforcing an AuthConfig with authentication based on API keys (invalid API key)</summary>

  <br/>

  - identity: k8s-auth, oidc, oauth2, apikey
  - metadata: http, oidc userinfo
  - authorization: opa, k8s-authz
  - response: wristband

  ```jsonc
  {"level":"info","ts":1634830373.2066543,"logger":"authorino.service.auth","msg":"incoming authorization request","request id":"12947265773116138711","object":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":52288}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"http":{"id":"12947265773116138711","method":"GET","path":"/hello","host":"talker-api","scheme":"http"}}}}
  {"level":"debug","ts":1634830373.2068064,"logger":"authorino.service.auth","msg":"incoming authorization request","request id":"12947265773116138711","object":{"source":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":52288}}}}},"destination":{"address":{"Address":{"SocketAddress":{"address":"127.0.0.1","PortSpecifier":{"PortValue":8000}}}}},"request":{"time":{"seconds":1634830373,"nanos":198329000},"http":{"id":"12947265773116138711","method":"GET","headers":{":authority":"talker-api",":method":"GET",":path":"/hello",":scheme":"http","accept":"*/*","authorization":"APIKEY invalid","user-agent":"curl/7.65.3","x-envoy-internal":"true","x-forwarded-for":"10.244.0.11","x-forwarded-proto":"http","x-request-id":"9e391846-afe4-489a-8716-23a2e1c1aa77"},"path":"/hello","host":"talker-api","scheme":"http","protocol":"HTTP/1.1"}},"context_extensions":{"virtual_host":"local_service"},"metadata_context":{}}}
  {"level":"debug","ts":1634830373.2070816,"logger":"authorino.service.auth.authpipeline.identity","msg":"cannot validate identity","request id":"12947265773116138711","config":{"Name":"keycloak-opaque","ExtendedProperties":[],"OAuth2":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"TokenIntrospectionUrl":"http://keycloak:8080/auth/realms/kuadrant/protocol/openid-connect/token/introspect","TokenTypeHint":"requesting_party_token","ClientID":"talker-api","ClientSecret":"523b92b6-625d-4e1e-a313-77e7a8ae4e88"},"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":null},"reason":"credential not found"}
  {"level":"debug","ts":1634830373.207225,"logger":"authorino.service.auth.authpipeline.identity","msg":"cannot validate identity","request id":"12947265773116138711","config":{"Name":"api-keys","ExtendedProperties":[{"Name":"sub","Value":{"Static":null,"Pattern":"auth.identity.metadata.annotations.userid"}}],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":{"AuthCredentials":{"KeySelector":"APIKEY","In":"authorization_header"},"Name":"api-keys","LabelSelectors":{"audience":"talker-api","authorino.kuadrant.io/managed-by":"authorino"}},"KubernetesAuth":null},"reason":"the API Key provided is invalid"}
  {"level":"debug","ts":1634830373.2072473,"logger":"authorino.service.auth.authpipeline.identity","msg":"cannot validate identity","request id":"12947265773116138711","config":{"Name":"k8s-service-accounts","ExtendedProperties":[],"OAuth2":null,"OIDC":null,"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"}}},"reason":"credential not found"}
  {"level":"debug","ts":1634830373.2072592,"logger":"authorino.service.auth.authpipeline.identity","msg":"cannot validate identity","request id":"12947265773116138711","config":{"Name":"keycloak-jwts","ExtendedProperties":[],"OAuth2":null,"OIDC":{"AuthCredentials":{"KeySelector":"Bearer","In":"authorization_header"},"Endpoint":"http://keycloak:8080/auth/realms/kuadrant"},"MTLS":null,"HMAC":null,"APIKey":null,"KubernetesAuth":null},"reason":"credential not found"}
  {"level":"info","ts":1634830373.2073083,"logger":"authorino.service.auth","msg":"outgoing authorization response","request id":"12947265773116138711","authorized":false,"response":"UNAUTHENTICATED","object":{"code":16,"status":302,"message":"Redirecting to login"}}
  {"level":"debug","ts":1634830373.2073889,"logger":"authorino.service.auth","msg":"outgoing authorization response","request id":"12947265773116138711","authorized":false,"response":"UNAUTHENTICATED","object":{"code":16,"status":302,"message":"Redirecting to login","headers":[{"Location":"https://my-app.io/login"}]}}
  ```
</details>

<details>
  <summary>Deleting an AuthConfig and 2 related API key secrets</summary>


  ```jsonc
  {"level":"info","ts":1669221361.5032296,"logger":"authorino.controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"default/api-key-1"}
  {"level":"info","ts":1669221361.5057878,"logger":"authorino.controller-runtime.manager.controller.secret","msg":"resource reconciled","secret":"default/api-key-2"}
  ```
</details>


<details>
  <summary>Shutting down the service</summary>

  ```jsonc
  {"level":"info","ts":1669221635.0135982,"logger":"authorino","msg":"Stopping and waiting for non leader election runnables"}
  {"level":"info","ts":1669221635.0136683,"logger":"authorino","msg":"Stopping and waiting for leader election runnables"}
  {"level":"info","ts":1669221635.0135982,"logger":"authorino","msg":"Stopping and waiting for non leader election runnables"}
  {"level":"info","ts":1669221635.0136883,"logger":"authorino","msg":"Stopping and waiting for leader election runnables"}
  {"level":"info","ts":1669221635.0137057,"logger":"authorino.controller.secret","msg":"Shutdown signal received, waiting for all workers to finish","reconciler group":"","reconciler kind":"Secret"}
  {"level":"info","ts":1669221635.013724,"logger":"authorino.controller.authconfig","msg":"Shutdown signal received, waiting for all workers to finish","reconciler group":"authorino.kuadrant.io","reconciler kind":"AuthConfig"}
  {"level":"info","ts":1669221635.01375,"logger":"authorino.controller.authconfig","msg":"All workers finished","reconciler group":"authorino.kuadrant.io","reconciler kind":"AuthConfig"}
  {"level":"info","ts":1669221635.013752,"logger":"authorino.controller.secret","msg":"All workers finished","reconciler group":"","reconciler kind":"Secret"}
  {"level":"info","ts":1669221635.0137632,"logger":"authorino","msg":"Stopping and waiting for caches"}
  {"level":"info","ts":1669221635.013751,"logger":"authorino.controller.authconfig","msg":"Shutdown signal received, waiting for all workers to finish","reconciler group":"authorino.kuadrant.io","reconciler kind":"AuthConfig"}
  {"level":"info","ts":1669221635.0137684,"logger":"authorino.controller.authconfig","msg":"All workers finished","reconciler group":"authorino.kuadrant.io","reconciler kind":"AuthConfig"}
  {"level":"info","ts":1669221635.0137722,"logger":"authorino","msg":"Stopping and waiting for caches"}
  {"level":"info","ts":1669221635.0138857,"logger":"authorino","msg":"Stopping and waiting for webhooks"}
  {"level":"info","ts":1669221635.0138955,"logger":"authorino","msg":"Wait completed, proceeding to shutdown the manager"}
  {"level":"info","ts":1669221635.0138893,"logger":"authorino","msg":"Stopping and waiting for webhooks"}
  {"level":"info","ts":1669221635.0139785,"logger":"authorino","msg":"Wait completed, proceeding to shutdown the manager"}
  ```
</details>

## Tracing

### Request ID

Processes related to the authorization request are identified and linked together by a _request ID_. The request ID can be:
* generated outside Authorino and passed in the authorization request – this is essentially the case of requests via GRPC authorization interface initiated by the Envoy;
* generated by Authorino – requests via [Raw HTTP Authorization interface](../architecture.md#raw-http-authorization-interface).

### Propagation

Authorino propagates trace identifiers compatible with the W3C Trace Context format (https://www.w3.org/TR/trace-context/) and user-defined baggage data in the W3C Baggage format (https://www.w3.org/TR/baggage).

### Log tracing

Most log messages associated with an authorization request include the [`request id`](#request-id) value. This value can be used to match incoming request and corresponding outgoing response log messages, including at deep level when more fine-grained log details are enabled ([`debug` level level](#log-levels-and-log-modes)).

### OpenTelemetry integration

Integration with an OpenTelemetry collector can be enabled by supplying the `--tracing-service-endpoint` command-line flag (e.g. `authorino server --tracing-service-endpoint=http://jaeger:14268/api/traces`).

The additional `--tracing-service-tags` command-line flag allow to specify fixed agent-level key-value tags for the trace signals emitted by Authorino (e.g. `authorino server --tracing-service-endpoint=... --tracing-service-tag=key1=value1 --tracing-service-tag=key2=value2`).

Traces related to authorization requests are additionally tagged with the [`authorino.request_id`](#request-id) attribute.
