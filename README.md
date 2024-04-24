# Stable FQDNNetworkPolicies

<!--toc:start-->
- [Stable FQDNNetworkPolicies](#stable-fqdnnetworkpolicies)
  - [Description](#description)
    - [Why this project is needed](#why-this-project-is-needed)
    - [How it works](#how-it-works)
    - [Internals](#internals)
    - [Achieving Stable FQDNNetworkPolicies](#achieving-stable-fqdnnetworkpolicies)
    - [Alternative solutions](#alternative-solutions)
    - [Differences with Google's FQDNNetworkPolicies](#differences-with-googles-fqdnnetworkpolicies)
  - [Deployment and configuration](#deployment-and-configuration)
    - [Command line options](#command-line-options)
    - [Installation with Helm](#installation-with-helm)
    - [Local testing](#local-testing)
    - [CoreDNS](#coredns)
<!--toc:end-->

## Description
FQDNNetworkPolicies are like Kubernetes NetworkPolicies, but they allow the user to specify domain names instead of CIDR IP ranges and podSelectors. The controller takes care of resolving the domain names to a list of IP addresses using the cluster's DNS servers.

This project is a fork of [Google's FQDNNetworkPolicies](https://github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang). Unlike that project, Stable FQDNNetworkPolicies are safe to use with hosts that dynamically return different A records on subsequent requests, especially if used in combination with the [k8s_cache plugin](https://github.com/delta10/k8s_cache) for CoreDNS. This plugin lets our controller update the NetworkPolicies before the Cluster's DNS cache expires. Without the plugin, a small percentage of requests to domains with dynamic DNS responses will fail ([see below](#achieving-stable-fqdnnetworkpolicies)).

### Why this project is needed 

Kubernetes [NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) can be used to allow or block ingress and egress traffic to parts of the cluster. While NetworkPolicies support allowing and blocking IP ranges, there is no support for hostnames. Such a feature is particularly useful for those who want to block all egress traffic except for a couple of whitelisted hostnames.

Existing solutions all have their [limitations](#alternative-solutions). There is a need for a simple solution based on DNS, that does not require a proxy nor altering DNS records and that works for any type of traffic (not just HTTPS). This solution should also be stable for domains with dynamic DNS reponses.

### How it works

A FQDNNetworkPolicy looks a lot like a NetworkPolicy, but you can configure hostnames
in the "to" field:

```
apiVersion: networking.delta10.nl/v1alpha4
kind: FQDNNetworkPolicy
metadata:
  name: example
spec:
  podSelector:
    matchLabels:
      role: example
  egress:
    - to:
      - fqdns:
        - example.com
      ports:
      - port: 443
        protocol: TCP
```

When you create this FQDNNetworkPolicy, the controller will in turn create a corresponding NetworkPolicy with
the same name, in the same namespace, that has the same `podSelector`, the same ports, but replacing
the hostnames with corresponding IP addresss it received by polling.

### Internals 

On each reconciliation of a FQDNNetworkPolicy, the controller first queries the API server for endpoints of the DNS service (by default kube-dns in namespace kube-system). It adds each endpoint to its list of DNS servers (but not the service ClusterIP). It then queries each DNS server for A records for each of the domains in the FQDNNetworkPolicy. (It is necessary to query all servers, since each server has its own internal cache.)

The resolved IP addressess are used to create a NetworkPolicy with the same name. Each IP address is also stored in a cache within the FQDNNetworkPolicy's `status` field, along with an expiration time based on the value of `-ip-expiration-period`. When an IP address expires and is not encountered again it gets removed from the cache and the NetworkPolicy.

The FQDNNetworkPolicy is requeued for reconciliation based on the earliest TTL from all records it received.

### Achieving Stable FQDNNetworkPolicies

Normally, whenever a DNS server in the cluster clears it cache, there is a period of about 2 seconds when NetworkPolicies are not yet updated with the new IP addresses. This means that connection attempts to these hostnames might fail for about 2 seconds. This problem can be solved by using the [k8s_cache plugin](https://github.com/delta10/k8s_cache) in combination with Stable FQDNNetworkPolicies.

Without the plugin, a small percentage of requests to hosts with dynamic DNS responses may fail. In my testing with `-ip-expiration-period` set to "12h", requests to www.google.com eventually have a failure rate of around 0%. However, in the first 10 minutes, the failure rate is about 1%.

When not using k8s_cache, there are a few things you can do to reduce the amount of connection failures:
- Ensure that all pods in the cluster use a caching DNS server. The instances of this server should be endpoints of a Kubernetes service. The controller should be configured to use this service ([see options](#command-line-options)).
- Make sure that the DNS server sends the remaining cache duration as TTL, which is the default in CoreDNS (see the `keepttl` option [in CoreDNS](https://coredns.io/plugins/cache/)).
- Increase the cache duration of the DNS server ([see below](#coredns)).
- Set a higher IPExpiration (see [Comand line options](#command-line-options)). This is the amount of time that IPs are retained in the NetworkPolicy since they were last seen in a DNS response.

### Alternative solutions
- [egress-operator](https://github.com/monzo/egress-operator) by Monzo. A very smart solution that runs a Layer 4 proxy for each whitelisted domain name. However, you need to run a proxy pod for each whitelisted domain, and you need to install a CoreDNS plugin to redirect traffic to the proxies. See also their [blog post](https://github.com/monzo/egress-operator).
- [FQDNNetworkPolicies](https://github.com/GoogleCloudPlatform/gke-fqdnnetworkpolicies-golang), of which this project is a fork. The GKE project is no longer maintained, but [there is a close fork here](https://github.com/nais/fqdn-policy). The GKE FQDNNetworkPolicies do not work well for domains whose A records change dynamically. [See below](#differences-with-googles-fqdnnetworkpolicies) for a list of differences.
- Service meshes such as Istio ([see docs](https://istio.io/latest/docs/tasks/traffic-management/egress/egress-control)) can be used to create an HTTPS egress proxy that only allows traffic to certain hostnames. Such a solution does not use DNS at all but TLS SNI (Server Name Indication). However, it can only be used for HTTPS traffic.
- Some network plugins have a DNS-based solution, like CiliumNetworkPolicies ([see docs](https://docs.cilium.io/en/stable/security/policy/language/#dns-based)).
- There is a [proposal](https://github.com/kubernetes-sigs/network-policy-api/blob/main/npeps/npep-133.md) to extend the NetworkPolicy API with an FQDN selector.

### Differences with Google's FQDNNetworkPolicies
- IP addresses are cached so that they remain in a NetworkPolicy for a while when they are no longer resolved.
- We use the `kube-dns` service to query *all* DNS servers in the cluster, instead of only one.
- We do not use a webhook to delete NetworkPolicies when FQDNNetworkPolicies are deleted. Instead we set (controller) ownerReferences so the API server takes care of garbage collection.
- The owned-by annotation is removed. If a NetworkPolicy with the same name exists, then the FQDNNetworkPolicy will adopt it unless another controller manages it.
- The delete-policy annotation is removed. You can achieve similar behavior using `kubectl delete --cascade=orphan`.

## Deployment and configuration
### Command line options
| Option                       | Type     | Description                                                                                                         | Default                 |
| ---------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `-dns-config-file`           | string   | Path to the DNS configuration file.                                                                                 | "/etc/resolv.conf"      |
| `-dns-environment`           | string   | Specify 'kubernetes' to configure DNS via a Kubernetes service or 'resolv.conf' to use a config file.               | "kubernetes"            |
| `-dns-service-name`          | string   | Upstream DNS service in kube-dns namespace (requires `--dns-environment=kubernetes`)                                | "kube-dns"              |
| `-dns-tcp`                   | flag     | Use DNS over TCP instead of UDP.                                                                                    | false                   |
| `-health-probe-bind-address` | string   | The address the probe endpoint binds to.                                                                            | ":8081"                 |
| `-ip-expiration-period`      | string   | Minimum duration to keep resolved IPs in a NetworkPolicy                                                            | "60m"                   |
| `-kubeconfig`                | string   | Paths to a kubeconfig. Only required if out-of-cluster.                                                             |                         |
| `-leader-elect`              | flag     | Enable leader election for controller manager.                                                                      | false                   |
| `-metrics-bind-address`      | string   | The address the metric endpoint binds to.                                                                           | ":8080"                 |
| `-next-sync-period`          | int      | Maximum values in seconds for the re-sync time on the FQDNNetworkPolicy, respecting the DNS TTL.                    | 3600                    |
| `-skip-aaaa`                 | flag     | Skip AAAA lookups                                                                                                   | false                   |
| `-zap-devel`                 | flag     | Enable development mode defaults (encoder=consoleEncoder, logLevel=Debug, stackTraceLevel=Warn)                     | false                   |
| `-zap-encoder`               | string   | Zap log encoding ('json' or 'console')                                                                              | "json" |
| `-zap-log-level`             | string   | Zap Level to configure the verbosity of logging. Can be one of 'debug', 'info', 'error', or any integer value > 0   | "info" |
| `-zap-stacktrace-level`      | string   | Zap Level at and above which stacktraces are captured (one of 'info', 'error', 'panic').                            | "error" |
| `-zap-time-encoding`         | string   | Zap time encoding ('epoch', 'millis', 'nano', 'iso8601', 'rfc3339', 'rfc3339nano').                                 | 'epoch'                 |

### Installation with Helm
To install with Helm:
```sh
helm install --namespace fqdnnetworkpolicies fqdnnetworkpolicies --repo https://delta10.github.io/fqdnnetworkpolicies fqdnnetworkpolicies
```
This should install the CRDs and controller. After installation, check the logs of the controller-manager running in the `fqdnnetworkpolicies` namespace.

### Local testing

To run the controller locally (outside of a cluster), make sure you have a kubeconfig set up to access the API server of a cluster. As DNS servers, you can use the local `/etc/resolv.conf` using the option `-dns-environment resolv.conf`. To use the cluster DNS servers, you can use `kubectl port-forward` to access the cluster's DNS servers locally. Create a separate `resolv.conf` containing the local addresses of the cluster DNS servers and run the controller with `-dns-tcp`, `-dns-environment resolv.conf` and `-dns-config-file [path/to/resolv.conf]`.

To install the CRDs one the cluster, compile and run the controller, execute
```bash
make run
```

Example of using `kubectl port-forward`:
```bash
kubectl -n kube-system port-forward pod/coredns-xxx --address=127.0.0.1 53:53
kubectl -n kube-system port-forward pod/coredns-yyy --address=127.0.0.2 53:53
# etc
```

### CoreDNS

It is best to setup CoreDNS with k8s_cache instead of cache. For instructions see [k8s_cache](https://github.com/delta10/k8s_cache).

If you are not using k8s_cache, stability might improve if you increase the cache for external domains. For example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
    ...
        cache 3600
    ...
    }
    cluster.local:53 {
    ...
        cache 30
    ...
    }
```

### Migration from Google's FQDNNetworkPolicies
We use a new API group and version (`networking.delta10.nl/v1alpha4`), but the `spec` field is unchanged. Hence, you can copy your existing FQDNNetworkPolicies and change only the `apiVersion`. If you want to use Google's FQDNNetworkPolicies in combination with Stable FQDNNetworkPolicies during a transition period, you need to choose different names (`metadata.name`) for the old and new policies.
