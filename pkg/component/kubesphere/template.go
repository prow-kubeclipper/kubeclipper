/*
 *
 *  * Copyright 2021 KubeClipper Authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package kubesphere

const (
	installerV3 = `---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: clusterconfigurations.installer.kubesphere.io
spec:
  group: installer.kubesphere.io
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              x-kubernetes-preserve-unknown-fields: true
            status:
              type: object
              x-kubernetes-preserve-unknown-fields: true
  scope: Namespaced
  names:
    plural: clusterconfigurations
    singular: clusterconfiguration
    kind: ClusterConfiguration
    shortNames:
      - cc

---
apiVersion: v1
kind: Namespace
metadata:
  name: kubesphere-system

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ks-installer
  namespace: kubesphere-system

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ks-installer
rules:
- apiGroups:
  - ""
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - apps
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - extensions
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - batch
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - rbac.authorization.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - apiregistration.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - apiextensions.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - tenant.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - certificates.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - devops.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - monitoring.coreos.com
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - logging.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - jaegertracing.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - storage.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - admissionregistration.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - policy
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - autoscaling
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - networking.istio.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - config.istio.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - iam.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - notification.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - auditing.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - events.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - core.kubefed.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - installer.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - storage.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - security.istio.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - monitoring.kiali.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - kiali.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - networking.k8s.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - kubeedge.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - types.kubefed.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - monitoring.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'
- apiGroups:
  - application.kubesphere.io
  resources:
  - '*'
  verbs:
  - '*'

---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: ks-installer
subjects:
- kind: ServiceAccount
  name: ks-installer
  namespace: kubesphere-system
roleRef:
  kind: ClusterRole
  name: ks-installer
  apiGroup: rbac.authorization.k8s.io

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ks-installer
  namespace: kubesphere-system
  labels:
    app: ks-install
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ks-install
  template:
    metadata:
      labels:
        app: ks-install
    spec:
      tolerations:
      - key: "node-role.kubernetes.io/master"
        operator: "Exists"
        effect: "NoSchedule"
      - key: "node-role.kubernetes.io/control-plane"
        operator: "Exists"
        effect: "NoSchedule"
      serviceAccountName: ks-installer
      containers:
      - name: installer
        image: {{with .ImageRepoMirror}}{{.}}/{{end}}kubesphere/ks-installer:{{.Version}}
        imagePullPolicy: "IfNotPresent"
        resources:
          limits:
            cpu: "1"
            memory: 1Gi
          requests:
            cpu: 20m
            memory: 100Mi
        volumeMounts:
        - mountPath: /etc/localtime
          name: host-time
          readOnly: true
      volumes:
      - hostPath:
          path: /etc/localtime
          type: ""
        name: host-time`

	clusterConfV3 = `---
apiVersion: installer.kubesphere.io/v1alpha1
kind: ClusterConfiguration
metadata:
  name: ks-installer
  namespace: kubesphere-system
  labels:
    version: {{.Version}}
spec:
  persistence:
    storageClass: {{if .StorageClass}}{{.StorageClass}}{{else}}""{{end}}      # If there is no default StorageClass in your cluster, you need to specify an existing StorageClass here.
  authentication:
    jwtSecret: {{if .JwtSecret}}{{.JwtSecret}}{{else}}""{{end}}            # Keep the jwtSecret consistent with the Host Cluster. Retrieve the jwtSecret by executing "kubectl -n kubesphere-system get cm kubesphere-config -o yaml | grep -v "apiVersion" | grep jwtSecret" on the Host Cluster.
  local_registry: {{if .ImageRepoMirror}}{{.ImageRepoMirror}}{{else}}""{{end}}        # Add your private registry address if it is needed.
  # dev_tag: ""               # Add your kubesphere image tag you want to install, by default it's same as ks-install release version.
  etcd:
    monitoring: false       # Enable or disable etcd monitoring dashboard installation. You have to create a Secret for etcd before you enable it.
    endpointIps: localhost  # etcd cluster EndpointIps. It can be a bunch of IPs here.
    port: 2379              # etcd port.
    tlsEnable: true
  common:
    core:
      console:
        enableMultiLogin: {{.Console.EnableMultiLogin}}  # Enable or disable simultaneous logins. It allows different users to log in with the same account at the same time.
        port: {{.Console.Port}}
        type: NodePort
    # apiserver:            # Enlarge the apiserver and controller manager's resource requests and limits for the large cluster
    #  resources: {}
    # controllerManager:
    #  resources: {}
    redis:
      enabled: true
      volumeSize: 2Gi # Redis PVC size.
    openldap:
      enabled: false
      volumeSize: 2Gi   # openldap PVC size.
    minio:
      volumeSize: 20Gi # Minio PVC size.
    monitoring:
      # type: external   # Whether to specify the external prometheus stack, and need to modify the endpoint at the next line.
      endpoint: http://prometheus-operated.kubesphere-monitoring-system.svc:9090 # Prometheus endpoint to get metrics data.
      GPUMonitoring:     # Enable or disable the GPU-related metrics. If you enable this switch but have no GPU resources, Kubesphere will set it to zero.
        enabled: false
    gpu:                 # Install GPUKinds. The default GPU kind is nvidia.com/gpu. Other GPU kinds can be added here according to your needs.
      kinds:
      - resourceName: "nvidia.com/gpu"
        resourceType: "GPU"
        default: true
    es:   # Storage backend for logging, events and auditing.
      master:
        volumeSize: {{.Es.ElasticsearchMasterVolumeSize}}  # The volume size of Elasticsearch master nodes.
        replicas: {{.Es.ElasticsearchMasterReplicas}}      # The total number of master nodes. Even numbers are not allowed.
      #   resources: {}
      data:
        volumeSize: {{.Es.ElasticsearchDataVolumeSize}}  # The volume size of Elasticsearch data nodes.
        replicas: {{.Es.ElasticsearchDataReplicas}}       # The total number of data nodes.
      #   resources: {}
      logMaxAge: {{.Es.LogMaxAge}}             # Log retention time in built-in Elasticsearch. It is 7 days by default.
      elkPrefix: {{.Es.ElkPrefix}}      # The string making up index names. The index name will be formatted as ks-<elk_prefix>-log.
      basicAuth:
        enabled: false
        username: ""
        password: ""
      externalElasticsearchUrl: ""
      externalElasticsearchPort: ""
  alerting:                # (CPU: 0.1 Core, Memory: 100 MiB) It enables users to customize alerting policies to send messages to receivers in time with different time intervals and alerting levels to choose from.
    enabled: {{.Plugin.EnableAlert}}          # Enable or disable the KubeSphere Alerting System.
    # thanosruler:
    #   replicas: 1
    #   resources: {}
  auditing:                # Provide a security-relevant chronological set of records，recording the sequence of activities happening on the platform, initiated by different tenants.
    enabled: {{.Plugin.EnableAudit}}         # Enable or disable the KubeSphere Auditing Log System.
    # operator:
    #   resources: {}
    # webhook:
    #   resources: {}
  devops:                  # (CPU: 0.47 Core, Memory: 8.6 G) Provide an out-of-the-box CI/CD system based on Jenkins, and automated workflow tools including Source-to-Image & Binary-to-Image.
    enabled: {{.Plugin.EnableDevops}}             # Enable or disable the KubeSphere DevOps System.
    # resources: {}
    jenkinsMemoryLim: 2Gi      # Jenkins memory limit.
    jenkinsMemoryReq: 1500Mi   # Jenkins memory request.
    jenkinsVolumeSize: 8Gi     # Jenkins volume size.
    jenkinsJavaOpts_Xms: 512m  # The following three fields are JVM parameters.
    jenkinsJavaOpts_Xmx: 512m
    jenkinsJavaOpts_MaxRAM: 2g
  events:                  # Provide a graphical web console for Kubernetes Events exporting, filtering and alerting in multi-tenant Kubernetes clusters.
    enabled: {{.Plugin.EnableEvent}}         # Enable or disable the KubeSphere Events System.
    # operator:
    #   resources: {}
    # exporter:
    #   resources: {}
    ruler:
      enabled: true
      replicas: 2
    #   resources: {}
  logging:                 # (CPU: 57 m, Memory: 2.76 G) Flexible logging functions are provided for log query, collection and management in a unified console. Additional log collectors can be added, such as Elasticsearch, Kafka and Fluentd.
    enabled: {{.Plugin.EnableLogging}}         # Enable or disable the KubeSphere Logging System.
    containerruntime: containerd
    logsidecar:
      enabled: true
      replicas: 2
      # resources: {}
  metrics_server:                    # (CPU: 56 m, Memory: 44.35 MiB) It enables HPA (Horizontal Pod Autoscaler).
    enabled: {{.Plugin.EnableMetricServer}}                   # Enable or disable metrics-server.
  monitoring:
    storageClass: {{if .StorageClass}}{{.StorageClass}}{{else}}""{{end}}                 # If there is an independent StorageClass you need for Prometheus, you can specify it here. The default StorageClass is used by default.
    # kube_rbac_proxy:
    #   resources: {}
    # kube_state_metrics:
    #   resources: {}
    prometheus:
      replicas: {{.Monitor.PrometheusReplicas}}  # Prometheus replicas are responsible for monitoring different segments of data source and providing high availability.
      volumeSize: {{.Monitor.PrometheusVolumeSize}}  # Prometheus PVC size.
      resources:
        limits:
          cpu: {{.Monitor.PrometheusCPULimit}}
          memory: {{.Monitor.PrometheusMemoryLimit}}
    #   operator:
    #     resources: {}
    #   adapter:
    #     resources: {}
    # node_exporter:
    #   resources: {}
    alertmanager:
      replicas: {{.Monitor.AlertManagerReplicas}}          # AlertManager Replicas.
    #   resources: {}
    # notification_manager:
    #   resources: {}
    #   operator:
    #     resources: {}
    #   proxy:
    #     resources: {}
    gpu:                           # GPU monitoring-related plug-in installation.
      nvidia_dcgm_exporter:        # Ensure that gpu resources on your hosts can be used normally, otherwise this plug-in will not work properly.
        enabled: false             # Check whether the labels on the GPU hosts contain "nvidia.com/gpu.present=true" to ensure that the DCGM pod is scheduled to these nodes.
        # resources: {}
  multicluster:
    clusterRole: {{.ClusterRole}}  # host | member | none  # You can install a solo cluster, or specify it as the Host or Member Cluster.
  network:
    networkpolicy: # Network policies allow network isolation within the same cluster, which means firewalls can be set up between certain instances (Pods).
      # Make sure that the CNI network plugin used by the cluster supports NetworkPolicy. There are a number of CNI network plugins that support NetworkPolicy, including Calico, Cilium, Kube-router, Romana and Weave Net.
      enabled: {{.Plugin.EnableNetwork}} # Enable or disable network policies.
    ippool: # Use Pod IP Pools to manage the Pod network address space. Pods to be created can be assigned IP addresses from a Pod IP Pool.
      type: none # Specify "calico" for this field if Calico is used as your CNI plugin. "none" means that Pod IP Pools are disabled.
    topology: # Use Service Topology to view Service-to-Service communication based on Weave Scope.
      type: none # Specify "weave-scope" for this field to enable Service Topology. "none" means that Service Topology is disabled.
  openpitrix: # An App Store that is accessible to all platform tenants. You can use it to manage apps across their entire lifecycle.
    store:
      enabled: {{.Plugin.EnableAppStore}} # Enable or disable the KubeSphere App Store.
  servicemesh:         # (0.3 Core, 300 MiB) Provide fine-grained traffic management, observability and tracing, and visualized traffic topology.
    enabled: {{.Plugin.EnableServiceMesh}}     # Base component (pilot). Enable or disable KubeSphere Service Mesh (Istio-based).
  kubeedge:          # Add edge nodes to your cluster and deploy workloads on edge nodes.
    enabled: false   # Enable or disable KubeEdge.
    cloudCore:
      nodeSelector: {"node-role.kubernetes.io/worker": ""}
      tolerations: []
      cloudhubPort: "10000"
      cloudhubQuicPort: "10001"
      cloudhubHttpsPort: "10002"
      cloudstreamPort: "10003"
      tunnelPort: "10004"
      cloudHub:
        advertiseAddress: # At least a public IP address or an IP address which can be accessed by edge nodes must be provided.
          - ""            # Note that once KubeEdge is enabled, CloudCore will malfunction if the address is not provided.
        nodeLimit: "100"
      service:
        cloudhubNodePort: "30000"
        cloudhubQuicNodePort: "30001"
        cloudhubHttpsNodePort: "30002"
        cloudstreamNodePort: "30003"
        tunnelNodePort: "30004"
    edgeWatcher:
      nodeSelector: {"node-role.kubernetes.io/worker": ""}
      tolerations: []
      edgeWatcherAgent:
        nodeSelector: {"node-role.kubernetes.io/worker": ""}
        tolerations: []`

	ksExtensionServer = `apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: ks-extension
  name: ks-extension
  namespace: kubesphere-system
spec:
  progressDeadlineSeconds: 600
  replicas: 1
  selector:
    matchLabels:
      app: ks-extension
      tier: backend
  template:
    metadata:
      labels:
        app: ks-extension
        tier: backend
    spec:
      affinity:
        nodeAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - preference:
                matchExpressions:
                  - key: node-role.kubernetes.io/master
                    operator: In
                    values:
                      - ""
              weight: 100
          preferredDuringSchedulingIgnoredDuringExecution:
            - preference:
                matchExpressions:
                  - key: node-role.kubernetes.io/control-plane
                    operator: In
                    values:
                      - ""
              weight: 100
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: app
                    operator: In
                    values:
                      - ks-extension
              namespaces:
                - kubesphere-system
              topologyKey: kubernetes.io/hostname
      containers:
        - command:
            - ks-extension
          image: {{with .ImageRepoMirror}}{{.}}/{{end}}caas4/ks-extension:{{.Version}}
          imagePullPolicy: IfNotPresent
          livenessProbe:
            failureThreshold: 3
            httpGet:
              path: /extension/metrics/health
              port: 80
              scheme: HTTP
            initialDelaySeconds: 15
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 15
          name: ks-extension
          ports:
            - containerPort: 80
              protocol: TCP
          resources:
            limits:
              cpu: "1"
              memory: 1Gi
            requests:
              cpu: 20m
              memory: 100Mi
          volumeMounts:
            - mountPath: /etc/localtime
              name: host-time
              readOnly: true
      serviceAccountName: kubesphere
      tolerations:
        - effect: NoSchedule
          key: node-role.kubernetes.io/master
        - effect: NoSchedule
          key: node-role.kubernetes.io/control-plane
        - key: CriticalAddonsOnly
          operator: Exists
        - effect: NoExecute
          key: node.kubernetes.io/not-ready
          operator: Exists
          tolerationSeconds: 60
        - effect: NoExecute
          key: node.kubernetes.io/unreachable
          operator: Exists
          tolerationSeconds: 60
      volumes:
        - hostPath:
            path: /etc/localtime
            type: ""
          name: host-time
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: ks-extension
    tier: backend
  name: ks-extension
  namespace: kubesphere-system
spec:
  ports:
    - port: 80
      protocol: TCP
      targetPort: 80
  selector:
    app: ks-extension
    tier: backend
  type: ClusterIP
`
)

const ksClusterFed = `
apiVersion: cluster.kubesphere.io/v1alpha1
kind: Cluster
metadata:
  annotations:
    kubesphere.io/creator: admin
  labels:
    cluster.kubesphere.io/group: %s
  name: %s
spec:
  connection:
    kubeconfig: %v
    kubernetesAPIEndpoint: https://%s
    type: direct
  joinFederation: true
`

const ksUninstallShell = `
#!/usr/bin/env bash

# duplicate helm from ks-installer pod
name=$(kubectl get pod -n kubesphere-system -l app=ks-install -o=jsonpath={.items[0].metadata.name})
kubectl exec -it $name -n kubesphere-system -- cp /usr/local/bin/helm /kubesphere/helm
kubectl cp kubesphere-system/$name:helm /tmp/.ks/helm
chmod 777 /tmp/.ks/helm

# delete ks-installer
kubectl delete deploy ks-installer -n kubesphere-system

# delete helm
for namespaces in kubesphere-system kubesphere-devops-system kubesphere-monitoring-system kubesphere-logging-system openpitrix-system kubesphere-monitoring-federated
do
  /tmp/.ks/helm list -n $namespaces | grep -v NAME | awk '{print $1}' | sort -u | xargs -r -L1 /tmp/.ks/helm uninstall -n $namespaces
done

# delete kubefed
kubectl get cc -n kubesphere-system ks-installer -o jsonpath="{.status.multicluster}" | grep enable
if [[ $? -eq 0 ]]; then
  # delete kubefed types resources
  for kubefed in $(kubectl api-resources --namespaced=true --api-group=types.kubefed.io -o name)
  do
    kubectl delete -n kube-federation-system "$kubefed" --all
  done
  for kubefed in $(kubectl api-resources --namespaced=false --api-group=types.kubefed.io -o name)
  do
    kubectl delete "$kubefed" --all
  done
  # delete kubefed core resouces
  for kubefed in $(kubectl api-resources --namespaced=true --api-group=core.kubefed.io -o name)
  do
    kubectl delete -n kube-federation-system "$kubefed" --all
  done
  for kubefed in $(kubectl api-resources --namespaced=false --api-group=core.kubefed.io -o name)
  do
    kubectl delete "$kubefed" --all
  done
  # uninstall kubefed chart
  /tmp/.ks/helm uninstall -n kube-federation-system kubefed
fi


/tmp/.ks/helm uninstall -n kube-system snapshot-controller

# delete kubesphere deployment & statefulset
kubectl delete deployment -n kubesphere-system $(kubectl get deployment -n kubesphere-system -o jsonpath="{.items[*].metadata.name}")
kubectl delete statefulset -n kubesphere-system $(kubectl get statefulset -n kubesphere-system -o jsonpath="{.items[*].metadata.name}")

# delete monitor resources
kubectl delete prometheus -n kubesphere-monitoring-system k8s
kubectl delete Alertmanager -n kubesphere-monitoring-system main
kubectl delete DaemonSet -n kubesphere-monitoring-system node-exporter
kubectl delete statefulset -n kubesphere-monitoring-system $(kubectl get statefulset -n kubesphere-monitoring-system -o jsonpath="{.items[*].metadata.name}")

# delete grafana
kubectl delete deployment -n kubesphere-monitoring-system grafana
kubectl --no-headers=true get pvc -n kubesphere-monitoring-system -o custom-columns=:metadata.namespace,:metadata.name | grep -E kubesphere-monitoring-system | xargs -n2 kubectl delete pvc -n

# delete pvc
pvcs="kubesphere-system|openpitrix-system|kubesphere-devops-system|kubesphere-logging-system"
kubectl --no-headers=true get pvc --all-namespaces -o custom-columns=:metadata.namespace,:metadata.name | grep -E $pvcs | xargs -n2 kubectl delete pvc -n


# delete rolebindings
delete_role_bindings() {
  for rolebinding in $(kubectl -n $1 get rolebindings -l iam.kubesphere.io/user-ref -o jsonpath="{.items[*].metadata.name}")
  do
    kubectl -n "$1" delete rolebinding "$rolebinding"
  done
}

# delete roles
delete_roles() {
  kubectl -n "$1" delete role admin
  kubectl -n "$1" delete role operator
  kubectl -n "$1" delete role viewer
  for role in $(kubectl -n $1 get roles -l iam.kubesphere.io/role-template -o jsonpath="{.items[*].metadata.name}")
  do
    kubectl -n "$1" delete role "$role"
  done
}

# remove useless labels and finalizers
for ns in $(kubectl get ns -o jsonpath="{.items[*].metadata.name}")
do
  kubectl label ns "$ns" kubesphere.io/workspace-
  kubectl label ns "$ns" kubesphere.io/namespace-
  kubectl patch ns "$ns" -p '{"metadata":{"finalizers":null,"ownerReferences":null}}'
  delete_role_bindings "$ns"
  delete_roles "$ns"
done

# delete clusterroles
delete_cluster_roles() {
  for role in $(kubectl get clusterrole -l iam.kubesphere.io/role-template -o jsonpath="{.items[*].metadata.name}")
  do
    kubectl delete clusterrole "$role"
  done

  for role in $(kubectl get clusterroles | grep "kubesphere" | awk '{print $1}'| paste -sd " ")
  do
    kubectl delete clusterrole "$role"
  done
}
delete_cluster_roles

# delete clusterrolebindings
delete_cluster_role_bindings() {
  for rolebinding in $(kubectl get clusterrolebindings -l iam.kubesphere.io/role-template -o jsonpath="{.items[*].metadata.name}")
  do
    kubectl delete clusterrolebindings "$rolebinding"
  done

  for rolebinding in $(kubectl get clusterrolebindings | grep "kubesphere" | awk '{print $1}'| paste -sd " ")
  do
    kubectl delete clusterrolebindings "$rolebinding"
  done
}
delete_cluster_role_bindings

# delete clusters
for cluster in $(kubectl get clusters -o jsonpath="{.items[*].metadata.name}")
do
  kubectl patch cluster "$cluster" -p '{"metadata":{"finalizers":null}}' --type=merge
done
kubectl delete clusters --all

# delete workspaces
for ws in $(kubectl get workspaces -o jsonpath="{.items[*].metadata.name}")
do
  kubectl patch workspace "$ws" -p '{"metadata":{"finalizers":null}}' --type=merge
done
kubectl delete workspaces --all

# make DevOps CRs deletable
for devops_crd in $(kubectl get crd -o=jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep "devops.kubesphere.io"); do
    for ns in $(kubectl get ns -ojsonpath='{.items..metadata.name}'); do
        for devops_res in $(kubectl get "$devops_crd" -n "$ns" -oname); do
            kubectl patch "$devops_res" -n "$ns" -p '{"metadata":{"finalizers":[]}}' --type=merge
        done
    done
done

# delete validatingwebhookconfigurations
for webhook in ks-events-admission-validate users.iam.kubesphere.io network.kubesphere.io validating-webhook-configuration resourcesquotas.quota.kubesphere.io
do
  kubectl delete validatingwebhookconfigurations.admissionregistration.k8s.io $webhook
done

# delete mutatingwebhookconfigurations
for webhook in ks-events-admission-mutate logsidecar-injector-admission-mutate mutating-webhook-configuration
do
  kubectl delete mutatingwebhookconfigurations.admissionregistration.k8s.io $webhook
done

# delete users
for user in $(kubectl get users -o jsonpath="{.items[*].metadata.name}")
do
  kubectl patch user "$user" -p '{"metadata":{"finalizers":null}}' --type=merge
done
kubectl delete users --all


# delete helm resources
for resource_type in $(echo helmcategories helmapplications helmapplicationversions helmrepos helmreleases); do
  for resource_name in $(kubectl get "${resource_type}".application.kubesphere.io -o jsonpath="{.items[*].metadata.name}"); do
    kubectl patch "${resource_type}".application.kubesphere.io "${resource_name}" -p '{"metadata":{"finalizers":null}}' --type=merge
  done
  kubectl delete "${resource_type}".application.kubesphere.io --all
done

# delete workspacetemplates
for workspacetemplate in $(kubectl get workspacetemplates.tenant.kubesphere.io -o jsonpath="{.items[*].metadata.name}")
do
  kubectl patch workspacetemplates.tenant.kubesphere.io "$workspacetemplate" -p '{"metadata":{"finalizers":null}}' --type=merge
done
kubectl delete workspacetemplates.tenant.kubesphere.io --all

# delete federatednamespaces in namespace kubesphere-monitoring-federated
for resource in $(kubectl get federatednamespaces.types.kubefed.io -n kubesphere-monitoring-federated -oname); do
  kubectl patch "${resource}" -p '{"metadata":{"finalizers":null}}' --type=merge -n kubesphere-monitoring-federated
done

# delete crds
for crd in $(kubectl get crds -o jsonpath="{.items[*].metadata.name}")
do
  if [[ $crd == *kubesphere.io ]] || [[ $crd == *kubefed.io ]] ; then kubectl delete crd $crd; fi
done

# delete relevance ns
for ns in kube-federation-system kubesphere-alerting-system kubesphere-controls-system kubesphere-devops-system kubesphere-devops-worker kubesphere-logging-system kubesphere-monitoring-system kubesphere-monitoring-federated openpitrix-system kubesphere-system
do
  kubectl delete ns $ns
done`
