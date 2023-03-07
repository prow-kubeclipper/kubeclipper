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

package cephcsi

import (
	"testing"
)

func TestRenderTo(t *testing.T) {
	// TODO: test failed

	//	expected := `
	//---
	//apiVersion: v1
	//kind: Namespace
	//metadata:
	//  name: kube-system
	//
	//---
	//apiVersion: v1
	//kind: ConfigMap
	//data:
	//  config.json: |-
	//    {
	//      "vault-test": {
	//        "encryptionKMSType": "vault",
	//        "vaultAddress": "http://vault.default.svc.cluster.local:8200",
	//        "vaultAuthPath": "/v1/auth/kubernetes/login",
	//        "vaultRole": "csi-kubernetes",
	//        "vaultBackend": "kv-v2",
	//        "vaultPassphraseRoot": "/v1/secret",
	//        "vaultPassphrasePath": "ceph-csi/",
	//        "vaultCAVerify": "false"
	//      },
	//      "vault-tokens-test": {
	//          "encryptionKMSType": "vaulttokens",
	//          "vaultAddress": "http://vault.default.svc.cluster.local:8200",
	//          "vaultBackend": "kv-v2",
	//          "vaultBackendPath": "secret/",
	//          "vaultTLSServerName": "vault.default.svc.cluster.local",
	//          "vaultCAVerify": "false",
	//          "tenantConfigName": "ceph-csi-kms-config",
	//          "tenantTokenName": "ceph-csi-kms-token",
	//          "tenants": {
	//              "my-app": {
	//                  "vaultAddress": "https://vault.example.com",
	//                  "vaultCAVerify": "true"
	//              },
	//              "an-other-app": {
	//                  "tenantTokenName": "storage-encryption-token"
	//              }
	//          }
	//      },
	//      "vault-tenant-sa-test": {
	//          "encryptionKMSType": "vaulttenantsa",
	//          "vaultAddress": "http://vault.default.svc.cluster.local:8200",
	//          "vaultBackend": "kv-v2",
	//          "vaultBackendPath": "shared-secrets",
	//          "vaultTLSServerName": "vault.default.svc.cluster.local",
	//          "vaultCAVerify": "false",
	//          "tenantConfigName": "ceph-csi-kms-config",
	//          "tenantSAName": "ceph-csi-vault-sa",
	//          "tenants": {
	//              "my-app": {
	//                  "vaultAddress": "https://vault.example.com",
	//                  "vaultCAVerify": "true"
	//              },
	//              "an-other-app": {
	//                  "tenantSAName": "storage-encryption-sa"
	//              }
	//          }
	//      },
	//      "secrets-metadata-test": {
	//          "encryptionKMSType": "metadata"
	//      },
	//      "user-ns-secrets-metadata-test": {
	//        "encryptionKMSType": "metadata",
	//        "secretName": "storage-encryption-secret",
	//        "secretNamespace": "default"
	//      },
	//      "user-secrets-metadata-test": {
	//        "encryptionKMSType": "metadata",
	//        "secretName": "storage-encryption-secret"
	//      }
	//    }
	//metadata:
	//  name: ceph-csi-encryption-kms-config
	//  namespace: kube-system
	//
	//---
	//apiVersion: v1
	//kind: ConfigMap
	//data:
	//  config.json: |-
	//    [
	//      {"clusterID":"ceph-cluster-id","monitors":["192.168.0.1","192.168.0.2","192.168.0.4"]}
	//    ]
	//metadata:
	//  name: ceph-csi-config
	//  namespace: kube-system
	//
	//---
	//apiVersion: v1
	//kind: Secret
	//metadata:
	//  name: csi-rbd-secret
	//  namespace: kube-system
	//stringData:
	//  # Key values correspond to a user name and its key, as defined in the
	//  # ceph cluster. User ID should have required access to the 'pool'
	//  # specified in the storage class
	//  userID:  ceph-user-id
	//  userKey: ceph-user-key
	//
	//---
	//apiVersion: policy/v1beta1
	//kind: PodSecurityPolicy
	//metadata:
	//  name: rbd-csi-nodeplugin-psp
	//spec:
	//  allowPrivilegeEscalation: true
	//  allowedCapabilities:
	//    - 'SYS_ADMIN'
	//  fsGroup:
	//    rule: RunAsAny
	//  privileged: true
	//  hostNetwork: true
	//  hostPID: true
	//  runAsUser:
	//    rule: RunAsAny
	//  seLinux:
	//    rule: RunAsAny
	//  supplementalGroups:
	//    rule: RunAsAny
	//  volumes:
	//    - 'configMap'
	//    - 'emptyDir'
	//    - 'projected'
	//    - 'secret'
	//    - 'downwardAPI'
	//    - 'hostPath'
	//  allowedHostPaths:
	//    - pathPrefix: '/dev'
	//      readOnly: false
	//    - pathPrefix: '/run/mount'
	//      readOnly: false
	//    - pathPrefix: '/sys'
	//      readOnly: false
	//    - pathPrefix: '/lib/modules'
	//      readOnly: true
	//    - pathPrefix: '/var/lib/kubelet/pods'
	//      readOnly: false
	//    - pathPrefix: '/var/lib/kubelet/plugins/rbd.csi.ceph.com'
	//      readOnly: false
	//    - pathPrefix: '/var/lib/kubelet/plugins_registry'
	//      readOnly: false
	//    - pathPrefix: '/var/lib/kubelet/plugins'
	//      readOnly: false
	//
	//---
	//kind: Role
	//apiVersion: rbac.authorization.k8s.io/v1
	//metadata:
	//  name: rbd-csi-nodeplugin-psp
	//  # replace with non-default namespace name
	//  namespace: kube-system
	//rules:
	//  - apiGroups: ['policy']
	//    resources: ['podsecuritypolicies']
	//    verbs: ['use']
	//    resourceNames: ['rbd-csi-nodeplugin-psp']
	//
	//---
	//kind: RoleBinding
	//apiVersion: rbac.authorization.k8s.io/v1
	//metadata:
	//  name: rbd-csi-nodeplugin-psp
	//  # replace with non-default namespace name
	//  namespace: kube-system
	//subjects:
	//  - kind: ServiceAccount
	//    name: rbd-csi-nodeplugin
	//    # replace with non-default namespace name
	//    namespace: kube-system
	//roleRef:
	//  kind: Role
	//  name: rbd-csi-nodeplugin-psp
	//  apiGroup: rbac.authorization.k8s.io
	//
	//---
	//apiVersion: v1
	//kind: ServiceAccount
	//metadata:
	//  name: rbd-csi-nodeplugin
	//  namespace: kube-system
	//
	//---
	//kind: ClusterRole
	//apiVersion: rbac.authorization.k8s.io/v1
	//metadata:
	//  name: rbd-csi-nodeplugin
	//rules:
	//  - apiGroups: [""]
	//    resources: ["nodes"]
	//    verbs: ["get"]
	//  # allow to read Vault Token and connection options from the Tenants namespace
	//  - apiGroups: [""]
	//    resources: ["secrets"]
	//    verbs: ["get"]
	//  - apiGroups: [""]
	//    resources: ["configmaps"]
	//    verbs: ["get"]
	//  - apiGroups: [""]
	//    resources: ["serviceaccounts"]
	//    verbs: ["get"]
	//  - apiGroups: [""]
	//    resources: ["persistentvolumes"]
	//    verbs: ["get"]
	//  - apiGroups: ["storage.k8s.io"]
	//    resources: ["volumeattachments"]
	//    verbs: ["list", "get"]
	//
	//---
	//kind: ClusterRoleBinding
	//apiVersion: rbac.authorization.k8s.io/v1
	//metadata:
	//  name: rbd-csi-nodeplugin
	//subjects:
	//  - kind: ServiceAccount
	//    name: rbd-csi-nodeplugin
	//    namespace: kube-system
	//roleRef:
	//  kind: ClusterRole
	//  name: rbd-csi-nodeplugin
	//  apiGroup: rbac.authorization.k8s.io
	//
	//---
	//apiVersion: policy/v1beta1
	//kind: PodSecurityPolicy
	//metadata:
	//  name: rbd-csi-provisioner-psp
	//spec:
	//  allowPrivilegeEscalation: true
	//  allowedCapabilities:
	//    - 'SYS_ADMIN'
	//  fsGroup:
	//    rule: RunAsAny
	//  privileged: true
	//  runAsUser:
	//    rule: RunAsAny
	//  seLinux:
	//    rule: RunAsAny
	//  supplementalGroups:
	//    rule: RunAsAny
	//  volumes:
	//    - 'configMap'
	//    - 'emptyDir'
	//    - 'projected'
	//    - 'secret'
	//    - 'downwardAPI'
	//    - 'hostPath'
	//  allowedHostPaths:
	//    - pathPrefix: '/dev'
	//      readOnly: false
	//    - pathPrefix: '/sys'
	//      readOnly: false
	//    - pathPrefix: '/lib/modules'
	//      readOnly: true
	//
	//---
	//kind: Role
	//apiVersion: rbac.authorization.k8s.io/v1
	//metadata:
	//  # replace with non-default namespace name
	//  namespace: kube-system
	//  name: rbd-csi-provisioner-psp
	//rules:
	//  - apiGroups: ['policy']
	//    resources: ['podsecuritypolicies']
	//    verbs: ['use']
	//    resourceNames: ['rbd-csi-provisioner-psp']
	//
	//---
	//kind: RoleBinding
	//apiVersion: rbac.authorization.k8s.io/v1
	//metadata:
	//  name: rbd-csi-provisioner-psp
	//  # replace with non-default namespace name
	//  namespace: kube-system
	//subjects:
	//  - kind: ServiceAccount
	//    name: rbd-csi-provisioner
	//    # replace with non-default namespace name
	//    namespace: kube-system
	//roleRef:
	//  kind: Role
	//  name: rbd-csi-provisioner-psp
	//  apiGroup: rbac.authorization.k8s.io
	//
	//---
	//apiVersion: v1
	//kind: ServiceAccount
	//metadata:
	//  name: rbd-csi-provisioner
	//  namespace: kube-system
	//
	//---
	//kind: ClusterRole
	//apiVersion: rbac.authorization.k8s.io/v1
	//metadata:
	//  name: rbd-external-provisioner-runner
	//rules:
	//  - apiGroups: [""]
	//    resources: ["nodes"]
	//    verbs: ["get", "list", "watch"]
	//  - apiGroups: [""]
	//    resources: ["secrets"]
	//    verbs: ["get", "list", "watch"]
	//  - apiGroups: [""]
	//    resources: ["events"]
	//    verbs: ["list", "watch", "create", "update", "patch"]
	//  - apiGroups: [""]
	//    resources: ["persistentvolumes"]
	//    verbs: ["get", "list", "watch", "create", "update", "delete", "patch"]
	//  - apiGroups: [""]
	//    resources: ["persistentvolumeclaims"]
	//    verbs: ["get", "list", "watch", "update"]
	//  - apiGroups: [""]
	//    resources: ["persistentvolumeclaims/status"]
	//    verbs: ["update", "patch"]
	//  - apiGroups: ["storage.k8s.io"]
	//    resources: ["storageclasses"]
	//    verbs: ["get", "list", "watch"]
	//  - apiGroups: ["snapshot.storage.k8s.io"]
	//    resources: ["volumesnapshots"]
	//    verbs: ["get", "list"]
	//  - apiGroups: ["snapshot.storage.k8s.io"]
	//    resources: ["volumesnapshotcontents"]
	//    verbs: ["create", "get", "list", "watch", "update", "delete"]
	//  - apiGroups: ["snapshot.storage.k8s.io"]
	//    resources: ["volumesnapshotclasses"]
	//    verbs: ["get", "list", "watch"]
	//  - apiGroups: ["storage.k8s.io"]
	//    resources: ["volumeattachments"]
	//    verbs: ["get", "list", "watch", "update", "patch"]
	//  - apiGroups: ["storage.k8s.io"]
	//    resources: ["volumeattachments/status"]
	//    verbs: ["patch"]
	//  - apiGroups: ["storage.k8s.io"]
	//    resources: ["csinodes"]
	//    verbs: ["get", "list", "watch"]
	//  - apiGroups: ["snapshot.storage.k8s.io"]
	//    resources: ["volumesnapshotcontents/status"]
	//    verbs: ["update"]
	//  - apiGroups: [""]
	//    resources: ["configmaps"]
	//    verbs: ["get"]
	//  - apiGroups: [""]
	//    resources: ["serviceaccounts"]
	//    verbs: ["get"]
	//
	//---
	//kind: ClusterRoleBinding
	//apiVersion: rbac.authorization.k8s.io/v1
	//metadata:
	//  name: rbd-csi-provisioner-role
	//subjects:
	//  - kind: ServiceAccount
	//    name: rbd-csi-provisioner
	//    namespace: kube-system
	//roleRef:
	//  kind: ClusterRole
	//  name: rbd-external-provisioner-runner
	//  apiGroup: rbac.authorization.k8s.io
	//
	//---
	//kind: Role
	//apiVersion: rbac.authorization.k8s.io/v1
	//metadata:
	//  # replace with non-default namespace name
	//  namespace: kube-system
	//  name: rbd-external-provisioner-cfg
	//rules:
	//  - apiGroups: [""]
	//    resources: ["configmaps"]
	//    verbs: ["get", "list", "watch", "create", "update", "delete"]
	//  - apiGroups: ["coordination.k8s.io"]
	//    resources: ["leases"]
	//    verbs: ["get", "watch", "list", "delete", "update", "create"]
	//
	//---
	//kind: RoleBinding
	//apiVersion: rbac.authorization.k8s.io/v1
	//metadata:
	//  name: rbd-csi-provisioner-role-cfg
	//  # replace with non-default namespace name
	//  namespace: kube-system
	//subjects:
	//  - kind: ServiceAccount
	//    name: rbd-csi-provisioner
	//    # replace with non-default namespace name
	//    namespace: kube-system
	//roleRef:
	//  kind: Role
	//  name: rbd-external-provisioner-cfg
	//  apiGroup: rbac.authorization.k8s.io
	//
	//---
	//kind: Service
	//apiVersion: v1
	//metadata:
	//  name: csi-rbdplugin-provisioner
	//  namespace: kube-system
	//  labels:
	//    app: csi-metrics
	//spec:
	//  selector:
	//    app: csi-rbdplugin-provisioner
	//  ports:
	//    - name: http-metrics
	//      port: 8080
	//      protocol: TCP
	//      targetPort: 8680
	//
	//---
	//kind: Deployment
	//apiVersion: apps/v1
	//metadata:
	//  name: csi-rbdplugin-provisioner
	//  namespace: kube-system
	//spec:
	//  replicas: 3
	//  selector:
	//    matchLabels:
	//      app: csi-rbdplugin-provisioner
	//  template:
	//    metadata:
	//      labels:
	//        app: csi-rbdplugin-provisioner
	//    spec:
	//      affinity:
	//        podAntiAffinity:
	//          requiredDuringSchedulingIgnoredDuringExecution:
	//            - labelSelector:
	//                matchExpressions:
	//                  - key: app
	//                    operator: In
	//                    values:
	//                      - csi-rbdplugin-provisioner
	//              topologyKey: "kubernetes.io/hostname"
	//      serviceAccountName: rbd-csi-provisioner
	//      priorityClassName: system-cluster-critical
	//      containers:
	//        - name: csi-provisioner
	//          image: 192.168.0.3:5000/caas4/csi-provisioner:v2.2.2
	//          args:
	//            - "--csi-address=$(ADDRESS)"
	//            - "--v=5"
	//            - "--timeout=150s"
	//            - "--retry-interval-start=500ms"
	//            - "--leader-election=true"
	//            #  set it to true to use topology based provisioning
	//            - "--feature-gates=Topology=false"
	//            # if fstype is not specified in storageclass, ext4 is default
	//            - "--default-fstype=ext4"
	//            - "--extra-create-metadata=true"
	//          env:
	//            - name: ADDRESS
	//              value: unix:///csi/csi-provisioner.sock
	//          imagePullPolicy: "IfNotPresent"
	//          volumeMounts:
	//            - name: socket-dir
	//              mountPath: /csi
	//        - name: csi-snapshotter
	//          image: 192.168.0.3:5000/caas4/csi-snapshotter:v4.1.1
	//          args:
	//            - "--csi-address=$(ADDRESS)"
	//            - "--v=5"
	//            - "--timeout=150s"
	//            - "--leader-election=true"
	//          env:
	//            - name: ADDRESS
	//              value: unix:///csi/csi-provisioner.sock
	//          imagePullPolicy: "IfNotPresent"
	//          securityContext:
	//            privileged: true
	//          volumeMounts:
	//            - name: socket-dir
	//              mountPath: /csi
	//        - name: csi-attacher
	//          image: 192.168.0.3:5000/caas4/csi-attacher:v3.2.1
	//          args:
	//            - "--v=5"
	//            - "--csi-address=$(ADDRESS)"
	//            - "--leader-election=true"
	//            - "--retry-interval-start=500ms"
	//          env:
	//            - name: ADDRESS
	//              value: /csi/csi-provisioner.sock
	//          imagePullPolicy: "IfNotPresent"
	//          volumeMounts:
	//            - name: socket-dir
	//              mountPath: /csi
	//        - name: csi-resizer
	//          image: 192.168.0.3:5000/caas4/csi-resizer:v1.2.0
	//          args:
	//            - "--csi-address=$(ADDRESS)"
	//            - "--v=5"
	//            - "--timeout=150s"
	//            - "--leader-election"
	//            - "--retry-interval-start=500ms"
	//            - "--handle-volume-inuse-error=false"
	//          env:
	//            - name: ADDRESS
	//              value: unix:///csi/csi-provisioner.sock
	//          imagePullPolicy: "IfNotPresent"
	//          volumeMounts:
	//            - name: socket-dir
	//              mountPath: /csi
	//        - name: csi-rbdplugin
	//          securityContext:
	//            privileged: true
	//            capabilities:
	//              add: ["SYS_ADMIN"]
	//          # for stable functionality replace canary with latest release version
	//          image: 192.168.0.3:5000/caas4/cephcsi:v3.4.0
	//          args:
	//            - "--nodeid=$(NODE_ID)"
	//            - "--type=rbd"
	//            - "--controllerserver=true"
	//            - "--endpoint=$(CSI_ENDPOINT)"
	//            - "--v=5"
	//            - "--drivername=rbd.csi.ceph.com"
	//            - "--pidlimit=-1"
	//            - "--rbdhardmaxclonedepth=8"
	//            - "--rbdsoftmaxclonedepth=4"
	//            - "--enableprofiling=false"
	//          env:
	//            - name: POD_IP
	//              valueFrom:
	//                fieldRef:
	//                  fieldPath: status.podIP
	//            - name: NODE_ID
	//              valueFrom:
	//                fieldRef:
	//                  fieldPath: spec.nodeName
	//            # - name: POD_NAMESPACE
	//            #   valueFrom:
	//            #     fieldRef:
	//            #       fieldPath: spec.namespace
	//            # - name: KMS_CONFIGMAP_NAME
	//            #   value: encryptionConfig
	//            - name: CSI_ENDPOINT
	//              value: unix:///csi/csi-provisioner.sock
	//          imagePullPolicy: "IfNotPresent"
	//          volumeMounts:
	//            - name: socket-dir
	//              mountPath: /csi
	//            - mountPath: /dev
	//              name: host-dev
	//            - mountPath: /sys
	//              name: host-sys
	//            - mountPath: /lib/modules
	//              name: lib-modules
	//              readOnly: true
	//            - name: ceph-csi-config
	//              mountPath: /etc/ceph-csi-config/
	//            - name: ceph-csi-encryption-kms-config
	//              mountPath: /etc/ceph-csi-encryption-kms-config/
	//            - name: keys-tmp-dir
	//              mountPath: /tmp/csi/keys
	//        - name: csi-rbdplugin-controller
	//          securityContext:
	//            privileged: true
	//            capabilities:
	//              add: ["SYS_ADMIN"]
	//          # for stable functionality replace canary with latest release version
	//          image: 192.168.0.3:5000/caas4/cephcsi:v3.4.0
	//          args:
	//            - "--type=controller"
	//            - "--v=5"
	//            - "--drivername=rbd.csi.ceph.com"
	//            - "--drivernamespace=$(DRIVER_NAMESPACE)"
	//          env:
	//            - name: DRIVER_NAMESPACE
	//              valueFrom:
	//                fieldRef:
	//                  fieldPath: metadata.namespace
	//          imagePullPolicy: "IfNotPresent"
	//          volumeMounts:
	//            - name: ceph-csi-config
	//              mountPath: /etc/ceph-csi-config/
	//            - name: keys-tmp-dir
	//              mountPath: /tmp/csi/keys
	//        - name: liveness-prometheus
	//          image: 192.168.0.3:5000/caas4/cephcsi:v3.4.0
	//          args:
	//            - "--type=liveness"
	//            - "--endpoint=$(CSI_ENDPOINT)"
	//            - "--metricsport=8680"
	//            - "--metricspath=/metrics"
	//            - "--polltime=60s"
	//            - "--timeout=3s"
	//          env:
	//            - name: CSI_ENDPOINT
	//              value: unix:///csi/csi-provisioner.sock
	//            - name: POD_IP
	//              valueFrom:
	//                fieldRef:
	//                  fieldPath: status.podIP
	//          volumeMounts:
	//            - name: socket-dir
	//              mountPath: /csi
	//          imagePullPolicy: "IfNotPresent"
	//      volumes:
	//        - name: host-dev
	//          hostPath:
	//            path: /dev
	//        - name: host-sys
	//          hostPath:
	//            path: /sys
	//        - name: lib-modules
	//          hostPath:
	//            path: /lib/modules
	//        - name: socket-dir
	//          emptyDir: {
	//            medium: "Memory"
	//          }
	//        - name: ceph-csi-config
	//          configMap:
	//            name: ceph-csi-config
	//        - name: ceph-csi-encryption-kms-config
	//          configMap:
	//            name: ceph-csi-encryption-kms-config
	//        - name: keys-tmp-dir
	//          emptyDir: {
	//            medium: "Memory"
	//          }
	//
	//---
	//kind: DaemonSet
	//apiVersion: apps/v1
	//metadata:
	//  name: csi-rbdplugin
	//  namespace: kube-system
	//spec:
	//  selector:
	//    matchLabels:
	//      app: csi-rbdplugin
	//  template:
	//    metadata:
	//      labels:
	//        app: csi-rbdplugin
	//    spec:
	//      serviceAccountName: rbd-csi-nodeplugin
	//      hostNetwork: true
	//      hostPID: true
	//      priorityClassName: system-node-critical
	//      # to use e.g. Rook orchestrated cluster, and mons' FQDN is
	//      # resolved through k8s service, set dns policy to cluster first
	//      dnsPolicy: ClusterFirstWithHostNet
	//      containers:
	//        - name: driver-registrar
	//          # This is necessary only for systems with SELinux, where
	//          # non-privileged sidecar containers cannot access unix domain socket
	//          # created by privileged CSI driver container.
	//          securityContext:
	//            privileged: true
	//          image: 192.168.0.3:5000/caas4/csi-node-driver-registrar:v2.2.0
	//          args:
	//            - "--v=5"
	//            - "--csi-address=/csi/csi.sock"
	//            - "--kubelet-registration-path=/var/lib/kubelet/plugins/rbd.csi.ceph.com/csi.sock"
	//          env:
	//            - name: KUBE_NODE_NAME
	//              valueFrom:
	//                fieldRef:
	//                  fieldPath: spec.nodeName
	//          volumeMounts:
	//            - name: socket-dir
	//              mountPath: /csi
	//            - name: registration-dir
	//              mountPath: /registration
	//        - name: csi-rbdplugin
	//          securityContext:
	//            privileged: true
	//            capabilities:
	//              add: ["SYS_ADMIN"]
	//            allowPrivilegeEscalation: true
	//          # for stable functionality replace canary with latest release version
	//          image: 192.168.0.3:5000/caas4/cephcsi:v3.4.0
	//          args:
	//            - "--nodeid=$(NODE_ID)"
	//            - "--pluginpath=/var/lib/kubelet/plugins"
	//            - "--stagingpath=/var/lib/kubelet/plugins/kubernetes.io/csi/pv/"
	//            - "--type=rbd"
	//            - "--nodeserver=true"
	//            - "--endpoint=$(CSI_ENDPOINT)"
	//            - "--v=5"
	//            - "--drivername=rbd.csi.ceph.com"
	//            - "--enableprofiling=false"
	//            # If topology based provisioning is desired, configure required
	//            # node labels representing the nodes topology domain
	//            # and pass the label names below, for CSI to consume and advertise
	//            # its equivalent topology domain
	//            # - "--domainlabels=failure-domain/region,failure-domain/zone"
	//          env:
	//            - name: POD_IP
	//              valueFrom:
	//                fieldRef:
	//                  fieldPath: status.podIP
	//            - name: NODE_ID
	//              valueFrom:
	//                fieldRef:
	//                  fieldPath: spec.nodeName
	//            # - name: POD_NAMESPACE
	//            #   valueFrom:
	//            #     fieldRef:
	//            #       fieldPath: spec.namespace
	//            # - name: KMS_CONFIGMAP_NAME
	//            #   value: encryptionConfig
	//            - name: CSI_ENDPOINT
	//              value: unix:///csi/csi.sock
	//          imagePullPolicy: "IfNotPresent"
	//          volumeMounts:
	//            - name: socket-dir
	//              mountPath: /csi
	//            - mountPath: /dev
	//              name: host-dev
	//            - mountPath: /sys
	//              name: host-sys
	//            - mountPath: /run/mount
	//              name: host-mount
	//            - mountPath: /lib/modules
	//              name: lib-modules
	//              readOnly: true
	//            - name: ceph-csi-config
	//              mountPath: /etc/ceph-csi-config/
	//            - name: ceph-csi-encryption-kms-config
	//              mountPath: /etc/ceph-csi-encryption-kms-config/
	//            - name: plugin-dir
	//              mountPath: /var/lib/kubelet/plugins
	//              mountPropagation: "Bidirectional"
	//            - name: mountpoint-dir
	//              mountPath: /var/lib/kubelet/pods
	//              mountPropagation: "Bidirectional"
	//            - name: keys-tmp-dir
	//              mountPath: /tmp/csi/keys
	//        - name: liveness-prometheus
	//          securityContext:
	//            privileged: true
	//          image: 192.168.0.3:5000/caas4/cephcsi:v3.4.0
	//          args:
	//            - "--type=liveness"
	//            - "--endpoint=$(CSI_ENDPOINT)"
	//            - "--metricsport=8680"
	//            - "--metricspath=/metrics"
	//            - "--polltime=60s"
	//            - "--timeout=3s"
	//          env:
	//            - name: CSI_ENDPOINT
	//              value: unix:///csi/csi.sock
	//            - name: POD_IP
	//              valueFrom:
	//                fieldRef:
	//                  fieldPath: status.podIP
	//          volumeMounts:
	//            - name: socket-dir
	//              mountPath: /csi
	//          imagePullPolicy: "IfNotPresent"
	//      volumes:
	//        - name: socket-dir
	//          hostPath:
	//            path: /var/lib/kubelet/plugins/rbd.csi.ceph.com
	//            type: DirectoryOrCreate
	//        - name: plugin-dir
	//          hostPath:
	//            path: /var/lib/kubelet/plugins
	//            type: Directory
	//        - name: mountpoint-dir
	//          hostPath:
	//            path: /var/lib/kubelet/pods
	//            type: DirectoryOrCreate
	//        - name: registration-dir
	//          hostPath:
	//            path: /var/lib/kubelet/plugins_registry/
	//            type: Directory
	//        - name: host-dev
	//          hostPath:
	//            path: /dev
	//        - name: host-sys
	//          hostPath:
	//            path: /sys
	//        - name: host-mount
	//          hostPath:
	//            path: /run/mount
	//        - name: lib-modules
	//          hostPath:
	//            path: /lib/modules
	//        - name: ceph-csi-config
	//          configMap:
	//            name: ceph-csi-config
	//        - name: ceph-csi-encryption-kms-config
	//          configMap:
	//            name: ceph-csi-encryption-kms-config
	//        - name: keys-tmp-dir
	//          emptyDir: {
	//            medium: "Memory"
	//          }
	//
	//---
	//apiVersion: v1
	//kind: Service
	//metadata:
	//  name: csi-metrics-rbdplugin
	//  namespace: kube-system
	//  labels:
	//    app: csi-metrics
	//spec:
	//  ports:
	//    - name: http-metrics
	//      port: 8080
	//      protocol: TCP
	//      targetPort: 8680
	//  selector:
	//    app: csi-rbdplugin
	//
	//---
	//# if Kubernetes version is less than 1.18 change
	//# apiVersion to storage.k8s.io/v1beta1
	//apiVersion: storage.k8s.io/v1
	//kind: CSIDriver
	//metadata:
	//  name: rbd.csi.ceph.com
	//spec:
	//  attachRequired: true
	//  podInfoOnMount: false
	//
	//---
	//apiVersion: storage.k8s.io/v1
	//kind: StorageClass
	//metadata:
	//  name: ceph-rbd-sc
	//  annotations:
	//    storageclass.kubernetes.io/is-default-class: "true"
	//provisioner: rbd.csi.ceph.com
	//parameters:
	//  clusterID: ceph-cluster-id
	//  pool: ceph-pool-id
	//  thickProvision: "false"
	//  imageFeatures: layering
	//  csi.storage.k8s.io/provisioner-secret-name: csi-rbd-secret
	//  csi.storage.k8s.io/provisioner-secret-namespace: kube-system
	//  csi.storage.k8s.io/controller-expand-secret-name: csi-rbd-secret
	//  csi.storage.k8s.io/controller-expand-secret-namespace: kube-system
	//  csi.storage.k8s.io/node-stage-secret-name: csi-rbd-secret
	//  csi.storage.k8s.io/node-stage-secret-namespace: kube-system
	//  csi.storage.k8s.io/fstype: ext4
	//reclaimPolicy: Delete
	//allowVolumeExpansion: true
	//mountOptions:
	//   - discard
	//`
	//
	//	cc := &CephCSI{
	//		Namespace: namespace,
	//		CSIConfig: CSIConfig{
	//			CephClusterID: "ceph-cluster-id",
	//			CephMonitors: []string{
	//				"192.168.0.1",
	//				"192.168.0.2",
	//				"192.168.0.4",
	//			},
	//		},
	//		UserID:            "ceph-user-id",
	//		UserKey:           "ceph-user-key",
	//		PoolID:            "ceph-pool-id",
	//		ImageRegistryAddr: "192.168.0.3:5000",
	//		StorageClassName:  scName,
	//		IsDefault:         true,
	//		FsType:            fsType,
	//		ReclaimPolicy:     reclaimPolicy,
	//	}
	//	sb := &strings.Builder{}
	//	if err := cc.renderTo(sb); err != nil {
	//		assert.FailNow(t, "template renderring failed, err: %v", err)
	//	}
	//	assert.Equal(t, expected, sb.String())
}
