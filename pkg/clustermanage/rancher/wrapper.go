package rancher

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/rancher/rke/hosts"
	"github.com/rancher/rke/pki"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/kubeclipper/kubeclipper/pkg/clustermanage"

	"github.com/kubeclipper/kubeclipper/pkg/scheme/common"
	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
)

type Wrapper struct {
	Provider v1.CloudProvider
	Operator clustermanage.Operator
}

func NewWrapper(provider v1.CloudProvider, operator clustermanage.Operator) Wrapper {
	return Wrapper{
		Provider: provider,
		Operator: operator,
	}
}

func (r Wrapper) ToClient() Client {
	data, err := r.Provider.Config.MarshalJSON()
	if err != nil {
		return Client{}
	}
	rancher := new(Config)
	if err = json.Unmarshal(data, rancher); err != nil {
		return Client{}
	}
	return Client{
		APIEndpoint: rancher.APIEndpoint,
		BearerToken: fmt.Sprintf("Bearer %s:%s", rancher.AccessKey, rancher.SecretKey),
	}
}

func (r Wrapper) ClusterIDs(ctx context.Context) ([]string, error) {
	return r.ToClient().ClusterIDs(ctx)
}

func (r Wrapper) ClusterInfo(ctx context.Context, clusterID string) (*v1.Cluster, error) {
	rancherCLuster, err := r.ToClient().GetCluster(ctx, clusterID)
	if err != nil {
		return nil, errors.WithMessagef(err, "get cluster %s", clusterID)
	}
	rancherNodes, err := r.ClusterNodes(ctx, clusterID)
	if err != nil {
		return nil, errors.WithMessagef(err, "get cluster fullState %s", clusterID)
	}
	fullState, err := r.ToClient().getFullState(ctx, clusterID)
	if err != nil {
		return nil, errors.WithMessagef(err, "get cluster fullState %s", clusterID)
	}

	return r.convert(fullState, rancherCLuster, rancherNodes)
}

func (r Wrapper) ClusterNodes(ctx context.Context, clusterID string) (*Nodes, error) {
	ids, err := r.ToClient().ClusterIDs(ctx)
	if err != nil {
		return nil, err
	}
	// if clusterID not in normalClusterIDs,we return nil node to drain all kc-agent
	if !sets.NewString(ids...).Has(clusterID) {
		return &Nodes{Data: nil}, nil
	}

	return r.ToClient().ClusterNodes(ctx, clusterID)
}

// convert rancher cluster to kc cluster.
func (r Wrapper) convert(fullState *FullState, rc *Cluster, nodes *Nodes) (*v1.Cluster, error) {
	rkeConfig := fullState.DesiredState.RancherKubernetesEngineConfig

	c := new(v1.Cluster)
	c.Kind = "cluster"
	c.APIVersion = "core.kubeclipper.io/v1"
	c.ObjectMeta = metav1.ObjectMeta{
		Name: rc.Name,
		Labels: map[string]string{
			common.LabelTopologyRegion:      r.Provider.Region,
			common.LabelClusterProviderType: ProviderRancher,
			common.LabelClusterProviderName: r.Provider.Name,
		},
		Annotations: map[string]string{
			common.AnnotationProviderClusterID: fullState.ClusterID,
			common.AnnotationDescription:       "rancher cluster import",
		},
	}

	c.Status = v1.ClusterStatus{
		Phase: v1.ClusterRunning,
	}

	certifications := ExtractCertifications(rc)
	c.Status.Certifications = certifications

	componentConditions := make([]v1.ComponentConditions, 0, len(rc.ComponentStatuses))
	for _, v := range rc.ComponentStatuses {
		item := v1.ComponentConditions{
			Name:     v.Name,
			Category: "",
		}
		if len(v.Conditions) != 0 {
			item.Status = v1.ComponentStatus(v.Conditions[0].Type)
		}
		componentConditions = append(componentConditions, item)
	}
	c.Status.ComponentConditions = componentConditions

	c.Kubelet.RootDir = "/var/lib/kubelet"
	c.KubeConfig = fullState.KubeConfig
	c.Addons = []v1.Addon{}
	// node
	masters := make([]v1.WorkerNode, 0)
	workers := make([]v1.WorkerNode, 0)

	// NOTE: rkeConfig.Nodes always one node,so we used nodes api.
	for _, node := range nodes.Data {
		var criType, criVersion string
		criType = "docker" // rancher cri is docker
		criVersion = node.Info.OS.DockerVersion
		c.ContainerRuntime = v1.ContainerRuntime{
			Type:             criType,
			Version:          criVersion,
			DataRootDir:      rc.AppliedSpec.DockerRootDir,
			InsecureRegistry: nil,
		}
		agentID, err := r.getNodeID(node)
		if err != nil {
			return nil, err
		}
		n := v1.WorkerNode{
			ID:     agentID,
			Labels: node.Labels,
			Taints: node.Taints,
			ContainerRuntime: v1.ContainerRuntime{
				Type:             criType,
				Version:          criVersion,
				DataRootDir:      rc.AppliedSpec.DockerRootDir,
				InsecureRegistry: nil,
			},
		}
		// check role by labels.
		_, controlplane := node.Labels["node-role.kubernetes.io/controlplane"]
		_, etcd := node.Labels["node-role.kubernetes.io/etcd"]
		if controlplane || etcd {
			masters = append(masters, n)
		} else {
			workers = append(workers, n)
		}
	}
	c.Masters = masters
	c.Workers = workers
	// sans
	sans := make([]string, 0)
	kubernetesServiceIP, err := pki.GetKubernetesServiceIP(rkeConfig.Services.KubeAPI.ServiceClusterIPRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get Kubernetes Service IP: %v", err)
	}
	clusterDomain := rkeConfig.Services.Kubelet.ClusterDomain
	cpHosts := hosts.NodesToHosts(rkeConfig.Nodes, controlRole)
	kubeAPIAltNames := pki.GetAltNames(cpHosts, clusterDomain, kubernetesServiceIP, rkeConfig.Authentication.SANs)
	sans = append(sans, kubeAPIAltNames.DNSNames...)
	for _, ip := range kubeAPIAltNames.IPs {
		sans = append(sans, ip.String())
	}
	c.CertSANs = sans

	// version
	c.KubernetesVersion = rkeConfig.Version

	// localRegistry
	localRegistry := ""
	for _, registry := range rkeConfig.PrivateRegistries {
		localRegistry = registry.URL
		break
	}
	c.LocalRegistry = localRegistry

	// etcd
	c.Etcd.DataDir = "/var/lib/etcd"
	if v, ok := rkeConfig.Services.Etcd.ExtraArgs["data-dir"]; ok {
		c.Etcd.DataDir = v
	}

	// network
	proxyMode := "iptables"
	if v, ok := rkeConfig.Services.Kubeproxy.ExtraArgs["proxy-mode"]; ok {
		if strings.Contains(v, "ipvs") {
			proxyMode = "ipvs"
		}
	}

	c.Networking = v1.Networking{
		IPFamily: getIPFamily(rkeConfig.Services.KubeController.ServiceClusterIPRange, rkeConfig.Services.KubeController.ClusterCIDR),
		Services: v1.NetworkRanges{
			CIDRBlocks: []string{rkeConfig.Services.KubeController.ServiceClusterIPRange},
		},
		Pods: v1.NetworkRanges{
			CIDRBlocks: []string{rkeConfig.Services.KubeController.ClusterCIDR},
		},
		DNSDomain:     rkeConfig.Services.Kubelet.ClusterDomain,
		ProxyMode:     proxyMode,
		WorkerNodeVip: "",
	}

	// maybe not calico
	var cniMode string
	// it's a const name,even if we used calico,it named flannel_backend_type too.
	if v, ok := rkeConfig.Network.Options["flannel_backend_type"]; ok {
		cniMode = v
	}
	var image, cniVersion string
	switch rkeConfig.Network.Plugin {
	case "calico":
		// rancher/calico-cni:v3.13.0
		image = rkeConfig.SystemImages.CalicoCNI
	case "flannel":
		// rancher/flannel-cni:v0.3.0-rancher5
		image = rkeConfig.SystemImages.FlannelCNI
	case "canal":
		// rancher/calico-cni:v3.13.0
		image = rkeConfig.SystemImages.CanalCNI
	}
	split := strings.Split(image, ":")
	if len(split) == 2 {
		cniVersion = split[1]
	}

	c.CNI = v1.CNI{
		LocalRegistry: "",
		Type:          rkeConfig.Network.Plugin,
		Version:       cniVersion,
		CriType:       "",
		Offline:       false,
		Calico: &v1.Calico{
			IPv4AutoDetection: "",
			IPv6AutoDetection: "",
			Mode:              cniMode,
			IPManger:          false,
			MTU:               rkeConfig.Network.MTU,
		},
	}

	return c, nil
}

func ExtractCertifications(rc *Cluster) []v1.Certification {
	certifications := make([]v1.Certification, 0, len(rc.CertificatesExpiration))
	for k, v := range rc.CertificatesExpiration {
		item := v1.Certification{
			Name:           k,
			ExpirationTime: v.ExpirationDate,
		}
		if k != "kube-ca" {
			item.CAName = "kube-ca"
		}
		certifications = append(certifications, item)
	}
	return certifications
}

func (r Wrapper) getNodeID(node Node) (string, error) {
	// first use label[uuid],because in add node action will use labels to set kc agentID to rancher.
	if uuid, ok := node.Labels[common.LabelNodeUUID]; ok {
		return uuid, nil
	}
	// if node state not active,maybe joining,must use ip to match avoid add twice in kc.
	if node.State != "active" {
		list, err := r.Operator.NodeLister.List(labels.Everything())
		if err != nil {
			return "", err
		}
		for _, v := range list {
			if v.Status.Ipv4DefaultIP == node.IPAddress {
				return v.Name, nil
			}
		}
	}
	return node.UUID, nil
}
