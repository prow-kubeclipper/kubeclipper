package rancher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	v3 "github.com/rancher/rke/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/kubeclipper/kubeclipper/pkg/logger"
	"github.com/kubeclipper/kubeclipper/pkg/scheme/common"

	"github.com/kubeclipper/kubeclipper/pkg/controller-runtime/client"
	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
	"github.com/kubeclipper/kubeclipper/pkg/utils/httputil"
)

// rancher API Path
// example: https://127.0.0.1/v3
const (
	preCheck                       = "clusters"
	listCluster                    = "clusters"
	deleteCluster                  = "clusters/%s"
	describeCluster                = "clusters/%s"
	clusterNodes                   = "clusters/%s/nodes"
	createClusterRegistrationToken = "clusterregistrationtoken"
	clusterRegistrationTokens      = "clusterregistrationtokens?clusterId=%s"
	removeClusterNode              = "nodes/%s"
	generateKubeconfig             = "clusters/%s?action=generateKubeconfig"
)

const (
	// etcdRole    = "etcd"
	controlRole = "controlplane"
	WorkerRole  = "worker"
)

type Client struct {
	APIEndpoint string `json:"apiEndpoint"`
	BearerToken string `json:"bearerToken"`
}

func NewRancherClient(config runtime.RawExtension) (*Client, error) {
	rancher, err := ParseConf(config)
	if err != nil {
		return nil, err
	}
	cli := Client{
		APIEndpoint: rancher.APIEndpoint,
		BearerToken: fmt.Sprintf("Bearer %s:%s", rancher.AccessKey, rancher.SecretKey),
	}
	return &cli, nil
}

func ParseConf(config runtime.RawExtension) (*Config, error) {
	data, err := config.MarshalJSON()
	if err != nil {
		return nil, err
	}
	rancher := new(Config)
	if err = json.Unmarshal(data, rancher); err != nil {
		return nil, err
	}
	return rancher, nil
}

var ErrInvalidAPIEndpoint = errors.New("invalid apiEndpoint")

func endPointCheck(apiEndpoint string) bool {
	parse, err := url.Parse(apiEndpoint)
	if err != nil {
		return false
	}
	return parse.Path == "/v3"
}

func (cli Client) PreCheck(ctx context.Context) (int, error) {
	if !endPointCheck(cli.APIEndpoint) {
		return -1, ErrInvalidAPIEndpoint
	}
	URL := cli.urlComplete(preCheck)
	header := make(map[string]string)
	header["Authorization"] = cli.BearerToken
	_, code, err := httputil.CommonRequest(URL, http.MethodGet, header, nil, nil)
	if err != nil {
		return -1, err
	}

	return code, nil
}

func (cli Client) ClusterIDs(ctx context.Context) ([]string, error) {
	u := cli.urlComplete(listCluster)
	bytes, err := cli.rancherRequest(u, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	clusters := &Clusters{}
	err = json.Unmarshal(bytes, clusters)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(clusters.Data))
	for _, v := range clusters.Data {
		if (v.State == "active" || v.State == "updating") && v.Driver == "rancherKubernetesEngine" { // just import rke driver and active cluster now
			ids = append(ids, v.ID)
		}
	}
	return ids, nil
}

func (cli Client) GetCluster(ctx context.Context, clusterID string) (*Cluster, error) {
	u := cli.urlComplete(describeCluster, clusterID)
	bytes, err := cli.rancherRequest(u, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	cluster := &Cluster{}
	err = json.Unmarshal(bytes, cluster)
	return cluster, err
}

func (cli Client) getFullState(ctx context.Context, clusterID string) (*FullState, error) {
	// generate kubeConfig
	conf, err := cli.KubeConfig(clusterID)
	if err != nil {
		return nil, errors.WithMessage(err, "generate kubeConfig")
	}
	// build clientSet from kubeConfig

	// why use client-go to get configmap ?
	// since the full config for the rancher-api is in a very complex format,
	// using client-go's configmap to parse it will be easier and will not result in the wrong format
	_, clientset, err := client.FromKubeConfig([]byte(conf))
	if err != nil {
		return nil, errors.WithMessage(err, "FromKubeConfig")
	}
	// get configmap full-cluster-state
	cm, err := clientset.CoreV1().ConfigMaps("kube-system").
		Get(ctx, "full-cluster-state", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	fullState := &FullState{}
	err = json.Unmarshal([]byte(cm.Data["full-cluster-state"]), fullState)
	if err != nil {
		return nil, errors.WithMessage(err, "unmarshal fullState")
	}
	fullState.KubeConfig = []byte(conf)

	// get node info for cri.
	nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	for _, node := range nodeList.Items {
		// nodeName is hostname,not rancher node id.
		m[node.Name] = node.Status.NodeInfo.ContainerRuntimeVersion
	}
	fullState.NodeCRI = m
	fullState.ClusterID = clusterID
	return fullState, err
}

func (cli Client) KubeConfig(clusterID string) (string, error) {
	u := cli.urlComplete(generateKubeconfig, clusterID)
	bytes, err := cli.rancherRequest(u, http.MethodPost, nil)
	if err != nil {
		return "", err
	}
	conf := &KubeConfig{}
	err = json.Unmarshal(bytes, conf)
	return conf.Config, err
}

func (cli Client) ClusterNodes(ctx context.Context, clusterID string) (*Nodes, error) {
	u := cli.urlComplete(clusterNodes, clusterID)
	bytes, err := cli.rancherRequest(u, http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	nodes := &Nodes{}
	err = json.Unmarshal(bytes, nodes)
	return nodes, err
}

// DeleteCluster the rancher api may have failed to delete the cluster
func (cli Client) DeleteCluster(ctx context.Context, cluster string) error {
	u := cli.urlComplete(deleteCluster, cluster)
	_, err := cli.rancherRequest(u, http.MethodDelete, nil)
	return err
}

func (cli Client) JoinNodeCmd(ctx context.Context, clusterID, kcNodeUUID string, roles []string) (string, error) {
	if len(roles) == 0 {
		return "", fmt.Errorf("node joining the cluster must have a role")
	}
	// create before get,avoid all token expired
	err := cli.createClusterRegistrationToken(ctx, clusterID)
	if err != nil {
		return "", errors.WithMessage(err, "create cluster registration token")
	}

	joinCmd, err := cli.clusterRegistrationTokens(ctx, clusterRegistrationTokens)
	if err != nil {
		return "", err
	}
	if joinCmd == "" {
		return "", errors.New("no join cmd find")
	}
	withRole := ""
	for _, role := range roles {
		withRole = fmt.Sprintf("%s --%s", withRole, role)
	}

	label := fmt.Sprintf("%s=%s", common.LabelNodeUUID, kcNodeUUID)
	withLabel := fmt.Sprintf("%s --label %s", withRole, label)

	logger.Debugf("join node cmd: %s", fmt.Sprintf("%s %s", joinCmd, withLabel))
	return fmt.Sprintf("%s %s", joinCmd, withLabel), nil
}

func (cli Client) createClusterRegistrationToken(ctx context.Context, clusterID string) error {
	u := cli.urlComplete(createClusterRegistrationToken)

	body := &struct {
		ClusterID string `json:"clusterId"`
		CmdType   string `json:"type"`
	}{
		clusterID,
		"clusterRegistrationToken",
	}

	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = cli.rancherRequest(u, http.MethodPost, b)
	return err
}

func (cli Client) clusterRegistrationTokens(ctx context.Context, clusterID string) (string, error) {
	u := cli.urlComplete(clusterRegistrationTokens, clusterID)
	resp, err := cli.rancherRequest(u, http.MethodGet, nil)
	if err != nil {
		return "", err
	}
	var tokens ClusterRegistrationToken
	if err = json.Unmarshal(resp, &tokens); err != nil {
		return "", err
	}
	if len(tokens.Data) == 0 {
		return "", errors.New("no cluster registration token,please create first")
	}
	return tokens.Data[0].NodeCommand, nil
}

// RemoveNode the rancher api may have failed to delete the cluster node
func (cli Client) RemoveNode(ctx context.Context, nodeID string) error {
	u := cli.urlComplete(removeClusterNode, nodeID)
	_, err := cli.rancherRequest(u, http.MethodDelete, nil)
	return err
}

func (cli Client) rancherRequest(url, httpMethod string, postBody json.RawMessage) ([]byte, error) {
	header := make(map[string]string)
	header["Authorization"] = cli.BearerToken

	resp, code, err := httputil.CommonRequest(url, httpMethod, header, nil, postBody)
	if err != nil {
		return nil, err
	}
	if code < http.StatusOK || code >= http.StatusBadRequest {
		return nil, fmt.Errorf(string(resp))
	}

	return resp, nil
}

func (cli Client) urlComplete(path string, args ...string) string {
	for _, arg := range args {
		path = fmt.Sprintf(path, arg)
	}
	return fmt.Sprintf("%s/%s", cli.APIEndpoint, path)
}

//nolint:unused
func (cli Client) joinNodeParseCmd(resp []byte, role []string) (string, error) {
	bodyMap := make(map[string]string)
	err := json.Unmarshal(resp, &bodyMap)
	if err != nil {
		return "", err
	}
	if _, ok := bodyMap["nodeCommand"]; !ok {
		return "", fmt.Errorf("rancher cluster join node cmd is empty")
	}

	cmdString := bodyMap["nodeCommand"]
	for _, val := range role {
		switch val {
		case "etcd", "controlplane", "worker":
			cmdString = fmt.Sprintf("%s --%s", cmdString, val)
		default:
			return "", fmt.Errorf("no support node role")
		}
	}

	return cmdString, nil
}

func getIPFamily(ServiceSubnet, podSubnet string) v1.IPFamily {
	serviceSubnets := strings.Split(ServiceSubnet, ",")
	podSubnets := strings.Split(podSubnet, ",")
	ipFamily := v1.IPFamilyIPv4
	if len(serviceSubnets) >= 2 && len(podSubnets) >= 2 {
		ipFamily = v1.IPFamilyDualStack
	}
	return ipFamily
}

type Clusters struct {
	Data []struct {
		ID     string `json:"id"`
		State  string `json:"state"`
		Driver string `json:"driver"`
	} `json:"data"`
}

type Cluster struct {
	Name        string `json:"name"`
	AppliedSpec struct {
		DockerRootDir string `json:"dockerRootDir"`
		Driver        string `json:"driver"`
	} `json:"appliedSpec"`
	ComponentStatuses []struct {
		Name       string `json:"name"`
		Conditions []struct {
			Message string `json:"message"`
			Status  string `json:"status"`
			Type    string `json:"type"`
		} `json:"conditions"`
	} `json:"componentStatuses"`
	CertificatesExpiration map[string]struct {
		ExpirationDate metav1.Time `json:"expirationDate"`
	} `json:"certificatesExpiration"`
	Conditions []struct {
		Status         string      `json:"status"`
		Type           string      `json:"type"`
		LastUpdateTime metav1.Time `json:"lastUpdateTime"`
	} `json:"conditions"`
}

type Nodes struct {
	Data []Node `json:"data"`
}

type Node struct {
	State             string            `json:"state"`
	Labels            map[string]string `json:"labels"`
	Taints            []v1.Taint        `yaml:"taints" json:"taints,omitempty"`
	Hostname          string            `json:"hostname"`
	Info              Info              `json:"info"`
	ExternalIPAddress string            `json:"externalIPAddress"`
	IPAddress         string            `json:"ipAddress"`
	NodeName          string            `json:"nodeName"`
	ID                string            `json:"id"`   // format: $cluster:$node e.g. cluster1:node1
	UUID              string            `json:"uuid"` // use rancher node's uuid as kc agentID
}
type Info struct {
	OS struct {
		DockerVersion string `json:"dockerVersion"`
	}
}

type KubeConfig struct {
	Config string `json:"config"`
}

type FullState struct {
	DesiredState State             `json:"desiredState,omitempty"`
	CurrentState State             `json:"currentState,omitempty"`
	NodeCRI      map[string]string `json:"-"`
	KubeConfig   []byte            `json:"-"`
	ClusterID    string            `json:"-"`
}

type State struct {
	RancherKubernetesEngineConfig *v3.RancherKubernetesEngineConfig `json:"rkeConfig,omitempty"`
	EncryptionConfig              string                            `json:"encryptionConfig,omitempty"`
}

type ClusterRegistrationToken struct {
	Data []JoinNodeCmd `json:"data"`
}

type JoinNodeCmd struct {
	NodeCommand string `json:"nodeCommand"`
}
