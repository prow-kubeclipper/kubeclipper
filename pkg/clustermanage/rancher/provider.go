package rancher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	apimachineryErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/kubeclipper/kubeclipper/pkg/constatns"

	"github.com/kubeclipper/kubeclipper/cmd/kcctl/app/options"
	"github.com/kubeclipper/kubeclipper/pkg/cli/config"
	"github.com/kubeclipper/kubeclipper/pkg/clustermanage"
	"github.com/kubeclipper/kubeclipper/pkg/logger"
	"github.com/kubeclipper/kubeclipper/pkg/scheme/common"
	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
	"github.com/kubeclipper/kubeclipper/pkg/utils/sshutils"
)

func init() {
	clustermanage.RegisterProvider(&RancherV3{})
}

const ProviderRancher = "rancher"

type RancherV3 struct {
	Operator clustermanage.Operator
	Provider v1.CloudProvider
	Config   Config
}

type Config struct {
	// APIEndpoint rancher apiServer address
	APIEndpoint string `json:"apiEndpoint,omitempty"`

	AccessKey string `json:"accessKey,omitempty"`
	SecretKey string `json:"secretKey,omitempty"`
}

func NewRancherV3(operator clustermanage.Operator, provider v1.CloudProvider) (clustermanage.CloudProvider, error) {
	conf, err := rawToConfig(provider.Config)
	if err != nil {
		return nil, err
	}
	r := RancherV3{
		Operator: operator,
		Provider: provider,
		Config:   conf,
	}
	return &r, nil
}

func (r RancherV3) ToWrapper() Wrapper {
	return Wrapper{
		Provider: r.Provider,
		Operator: r.Operator,
	}
}

func (r *RancherV3) ClusterType() string {
	return ProviderRancher
}

func (r *RancherV3) InitCloudProvider(operator clustermanage.Operator, provider v1.CloudProvider) (clustermanage.CloudProvider, error) {
	return NewRancherV3(operator, provider)
}

// Sync keep cluster consistent in kc and rancher.
/*
1. list all rancher clusters
2. import all rancher cluster to kc
	import cluster
	sync node
3. delete legacy rancher cluster from kc
*/
func (r RancherV3) Sync(ctx context.Context) error {
	log := logger.FromContext(ctx)
	log.Debugf("beginning sync provider %s", r.Provider.Name)

	// 1. list all rancher clusters
	clusterIDs, err := r.ToWrapper().ClusterIDs(ctx)
	if err != nil {
		return errors.WithMessagef(err, "[%s] list rancher cluster ids", r.Provider.Name)
	}
	log.Debugf("wait for sync provider %s's cluster [%v]", r.Provider.Name, clusterIDs)

	// 2.import all rancher cluster to kc
	if err = r.importClusterToKC(ctx, clusterIDs); err != nil {
		return errors.WithMessagef(err, "import provider %s's all cluster to kc", r.Provider.Name)
	}
	log.Debugf("wait for delete provider %s's legacy cluster,current clusterIDs:[%v]", r.Provider.Name, clusterIDs)

	// 	3.delete legacy rancher cluster from kc
	if err = r.deleteLegacyCluster(ctx, clusterIDs); err != nil {
		return errors.WithMessagef(err, "delete provider %s's legacy cluster from kc", r.Provider.Name)
	}
	log.Debugf("sync provider %s successfully", r.Provider.Name)

	return nil
}

// Cleanup clean provider's all cluster & node in kc.
/*
1.list kc clusters
2.drain cluster's node
3.delete cluster
*/
func (r RancherV3) Cleanup(ctx context.Context) error {
	log := logger.FromContext(ctx)
	log.Debugf("beginning cleanup provider %s", r.Provider.Name)

	// 1.list kc clusters
	clusters, err := r.listKCCluster(r.Provider.Name)
	if err != nil {
		return errors.WithMessage(err, "load cluster ids")
	}
	log.Debugf("[cleanup] provider %s's cluster:%v", r.Provider.Name, clusters)

	deployConfig, err := r.getDeployConfig()
	if err != nil {
		return errors.WithMessage(err, "get deploy config")
	}

	for _, clu := range clusters {
		// 2. drain nodes first
		nodes, err := r.listKCNode(clu.Name)
		if err != nil {
			return errors.WithMessagef(err, "load cluster %s's node", clu.Name)
		}
		log.Debugf("[cleanup] drain cluster %s's node count:%#v", clu.Name, len(nodes))

		for _, node := range nodes {
			log.Debugf("[cleanup] drain cluster %s's nodes:%v", clu.Name, node.Name)
			ssh := r.ssh()
			// origin node use deployConfig.ssh,others use provider.ssh
			if _, isOriginNode := node.Annotations[common.AnnotationOriginNode]; isOriginNode {
				ssh = deployConfig.SSHConfig
			}
			if err = r.drainAgent(node.Status.Ipv4DefaultIP, node.Name, ssh); err != nil {
				return errors.WithMessagef(err, "drain cluster %s's node %s", clu.Name, node.Name)
			}
		}
		// 3. delete cluster
		// NOTE: must delete cluster after drain node
		// because cluster controller will remove node's label,if delete cluster first
		// then,the note will lost connection about this rancher cluster,case we can't drain it.
		if err = r.Operator.ClusterWriter.DeleteCluster(ctx, clu.Name); err != nil {
			return errors.WithMessagef(err, "delete cluster  %s", clu.Name)
		}
	}

	log.Debugf("cleanup provider %s successfully", r.Provider.Name)
	return nil
}

func rawToConfig(config runtime.RawExtension) (Config, error) {
	var rancher Config
	data, err := config.MarshalJSON()
	if err != nil {
		return rancher, err
	}
	if err = json.Unmarshal(data, &rancher); err != nil {
		return rancher, err
	}
	return rancher, nil
}

func (r RancherV3) importClusterToKC(ctx context.Context, clusterIDs []string) error {
	log := logger.FromContext(ctx)
	log.Debugf("beginning import provider %s's cluster [%s] to kc", r.Provider.Name, clusterIDs)

	for _, clusterID := range clusterIDs {
		// import cluster to kc
		clu, err := r.ToWrapper().ClusterInfo(ctx, clusterID)
		if err != nil {
			return errors.WithMessagef(err, "get rancher cluster %s's info", clusterID)
		}
		oldClu, err := r.Operator.ClusterLister.Get(clu.Name)
		if err == nil && oldClu != nil {
			// same name cluster check
			if oldClu.Labels[common.LabelClusterProviderName] != r.Provider.Name {
				return fmt.Errorf("cluster %s already exist in kc,please edit the cluster name in rancher", clu.Name)
			}
		}

		// cluster controller will delete node's label,so we must query nodes before delete cluster
		kcNodes, err := r.listKCNode(clu.Name)
		if err != nil {
			return errors.WithMessagef(err, "list cluster %s's node in kc", clu.Name)
		}
		// sync cluster's node first
		if err = r.syncNode(ctx, clusterID, clu.Name, kcNodes); err != nil {
			return errors.WithMessagef(err, "sync cluster %s's node", clusterID)
		}

		// then,import cluster
		oldClu, err = r.Operator.ClusterLister.Get(clu.Name)
		if err != nil {
			// create,if not exists
			if apimachineryErrors.IsNotFound(err) {
				// maybe rancher cluster name changed,try to match clusterID
				cluster, err := r.getKCClusterByRancherID(r.Provider.Name, clusterID)
				if err != nil {
					return err
				}
				if cluster != nil { // because can edit cluster's name,so if found cluster by id but name changed,we need delete it,then crate a new one with new name
					if err = r.Operator.ClusterWriter.DeleteCluster(context.TODO(), cluster.Name); err != nil {
						return err
					}
				}
				if _, err = r.Operator.ClusterWriter.CreateCluster(context.TODO(), clu); err != nil {
					return errors.WithMessagef(err, "create cluster %s", clu.Name)
				}
			} else {
				return errors.WithMessagef(err, "check cluster %s exits", clu.Name)
			}
		} else {
			// update,if exists
			// get resourceVersion for update
			clu.ObjectMeta.ResourceVersion = oldClu.ObjectMeta.ResourceVersion
			// merge labels
			clu.ObjectMeta.Labels = mergeLabels(oldClu.Labels, clu.Labels)
			clu.Annotations[common.AnnotationDescription] = oldClu.Annotations[common.AnnotationDescription]
			_, err = r.Operator.ClusterWriter.UpdateCluster(context.TODO(), clu)
			if err != nil {
				return errors.WithMessagef(err, "update cluster %s", clu.Name)
			}
		}
	}

	log.Debugf("import provider %s's cluster [%v] successfully", r.Provider.Name, clusterIDs)
	return nil
}

func (r RancherV3) deleteLegacyCluster(ctx context.Context, clusterIDs []string) error {
	log := logger.FromContext(ctx)
	log.Debugf("beginning delete provider %s's legacy cluster", r.Provider.Name)

	allClusters, err := r.listKCCluster(r.Provider.Name)
	if err != nil {
		return errors.WithMessagef(err, "listKCCluster")
	}

	for _, clu := range allClusters {
		rancherID := clu.Annotations[common.AnnotationProviderClusterID]
		if !sets.NewString(clusterIDs...).Has(rancherID) {
			// NOTE: cluster controller will delete node's label,so we must query nodes before delete cluster
			kcNodes, err := r.listKCNode(clu.Name)
			if err != nil {
				return errors.WithMessagef(err, "list cluster %s's node in kc", clu.Name)
			}
			log.Debugf("listKCNode clusterName:%s node count:%v\n", clu.Name, len(kcNodes))
			// in kc but not in rancher,it's a legacy cluster,we need delete it.
			if err = r.Operator.ClusterWriter.DeleteCluster(context.TODO(), clu.Name); err != nil {
				return errors.WithMessagef(err, "delete legacy cluster %s", clu.Name)
			}
			// sync cluster's node again after delete
			if err = r.syncNode(ctx, rancherID, clu.Name, kcNodes); err != nil {
				return errors.WithMessagef(err, "sync legacy cluster %s' node", rancherID)
			}
		}
	}

	log.Debugf("delete legacy cluster successfully", clusterIDs)
	return nil
}

func (r RancherV3) ssh() *sshutils.SSH {
	ssh := &sshutils.SSH{
		User:              r.Provider.SSH.User,
		Port:              r.Provider.SSH.Port,
		ConnectionTimeout: nil,
	}
	if r.Provider.SSH.PrivateKey != "" {
		decodeString, _ := base64.StdEncoding.DecodeString(r.Provider.SSH.PrivateKey)
		ssh.PrivateKey = string(decodeString)
	}

	if r.Provider.SSH.Password != "" {
		decodeString, _ := base64.StdEncoding.DecodeString(r.Provider.SSH.Password)
		ssh.Password = string(decodeString)
	}

	if r.Provider.SSH.PrivateKeyPassword != "" {
		decodeString, _ := base64.StdEncoding.DecodeString(r.Provider.SSH.PrivateKeyPassword)
		ssh.PkPassword = string(decodeString)
	}

	return ssh
}

func (r RancherV3) listKCCluster(provider string) ([]*v1.Cluster, error) {
	requirement, err := labels.NewRequirement(common.LabelClusterProviderName, selection.Equals, []string{provider})
	if err != nil {
		return nil, err
	}
	return r.Operator.ClusterLister.List(labels.NewSelector().Add(*requirement))
}

func (r RancherV3) getKCClusterByRancherID(provider, rancherID string) (*v1.Cluster, error) {
	cluster, err := r.listKCCluster(provider)
	if err != nil {
		return nil, err
	}
	for _, v := range cluster {
		if v.Annotations[common.AnnotationProviderClusterID] == rancherID {
			return v, nil
		}
	}
	return nil, nil
}

func (r RancherV3) listKCNode(clusterName string) ([]*v1.Node, error) {
	requirement, err := labels.NewRequirement(common.LabelClusterName, selection.Equals, []string{clusterName})
	if err != nil {
		return nil, err
	}
	return r.Operator.NodeLister.List(labels.NewSelector().Add(*requirement))
}

// syncNode keep cluster's node consistent in kc and rancher.
/*
1.list cluster's nodes
2.sync node
	if not exists, means it's a new node,we need deploy kc-agent to it.
	if node already exists,do nothing,but if add origin to rancher cluster,will match this case,we need check node's label.
3.delete legacy node from kc: in kc but not in rancher,it's a legacy node,we need delete it.
	not origin node,drain it
	origin node,just clean label&annotations to mark node free
*/
func (r RancherV3) syncNode(ctx context.Context, clusterID, clusterName string, kcNodes []*v1.Node) error {
	log := logger.FromContext(ctx)
	log.Debugf("beginning sync cluster %s's node", clusterName)

	// 1.list cluster's nodes
	rancherNodes, err := r.ToWrapper().ClusterNodes(context.TODO(), clusterID)
	if err != nil {
		return errors.WithMessagef(err, "list rancher cluster %s's nodes", clusterID)
	}
	log.Debugf("rancher cluster %s's all node count [%v]", clusterID, len(rancherNodes.Data))

	// 2.sync node
	for i, node := range rancherNodes.Data {
		log.Debugf("rancher cluster %s's node%v %s", clusterID, i, node.NodeName)
		// use rancher node's uuid as kc node's agentID
		agentID, err := r.ToWrapper().getNodeID(node)
		if err != nil {
			return errors.WithMessage(err, "sync node transfer rancher node id to kc node id")
		}
		// if not exists, means it's a new node,we need deploy kc-agent to it.
		ip := node.IPAddress
		if node.ExternalIPAddress != "" {
			ip = node.ExternalIPAddress // use externalIP first
		}
		if _, err = r.Operator.NodeLister.Get(agentID); err != nil {
			if apimachineryErrors.IsNotFound(err) {
				if err = r.deployKCAgent(ctx, agentID, ip); err != nil {
					return errors.WithMessagef(err, "deploy kc-agent to node %s", ip)
				}
			} else {
				return errors.WithMessagef(err, "check kc node %s", agentID)
			}
		}

		// TODO optimization,use goroutine + channel to concurrency deploy
		// add labels to this node
		if err = r.markNodeRoles(ctx, agentID, clusterName, node); err != nil {
			return errors.WithMessagef(err, "mark node role agent:%s ip:%s", agentID, ip)
		}
	}

	// 3.delete legacy node from kc
	rancherNodeIDs := sets.NewString()
	for _, node := range rancherNodes.Data {
		agentID, err := r.ToWrapper().getNodeID(node)
		if err != nil {
			return errors.WithMessage(err, "delete legacy node transfer rancher node id to kc node id")
		}
		rancherNodeIDs.Insert(agentID)
	}

	for _, node := range kcNodes {
		// in kc but not in rancher,it's a legacy node,we need delete it.
		if !rancherNodeIDs.Has(node.Name) {
			ssh := r.ssh()
			// don't drain origin node
			if _, isOriginNode := node.Annotations[common.AnnotationOriginNode]; isOriginNode {
				// mark to free
				if err = r.markToFree(ctx, node); err != nil {
					return errors.WithMessagef(err, "mark node to free")
				}
				log.Infof("sync cluster %s's node,mark origin node %s to free,because not in rancher", clusterName, node.Name)
				continue
			}
			err = r.drainAgent(node.Status.Ipv4DefaultIP, node.Name, ssh)
			if err != nil {
				return errors.WithMessagef(err, "drain node %s", node.Name)
			}
			log.Infof("sync cluster %s's node,drain node %s,because not in rancher", clusterName, node.Name)
		}
	}

	log.Debugf("sync cluster %s's node successfully", clusterName)
	return nil
}

func (r RancherV3) markToFree(ctx context.Context, node *v1.Node) error {
	delete(node.Labels, common.LabelNodeRole)
	delete(node.Labels, common.LabelClusterName)
	delete(node.Annotations, common.AnnotationProviderNodeID)
	delete(node.Annotations, common.AnnotationOriginNode)
	_, err := r.Operator.NodeWriter.UpdateNode(ctx, node)
	return err
}

func (r RancherV3) deployKCAgent(ctx context.Context, agentID, ip string) error {
	metadata := options.Metadata{Region: r.Provider.Region, AgentID: agentID}
	err := r.doDeploy(ctx, ip, metadata)
	if err != nil {
		return err
	}
	deployConfig, err := r.getDeployConfig()
	if err != nil {
		return errors.WithMessage(err, "getDeployConfig")
	}
	deployConfig.Agents.Add(ip, metadata)
	if err = r.updateDeployConfig(deployConfig); err != nil {
		return err
	}
	return err
}

func (r RancherV3) doDeploy(ctx context.Context, ip string, metadata options.Metadata) error {
	log := logger.FromContext(ctx)
	log.Debugf("beginning deploy kc agent to node agent:%s ip:%s", metadata.AgentID, ip)

	// 1.download kc-agent binary from kc-server & get certs from configmap.
	deployConfig, err := r.getDeployConfig()
	if err != nil {
		return errors.WithMessage(err, "getDeployConfig")
	}
	// wget http://192.168.10.123:8081/kc/kubeclipper-agent
	url := fmt.Sprintf("http://%s:%v/kc/kubeclipper-agent", deployConfig.ServerIPs[0], deployConfig.StaticServerPort)
	cmdList := []string{
		"systemctl stop kc-agent || true",
		fmt.Sprintf("curl %s -o /usr/local/bin/kubeclipper-agent", url),
		"chmod +x /usr/local/bin/kubeclipper-agent",
	}

	for _, cmd := range cmdList {
		ret, err := sshutils.SSHCmdWithSudo(r.ssh(), ip, cmd)
		if err != nil {
			return errors.WithMessagef(err, "run cmd [%s] on node [%s]", cmd, ip)
		}
		if err = ret.Error(); err != nil {
			return errors.WithMessage(err, ret.String())
		}
	}

	ca, cliCert, cliKey, err := r.gerCerts()
	if err != nil {
		return errors.WithMessage(err, "gerCerts from kc configmap")
	}
	destCa := filepath.Join(options.DefaultKcAgentConfigPath, options.DefaultCaPath, "ca.crt")
	destCert := filepath.Join(options.DefaultKcAgentConfigPath, options.DefaultNatsPKIPath, "kc-server-nats-client.crt")
	destKey := filepath.Join(options.DefaultKcAgentConfigPath, options.DefaultNatsPKIPath, "kc-server-nats-client.key")
	cmds := []string{
		"mkdir -p /etc/kubeclipper-agent/pki/nats",
		sshutils.WrapEcho(string(ca), destCa),
		sshutils.WrapEcho(string(cliCert), destCert),
		sshutils.WrapEcho(string(cliKey), destKey),
	}

	for _, cmd := range cmds {
		ret, err := sshutils.SSHCmdWithSudo(r.ssh(), ip, cmd)
		if err != nil {
			return errors.WithMessagef(err, "run %s cmd", cmd)
		}
		if err = ret.Error(); err != nil {
			return errors.WithMessage(err, ret.String())
		}
	}

	// 2. generate kubeclipper-agent.yaml、systemd conf,then start kc-agent
	agentConfig, err := deployConfig.GetKcAgentConfigTemplateContent(metadata)
	if err != nil {
		return errors.WithMessage(err, "GetKcAgentConfigTemplateContent")
	}
	cmdList = []string{
		sshutils.WrapEcho(config.KcAgentService, "/usr/lib/systemd/system/kc-agent.service"),
		"mkdir -pv /etc/kubeclipper-agent",
		sshutils.WrapEcho(agentConfig, "/etc/kubeclipper-agent/kubeclipper-agent.yaml"),
		"systemctl daemon-reload && systemctl enable kc-agent && systemctl restart kc-agent",
	}
	for _, cmd := range cmdList {
		ret, err := sshutils.SSHCmdWithSudo(r.ssh(), ip, cmd)
		if err != nil {
			return errors.WithMessagef(err, "run %s cmd", cmd)
		}
		if err = ret.Error(); err != nil {
			return errors.WithMessage(err, ret.String())
		}
	}

	log.Debugf("deploy kc agent to node agent:%s ip:%s successfully", metadata.AgentID, ip)
	return nil
}

// drainAgent remote kc-agent for node,and delete node from kc-server
func (r RancherV3) drainAgent(nodeIP, agentID string, ssh *sshutils.SSH) error {
	// 1. remove agent
	cmdList := []string{
		"systemctl disable kc-agent --now || true", // 	// disable agent service
		"rm -rf /usr/local/bin/kubeclipper-agent /etc/kubeclipper-agent /usr/lib/systemd/system/kc-agent.service ", // remove agent files
	}

	for _, cmd := range cmdList {
		ret, err := sshutils.SSHCmdWithSudo(ssh, nodeIP, cmd)
		if err != nil {
			return errors.WithMessagef(err, "run cmd %s on %s failed", cmd, nodeIP)
		}
		if err = ret.Error(); err != nil {
			return errors.WithMessage(err, ret.String())
		}
	}

	// 2. delete from etcd
	err := r.Operator.NodeWriter.DeleteNode(context.TODO(), agentID)
	if err != nil {
		return errors.WithMessagef(err, "delete node %s failed", agentID)
	}

	// 3.update online deploy config
	deployConfig, err := r.getDeployConfig()
	if err != nil {
		return err
	}
	if deployConfig.Agents.ExistsByID(agentID) {
		deployConfig.Agents.Delete(agentID)
		if err = r.updateDeployConfig(deployConfig); err != nil {
			logger.Errorf("delete agent from deploy config failed: %v", err)
			return err
		}
	}

	return nil
}

func (r RancherV3) gerCerts() (ca, natsCliCert, natsCliKey []byte, err error) {
	kcca, err := r.Operator.ConfigmapLister.Get("kc-ca")
	if err != nil {
		return nil, nil, nil, err
	}
	nats, err := r.Operator.ConfigmapLister.Get("kc-nats")
	if err != nil {
		return nil, nil, nil, err
	}

	ca, err = base64.StdEncoding.DecodeString(kcca.Data["ca.crt"])
	if err != nil {
		return nil, nil, nil, err
	}
	natsCliCert, err = base64.StdEncoding.DecodeString(nats.Data["kc-server-nats-client.crt"])
	if err != nil {
		return nil, nil, nil, err
	}
	natsCliKey, err = base64.StdEncoding.DecodeString(nats.Data["kc-server-nats-client.key"])
	if err != nil {
		return nil, nil, nil, err
	}

	return ca, natsCliCert, natsCliKey, nil
}

func (r RancherV3) getDeployConfig() (*options.DeployConfig, error) {
	configMap, err := r.Operator.ConfigmapLister.Get(constatns.DeployConfigConfigMapName)
	if err != nil {
		return nil, err
	}

	var c options.DeployConfig
	err = yaml.Unmarshal([]byte(configMap.Data[constatns.DeployConfigConfigMapKey]), &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r RancherV3) updateDeployConfig(deployConfig *options.DeployConfig) error {
	deploy, err := r.Operator.ConfigmapLister.Get(constatns.DeployConfigConfigMapName)
	if err != nil {
		return fmt.Errorf("get deploy config failed: %v", err)
	}
	dcData, err := yaml.Marshal(deployConfig)
	if err != nil {
		return fmt.Errorf("deploy config marshal failed: %v", err)
	}
	deploy.Data[constatns.DeployConfigConfigMapKey] = string(dcData)
	_, err = r.Operator.ConfigmapWriter.UpdateConfigMap(context.TODO(), deploy)
	return err
}

func (r RancherV3) markNodeRoles(ctx context.Context, agentID, clusterName string, rNode Node) error {
	log := logger.FromContext(ctx)
	log.Debugf("beginning markNodeRoles clusterName:%s agentID:%s rancherNodeID :%s", clusterName, agentID, rNode.ID)

	// wait for kc-agent register node, set timeout as 15s
	return wait.Poll(time.Second, time.Second*15, func() (done bool, err error) {
		// 	1.check is node exits
		kcNode, err := r.Operator.NodeLister.Get(agentID)
		if err != nil {
			if apimachineryErrors.IsNotFound(err) {
				// if not found,maybe kc-agent not start,retry again
				return false, nil
			}
			return false, err
		}
		// 	2.add labels
		kcNode.Labels[common.LabelClusterProviderType] = ProviderRancher
		kcNode.Labels[common.LabelClusterProviderName] = r.Provider.Name
		if kcNode.Annotations == nil {
			kcNode.Annotations = make(map[string]string)
		}
		kcNode.Annotations[common.AnnotationProviderNodeID] = rNode.ID
		_, err = r.Operator.NodeWriter.UpdateNode(context.TODO(), kcNode)
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

func (r RancherV3) PreCheck(ctx context.Context) (bool, error) {
	client, err := NewRancherClient(r.Provider.Config)
	if err != nil {
		return false, errors.New("invalid provider config")
	}
	code, err := client.PreCheck(ctx)
	if err != nil {
		return false, err
	}
	switch code {
	case http.StatusNotFound:
		return false, errors.New("api endpoint wrong")
	case http.StatusUnauthorized:
		return false, errors.New("incorrect accessKey or secretKey")
	}
	return true, nil
}

func (r RancherV3) GetKubeConfig(ctx context.Context, clusterName string) (string, error) {
	cli, err := NewRancherClient(r.Provider.Config)
	if err != nil {
		return "", err
	}
	return cli.KubeConfig(clusterName)
}

func (r RancherV3) GetCertification(ctx context.Context, clusterName string) ([]v1.Certification, error) {
	cli, err := NewRancherClient(r.Provider.Config)
	if err != nil {
		return nil, err
	}
	rc, err := cli.GetCluster(ctx, clusterName)
	if err != nil {
		return nil, err
	}
	return ExtractCertifications(rc), nil
}
