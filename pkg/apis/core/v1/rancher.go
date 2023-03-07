package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubeclipper/kubeclipper/pkg/clustermanage/rancher"
	"github.com/kubeclipper/kubeclipper/pkg/component"
	"github.com/kubeclipper/kubeclipper/pkg/logger"
	"github.com/kubeclipper/kubeclipper/pkg/models/cluster"
	"github.com/kubeclipper/kubeclipper/pkg/scheme/common"
	corev1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
	"github.com/kubeclipper/kubeclipper/pkg/utils/strutil"
)

func MakeOperationRancher(extra component.ExtraMetadata, p *PatchNodes, cluster *corev1.Cluster, operator cluster.Operator) (*corev1.Operation, error) {
	switch p.Role {
	case common.NodeRoleMaster:
		return nil, fmt.Errorf("no support add or remove master node opertion")
	case common.NodeRoleWorker:
		return makeWorkerOperationRancher(extra, p, cluster, operator)
	default:
		return nil, ErrInvalidNodesRole
	}
}

func makeWorkerOperationRancher(extra component.ExtraMetadata, p *PatchNodes, cluster *corev1.Cluster, operator cluster.Operator) (*corev1.Operation, error) {
	// no node need to be operated
	if len(p.Nodes) == 0 {
		return nil, ErrZeroNode
	}
	providerName := cluster.Labels[common.LabelClusterProviderName]
	// make operation for adding worker nodes to cluster
	op := &corev1.Operation{}
	op.Name = uuid.New().String()
	op.Labels = map[string]string{
		common.LabelClusterName:         cluster.Name,
		common.LabelClusterProviderName: providerName,
	}
	ctx := context.TODO()
	ctx = component.WithExtraMetadata(ctx, extra)
	var stepNodes []corev1.StepNode
	workerIPs := extra.GetWorkerNodeIP()
	for _, nodeID := range p.Nodes.GetNodeIDs() {
		stepNode := corev1.StepNode{
			ID:       nodeID,
			IPv4:     workerIPs[nodeID],
			Hostname: extra.GetWorkerHostname(nodeID),
		}
		stepNodes = append(stepNodes, stepNode)
	}

	clusterID := cluster.Annotations[common.AnnotationProviderClusterID]
	provider, err := operator.GetCloudProvider(ctx, providerName)
	if err != nil {
		return nil, err
	}
	client, err := rancher.NewRancherClient(provider.Config)
	if err != nil {
		return nil, err
	}
	var action corev1.StepAction
	switch p.Operation {
	case NodesOperationAdd:
		// call rancher api get joinCmd
		// install docker on node
		// remove tmp files
		// run joinCmd
		// update node annotations when op successfully
		// add originNode annot on this node

		action = corev1.ActionInstall
		op.Labels[common.LabelOperationAction] = corev1.OperationAddNodes
		// get joinCmd
		m := make(map[string]string)
		for _, node := range p.Nodes {
			joinCmd, err := client.JoinNodeCmd(ctx, clusterID, node.ID, []string{rancher.WorkerRole})
			if err != nil {
				return nil, err
			}
			m[node.ID] = joinCmd
		}
		// use a fixed version
		cluster.ContainerRuntime = fixedCRIForRancher(cluster.ContainerRuntime)
		// container runtime
		steps, err := GetCriStep(ctx, cluster, action, stepNodes)
		if err != nil {
			return nil, err
		}
		op.Steps = append(op.Steps, steps...)

		// remove tmp files
		op.Steps = append(op.Steps, removeTemFiles(stepNodes, true))

		for _, node := range p.Nodes {
			joinCmd := m[node.ID]
			stepNode := corev1.StepNode{
				ID:       node.ID,
				IPv4:     workerIPs[node.ID],
				Hostname: extra.GetWorkerHostname(node.ID),
			}
			// run cmd on agent
			op.Steps = append(op.Steps, runCmd(joinCmd, "runJoinCmd", []corev1.StepNode{stepNode}, false, metav1.Duration{Duration: 5 * time.Minute}))

			// check install status
			agent, err := json.Marshal(&rancher.CheckInstall{})
			if err != nil {
				return nil, err
			}
			checkAgentInstallStep := corev1.Step{
				ID:         strutil.GetUUID(),
				Name:       "CheckInstall",
				Timeout:    metav1.Duration{Duration: 10 * time.Minute},
				ErrIgnore:  true,
				RetryTimes: 1,
				Nodes:      []corev1.StepNode{stepNode},
				Action:     corev1.ActionInstall,
				Commands: []corev1.Command{
					{
						Type:          corev1.CommandCustom,
						Identity:      fmt.Sprintf(component.RegisterStepKeyFormat, rancher.Name, rancher.Version, rancher.AgentCheckInstall),
						CustomCommand: agent,
					},
				},
			}
			op.Steps = append(op.Steps, checkAgentInstallStep)
		}

	case NodesOperationRemove:
		// caller rancher api get removeCmd
		// uninstall docker
		// remove tmp files
		// update node annotations when op successfully

		action = corev1.ActionUninstall
		op.Labels[common.LabelOperationAction] = corev1.OperationRemoveNodes

		// NOTE: caller rancher api to remove node,must process one node at per loop
		for _, node := range p.Nodes {
			kcNode, err := markToOriginNode(ctx, operator, node.ID)
			if err != nil {
				logger.Error("mark node to free", zap.String("id", kcNode.Name), zap.Error(err))
				continue
			}
			// if kc node's annotations not record rancher node id，we try to get from rancher api
			nodeID, err := getRancherNodeID(ctx, client, clusterID, *kcNode)
			if err != nil {
				logger.Error("get rancher node id", zap.String("id", kcNode.Name), zap.Error(err))
				continue
			}
			if err = client.RemoveNode(ctx, nodeID); err != nil {
				logger.Error("remove provider node", zap.String("kcID", kcNode.Name), zap.String("rancherID", nodeID), zap.Error(err))
				continue
			}
			// remove node role when called rancher remove api
			delete(kcNode.Labels, common.LabelNodeRole)
			delete(kcNode.Labels, common.LabelClusterName)
			kcNode, err = operator.UpdateNode(ctx, kcNode)
			if err != nil {
				logger.Error("remove node role", zap.String("id", kcNode.Name), zap.Error(err))
				continue
			}
			stepNode := corev1.StepNode{
				ID:       node.ID,
				IPv4:     workerIPs[node.ID],
				Hostname: extra.GetWorkerHostname(node.ID),
			}

			// container runtime
			// use a fixed version
			cluster.ContainerRuntime = fixedCRIForRancher(cluster.ContainerRuntime)
			steps, err := GetCriStep(ctx, cluster, action, []corev1.StepNode{stepNode})
			if err != nil {
				logger.Errorf("get cri step", zap.String("id", kcNode.Name), zap.Error(err))
				continue
			}
			for i := range steps {
				steps[i].ErrIgnore = true // when remove rancher node,all cri step can ignore
			}

			op.Steps = append(op.Steps, steps...)

			// remove tmp files
			op.Steps = append(op.Steps, removeTemFiles([]corev1.StepNode{stepNode}, true))
		}

		if len(op.Steps) == 0 {
			return op, errors.New("node are updating,please wait")
		}

	default:
		return nil, ErrInvalidNodesOperation
	}

	return op, nil
}

func removeTemFiles(stepNodes []corev1.StepNode, ignoreError bool) corev1.Step {
	cmd := "rm -rf /var/lib/etcd /etc/kubernetes"
	return runCmd(cmd, "removeTempFiles", stepNodes, ignoreError, metav1.Duration{Duration: 10 * time.Second})
}

// current just used a fixed version to scale rancher cluster's node
// TODO get cri version dynamic
func fixedCRIForRancher(cri corev1.ContainerRuntime) corev1.ContainerRuntime {
	if cri.Type == corev1.CRIDocker {
		cri.Version = "19.03.12"
	} else if cri.Type == corev1.CRIContainerd {
		cri.Version = "1.6.4"
	}
	return cri
}

func getRancherNodeID(ctx context.Context, client *rancher.Client, clusterID string, kcNode corev1.Node) (string, error) {
	// first use label[uuid] in kc
	nodeID, ok := kcNode.Annotations[common.AnnotationProviderNodeID]
	if ok {
		return nodeID, nil
	}
	logger.Warnf("node without annotation rancher node id", zap.String("id", kcNode.Name))

	// then use label[uuid] in rancher
	nodes, err := client.ClusterNodes(ctx, clusterID)
	if err != nil {
		return "", err
	}
	for _, v := range nodes.Data {
		if v.Labels[common.LabelNodeUUID] == kcNode.Name {
			return v.ID, nil
		}
	}
	logger.Warnf("node without label in rancher", zap.String("id", kcNode.Name))

	// last use ip match
	for _, v := range nodes.Data {
		if v.IPAddress == kcNode.Status.Ipv4DefaultIP {
			return v.ID, nil
		}
	}
	return "", errors.New("get rancher node failed")
}

func markToOriginNode(ctx context.Context, operator cluster.Operator, kcNodeID string) (*corev1.Node, error) {
	node, err := operator.GetNode(ctx, kcNodeID)
	if err != nil {
		return nil, err
	}
	if node.Annotations == nil {
		node.Annotations = make(map[string]string)
	}
	node.Annotations[common.AnnotationOriginNode] = "true"
	return operator.UpdateNode(ctx, node)
}

func runCmd(cmd, name string, nodes []corev1.StepNode, ignore bool, timeout metav1.Duration) corev1.Step {
	return corev1.Step{
		ID:         strutil.GetUUID(),
		Name:       name,
		Timeout:    timeout,
		ErrIgnore:  ignore,
		RetryTimes: 1,
		Nodes:      nodes,
		Action:     corev1.ActionInstall,
		Commands: []corev1.Command{
			{
				Type:         corev1.CommandShell,
				ShellCommand: []string{"bash", "-c", cmd},
			},
		},
	}
}
