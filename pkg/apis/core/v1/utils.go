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

package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/google/uuid"
	apimachineryErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/kubeclipper/kubeclipper/pkg/component"
	"github.com/kubeclipper/kubeclipper/pkg/component/kubesphere"
	"github.com/kubeclipper/kubeclipper/pkg/component/utils"
	"github.com/kubeclipper/kubeclipper/pkg/models/cluster"
	"github.com/kubeclipper/kubeclipper/pkg/query"

	"github.com/kubeclipper/kubeclipper/pkg/scheme/common"
	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
	"github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1/cri"
	"github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1/k8s"
	bs "github.com/kubeclipper/kubeclipper/pkg/simple/backupstore"
)

var (
	ErrNodesRegionDifferent = errors.New("nodes belongs to different region")
)

func reverseComponents(components []v1.Addon) {
	length := len(components)
	for i := 0; i < length/2; i++ {
		components[i], components[length-(i+1)] = components[length-(i+1)], components[i]
	}
}

func GetCriStep(ctx context.Context, c *v1.Cluster, action v1.StepAction, nodes []v1.StepNode) ([]v1.Step, error) {
	switch c.ContainerRuntime.Type {
	case v1.CRIDocker:
		r := cri.DockerRunnable{}
		err := r.InitStep(ctx, c, nodes)
		if err != nil {
			return nil, err
		}
		return r.GetActionSteps(action), nil
	case v1.CRIContainerd:
		r := cri.ContainerdRunnable{}
		err := r.InitStep(ctx, c, nodes)
		if err != nil {
			return nil, err
		}
		return r.GetActionSteps(action), nil
	}
	return nil, fmt.Errorf("%v type CRI is not supported", c.ContainerRuntime.Type)
}

func getK8sSteps(ctx context.Context, c *v1.Cluster, action v1.StepAction) ([]v1.Step, error) {
	runnable := k8s.Runnable(*c)

	return runnable.GetStep(ctx, action)
}

func getSteps(c component.Interface, action v1.StepAction) ([]v1.Step, error) {
	switch action {
	case v1.ActionInstall:
		return c.GetInstallSteps(), nil
	case v1.ActionUninstall:
		return c.GetUninstallSteps(), nil
	case v1.ActionUpgrade:
		return c.GetUpgradeSteps(), nil
	default:
		return nil, fmt.Errorf("unsupported step action %s", action)
	}
}

func ParseOperationFromCluster(cluOperator cluster.Operator, extraMetadata *component.ExtraMetadata, c *v1.Cluster, action v1.StepAction) (*v1.Operation, error) {
	var steps []v1.Step
	region := extraMetadata.Masters[0].Region
	if c.Labels == nil {
		c.Labels = map[string]string{
			common.LabelTopologyRegion: region,
		}
	}
	op := &v1.Operation{}
	op.Name = uuid.New().String()
	op.Labels = map[string]string{
		common.LabelClusterName:    c.Name,
		common.LabelTopologyRegion: region,
	}

	// Container runtime should be installed on all nodes.
	ctx := component.WithExtraMetadata(context.TODO(), *extraMetadata)
	stepNodes := utils.UnwrapNodeList(extraMetadata.GetAllNodes())
	cSteps, err := GetCriStep(ctx, c, action, stepNodes)
	if err != nil {
		return nil, err
	}

	// kubernetes
	k8sSteps, err := getK8sSteps(ctx, c, action)
	if err != nil {
		return nil, err
	}

	carr := make([]v1.Addon, len(c.Addons))
	copy(carr, c.Addons)
	if action == v1.ActionUninstall {
		// reverse order of the addons
		reverseComponents(carr)
	} else {
		steps = append(steps, cSteps...)
		steps = append(steps, k8sSteps...)
	}

	addonSteps, err := parseAddonStep(ctx, c, cluOperator, carr, action)
	if err != nil {
		return nil, err
	}
	steps = append(steps, addonSteps...)

	if action == v1.ActionUninstall {
		steps = append(steps, k8sSteps...)
		steps = append(steps, cSteps...)
	}

	op.Steps = steps
	return op, nil
}

func initComponentExtraCluster(ctx context.Context, cluOperator cluster.Operator, p component.Interface) error {
	cluNames := p.RequireExtraCluster()
	extraClulsterMeta := make(map[string]component.ExtraMetadata, len(cluNames))
	for _, cluName := range cluNames {
		if clu, err := cluOperator.GetClusterEx(ctx, cluName, "0"); err == nil {
			extra, err := GetClusterMetadata(ctx, cluOperator, clu, false)
			if err != nil {
				return err
			}
			extraClulsterMeta[cluName] = *extra
		} else {
			return err
		}
	}
	return p.CompleteWithExtraCluster(extraClulsterMeta)
}

func GetClusterMetadata(ctx context.Context, cluOperator cluster.Operator, c *v1.Cluster, skipNodeNotFound bool) (*component.ExtraMetadata, error) {
	meta := &component.ExtraMetadata{
		ClusterName:        c.Name,
		Offline:            c.Offline(),
		LocalRegistry:      c.LocalRegistry,
		CRI:                c.ContainerRuntime.Type,
		KubeVersion:        c.KubernetesVersion,
		KubeletDataDir:     c.Kubelet.RootDir,
		ControlPlaneStatus: c.Status.ControlPlaneHealth,
	}
	for _, addon := range c.Addons {
		if addon.Name == "kubesphere" {
			var cfg kubesphere.Kubesphere
			_ = json.Unmarshal(addon.Config.Raw, &cfg)
			meta.KsJwtSecret = cfg.JwtSecret
		}
		meta.Addons = append(meta.Addons, addon)
	}
	masters, err := GetNodeInfo(ctx, cluOperator, c.Masters, skipNodeNotFound)
	if err != nil {
		return nil, err
	}
	meta.Masters = append(meta.Masters, masters...)
	workers, err := GetNodeInfo(ctx, cluOperator, c.Workers, skipNodeNotFound)
	if err != nil {
		return nil, err
	}
	meta.Workers = append(meta.Workers, workers...)
	err = regionCheck(meta.Masters, meta.Workers)
	if err != nil {
		return nil, err
	}
	return meta, nil
}

func regionCheck(master, worker []component.Node) error {
	list := sets.NewString()
	for _, node := range master {
		list.Insert(node.Region)
	}
	for _, node := range worker {
		list.Insert(node.Region)
	}
	if list.Len() > 1 {
		return ErrNodesRegionDifferent
	}
	return nil
}

func GetNodeInfo(ctx context.Context, cluOperator cluster.Operator, nodes v1.WorkerNodeList, skipNodeNotFound bool) ([]component.Node, error) {
	var meta []component.Node
	for _, node := range nodes {
		n, err := cluOperator.GetNodeEx(ctx, node.ID, "0")
		if err != nil {
			if skipNodeNotFound && apimachineryErrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		item := component.Node{
			ID:       n.Name,
			IPv4:     n.Status.Ipv4DefaultIP,
			NodeIPv4: n.Status.NodeIpv4DefaultIP,
			Region:   n.Labels[common.LabelTopologyRegion],
			Hostname: n.Labels[common.LabelHostname],
			Role:     n.Labels[common.LabelNodeRole],
		}
		_, item.Disable = n.Labels[common.LabelNodeDisable]
		meta = append(meta, item)
	}

	return meta, nil
}

func ParseRecoverySteps(cluOperator cluster.Operator, c *v1.Cluster, b *v1.Backup, restoreDir string, action v1.StepAction) ([]v1.Step, error) {
	steps := make([]v1.Step, 0)

	q := query.New()
	q.LabelSelector = fmt.Sprintf("%s=%s", common.LabelClusterName, c.Name)
	nodeList, err := cluOperator.ListNodes(context.TODO(), q)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0)
	ips := make([]string, 0)
	var masters, workers []component.Node
	for _, node := range nodeList.Items {
		if node.Labels[common.LabelNodeRole] != k8s.NodeRoleMaster {
			workers = append(workers, component.Node{
				ID:       node.Name,
				IPv4:     node.Status.Ipv4DefaultIP,
				NodeIPv4: node.Status.NodeIpv4DefaultIP,
				Hostname: node.Status.NodeInfo.Hostname,
			})
			continue
		}
		names = append(names, node.Status.NodeInfo.Hostname)
		ips = append(ips, node.Status.Ipv4DefaultIP)
		masters = append(masters, component.Node{
			ID:       node.Name,
			IPv4:     node.Status.Ipv4DefaultIP,
			NodeIPv4: node.Status.NodeIpv4DefaultIP,
			Hostname: node.Status.NodeInfo.Hostname,
		})
	}

	bp, err := cluOperator.GetBackupPoint(context.TODO(), b.BackupPointName, "0")
	if err != nil {
		return nil, err
	}

	recoveryStep, err := getRecoveryStep(c, bp, b, restoreDir, masters, workers, names, ips, action)
	if err != nil {
		return nil, err
	}

	steps = append(steps, recoveryStep...)

	return steps, nil
}

func getRecoveryStep(c *v1.Cluster, bp *v1.BackupPoint, b *v1.Backup, restoreDir string, masters, workers []component.Node, nodeNames, nodeIPs []string, action v1.StepAction) (steps []v1.Step, err error) {
	meta := component.ExtraMetadata{
		ClusterName:        c.Name,
		Masters:            masters,
		Workers:            workers,
		CNI:                c.CNI.Type,
		CNINamespace:       c.CNI.Namespace,
		ControlPlaneStatus: c.Status.ControlPlaneHealth,
	}
	ctx := component.WithExtraMetadata(context.TODO(), meta)

	f := k8s.FileDir{
		EtcdDataDir:    c.Etcd.DataDir,
		ManifestsYaml:  k8s.KubeManifestsDir,
		TmpEtcdDataDir: filepath.Join(restoreDir, "etcd"),
		TmpStaticYaml:  filepath.Join(restoreDir, "manifests"),
	}

	r := k8s.Recovery{
		StoreType:      bp.StorageType,
		RestoreDir:     restoreDir,
		BackupFileName: b.Status.FileName,
		NodeNameList:   nodeNames,
		NodeIPList:     nodeIPs,
		BackupFileSize: b.Status.BackupFileSize,
		BackupFileMD5:  b.Status.BackupFileMD5,
		FileDir:        f,
	}

	switch bp.StorageType {
	case bs.FSStorage:
		r.BackupPointRootDir = bp.FsConfig.BackupRootDir
	case bs.S3Storage:
		r.AccessKeyID = bp.S3Config.AccessKeyID
		r.AccessKeySecret = bp.S3Config.AccessKeySecret
		r.Bucket = bp.S3Config.Bucket
		r.Endpoint = bp.S3Config.Endpoint
	}

	err = r.InitSteps(ctx)
	if err != nil {
		return nil, err
	}

	switch action {
	case v1.ActionInstall:
		return r.GetInstallSteps(), nil
	}
	return nil, nil
}

// parseOperationFromComponent parse operation instance from component

func ParseOperationFromComponent(ctx context.Context, cluOperator cluster.Operator, extraMetadata *component.ExtraMetadata, addons []v1.Addon, c *v1.Cluster, action v1.StepAction) (*v1.Operation, error) {
	var err error
	op := &v1.Operation{}
	op.Name = uuid.New().String()
	op.Labels = map[string]string{
		common.LabelClusterName:    c.Name,
		common.LabelTopologyRegion: extraMetadata.Masters[0].Region,
	}
	// with extra meta data
	ctx = component.WithExtraMetadata(ctx, *extraMetadata)
	op.Steps, err = parseAddonStep(ctx, c, cluOperator, addons, action)
	if err != nil {
		return nil, err
	}
	return op, nil
}

func ParseActBackupSteps(cluOperator cluster.Operator, c *v1.Cluster, b *v1.Backup, action v1.StepAction) ([]v1.Step, error) {
	steps := make([]v1.Step, 0)

	q := query.New()
	q.LabelSelector = fmt.Sprintf("%s=%s", common.LabelClusterName, c.Name)

	bp, err := cluOperator.GetBackupPointEx(context.TODO(), b.BackupPointName, "0")
	if err != nil {
		return nil, err
	}
	pNode, err := cluOperator.GetNodeEx(context.TODO(), b.PreferredNode, "0")
	if err != nil {
		return nil, err
	}
	actBackupStep, err := getActBackupStep(c, b, bp, pNode, action)
	if err != nil {
		return nil, err
	}

	steps = append(steps, actBackupStep...)

	return steps, nil
}

func getActBackupStep(c *v1.Cluster, b *v1.Backup, bp *v1.BackupPoint, pNode *v1.Node, action v1.StepAction) (steps []v1.Step, err error) {
	var actBackup *k8s.ActBackup
	meta := component.ExtraMetadata{
		ClusterName: c.Name,
	}
	meta.Masters = []component.Node{{
		ID:       b.PreferredNode, // the preferred node is used by default
		IPv4:     pNode.Status.Ipv4DefaultIP,
		NodeIPv4: pNode.Status.NodeIpv4DefaultIP,
		Hostname: pNode.Status.NodeInfo.Hostname,
	}}
	ctx := component.WithExtraMetadata(context.TODO(), meta)

	switch bp.StorageType {
	case bs.S3Storage:
		actBackup = &k8s.ActBackup{
			StoreType:       bp.StorageType,
			BackupFileName:  b.Status.FileName,
			AccessKeyID:     bp.S3Config.AccessKeyID,
			AccessKeySecret: bp.S3Config.AccessKeySecret,
			Bucket:          bp.S3Config.Bucket,
			Endpoint:        bp.S3Config.Endpoint,
		}
	case bs.FSStorage:
		actBackup = &k8s.ActBackup{
			StoreType:          bp.StorageType,
			BackupFileName:     b.Status.FileName,
			BackupPointRootDir: bp.FsConfig.BackupRootDir,
		}
	}

	if err = actBackup.InitSteps(ctx); err != nil {
		return
	}

	return actBackup.GetStep(action), nil
}

func ParseUpdateCertOperation(clu *v1.Cluster, extraMetadata *component.ExtraMetadata) (*v1.Operation, error) {
	cert := &k8s.Certification{}
	op := &v1.Operation{}
	nodes := utils.UnwrapNodeList(extraMetadata.Masters)
	op.Steps, _ = cert.InstallSteps(clu, nodes)
	return op, nil
}

func CheckBackupPointInUse(backups *v1.BackupList, name string) bool {
	for _, item := range backups.Items {
		if item.BackupPointName == name {
			return true
		}
	}
	return false
}

func MarkToOriginNode(ctx context.Context, operator cluster.Operator, kcNodeID string) (*v1.Node, error) {
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

func parseAddonStep(ctx context.Context, clu *v1.Cluster, cluOperator cluster.Operator, addons []v1.Addon, action v1.StepAction) ([]v1.Step, error) {
	var steps []v1.Step
	registry := sets.NewString(clu.ContainerRuntime.InsecureRegistry...)
	for _, comp := range addons {
		cInterface, ok := component.Load(fmt.Sprintf(component.RegisterFormat, comp.Name, comp.Version))
		if !ok {
			continue
		}
		instance := cInterface.NewInstance()
		if err := json.Unmarshal(comp.Config.Raw, instance); err != nil {
			return []v1.Step{}, err
		}
		newComp, ok := instance.(component.Interface)
		if !ok {
			continue
		}
		if m := newComp.GetImageRepoMirror(); m != "" {
			if !registry.Has(m) {
				registry.Insert(m)
			}
		}
		if err := initComponentExtraCluster(ctx, cluOperator, newComp); err != nil {
			return []v1.Step{}, err
		}
		if err := newComp.Validate(); err != nil {
			return []v1.Step{}, err
		}
		if err := newComp.InitSteps(ctx); err != nil {
			return []v1.Step{}, err
		}
		s, err := getSteps(newComp, action)
		if err != nil {
			return []v1.Step{}, err
		}
		steps = append(steps, s...)
	}
	clu.ContainerRuntime.InsecureRegistry = registry.List()
	return steps, nil
}
