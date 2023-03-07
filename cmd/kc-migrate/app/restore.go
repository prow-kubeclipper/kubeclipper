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

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubeclipper/kubeclipper/pkg/models/operation"
	"github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1/k8s"

	"github.com/kubeclipper/kubeclipper/cmd/kcctl/app/options"
	svcoptions "github.com/kubeclipper/kubeclipper/cmd/kubeclipper-server/app/options"
	"github.com/kubeclipper/kubeclipper/pkg/agent/config"
	pkglogger "github.com/kubeclipper/kubeclipper/pkg/logger"
	bs "github.com/kubeclipper/kubeclipper/pkg/simple/backupstore"
	"github.com/kubeclipper/kubeclipper/pkg/simple/client/natsio"
	"github.com/kubeclipper/kubeclipper/pkg/simple/downloader"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	apimachineryErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/kubeclipper/kubeclipper/pkg/cli/logger"
	"github.com/kubeclipper/kubeclipper/pkg/models/cluster"
	"github.com/kubeclipper/kubeclipper/pkg/models/iam"
	"github.com/kubeclipper/kubeclipper/pkg/scheme/common"
	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
	"github.com/kubeclipper/kubeclipper/pkg/server"
	"github.com/kubeclipper/kubeclipper/pkg/server/registry"
	"github.com/kubeclipper/kubeclipper/pkg/utils/sshutils"
)

var (
	etcd431CaFile   = "/etc/kubeclipper-server/pki/ca.crt"
	etcd431CertFile = "/etc/kubeclipper-server/pki/etcd/kc-server-etcd-client.crt"
	etcd431KeyFile  = "/etc/kubeclipper-server/pki/etcd/kc-server-etcd-client.key"
)

func NewCmdRestore() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "restore",
		DisableFlagsInUseLine: true,
		Short:                 "restore kubeclipper 4.3.0 etcd data to 4.3.1",
		Long:                  "restore kubeclipper 4.3.0 etcd data to 4.3.1",
		Example:               "TODO..",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	cmd.AddCommand(NewCmdRestoreData())
	cmd.AddCommand(NewCmdRestoreConfig())
	return cmd
}

func NewCmdRestoreData() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "data",
		DisableFlagsInUseLine: true,
		Short:                 "restore kubeclipper 4.3.0 etcd data to 4.3.1",
		Long:                  "restore kubeclipper 4.3.0 etcd data to 4.3.1",
		Example:               "TODO..",
		Run: func(cmd *cobra.Command, args []string) {
			if !etcdCheck431() {
				return
			}

			if err := restoreEtcdData(); err != nil {
				logger.Error("restore etcd data failed", err)
				return
			}
			if err := upgradeData(); err != nil {
				logger.Error("update etcd data failed", err)
				return
			}
			logger.Info("all data restored")
		},
	}

	cmd.Flags().IntVar(&etcdClientPort, "etcd-port", etcdClientPort, "etcd client port")
	return cmd
}

func opServer(cmd string) error {
	var d options.DeployConfig
	d.Config = options.DefaultDeployConfigPath
	if err := d.Complete(); err != nil {
		return err
	}
	return sshutils.CmdBatchWithSudo(d.SSHConfig, d.ServerIPs, cmd, sshutils.DefaultWalk)
}

func NewCmdRestoreConfig() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "config",
		DisableFlagsInUseLine: true,
		Short:                 "restore kubeclipper 4.3.0 agent config to 4.3.1",
		Long:                  "restore kubeclipper 4.3.0 agent config to 4.3.1",
		Example:               "TODO..",
		Run: func(cmd *cobra.Command, args []string) {
			if !deployConfigCheck() {
				return
			}
			if err := restoreConfigFile(); err != nil {
				logger.Error("restore config file failed", err)
				return
			}
			if err := restartAgent(); err != nil {
				logger.Error("restart agent failed", err)
				return
			}
			logger.Info("all node config update")
		},
	}

	cmd.Flags().StringVar(&KcDeployConfig, "deploy-config", KcDeployConfig, "path to deploy-config.yaml")
	return cmd
}

func etcdCheck431() bool {
	logger.Info("etcd endpoint health check")
	err := sshutils.Cmd("/bin/sh", "-c", fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:%d --cacert=%s --cert=%s --key=%s endpoint health", etcdClientPort, etcd431CaFile, etcd431CertFile, etcd431KeyFile))
	if err != nil {
		logger.Error("etcd endpoint health check failed", err)
		return false
	}
	return true
}

func restoreEtcdData() error {
	if err := opServer("systemctl stop kc-server || true"); err != nil {
		return errors.WithMessage(err, "stop kc server")
	}
	defer func() {
		if err := opServer("systemctl start kc-server || true"); err != nil {
			logger.Error("failed to start kc server", err)
		}
	}()

	logger.Info("generate restore shell")
	err := sshutils.Cmd("mkdir", "-p", filepath.Dir(shRestoreData))
	if err != nil {
		return err
	}
	all := strings.ReplaceAll(shImport, "{{ endpoint }}", fmt.Sprintf("https://127.0.0.1:%v", etcdClientPort))
	all = strings.ReplaceAll(all, "{{ etcd-ca }}", etcd431CaFile)
	all = strings.ReplaceAll(all, "{{ etcd-cert }}", etcd431CertFile)
	all = strings.ReplaceAll(all, "{{ etcd-key }}", etcd431KeyFile)

	f, err := os.Create(shRestoreData)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(all)
	if err != nil {
		return err
	}
	logger.Info("run restore shell")
	return sshutils.Cmd("/bin/sh", shRestoreData)
}

func restoreConfigFile() error {
	var d options.DeployConfig
	d.Config = KcDeployConfig
	err := d.Complete()
	if err != nil {
		return err
	}

	logger.Info("merge kc-agent.yaml")
	for ip := range d.Agents {
		oldAgentConfig, err := readFile(d.SSHConfig, ip, backupFile(KcAgentConfig))
		if err != nil {
			return errors.WithMessagef(err, "[%s] read old  agent config", ip)
		}
		agentConfig, err := readFile(d.SSHConfig, ip, KcAgentConfig)
		if err != nil {
			return errors.WithMessagef(err, "[%s] read old  agent config", ip)
		}
		mergedConfig, err := mergeAgentConfig(oldAgentConfig, agentConfig)
		if err != nil {
			return errors.WithMessagef(err, "[%s] generate agent config", ip)
		}
		ret, err := sshutils.SSHCmdWithSudo(d.SSHConfig, ip, sshutils.WrapEcho(mergedConfig, KcAgentConfig))
		if err != nil {
			return errors.WithMessagef(err, "[%s] rewrite agent config", ip)
		}
		if err = ret.Error(); err != nil {
			return errors.WithMessagef(err, "[%s] rewrite agent config ret", ip)
		}
	}
	return nil
}

func readFile(ssh *sshutils.SSH, ip, file string) (string, error) {
	ret, err := sshutils.SSHCmdWithSudo(ssh, ip, fmt.Sprintf("cat %s", file))
	if err != nil {
		return "", err
	}
	if err = ret.Error(); err != nil {
		return "", err
	}
	return strings.TrimRight(ret.Stdout, "\n"), nil
}

func mergeAgentConfig(old, new string) (string, error) {
	// read old、new agent config,and merge
	var oa AgentConfig430
	if err := yaml.Unmarshal([]byte(old), &oa); err != nil {
		return "", err
	}

	var na config.Config
	if err := yaml.Unmarshal([]byte(new), &na); err != nil {
		return "", err
	}

	na.AgentID = oa.AgentID
	na.Metadata.Region = oa.Region
	na.OpLogOptions.Dir = oa.AOFOptions.Dir
	na.RegisterNode = oa.RegisterNode
	marshal, err := yaml.Marshal(na)
	if err != nil {
		return "", err
	}

	return string(marshal), nil
}

func restartAgent() error {
	var d options.DeployConfig
	d.Config = options.DefaultDeployConfigPath
	err := d.Complete()
	if err != nil {
		return err
	}
	for agent := range d.Agents {
		ret, err := sshutils.SSHCmdWithSudo(d.SSHConfig, agent, "systemctl enable kc-agent  && systemctl restart kc-agent")
		if err != nil {
			return errors.WithMessagef(err, "[%s]deploy kc agent failed due to %s", agent, err.Error())
		}
		if err = ret.Error(); err != nil {
			return errors.WithMessagef(err, "[%s]deploy kc agent failed due to %s", agent, err.Error())
		}
	}
	return nil
}

func upgradeData() error {
	logger.Info("transform 4.3.0 data to 4.3.1")
	opts := svcoptions.NewServerOptions()
	opts.EtcdOptions.Prefix = "/registry/kc-server"
	opts.EtcdOptions.ServerList = []string{fmt.Sprintf("%s:%d", "127.0.0.1", etcdClientPort)}
	opts.EtcdOptions.TrustedCAFile = etcd431CaFile
	opts.EtcdOptions.CertFile = etcd431CertFile
	opts.EtcdOptions.KeyFile = etcd431KeyFile
	storageFactory := registry.NewSharedStorageFactory(opts.CompleteEtcdOptions())
	opOperator := operation.NewOperationOperator(storageFactory.Operations())
	iamOperator := iam.NewOperator(storageFactory.Users(), storageFactory.GlobalRoles(),
		storageFactory.GlobalRoleBindings(), storageFactory.Tokens(), storageFactory.LoginRecords())
	clusterOperator := cluster.NewClusterOperator(storageFactory.Clusters(),
		storageFactory.Nodes(),
		storageFactory.Regions(),
		storageFactory.Backups(),
		storageFactory.Recoveries(),
		storageFactory.BackupPoints(),
		storageFactory.CronBackups(),
		storageFactory.DNSDomains(),
		storageFactory.Template(),
		storageFactory.CloudProvider(),
		storageFactory.Registry(),
	)

	// migrate role and cluster
	if err := migrateRole(iamOperator); err != nil {
		return errors.WithMessage(err, "migrate role")
	}
	if err := migrateCluster(clusterOperator); err != nil {
		return errors.WithMessage(err, "migrate cluster")
	}

	if err := migrateOperation(clusterOperator, opOperator); err != nil {
		return errors.WithMessage(err, "migrate operation")
	}

	if err := migrateBackup(clusterOperator); err != nil {
		return errors.WithMessage(err, "migrate backup")
	}

	return nil
}

func migrateRole(operator iam.Operator) error {
	logger.Info("migrateRole")

	for index := range server.Roles {
		role, err := operator.GetRole(context.TODO(), server.Roles[index].Name)
		if err != nil {
			if apimachineryErrors.IsNotFound(err) {
				if _, err = operator.CreateRole(context.TODO(), &server.Roles[index]); err != nil {
					return err
				}
				continue
			}
		}
		item := server.Roles[index]
		item.ResourceVersion = role.ResourceVersion
		if _, err = operator.UpdateRole(context.TODO(), &item); err != nil {
			return err
		}
	}
	return nil
}

func migrateCluster(op cluster.Operator) error {
	logger.Info("migrateCluster")

	ret, err := getCluster()
	if err != nil {
		return err
	}
	data := strings.TrimRight(ret.Stdout, "\n")
	split := strings.Split(data, "\n")
	for _, v := range split {
		if v == "" {
			continue
		}

		var c Cluster430
		if err = json.Unmarshal([]byte(v), &c); err != nil {
			return err
		}
		oldCluster, err := op.GetCluster(context.TODO(), c.Name)
		if err != nil {
			return err
		}
		item := &v1.Cluster{
			TypeMeta:   c.TypeMeta,
			ObjectMeta: c.ObjectMeta,
			// Provider:          v1.ProviderSpec{},
			LocalRegistry:     c.LocalRegistry,
			Masters:           c.Masters,
			Workers:           c.Workers,
			KubernetesVersion: c.KubernetesVersion,
			CertSANs:          c.CertSANs,
			KubeProxy:         v1.KubeProxy{},
			Etcd:              c.KubeComponents.Etcd,
			Kubelet:           v1.Kubelet{RootDir: "/var/lib/kubelet"},
			Networking: v1.Networking{
				IPFamily: "",
				Services: v1.NetworkRanges{
					CIDRBlocks: []string{c.Networking.ServiceSubnet},
				},
				Pods: v1.NetworkRanges{
					CIDRBlocks: []string{c.Networking.PodSubnet},
				},
				DNSDomain:     c.Networking.DNSDomain,
				ProxyMode:     "",
				WorkerNodeVip: c.WorkerNodeVip,
			},
			ContainerRuntime: v1.ContainerRuntime{
				Type:             c.ContainerRuntime.Type,
				Version:          "",
				DataRootDir:      "",
				InsecureRegistry: nil,
			},
			CNI: v1.CNI{
				LocalRegistry: c.KubeComponents.CNI.LocalRegistry,
				Type:          c.KubeComponents.CNI.Type,
				Version:       c.KubeComponents.CNI.Calico.Version,
				CriType:       c.ContainerRuntime.Type,
				Offline:       c.Offline,
				Namespace:     "kube-system",
				Calico: &v1.Calico{
					IPv4AutoDetection: c.KubeComponents.CNI.Calico.IPv4AutoDetection,
					IPv6AutoDetection: c.KubeComponents.CNI.Calico.IPv4AutoDetection,
					Mode:              c.KubeComponents.CNI.Calico.Mode,
					IPManger:          c.KubeComponents.CNI.Calico.IPManger,
					MTU:               c.KubeComponents.CNI.MTU,
				},
			},
			KubeConfig: c.KubeConfig,
			Addons:     c.Components,
			// Description:       "",
			Status: v1.ClusterStatus{
				Phase:               c.Status.Status,
				Versions:            v1.ClusterVersionsStatus{},
				ComponentConditions: c.Status.ComponentConditions,
				Certifications:      nil,
				ControlPlaneHealth:  []v1.ControlPlaneHealth{},
			},
		}
		addons := make([]v1.Addon, 0, len(c.Components))
		for _, component := range c.Components {
			addon := v1.Addon{
				Name:    component.Name,
				Version: component.Version,
				Config:  component.Config,
			}
			addons = append(addons, addon)
		}
		item.Addons = addons

		proxyMode := "iptables"
		if c.KubeComponents.KubeProxy.IPvs {
			proxyMode = "ipvs"
		}
		item.Networking.ProxyMode = proxyMode
		ipFamily := v1.IPFamilyIPv4
		if c.KubeComponents.CNI.Calico.DualStack {
			ipFamily = v1.IPFamilyDualStack
		}
		item.Networking.IPFamily = ipFamily

		if c.ContainerRuntime.Type == v1.CRIDocker {
			item.ContainerRuntime = v1.ContainerRuntime{
				Type:             c.ContainerRuntime.Type,
				Version:          c.ContainerRuntime.Docker.Version,
				DataRootDir:      c.ContainerRuntime.Docker.DataRootDir,
				InsecureRegistry: c.ContainerRuntime.Docker.InsecureRegistry,
			}
		} else if c.ContainerRuntime.Type == v1.CRIContainerd {
			item.ContainerRuntime = v1.ContainerRuntime{
				Type:             c.ContainerRuntime.Type,
				Version:          c.ContainerRuntime.Containerd.Version,
				DataRootDir:      c.ContainerRuntime.Containerd.DataRootDir,
				InsecureRegistry: c.ContainerRuntime.Containerd.InsecureRegistry,
			}
		}

		if item.Annotations == nil {
			item.Annotations = make(map[string]string)
		}
		item.Annotations[common.AnnotationOffline] = strconv.FormatBool(c.Offline)
		item.ResourceVersion = oldCluster.ResourceVersion
		if _, err = op.UpdateCluster(context.TODO(), item); err != nil {
			return err
		}
	}
	return nil
}

const (
	defaultBackupPoint = "default"
	defaultBackupPath  = "/opt/kc/backups"
)

func migrateBackup(clusterOp cluster.Operator) error {
	logger.Info("migrateBackup")

	var d options.DeployConfig
	d.Config = options.DefaultDeployConfigPath
	if err := d.Complete(); err != nil {
		return err
	}
	ret, err := getBackup()
	if err != nil {
		return errors.WithMessage(err, "get backup")
	}
	if err = ret.Error(); err != nil {
		return errors.WithMessage(err, "get backup cmd")
	}
	data := strings.TrimRight(ret.Stdout, "\n")
	split := strings.Split(data, "\n")

	if len(split) != 0 { // if exist backup,we need create a default backup point.
		if err = createDefaultBackupPoint(clusterOp); err != nil {
			return err
		}
	}

	for _, v := range split {
		if v == "" {
			continue
		}

		var b Backup430
		if err = json.Unmarshal([]byte(v), &b); err != nil {
			return err
		}

		node, err := clusterOp.GetNode(context.TODO(), b.PreferredNode)
		if err != nil {
			return errors.WithMessage(err, "get node")
		}
		host := node.Status.Ipv4DefaultIP
		info, err := getBackupFileInfo(d.SSHConfig, host, filepath.Join(defaultBackupPath, b.FileName))
		if err != nil {
			return errors.WithMessage(err, "getBackupFileInfo")
		}
		item := &v1.Backup{
			TypeMeta:   b.TypeMeta,
			ObjectMeta: b.ObjectMeta,
			Status: v1.BackupStatus{
				KubernetesVersion:   b.KubernetesVersion,
				FileName:            b.FileName,
				BackupFileSize:      info.BackupFileSize,
				BackupFileMD5:       info.BackupFileMD5,
				ClusterBackupStatus: b.Status,
			},
			ClusterNodes:    b.ClusterNodes,
			PreferredNode:   b.PreferredNode,
			BackupPointName: defaultBackupPoint,
		}
		if item.Annotations == nil {
			item.Annotations = make(map[string]string)
		}
		item.Annotations[common.AnnotationDescription] = b.Description
		// create a default backuppoint
		clusterName := b.Labels[common.LabelClusterName]
		oldBackup, err := clusterOp.GetBackup(context.TODO(), clusterName, b.Name)
		if err != nil {
			return err
		}
		item.ResourceVersion = oldBackup.ResourceVersion
		if _, err = clusterOp.UpdateBackup(context.TODO(), item); err != nil {
			return err
		}
		// 	update cluster,add backuppoint
		clu, err := clusterOp.GetCluster(context.TODO(), clusterName)
		if err != nil {
			return err
		}
		if clu.Labels == nil {
			clu.Labels = make(map[string]string)
		}
		clu.Labels[common.LabelBackupPoint] = defaultBackupPoint
		if _, err = clusterOp.UpdateCluster(context.TODO(), clu); err != nil {
			return err
		}
	}
	return nil
}

func createDefaultBackupPoint(clusterOp cluster.Operator) error {
	_, err := clusterOp.GetBackupPoint(context.TODO(), defaultBackupPoint, "")
	if err != nil {
		if apimachineryErrors.IsNotFound(err) {
			bp := &v1.BackupPoint{
				TypeMeta: metav1.TypeMeta{
					Kind:       "BackupPoint",
					APIVersion: "core.kubeclipper.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: defaultBackupPoint,
				},
				StorageType: "fs",
				Description: "4.3.0 default backup path,created by kc-migrate",
				FsConfig: &v1.FsConfig{
					BackupRootDir: defaultBackupPath,
				},
			}
			if _, err = clusterOp.CreateBackupPoint(context.TODO(), bp); err != nil {
				return err
			}
		}
		return err
	}
	return nil
}

func getBackupFileInfo(sshConfig *sshutils.SSH, host, fileName string) (*k8s.CheckFile, error) {
	ret, err := sshutils.SSHCmdWithSudo(sshConfig, host, fmt.Sprintf("ls -l %s | awk '{print $5}'", fileName))
	if err != nil {
		return nil, err
	}
	if err = ret.Error(); err != nil {
		return nil, err
	}
	sizeStr := ret.StdoutToString("")
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		return nil, err
	}

	ret, err = sshutils.SSHCmdWithSudo(sshConfig, host, fmt.Sprintf("md5sum %s|awk '{print $1}'", fileName))
	if err != nil {
		return nil, err
	}
	if err = ret.Error(); err != nil {
		return nil, err
	}
	md5sum := ret.StdoutToString("")
	checkFile := &k8s.CheckFile{
		BackupFileSize: int64(size),
		BackupFileMD5:  md5sum,
	}

	return checkFile, nil
}

func getCluster() (sshutils.Result, error) {
	return sshutils.CmdToString("/bin/sh", "-c", fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:%d --cacert=%s --cert=%s --key=%s get /registry/kc-server/core.kubeclipper.io/clusters/ --prefix --print-value-only", etcdClientPort, etcd431CaFile, etcd431CertFile, etcd431KeyFile))
}

func getBackup() (sshutils.Result, error) {
	return sshutils.CmdToString("/bin/sh", "-c", fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:%d --cacert=%s --cert=%s --key=%s get /registry/kc-server/core.kubeclipper.io/backups/ --prefix --print-value-only", etcdClientPort, etcd431CaFile, etcd431CertFile, etcd431KeyFile))
}

func getOperation() (sshutils.Result, error) {
	return sshutils.CmdToString("/bin/sh", "-c", fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:%d --cacert=%s --cert=%s --key=%s get /registry/kc-server/core.kubeclipper.io/operations --prefix --print-value-only", etcdClientPort, etcd431CaFile, etcd431CertFile, etcd431KeyFile))
}

func deleteEtcd(key string) error {
	return sshutils.Cmd("/bin/sh", "-c", fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:%d --cacert=%s --cert=%s --key=%s del %s 1>/dev/null", etcdClientPort, etcd431CaFile, etcd431CertFile, etcd431KeyFile, key))
}

func migrateOperation(clusterOp cluster.Operator, op operation.Operator) error {
	logger.Info("migrateOperation")

	ret, err := getOperation()
	if err != nil {
		return err
	}
	if err = ret.Error(); err != nil {
		return err
	}
	data := strings.TrimRight(ret.Stdout, "\n")
	split := strings.Split(data, "\n")
	for _, v := range split {
		if v == "" {
			continue
		}
		var o Operation430
		if err = json.Unmarshal([]byte(v), &o); err != nil {
			return errors.WithMessage(err, "Unmarshal")
		}

		steps := make([]v1.Step, 0, len(o.Steps))
		for i := range o.Steps {
			nodes := make([]v1.StepNode, 0, len(o.Steps[i].Nodes))
			for _, nodeID := range o.Steps[i].Nodes {
				node, err := clusterOp.GetNode(context.TODO(), nodeID)
				if err != nil {
					return errors.WithMessage(err, "get node")
				}
				item := v1.StepNode{
					ID:       node.Name,
					IPv4:     node.Status.Ipv4DefaultIP,
					Hostname: node.Status.NodeInfo.Hostname,
				}
				nodes = append(nodes, item)
			}

			step := v1.Step{
				ID:                o.Steps[i].ID,
				Name:              o.Steps[i].Name,
				Nodes:             nodes,
				Action:            o.Steps[i].Action,
				Timeout:           o.Steps[i].Timeout,
				ErrIgnore:         o.Steps[i].ErrIgnore,
				Commands:          o.Steps[i].Commands,
				BeforeRunCommands: o.Steps[i].BeforeRunCommands,
				AfterRunCommands:  o.Steps[i].AfterRunCommands,
				RetryTimes:        o.Steps[i].RetryTimes,
			}
			steps = append(steps, step)
		}

		n := v1.Operation{
			TypeMeta:   o.TypeMeta,
			ObjectMeta: o.ObjectMeta,
			Steps:      steps,
			Status:     o.Status,
		}
		// use etcdctl to delete
		key := fmt.Sprintf("/registry/kc-server/core.kubeclipper.io/operations/%s", o.Name)
		if err = deleteEtcd(key); err != nil {
			return errors.WithMessage(err, "delete etcd")
		}
		_, err = op.CreateOperation(context.TODO(), &n)
		if err != nil {
			return errors.WithMessage(err, "CreateOperation")
		}
	}
	return nil
}

var shImport = `
# read form file and put to etcd
files=$(ls /tmp/kcupgrade/etcdr)
for file in $files;do \
key=$(echo ${file//#/\/});\
#echo $file  + $key;\
cat /tmp/kcupgrade/etcdr/$file | ETCDCTL_API=3 etcdctl --endpoints={{ endpoint }}  --cacert={{ etcd-ca }} --cert={{ etcd-cert }} --key={{ etcd-key }} put $key 1>/dev/null ;\
done;
`

type Cluster430 struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Description       string              `json:"description,omitempty" optional:"true"`
	Masters           v1.WorkerNodeList   `json:"masters"`
	Workers           v1.WorkerNodeList   `json:"workers" optional:"true"`
	KubernetesVersion string              `json:"kubernetesVersion" enum:"v1.20.13"`
	CertSANs          []string            `json:"certSANs,omitempty" optional:"true"`
	LocalRegistry     string              `json:"localRegistry,omitempty" optional:"true"`
	ContainerRuntime  ContainerRuntime430 `json:"containerRuntime"`
	Networking        Networking430       `json:"networking"`
	KubeComponents    KubeComponents      `json:"kubeComponents"`
	KubeConfig        []byte              `json:"kubeconfig,omitempty"`
	Components        []v1.Addon          `json:"components" optional:"true"`
	WorkerNodeVip     string              `json:"workerNodeVip" optional:"true"`
	Status            ClusterStatus430    `json:"status,omitempty" optional:"true"`
	Offline           bool                `json:"offline" optional:"true"`
}
type ClusterStatus430 struct {
	Status v1.ClusterPhase `json:"status,omitempty"`
	// cluster component health status
	ComponentConditions []v1.ComponentConditions `json:"componentConditions,omitempty"`
	// Conditions          []ClusterCondition    `json:"conditions,omitempty"`
}

type KubeComponents struct {
	KubeProxy KubeProxy `json:"kubeProxy,omitempty" optional:"true"`
	Etcd      v1.Etcd   `json:"etcd,omitempty" optional:"true"`
	CNI       CNI430    `json:"cni"`
}

type KubeProxy struct {
	IPvs bool `json:"ipvs,omitempty" optional:"true"`
}
type CNI430 struct {
	LocalRegistry string    `json:"localRegistry" optional:"true"`
	Type          string    `json:"type" enum:"calico"`
	PodIPv4CIDR   string    `json:"podIPv4CIDR"`
	PodIPv6CIDR   string    `json:"podIPv6CIDR"`
	MTU           int       `json:"mtu"`
	Calico        Calico430 `json:"calico" optional:"true"`
}
type Calico430 struct {
	IPv4AutoDetection string `json:"IPv4AutoDetection" enum:"first-found|can-reach=DESTINATION|interface=INTERFACE-REGEX|skip-interface=INTERFACE-REGEX"`
	IPv6AutoDetection string `json:"IPv6AutoDetection" enum:"first-found|can-reach=DESTINATION|interface=INTERFACE-REGEX|skip-interface=INTERFACE-REGEX"`
	Mode              string `json:"mode" enum:"BGP|Overlay-IPIP-All|Overlay-IPIP-Cross-Subnet|Overlay-Vxlan-All|Overlay-Vxlan-Cross-Subnet|overlay"`
	DualStack         bool   `json:"dualStack" optional:"true"`
	IPManger          bool   `json:"IPManger" optional:"true"`
	Version           string `json:"version" enum:"v3.11.2"`
}
type ContainerRuntime430 struct {
	Type       string     `json:"containerRuntimeType" enum:"docker|containerd"`
	Docker     Docker     `json:"docker,omitempty"`
	Containerd Containerd `json:"containerd,omitempty"`
}

type Docker struct {
	Version          string   `json:"version,omitempty" enum:"19.03.12"`
	DataRootDir      string   `json:"rootDir,omitempty"`
	InsecureRegistry []string `json:"insecureRegistry,omitempty"`
}

type Containerd struct {
	Version          string   `json:"version,omitempty" enum:"1.4.4"`
	DataRootDir      string   `json:"rootDir,omitempty"`
	InsecureRegistry []string `json:"insecureRegistry,omitempty"`
}

type Networking430 struct {
	ServiceSubnet string `json:"serviceSubnet"`
	PodSubnet     string `json:"podSubnet"`
	DNSDomain     string `json:"dnsDomain"`
}

type DeployConfig430 struct {
	Config           string        `json:"-" yaml:"-"`
	SSHConfig        *sshutils.SSH `json:"ssh" yaml:"ssh"`
	EtcdConfig       *options.Etcd `json:"etcd" yaml:"etcd"`
	ServerIPs        []string      `json:"serverIPs" yaml:"serverIPs"`
	AgentIPs         []string      `json:"agentIPs" yaml:"agentIPs"`
	Debug            bool          `json:"debug" yaml:"debug"`
	Region           string        `json:"region" yaml:"region"`
	ServerPort       int           `json:"serverPort" yaml:"serverPort"`
	StaticServerPort int           `json:"staticServerPort" yaml:"staticServerPort"`
	StaticServerPath string        `json:"staticServerPath" yaml:"staticServerPath"`
	MQPort           int           `json:"mqPort" yaml:"mqPort"`
	MQClusterPort    int           `json:"mqClusterPort" yaml:"MQClusterPort"`
	Pkg              string        `json:"pkg" yaml:"pkg"`
	ConsolePort      int           `json:"consolePort" yaml:"consolePort"`
	LogDir           string        `json:"logDir" yaml:"logDir"`
	JWTSecret        string        `json:"jwtSecret" yaml:"jwtSecret"`
	MQSecret         string        `json:"mqSecret" yaml:"mqSecret"`
}

type AgentConfig430 struct {
	AgentID                   string              `json:"agentID,omitempty" yaml:"agentID"`
	Region                    string              `json:"region,omitempty" yaml:"region"`
	RegisterNode              bool                `json:"registerNode,omitempty" yaml:"registerNode"`
	NodeStatusUpdateFrequency time.Duration       `json:"nodeStatusUpdateFrequency,omitempty" yaml:"nodeStatusUpdateFrequency"`
	DownloaderOptions         *downloader.Options `json:"downloader" yaml:"downloader" mapstructure:"downloader"`
	LogOptions                *pkglogger.Options  `json:"log,omitempty" yaml:"log,omitempty" mapstructure:"log"`
	MQOptions                 *natsio.NatsOptions `json:"mq,omitempty" yaml:"mq,omitempty"  mapstructure:"mq"`
	AOFOptions                *aofOptions         `json:"aof,omitempty" yaml:"aof,omitempty" mapstructure:"aof"`
	BackupStoreOptions        *bs.Options         `json:"backupStore,omitempty" yaml:"backupStore,omitempty" mapstructure:"backupStore"`
}

type aofOptions struct {
	Dir string `json:"dir" yaml:"dir"`
}

type Backup430 struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Description       string            `json:"description,omitempty" optional:"true"`
	KubernetesVersion string            `json:"kubernetesVersion"`
	Digest            string            `json:"digest"`
	Size              uint32            `json:"size"`
	FileName          string            `json:"fileName"`
	ClusterNodes      map[string]string `json:"clusterNodes"`
	// a node selected for executing backup tasks
	PreferredNode string `json:"preferredNode,omitempty" optional:"true"`

	Status v1.ClusterBackupStatus `json:"status"`
}

type Backup struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            BackupStatus      `json:"backupStatus,omitempty"`
	ClusterNodes      map[string]string `json:"clusterNodes"`
	// a node selected for executing backup tasks
	PreferredNode   string `json:"preferredNode,omitempty" optional:"true"`
	BackupPointName string `json:"backupPointName"`
}

type BackupStatus struct {
	KubernetesVersion      string `json:"kubernetesVersion"`
	FileName               string `json:"fileName"`
	BackupFileSize         int64  `json:"backupFileSize"`
	BackupFileMD5          string `json:"backupFileMD5"`
	v1.ClusterBackupStatus `json:"status"`
}

type Operation430 struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Steps             []Step             `json:"steps,omitempty"`
	Status            v1.OperationStatus `json:"status,omitempty"`
}

type Step struct {
	ID                string          `json:"id,omitempty"`
	Name              string          `json:"name,omitempty"`
	Nodes             []string        `json:"nodes,omitempty"`
	Action            v1.StepAction   `json:"action,omitempty"`
	Timeout           metav1.Duration `json:"timeout,omitempty"`
	ErrIgnore         bool            `json:"errIgnore"`
	Commands          []v1.Command    `json:"commands,omitempty"`
	BeforeRunCommands []v1.Command    `json:"beforeRunCommands,omitempty"`
	AfterRunCommands  []v1.Command    `json:"afterRunCommands,omitempty"`
	RetryTimes        int32           `json:"retryTimes,omitempty"`
}

type Command struct {
	Type          v1.CommandType   `json:"type"`
	ShellCommand  []string         `json:"shellCommand,omitempty"`
	Identity      string           `json:"identity,omitempty"`
	CustomCommand []byte           `json:"customCommand,omitempty"`
	Template      *TemplateCommand `json:"template,omitempty"`
}
type TemplateCommand struct {
	Identity string `json:"identity,omitempty"`
	Data     []byte `json:"data,omitempty"`
}

type OperationCondition struct {
	StepID string       `json:"stepID,omitempty"`
	Status []StepStatus `json:"status,omitempty"`
}
type StepStatusType string

type StepStatus struct {
	StartAt metav1.Time    `json:"startAt,omitempty"`
	EndAt   metav1.Time    `json:"endAt,omitempty"`
	Node    string         `json:"node,omitempty"`
	Status  StepStatusType `json:"status,omitempty"`
	// (brief) reason for the condition's last transition.
	// +optional
	Reason string `json:"reason,omitempty"`
	// Human readable message indicating details about last transition.
	// +optional
	Message  string `json:"message,omitempty"`
	Response []byte `json:"response,omitempty"`
}
