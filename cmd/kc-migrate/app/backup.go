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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/kubeclipper/kubeclipper/pkg/cli/utils"

	"github.com/kubeclipper/kubeclipper/cmd/kcctl/app/options"
	"github.com/kubeclipper/kubeclipper/pkg/cli/logger"
	"github.com/kubeclipper/kubeclipper/pkg/utils/sshutils"
)

var (
	etcdClientPort = 12379
	shBackupData   = "/tmp/kcupgrade/etcd-backup.sh"
	shRestoreData  = "/tmp/kcupgrade/etcd-restore.sh"
)

var (
	etcd430CaFile   = "/etc/kubeclipper-server/pki/etcd/ca.crt"
	etcd430CertFile = "/etc/kubeclipper-server/pki/etcd/kc-server-etcd-client.crt"
	etcd430KeyFile  = "/etc/kubeclipper-server/pki/etcd/kc-server-etcd-client.key"
)

var (
	KcAgentConfig  = "/etc/kubeclipper-agent/kubeclipper-agent.yaml"
	KcServerConfig = "/etc/kubeclipper-server/kubeclipper-server.yaml"
	KcDeployConfig = options.DefaultDeployConfigPath
	BackupSuffix   = ".4.3.0.bak"
)

func NewCmdBackup() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "backup",
		DisableFlagsInUseLine: true,
		Short:                 "backup kubeclipper 4.3.0 etcd data and config file",
		Long:                  "backup kubeclipper 4.3.0 etcd data and config file",
		Example:               "TODO..",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	cmd.AddCommand(NewCmdBackupData())
	cmd.AddCommand(NewCmdBackupConfig())
	cmd.Flags().IntVar(&etcdClientPort, "etcd-port", etcdClientPort, "etcd client port")
	return cmd
}

func NewCmdBackupData() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "data",
		DisableFlagsInUseLine: true,
		Short:                 "backup kubeclipper 4.3.0 etcd data",
		Long:                  "backup kubeclipper 4.3.0 etcd data",
		Example:               "TODO..",
		Run: func(cmd *cobra.Command, args []string) {
			if !etcdCheck430() {
				return
			}
			if err := backupEtcdData(); err != nil {
				logger.Error("backup etcd data failed", err)
				return
			}
			logger.Infof("all data are backup to /tmp/kcupgrade")
		},
	}
	cmd.Flags().IntVar(&etcdClientPort, "etcd-port", etcdClientPort, "etcd client port")
	return cmd
}

func etcdCheck430() bool {
	logger.Info("etcd endpoint health check")
	err := sshutils.Cmd("/bin/sh", "-c", fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:%d --cacert=%s --cert=%s --key=%s endpoint health", etcdClientPort, etcd430CaFile, etcd430CertFile, etcd430KeyFile))
	if err != nil {
		logger.Error("etcd endpoint health check failed", err)
		return false
	}
	return true
}

func NewCmdBackupConfig() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "config",
		DisableFlagsInUseLine: true,
		Short:                 "backup kubeclipper 4.3.0 agent config",
		Long:                  "backup kubeclipper 4.3.0 agent config",
		Example:               "TODO..",
		Run: func(cmd *cobra.Command, args []string) {
			if !deployConfigCheck() {
				return
			}
			if err := backupConfig(); err != nil {
				logger.Error("backup config file failed", err)
				return
			}
			logger.Info("backup config file success")
		},
	}
	cmd.Flags().StringVar(&KcDeployConfig, "deploy-config", KcDeployConfig, "path to deploy-config.yaml")
	return cmd
}

func deployConfigCheck() bool {
	logger.Infof("check %s", KcDeployConfig)
	if !utils.FileExist(KcDeployConfig) {
		logger.Errorf("deploy-config %s  file not exist", KcDeployConfig)
		return false
	}
	return true
}

func backupEtcdData() error {
	err := sshutils.Cmd("mkdir", "-p", filepath.Dir(shBackupData))
	if err != nil {
		return err
	}
	logger.Info("etcd snapshot")
	// snapshot
	err = sshutils.Cmd("/bin/sh", "-c", fmt.Sprintf("ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:%d --cacert=%s --cert=%s --key=%s snapshot save /tmp/kcupgrade/etcd-%s.db", etcdClientPort, etcd430CaFile, etcd430CertFile, etcd430KeyFile, time.Now().Format(time.RFC3339)))
	if err != nil {
		return err
	}
	logger.Info("generate data export shell")
	all := strings.ReplaceAll(shExport, "{{ endpoint }}", fmt.Sprintf("https://127.0.0.1:%v", etcdClientPort))
	all = strings.ReplaceAll(all, "{{ etcd-ca }}", etcd430CaFile)
	all = strings.ReplaceAll(all, "{{ etcd-cert }}", etcd430CertFile)
	all = strings.ReplaceAll(all, "{{ etcd-key }}", etcd430KeyFile)

	f, err := os.Create(shBackupData)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(all)
	if err != nil {
		return err
	}
	logger.Info("run data export shell")
	return sshutils.Cmd("/bin/sh", shBackupData)
}

func backupConfig() error {
	// 1.read old server config
	logger.Infof("backup %s", KcDeployConfig)
	oldDP, err := readOldDC(KcDeployConfig)
	if err != nil {
		return err
	}
	backupOldDC()

	// 2.backup
	logger.Infof("backup %s", KcAgentConfig)
	for _, ip := range oldDP.ServerIPs {
		err = backupOldConfig(oldDP.SSHConfig, ip, []string{KcServerConfig, KcAgentConfig})
		if err != nil {
			return errors.WithMessage(err, "backup old server config")
		}
	}
	for _, ip := range oldDP.AgentIPs {
		err = backupOldConfig(oldDP.SSHConfig, ip, []string{KcAgentConfig})
		if err != nil {
			return errors.WithMessage(err, "backup old agent config")
		}
	}
	return nil
}

func backupFile(file string) string {
	return file + BackupSuffix
}

func readOldDC(path string) (DeployConfig430, error) {
	var oldConfig DeployConfig430
	data, err := os.ReadFile(path)
	if err != nil {
		return oldConfig, err
	}
	if err = yaml.Unmarshal(data, &oldConfig); err != nil {
		return oldConfig, err
	}
	oldConfig.SSHConfig.Port = 22
	return oldConfig, nil
}

func backupOldDC() {
	_ = sshutils.Cmd("cp", KcDeployConfig, backupFile(KcDeployConfig))
}

func backupOldConfig(ssh *sshutils.SSH, ip string, files []string) error {
	for _, file := range files {
		cp := fmt.Sprintf("cp %s %s", file, backupFile(file))
		ret, err := sshutils.SSHCmdWithSudo(ssh, ip, cp)
		if err != nil {
			return errors.WithMessagef(err, "[%s] backup file %s", ip, file)
		}
		if err = ret.Error(); err != nil {
			return errors.WithMessagef(err, "[%s] backup file %s ret", ip, file)
		}
	}
	return nil
}

var shExport = `
# get all 99cloud.net keys
keys=$(ETCDCTL_API=3 etcdctl --endpoints={{ endpoint }}  --cacert={{ etcd-ca }} --cert={{ etcd-cert }} --key={{ etcd-key }} get "/registry" --prefix --keys-only=true | grep "99cloud.net")
#echo $keys

# export to etcdo dir
rm -rf /tmp/kcupgrade/etcdo;
mkdir -p /tmp/kcupgrade/etcdo;
for key in $keys;do \
data=$(ETCDCTL_API=3 etcdctl --endpoints={{ endpoint }} --cacert={{ etcd-ca }} --cert={{ etcd-cert }} --key={{ etcd-key }} get $key --print-value-only);\
fileKey=$(echo ${key//\//#});\
#echo $fileKey  + $data;\
echo $data > /tmp/kcupgrade/etcdo/$fileKey;\
done;

#replace 99cloud.net to kubeclipper.io,and export to etcdr dir
rm -rf /tmp/kcupgrade/etcdr;
mkdir -p /tmp/kcupgrade/etcdr;
for key in $keys;do \
data=$(ETCDCTL_API=3 etcdctl --endpoints={{ endpoint }} --cacert={{ etcd-ca }} --cert={{ etcd-cert }} --key={{ etcd-key }} get $key --print-value-only);\
newKey=$(echo ${key//99cloud.net/kubeclipper.io});\
newData=$(echo ${data//99cloud.net/kubeclipper.io});\
fileKey=$(echo ${newKey//\//#});\
echo $newData > /tmp/kcupgrade/etcdr/$fileKey;\
done;
`
