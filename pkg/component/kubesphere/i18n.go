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

import "github.com/kubeclipper/kubeclipper/pkg/component"

func initI18nForComponentMeta() error {
	return component.AddI18nMessages(component.I18nMessages{
		{
			ID:      "ks.metaTitle",
			English: `Kubesphere Setting`,
			Chinese: `Kubesphere设置`,
		},
		{
			ID:      "ks.version",
			English: `Version`,
			Chinese: `版本`,
		},
		{
			ID:      "ks.clusterRole",
			English: `Cluster Role`,
			Chinese: `集群角色`,
		},
		{
			ID:      "ks.clusterType",
			English: `Cluster Type`,
			Chinese: `集群类型`,
		},
		{
			ID:      "ks.jwtSecret",
			English: `JWT Secret`,
			Chinese: `JWT密钥`,
		},
		{
			ID:      "ks.hostClusterName",
			English: `Host Cluster Name`,
			Chinese: `主机集群名称`,
		},
		{
			ID:      "ks.storageClass",
			English: `Storage Class`,
			Chinese: `存储类型`,
		},
		{
			ID:      "ks.console",
			English: `Console Config`,
			Chinese: `控制台配置`,
		},
		{
			ID:      "ks.console.enableMultiLogin",
			English: `Enable Multi Login`,
			Chinese: `启用多点登录`,
		},
		{
			ID:      "ks.console.port",
			English: `Port`,
			Chinese: `端口`,
		},
		{
			ID:      "ks.monitor",
			English: `Monitor Config`,
			Chinese: `监控配置`,
		},
		{
			ID:      "ks.monitor.prometheusReplicas",
			English: `Prometheus Replicas`,
			Chinese: `Prometheus副本数`,
		},
		{
			ID:      "ks.monitor.prometheusMemoryLimit",
			English: `Prometheus Memory Limit`,
			Chinese: `Prometheus内存限制`,
		},
		{
			ID:      "ks.monitor.prometheusVolumeSize",
			English: `Prometheus Volume Size`,
			Chinese: `Prometheus卷大小`,
		},
		{
			ID:      "ks.monitor.prometheusCPULimit",
			English: `Prometheus CPU Limit`,
			Chinese: `Prometheus CPU限制`,
		},
		{
			ID:      "ks.monitor.alertManagerReplicas",
			English: `Alert Manager Replicas`,
			Chinese: `Alert Manager副本数`,
		},
		{
			ID:      "ks.es",
			English: `Elasticsearch Config`,
			Chinese: `Elasticsearch配置`,
		},
		{
			ID:      "ks.es.elasticsearchMasterReplicas",
			English: `Elasticsearch Master Replicas`,
			Chinese: `Elasticsearch主节点副本数`,
		},
		{
			ID:      "ks.es.elasticsearchDataReplicas",
			English: `Elasticsearch Data Replicas`,
			Chinese: `Elasticsearch数据节点副本数`,
		},
		{
			ID:      "ks.es.elasticsearchMasterVolumeSize",
			English: `Elasticsearch Master Volume Size`,
			Chinese: `Elasticsearch主节点卷大小`,
		},
		{
			ID:      "ks.es.elasticsearchDataVolumeSize",
			English: `Elasticsearch Data Volume Size`,
			Chinese: `Elasticsearch数据节点卷大小`,
		},
		{
			ID:      "ks.es.logMaxAge",
			English: `Log Max Age`,
			Chinese: `日志最大保存时间`,
		},
		{
			ID:      "ks.es.elkPrefix",
			English: `Elk Prefix`,
			Chinese: `Elk前缀`,
		},
		{
			ID:      "ks.plugin",
			English: `Plugin Config`,
			Chinese: `插件配置`,
		},
		{
			ID:      "ks.plugin.enableEvent",
			English: `Enable Event`,
			Chinese: `启用事件`,
		},
		{
			ID:      "ks.plugin.enableDevops",
			English: `Enable Devops`,
			Chinese: `启用Devops`,
		},
		{
			ID:      "ks.plugin.enableLogging",
			English: `Enable Logging`,
			Chinese: `启用日志`,
		},
		{
			ID:      "ks.plugin.enableAlert",
			English: `Enable Alert`,
			Chinese: `启用告警`,
		},
		{
			ID:      "ks.plugin.enableNetwork",
			English: `Enable Network`,
			Chinese: `启用网络`,
		},
		{
			ID:      "ks.plugin.enableAudit",
			English: `Enable Audit`,
			Chinese: `启用审计`,
		},
		{
			ID:      "ks.plugin.enableMetricServer",
			English: `Enable Metric Server`,
			Chinese: `启用Metric Server`,
		},
		{
			ID:      "ks.plugin.enableServiceMesh",
			English: `Enable Service Mesh`,
			Chinese: `启用Service Mesh`,
		},
		{
			ID:      "ks.plugin.enableAppStore",
			English: `Enable App Store`,
			Chinese: `启用App Store`,
		},
		{
			ID:      "ks.imageRepoMirror",
			English: "KubeSphere Image Repository Mirror",
			Chinese: "KubeSphere镜像仓库代理",
		},
	})
}
