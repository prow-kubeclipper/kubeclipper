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

import "github.com/kubeclipper/kubeclipper/pkg/component"

func initI18nForComponentMeta() error {
	return component.AddI18nMessages(component.I18nMessages{
		{
			ID:      "ceph.metaTitle",
			English: "Ceph CSI Setting",
			Chinese: "Ceph CSI 设置",
		},
		{
			ID:      "ceph.clusterID",
			English: "Ceph Cluster ID",
			Chinese: "Ceph集群ID",
		},
		{
			ID:      "ceph.monitors",
			English: "Ceph Monitors",
			Chinese: "Ceph监控节点",
		},
		{
			ID:      "ceph.userID",
			English: "Ceph User ID",
			Chinese: "Ceph用户ID",
		},
		{
			ID:      "ceph.userKey",
			English: "Ceph User Key",
			Chinese: "Ceph用户密钥",
		},
		{
			ID:      "ceph.poolID",
			English: "Ceph Pool ID",
			Chinese: "Ceph存储池ID",
		},
		{
			ID:      "ceph.scName",
			English: "Ceph Storage Class Name",
			Chinese: "Ceph存储类别名称",
		},
		{
			ID:      "ceph.isDefaultSC",
			English: "Is Default Storage Class",
			Chinese: "是否默认存储类别",
		},
		{
			ID:      "ceph.reclaimPolicy",
			English: "Ceph Reclaim Policy",
			Chinese: "Ceph回收策略",
		},
		{
			ID:      "ceph.fsType",
			English: "Ceph Filesystem Type",
			Chinese: "Ceph文件系统类型",
		},
		{
			ID:      "ceph.replicas",
			English: "Ceph Replicas",
			Chinese: "Ceph副本数",
		},
		{
			ID:      "ceph.imageRepoMirror",
			English: "Ceph Image Repository Mirror",
			Chinese: "Ceph镜像仓库代理",
		},
	})
}
