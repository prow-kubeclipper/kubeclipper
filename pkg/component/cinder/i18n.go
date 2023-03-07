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

package cinder

import "github.com/kubeclipper/kubeclipper/pkg/component"

func initI18nForComponentMeta() error {
	return component.AddI18nMessages(component.I18nMessages{
		{
			ID:      "cinder.metaTitle",
			English: "Cinder CSI Setting",
			Chinese: "Cinder CSI 设置",
		},
		{
			ID:      "cinder.version",
			English: "CinderVersion",
			Chinese: "Cinder版本",
		},
		{
			ID:      "cinder.authUrl",
			English: "Keystone URL",
			Chinese: "Keystone地址",
		},
		{
			ID:      "cinder.username",
			English: "Username",
			Chinese: "用户名",
		},
		{
			ID:      "cinder.password",
			English: "Password",
			Chinese: "密码",
		},
		{
			ID:      "cinder.projectID",
			English: "ProjectID",
			Chinese: "项目ID",
		},
		{
			ID:      "cinder.domainID",
			English: "DomainID",
			Chinese: "域ID",
		},
		{
			ID:      "cinder.region",
			English: "Region",
			Chinese: "区域",
		},
		{
			ID:      "cinder.caCert",
			English: "CA Certificate",
			Chinese: "CA证书",
		},
		{
			ID:      "cinder.availabilityZone",
			English: "AvailabilityZone",
			Chinese: "可用区",
		},
		{
			ID:      "cinder.backendType",
			English: "BackendType",
			Chinese: "后端类型",
		},
		{
			ID:      "cinder.scName",
			English: "StorageClassName",
			Chinese: "存储类型",
		},
		{
			ID:      "cinder.reclaimPolicy",
			English: "ReclaimPolicy",
			Chinese: "回收策略",
		},
		{
			ID:      "cinder.isDefaultSC",
			English: "IsDefaultSC",
			Chinese: "是否默认存储类型",
		},
		{
			ID:      "cinder.replicas",
			English: "Replicas",
			Chinese: "副本数",
		},
		{
			ID:      "cinder.imageRepoMirror",
			English: "Cinder Image Repository Mirror",
			Chinese: "Cinder镜像仓库代理",
		},
	})
}
