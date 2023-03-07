package cluster

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	cephcsi "github.com/kubeclipper/kubeclipper/pkg/component/ceph"
	cindercsi "github.com/kubeclipper/kubeclipper/pkg/component/cinder"
	"github.com/kubeclipper/kubeclipper/pkg/component/kubesphere"

	nfsprovisioner "github.com/kubeclipper/kubeclipper/pkg/component/nfs"
	"github.com/kubeclipper/kubeclipper/pkg/component/nfscsi"
	"github.com/kubeclipper/kubeclipper/pkg/scheme/common"
	corev1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"
)

const (
	nameNFSProvider = "nfs-provisioner"
	nameNFSCSI      = "nfs-csi"
	nameCephCSI     = "ceph-csi"
	nameCinderCSI   = "cinder-csi"
	nameKubesphere  = "kubesphere"

	Storage = "storage"
	Paas    = "PAAS"
)

type addonE2E struct {
	name      string
	labels    map[string]string
	data      []byte
	component string
	category  string
}

func initAddonList() ([]addonE2E, error) {
	dataList, err := initAddonDataList()
	if err != nil {
		return nil, err
	}

	list := make([]addonE2E, 0)

	v := addonE2E{
		name:      nameNFSProvider,
		labels:    initAddonLabelV1(Storage, nameNFSProvider),
		data:      dataList[nameNFSProvider],
		component: nameNFSProvider,
		category:  Storage,
	}
	list = append(list, v)

	v = addonE2E{
		name:      nameNFSCSI,
		labels:    initAddonLabelV1(Storage, nameNFSCSI),
		data:      dataList[nameNFSCSI],
		component: nameNFSCSI,
		category:  Storage,
	}
	list = append(list, v)

	v = addonE2E{
		name:      nameCephCSI,
		labels:    initAddonLabelV1(Storage, nameCephCSI),
		data:      dataList[nameCephCSI],
		component: nameCephCSI,
		category:  Storage,
	}
	list = append(list, v)

	v = addonE2E{
		name:      nameCinderCSI,
		labels:    initAddonLabelV1(Storage, nameCinderCSI),
		data:      dataList[nameCinderCSI],
		component: nameCinderCSI,
		category:  Storage,
	}
	list = append(list, v)

	v = addonE2E{
		name:      nameKubesphere,
		labels:    initAddonLabelV1(Storage, nameKubesphere),
		data:      dataList[nameKubesphere],
		component: nameKubesphere,
		category:  Paas,
	}
	list = append(list, v)

	return list, nil
}

func initAddonDataList() (map[string][]byte, error) {
	list := make(map[string][]byte)

	nfsProvider := nfsprovisioner.NFSProvisioner{}
	nfsProviderData, err := json.Marshal(nfsProvider)
	if err != nil {
		return nil, err
	}
	list[nameNFSProvider] = nfsProviderData

	nfsCsi := nfscsi.NFS{}
	nfsCsiData, err := json.Marshal(nfsCsi)
	if err != nil {
		return nil, err
	}
	list[nameNFSCSI] = nfsCsiData

	cephCsi := cephcsi.CephCSI{}
	cephCsiData, err := json.Marshal(cephCsi)
	if err != nil {
		return nil, err
	}
	list[nameCephCSI] = cephCsiData

	cinderCsi := cindercsi.Cinder{}
	cinderCsiData, err := json.Marshal(cinderCsi)
	if err != nil {
		return nil, err
	}
	list[nameCinderCSI] = cinderCsiData

	ks := kubesphere.Kubesphere{}
	ksData, err := json.Marshal(ks)
	if err != nil {
		return nil, err
	}
	list[nameKubesphere] = ksData

	return list, nil
}

func initAddonLabelV1(category, addonName string) map[string]string {
	return map[string]string{
		common.LabelCategory:         category,
		common.LabelComponentName:    addonName,
		common.LabelComponentVersion: "v1",
	}
}

func initAddonTemplate(name string, labels map[string]string, addon []byte) *corev1.Template {
	return &corev1.Template{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Template",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				common.AnnotationDisplayName: name,
			},
			Labels: labels,
		},
		Config: runtime.RawExtension{Raw: addon},
	}
}

func editReplace(t *corev1.Template) error {
	var (
		err  error
		data []byte
	)

	switch t.Labels[common.LabelComponentName] {
	case nameNFSProvider:
		v := &nfsprovisioner.NFSProvisioner{}
		err = json.Unmarshal(t.Config.Raw, v)
		if err != nil {
			return err
		}
		v.Replicas = 3
		data, err = json.Marshal(v)
	case nameNFSCSI:
		v := &nfscsi.NFS{}
		err = json.Unmarshal(t.Config.Raw, v)
		if err != nil {
			return err
		}
		v.Replicas = 3
		data, err = json.Marshal(v)
	case nameCephCSI:
		v := &cephcsi.CephCSI{}
		err = json.Unmarshal(t.Config.Raw, v)
		if err != nil {
			return err
		}
		v.Replicas = 3
		data, err = json.Marshal(v)
	case nameCinderCSI:
		v := &cindercsi.Cinder{}
		err = json.Unmarshal(t.Config.Raw, v)
		if err != nil {
			return err
		}
		v.Replicas = 3
		data, err = json.Marshal(v)
	case nameKubesphere:
		v := &kubesphere.Kubesphere{}
		err = json.Unmarshal(t.Config.Raw, v)
		if err != nil {
			return err
		}
		v.JwtSecret = "update-test"
		data, err = json.Marshal(v)
	}

	t.Config.Raw = data
	return err
}

func initClusterTemplate(clu *corev1.Cluster, name, displayname string) (*corev1.Template, error) {
	data, err := json.Marshal(clu)
	if err != nil {
		return nil, err
	}

	return &corev1.Template{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Template",
			APIVersion: corev1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				common.AnnotationDisplayName: displayname,
			},
			Labels: map[string]string{
				common.LabelCategory:         "kubernetes",
				common.LabelComponentName:    "kubernetes",
				common.LabelComponentVersion: "v1",
			},
			Name: name,
		},
		Config: runtime.RawExtension{Raw: data},
	}, nil
}
