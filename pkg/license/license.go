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

package license

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base32"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/kubeclipper/kubeclipper/pkg/logger"

	"github.com/kubeclipper/kubeclipper/pkg/query"
	v1 "github.com/kubeclipper/kubeclipper/pkg/scheme/core/v1"

	"github.com/kubeclipper/kubeclipper/pkg/models/cluster"

	"github.com/thoas/go-funk"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	SystemInfoProduct = "caas"
	SystemInfoVersion = "4.3.1"
)

const PublicKEY = "AQAH4SYXUTDCENKLLJFWABCS4SKNYOHJIACL75OZEOETLBEKNAJ4GFPLGATFFNAGNMRE572MQIFOCRS66NM3HQCZBQT74L2UROWST5YQMQKVI3YOBHSRDCEB4SWWG6A3B6ZLZEBF6R3YQVZYCZ2S3EON4WGA===="

var _localMacAddressList = getMacAddressList()

type LicenseInfo struct {
	Company       string       `json:"company" description:"do not input auto generator, license company info"`
	Expired       *metav1.Time `json:"end,omitempty" description:"do not input auto generator, license expired date"`
	CPU           string       `json:"cpu" description:"do not input auto generator, license cpu limit info"`
	Node          string       `json:"node" description:"do not input auto generator, license node limit info"`
	CPUUsed       int          `json:"cpu_used"`
	NodeUsed      int          `json:"node_used"`
	Product       string       `json:"product" description:"do not input auto generator, license production info"`
	Version       string       `json:"version" description:"do not input auto generator, license version info"`
	MacAddress    string       `json:"mac_address" description:"do not input auto generator, license mac address info"`
	SystemVersion string       `json:"systemVersion" description:"do not input auto generator, license system version info"`
	SystemProduct string       `json:"systemProduct" description:"do not input auto generator, license system product info"`
	License       string       `json:"license" description:"do not input auto generator, license string"`
	Modules       string       `json:"modules" description:"do not input auto generator, such as-> modules:web-console"`
	ErrorDetail   string       `json:"reason,omitempty" description:"do not input auto generator, license check failed root cause"`
	LicenseValid  bool         `json:"valid" description:"do not input auto generator, license is valid"`
}

type Interface interface {
	GetLicenseInfo(lic string) (*LicenseInfo, error)
	Verify(lic string) (bool, string, error)
}

var _ Interface = (*operator)(nil)

type operator struct {
	nodeOperator cluster.NodeReader
}

func NewOperator(ex cluster.NodeReader) Interface {
	return &operator{nodeOperator: ex}
}

func (o *operator) GetLicenseInfo(lic string) (*LicenseInfo, error) {
	result := LicenseInfo{
		SystemProduct: SystemInfoProduct,
		SystemVersion: SystemInfoVersion,
		License:       lic,
	}

	publicKey, err := PublicKeyFromB32String(PublicKEY)
	if err != nil {
		result.ErrorDetail = fmt.Sprintf("illegal license %v", err)
		return &result, err
	}

	l, err := LicenseFromB32String(lic)
	if err != nil {
		result.ErrorDetail = fmt.Sprintf("illegal license %v", err)
		return &result, err
	}

	if ok, err := l.Verify(publicKey); err != nil {
		result.ErrorDetail = fmt.Sprintf("illegal license %v", err)
		return &result, err
	} else if !ok {
		result.ErrorDetail = fmt.Sprintf("illegal license %v", err)
		return &result, nil
	}

	if err := json.Unmarshal(l.Data, &result); err != nil {
		return &result, err
	}

	if err = o.validateLicense(&result); err != nil {
		logger.Error("valid license failed", zap.Error(err))
	}

	return &result, nil
}

func (o *operator) Verify(lic string) (bool, string, error) {
	lInfo, err := o.GetLicenseInfo(lic)
	if err != nil {
		return false, "", err
	}
	err = o.validateLicense(lInfo)
	return lInfo.LicenseValid, lInfo.ErrorDetail, err
}

func (o *operator) validateLicense(lic *LicenseInfo) error {
	sysVer := splitTrimFilter(SystemInfoVersion, ".")
	licVer := splitTrimFilter(lic.Version, ".")
	if SystemInfoProduct != lic.Product || len(sysVer) < 1 || len(licVer) < 1 || sysVer[0] != licVer[0] {
		lic.ErrorDetail = "license product or version invalid"
		return nil
	}
	now := metav1.Now()
	if lic.Expired.Before(&now) {
		lic.ErrorDetail = "license expired"
		return nil
	}
	node, cpu, err := o.getNodeCab()
	if err != nil {
		return err
	}
	lic.CPUUsed = cpu
	lic.NodeUsed = node

	licNode, err := strconv.ParseInt(lic.Node, 10, 64)
	if err != nil {
		return err
	}

	if node > int(licNode) {
		lic.ErrorDetail = "node number exceed limit"
		return nil
	}

	licCPU, err := strconv.ParseInt(lic.CPU, 10, 64)
	if err != nil {
		return err
	}
	if cpu > int(licCPU) {
		lic.ErrorDetail = "cpu number exceed limit"
		return nil
	}

	licMacAddressList := splitTrimFilter(lic.MacAddress, " ")
	licMacAddressList = funk.Map(licMacAddressList, func(s string) string {
		return strings.ToLower(s)
	}).([]string)
	if len(licMacAddressList) > 0 {
		result := funk.Join(_localMacAddressList, licMacAddressList, funk.InnerJoin).([]string)
		if len(result) < 1 {
			lic.ErrorDetail = fmt.Sprintf("Local mac address (%#v) does not match the license (%#v)", _localMacAddressList, licMacAddressList)
			return nil
		}
	}
	lic.LicenseValid = true
	return nil
}

func (o *operator) getNodeCab() (int, int, error) {
	// TODO: use cache query
	nodes, err := o.nodeOperator.ListNodes(context.TODO(), query.New())
	if err != nil {
		return 0, 0, err
	}
	var cpuCoreCount int64
	for _, node := range nodes.Items {
		quantity := node.Status.Capacity[v1.ResourceCPU]
		cpuCoreCount += quantity.Value()
	}

	return len(nodes.Items), int(cpuCoreCount), nil
}

type License struct {
	Data []byte
	R    *big.Int
	S    *big.Int
}

func PublicKeyFromBytes(b []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P384(), b)
	if x == nil {
		return nil, errors.New("invalid key")
	}

	k := ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     x,
		Y:     y,
	}
	return &k, nil
}

func PublicKeyFromB32String(str string) (*ecdsa.PublicKey, error) {
	b, err := base32.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return PublicKeyFromBytes(b)
}

func fromB32String(obj interface{}, s string) error {
	b, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	return fromBytes(obj, b)
}

func fromBytes(obj interface{}, b []byte) error {
	buffBin := bytes.NewBuffer(b)
	decoder := gob.NewDecoder(buffBin)

	return decoder.Decode(obj)
}

func (l *License) hash() ([]byte, error) {
	h256 := sha256.New()

	if _, err := h256.Write(l.Data); err != nil {
		return nil, err
	}
	return h256.Sum(nil), nil
}

func (l *License) Verify(k *ecdsa.PublicKey) (bool, error) {
	h, err := l.hash()
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(k, h, l.R, l.S), nil
}

func LicenseFromB32String(str string) (*License, error) {
	l := &License{}
	return l, fromB32String(l, str)
}

func splitTrimFilter(s string, sep string) []string {
	splitList := strings.Split(s, sep)
	var strList []string
	for _, value := range splitList {
		value = strings.TrimSpace(value)
		if len(value) > 0 {
			strList = append(strList, value)
		}
	}
	return strList
}

func getMacAddressList() (macAddressList []string) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("fail to get net interfaces: %v", err)
		return macAddressList
	}

	macAddressList = funk.Map(netInterfaces, func(n net.Interface) string {
		return strings.ToLower(n.HardwareAddr.String())
	}).([]string)
	macAddressList = funk.Filter(macAddressList, func(s string) bool {
		return len(s) > 0
	}).([]string)

	return macAddressList
}
