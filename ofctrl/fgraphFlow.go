/***
Copyright 2014 Cisco Systems Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ofctrl

// This file implements the forwarding graph API for the flow

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/contiv/libOpenflow/util"
	"net"
	"sync"

	"github.com/contiv/libOpenflow/openflow13"
	log "github.com/sirupsen/logrus"
)

// Small subset of openflow fields we currently support
type FlowMatch struct {
	Priority      uint16               // Priority of the flow
	InputPort     uint32               // Input port number
	MacDa         *net.HardwareAddr    // Mac dest
	MacDaMask     *net.HardwareAddr    // Mac dest mask
	MacSa         *net.HardwareAddr    // Mac source
	MacSaMask     *net.HardwareAddr    // Mac source mask
	Ethertype     uint16               // Ethertype
	VlanId        uint16               // vlan id
	ArpOper       uint16               // ARP Oper type
	ArpSha        *net.HardwareAddr    // ARP source host address
	ArpTha        *net.HardwareAddr    // ARP target host address
	ArpSpa        *net.IP              // ARP source protocol address
	ArpTpa        *net.IP              // ARP target protocol address
	IpSa          *net.IP              // IPv4 source addr
	IpSaMask      *net.IP              // IPv4 source mask
	IpDa          *net.IP              // IPv4 dest addr
	IpDaMask      *net.IP              // IPv4 dest mask
	CtIpSa        *net.IP              // IPv4 source addr in ct
	CtIpSaMask    *net.IP              // IPv4 source mask in ct
	CtIpDa        *net.IP              // IPv4 dest addr in ct
	CtIpDaMask    *net.IP              // IPv4 dest mask in ct
	Ipv6Sa        *net.IP              // IPv6 source addr
	Ipv6SaMask    *net.IP              // IPv6 source mask
	Ipv6Da        *net.IP              // IPv6 dest addr
	Ipv6DaMask    *net.IP              // IPv6 dest mask
	CtIpv6Sa      *net.IP              // IPv6 source addr
	CtIpv6Da      *net.IP              // IPv6 dest addr in ct
	IpProto       uint8                // IP protocol
	CtIpProto     uint8                // IP protocol in ct
	IpDscp        uint8                // DSCP/TOS field
	TcpSrcPort    uint16               // TCP source port
	TcpDstPort    uint16               // TCP dest port
	UdpSrcPort    uint16               // UDP source port
	UdpDstPort    uint16               // UDP dest port
	SctpSrcPort   uint16               // SCTP source port
	SctpDstPort   uint16               // SCTP dest port
	CtTpSrcPort   uint16               // Source port in the transport layer in ct
	CtTpDstPort   uint16               // Dest port in the transport layer in ct
	Metadata      *uint64              // OVS metadata
	MetadataMask  *uint64              // Metadata mask
	TunnelId      uint64               // Vxlan Tunnel id i.e. VNI
	TcpFlags      *uint16              // TCP flags
	TcpFlagsMask  *uint16              // Mask for TCP flags
	ConjunctionID *uint32              // Add AddConjunction ID
	CtStates      *openflow13.CTStates // Connection tracking states
	NxRegs        []*NXRegister        // regX or regX[m..n]
	XxRegs        []*XXRegister        // xxregN or xxRegN[m..n]
	CtMark        uint32               // conn_track mark
	CtMarkMask    *uint32              // Mask of conn_track mark
	ActsetOutput  uint32               // Output port number
	TunMetadatas  []*NXTunMetadata     // tun_metadataX or tun_metadataX[m..n]
}

// additional Actions in flow's instruction set
type FlowAction struct {
	ActionType   string               // Type of action "setVlan", "setMetadata"
	vlanId       uint16               // Vlan Id in case of "setVlan"
	macAddr      net.HardwareAddr     // Mac address to set
	ipAddr       net.IP               // IP address to be set
	l4Port       uint16               // Transport port to be set
	arpOper      uint16               // Arp operation type to be set
	tunnelId     uint64               // Tunnel Id (used for setting VNI)
	metadata     uint64               // Metadata in case of "setMetadata"
	metadataMask uint64               // Metadata mask
	dscp         uint8                // DSCP field
	loadAct      *NXLoadAction        // Load data into OXM/NXM fields, one or more Actions
	moveAct      *NXMoveAction        // Move data from src OXM/NXM field to dst field
	conjunction  *NXConjunctionAction // AddConjunction Actions to be set
	connTrack    *NXConnTrackAction   // ct Actions to be set
	resubmit     *Resubmit            // resubmit packet to a specific Table and port. Resubmit could also be a NextElem.
	// If the packet is resubmitted to multiple ports, use resubmit as a FlowAction
	// and the NextElem should be Empty.
	learn      *FlowLearn    // nxm learn action
	notes      []byte        // data to set in note action
	controller *NXController // send packet to controller
	nxOutput   *NXOutput     // output packet to a provided register
}

// State of a flow entry
type Flow struct {
	Table       *Table        // Table where this flow resides
	Match       FlowMatch     // Fields to be matched
	NextElem    FgraphElem    // Next fw graph element
	HardTimeout uint16        // Timeout to remove the flow after it is installed in the switch
	IdleTimeout uint16        // Timeout to remove the flow after its last hit
	isInstalled bool          // Is the flow installed in the switch
	CookieID    uint64        // Cookie ID for flowMod message
	CookieMask  uint64        // Cookie Mask for flowMod message
	flowActions []*FlowAction // List of flow Actions
	lock        sync.RWMutex  // lock for modifying flow state
	statusLock  sync.RWMutex  // lock for modifying flow realized status
	realized    bool          // Realized status of flow

	appliedActions []OFAction
	writeActions   []OFAction
	metadata       *writeMetadata
	gotoTable      *uint8
	clearActions   bool
}

type writeMetadata struct {
	data uint64
	mask uint64
}

// Matches data either exactly or with optional mask in register number ID. The mask
// could be calculated according to range automatically
type NXRegister struct {
	ID    int                 // ID of NXM_NX_REG, value should be from 0 to 15
	Data  uint32              // Data to cache in register
	Range *openflow13.NXRange // Range of bits in register
}

func (r *NXRegister) getShiftedValue() uint32 {
	if r.Range == nil {
		return r.Data
	}
	return r.Data << r.Range.GetOfs()
}

type XXRegister struct {
	ID   int    // ID of NXM_NX_XXREG, value should be from 0 to 3
	Data []byte // Data to cache in xxreg
}

type NXTunMetadata struct {
	ID    int                 // ID of NXM_NX_TUN_METADATA, value should be from 0 to 7. OVS supports 64 tun_metadata, but only 0-7 is implemented in libOpenflow
	Data  interface{}         // Data to set in the register
	Range *openflow13.NXRange // Range of bits in the field
}

const IP_PROTO_TCP = 6
const IP_PROTO_UDP = 17
const IP_PROTO_SCTP = 132

var (
	EmptyFlowActionError    = errors.New("flow Actions is empty")
	UnknownElementTypeError = errors.New("unknown Fgraph element type")
	UnknownActionTypeError  = errors.New("unknown action type")
)

type FlowBundleMessage struct {
	message *openflow13.FlowMod
}

func (m *FlowBundleMessage) resetXid(xid uint32) util.Message {
	m.message.Xid = xid
	return m.message
}

// string key for the flow
// FIXME: simple json conversion for now. This needs to be smarter
func (self *Flow) flowKey() string {
	jsonVal, err := json.Marshal(self.Match)
	if err != nil {
		log.Errorf("Error forming flowkey for %+v. Err: %v", self, err)
		return ""
	}

	return string(jsonVal)
}

// Fgraph element type for the flow
func (self *Flow) Type() string {
	return "flow"
}

// instruction set for flow element
func (self *Flow) GetFlowInstr() openflow13.Instruction {
	log.Fatalf("Unexpected call to get flow's instruction set")
	return nil
}

// Translate our match fields into openflow 1.3 match fields
func (self *Flow) xlateMatch() openflow13.Match {
	ofMatch := openflow13.NewMatch()

	// Handle input poty
	if self.Match.InputPort != 0 {
		inportField := openflow13.NewInPortField(self.Match.InputPort)
		ofMatch.AddField(*inportField)
	}

	// Handle mac DA field
	if self.Match.MacDa != nil {
		if self.Match.MacDaMask != nil {
			macDaField := openflow13.NewEthDstField(*self.Match.MacDa, self.Match.MacDaMask)
			ofMatch.AddField(*macDaField)
		} else {
			macDaField := openflow13.NewEthDstField(*self.Match.MacDa, nil)
			ofMatch.AddField(*macDaField)
		}
	}

	// Handle MacSa field
	if self.Match.MacSa != nil {
		if self.Match.MacSaMask != nil {
			macSaField := openflow13.NewEthSrcField(*self.Match.MacSa, self.Match.MacSaMask)
			ofMatch.AddField(*macSaField)
		} else {
			macSaField := openflow13.NewEthSrcField(*self.Match.MacSa, nil)
			ofMatch.AddField(*macSaField)
		}
	}

	// Handle ethertype
	if self.Match.Ethertype != 0 {
		etypeField := openflow13.NewEthTypeField(self.Match.Ethertype)
		ofMatch.AddField(*etypeField)
	}

	// Handle Vlan id
	if self.Match.VlanId != 0 {
		vidField := openflow13.NewVlanIdField(self.Match.VlanId, nil)
		ofMatch.AddField(*vidField)
	}

	// Handle ARP Oper type
	if self.Match.ArpOper != 0 {
		arpOperField := openflow13.NewArpOperField(self.Match.ArpOper)
		ofMatch.AddField(*arpOperField)
	}

	// Handle ARP THA
	if self.Match.ArpTha != nil {
		arpTHAField := openflow13.NewArpThaField(*self.Match.ArpTha)
		ofMatch.AddField(*arpTHAField)
	}

	// Handle ARP SHA
	if self.Match.ArpSha != nil {
		arpSHAField := openflow13.NewArpShaField(*self.Match.ArpSha)
		ofMatch.AddField(*arpSHAField)
	}

	// Handle ARP TPA
	if self.Match.ArpTpa != nil {
		arpTPAField := openflow13.NewArpTpaField(*self.Match.ArpTpa)
		ofMatch.AddField(*arpTPAField)
	}

	// Handle ARP SPA
	if self.Match.ArpSpa != nil {
		arpSPAField := openflow13.NewArpSpaField(*self.Match.ArpSpa)
		ofMatch.AddField(*arpSPAField)
	}

	// Handle IP Dst
	if self.Match.IpDa != nil {
		if self.Match.IpDaMask != nil {
			ipDaField := openflow13.NewIpv4DstField(*self.Match.IpDa, self.Match.IpDaMask)
			ofMatch.AddField(*ipDaField)
		} else {
			ipDaField := openflow13.NewIpv4DstField(*self.Match.IpDa, nil)
			ofMatch.AddField(*ipDaField)
		}
	}

	// Handle IP Src
	if self.Match.IpSa != nil {
		if self.Match.IpSaMask != nil {
			ipSaField := openflow13.NewIpv4SrcField(*self.Match.IpSa, self.Match.IpSaMask)
			ofMatch.AddField(*ipSaField)
		} else {
			ipSaField := openflow13.NewIpv4SrcField(*self.Match.IpSa, nil)
			ofMatch.AddField(*ipSaField)
		}
	}

	// Handle IPv6 Dst
	if self.Match.Ipv6Da != nil {
		ipv6DaField := openflow13.NewIpv6DstField(*self.Match.Ipv6Da, self.Match.Ipv6DaMask)
		ofMatch.AddField(*ipv6DaField)
	}

	// Handle IPv6 Src
	if self.Match.Ipv6Sa != nil {
		ipv6SaField := openflow13.NewIpv6SrcField(*self.Match.Ipv6Sa, self.Match.Ipv6SaMask)
		ofMatch.AddField(*ipv6SaField)
	}

	// Handle IP protocol
	if self.Match.IpProto != 0 {
		protoField := openflow13.NewIpProtoField(self.Match.IpProto)
		ofMatch.AddField(*protoField)
	}

	// Handle IP dscp
	if self.Match.IpDscp != 0 {
		dscpField := openflow13.NewIpDscpField(self.Match.IpDscp)
		ofMatch.AddField(*dscpField)
	}

	// Handle port numbers
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpSrcPort != 0 {
		portField := openflow13.NewTcpSrcField(self.Match.TcpSrcPort)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpDstPort != 0 {
		portField := openflow13.NewTcpDstField(self.Match.TcpDstPort)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_UDP && self.Match.UdpSrcPort != 0 {
		portField := openflow13.NewUdpSrcField(self.Match.UdpSrcPort)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_UDP && self.Match.UdpDstPort != 0 {
		portField := openflow13.NewUdpDstField(self.Match.UdpDstPort)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_SCTP && self.Match.SctpSrcPort != 0 {
		portField := openflow13.NewSctpSrcField(self.Match.SctpSrcPort)
		ofMatch.AddField(*portField)
	}
	if self.Match.IpProto == IP_PROTO_SCTP && self.Match.SctpDstPort != 0 {
		portField := openflow13.NewSctpDstField(self.Match.SctpDstPort)
		ofMatch.AddField(*portField)
	}

	// Handle tcp flags
	if self.Match.IpProto == IP_PROTO_TCP && self.Match.TcpFlags != nil {
		tcpFlagField := openflow13.NewTcpFlagsField(*self.Match.TcpFlags, self.Match.TcpFlagsMask)
		ofMatch.AddField(*tcpFlagField)
	}

	// Handle metadata
	if self.Match.Metadata != nil {
		if self.Match.MetadataMask != nil {
			metadataField := openflow13.NewMetadataField(*self.Match.Metadata, self.Match.MetadataMask)
			ofMatch.AddField(*metadataField)
		} else {
			metadataField := openflow13.NewMetadataField(*self.Match.Metadata, nil)
			ofMatch.AddField(*metadataField)
		}
	}

	// Handle Vxlan tunnel id
	if self.Match.TunnelId != 0 {
		tunnelIdField := openflow13.NewTunnelIdField(self.Match.TunnelId)
		ofMatch.AddField(*tunnelIdField)
	}

	// Handle conjunction id
	if self.Match.ConjunctionID != nil {
		conjIDField := openflow13.NewConjIDMatchField(*self.Match.ConjunctionID)
		ofMatch.AddField(*conjIDField)
	}

	// Handle ct states
	if self.Match.CtStates != nil {
		ctStateField := openflow13.NewCTStateMatchField(self.Match.CtStates)
		ofMatch.AddField(*ctStateField)
	}

	// Handle reg match
	if self.Match.NxRegs != nil {
		regMap := make(map[int][]*NXRegister)
		for _, reg := range self.Match.NxRegs {
			_, found := regMap[reg.ID]
			if !found {
				regMap[reg.ID] = []*NXRegister{reg}
			} else {
				regMap[reg.ID] = append(regMap[reg.ID], reg)
			}
		}
		for _, regs := range regMap {
			reg := merge(regs)
			regField := openflow13.NewRegMatchField(reg.ID, reg.Data, reg.Range)
			ofMatch.AddField(*regField)
		}
	}

	// Handle xxreg match
	if self.Match.XxRegs != nil {
		for _, reg := range self.Match.XxRegs {
			fieldName := fmt.Sprintf("NXM_NX_XXReg%d", reg.ID)
			field, _ := openflow13.FindFieldHeaderByName(fieldName, false)
			field.Value = &openflow13.ByteArrayField{Data: reg.Data, Length: uint8(len(reg.Data))}
			ofMatch.AddField(*field)
		}
	}

	// Handle ct_mark match
	if self.Match.CtMark != 0 {
		ctMarkField := openflow13.NewCTMarkMatchField(self.Match.CtMark, self.Match.CtMarkMask)
		ofMatch.AddField(*ctMarkField)
	}

	// Handle actset_output match
	if self.Match.ActsetOutput != 0 {
		actsetOutputField := openflow13.NewActsetOutputField(self.Match.ActsetOutput)
		ofMatch.AddField(*actsetOutputField)
	}

	// Handle tun_metadata match
	if len(self.Match.TunMetadatas) > 0 {
		for _, m := range self.Match.TunMetadatas {
			data := getDataBytes(m.Data, m.Range)
			var mask []byte
			if m.Range != nil {
				start := int(m.Range.GetOfs())
				length := int(m.Range.GetNbits())
				mask = getMaskBytes(start, length)
			}
			tmField := openflow13.NewTunMetadataField(m.ID, data, mask)
			ofMatch.AddField(*tmField)
		}
	}

	if self.Match.CtIpSa != nil {
		ctIPSaField, _ := openflow13.FindFieldHeaderByName("NXM_NX_CT_NW_SRC", false)
		ctIPSaField.Value = &openflow13.Ipv4SrcField{
			Ipv4Src: *self.Match.CtIpSa,
		}
		if self.Match.CtIpSaMask != nil {
			mask := new(openflow13.Ipv4SrcField)
			mask.Ipv4Src = *self.Match.CtIpSaMask
			ctIPSaField.HasMask = true
			ctIPSaField.Mask = mask
			ctIPSaField.Length += uint8(mask.Len())
		}
		ofMatch.AddField(*ctIPSaField)
	}

	if self.Match.CtIpDa != nil {
		ctIPDaField, _ := openflow13.FindFieldHeaderByName("NXM_NX_CT_NW_DST", false)
		ctIPDaField.Value = &openflow13.Ipv4DstField{
			Ipv4Dst: *self.Match.CtIpDa,
		}
		if self.Match.CtIpDaMask != nil {
			mask := new(openflow13.Ipv4DstField)
			mask.Ipv4Dst = *self.Match.CtIpDaMask
			ctIPDaField.HasMask = true
			ctIPDaField.Mask = mask
			ctIPDaField.Length += uint8(mask.Len())
		}
		ofMatch.AddField(*ctIPDaField)
	}

	if self.Match.CtIpProto > 0 {
		ctIPProtoField, _ := openflow13.FindFieldHeaderByName("NXM_NX_CT_NW_PROTO", false)
		ctIPProtoField.Value = &ProtocolField{protocol: self.Match.CtIpProto}
		ofMatch.AddField(*ctIPProtoField)
	}

	if self.Match.CtIpv6Sa != nil {
		ctIPv6SaField, _ := openflow13.FindFieldHeaderByName("NXM_NX_CT_IPV6_SRC", false)
		ctIPv6SaField.Value = &openflow13.Ipv6SrcField{Ipv6Src: *self.Match.CtIpv6Sa}
		ofMatch.AddField(*ctIPv6SaField)
	}

	if self.Match.CtIpv6Da != nil {
		ctIPv6DaField, _ := openflow13.FindFieldHeaderByName("NXM_NX_CT_IPV6_DST", false)
		ctIPv6DaField.Value = &openflow13.Ipv6DstField{Ipv6Dst: *self.Match.CtIpv6Da}
		ofMatch.AddField(*ctIPv6DaField)
	}

	if self.Match.CtTpSrcPort > 0 {
		ctTpSrcPortField, _ := openflow13.FindFieldHeaderByName("NXM_NX_CT_TP_SRC", false)
		ctTpSrcPortField.Value = &PortField{port: self.Match.CtTpSrcPort}
		ofMatch.AddField(*ctTpSrcPortField)
	}

	if self.Match.CtTpDstPort > 0 {
		ctTpDstPortField, _ := openflow13.FindFieldHeaderByName("NXM_NX_CT_TP_DST", false)
		ctTpDstPortField.Value = &PortField{port: self.Match.CtTpDstPort}
		ofMatch.AddField(*ctTpDstPortField)
	}

	return *ofMatch
}

func getRangeEnd(rng *openflow13.NXRange) uint16 {
	return rng.GetOfs() + rng.GetNbits() - 1
}

func merge(regs []*NXRegister) *NXRegister {
	if len(regs) == 1 {
		return regs[0]
	}
	var data uint32
	min := regs[0].Range.GetOfs()
	max := getRangeEnd(regs[0].Range)
	for _, reg := range regs {
		data |= reg.Data << reg.Range.GetOfs()
		end := getRangeEnd(reg.Range)
		if reg.Range.GetOfs() < min {
			min = reg.Range.GetOfs()
		}
		if end > max {
			max = end
		}
	}
	return &NXRegister{
		ID:    regs[0].ID,
		Data:  data,
		Range: openflow13.NewNXRange(int(min), int(max)),
	}
}

func getDataBytes(value interface{}, nxRange *openflow13.NXRange) []byte {
	start := int(nxRange.GetOfs())
	length := int(nxRange.GetNbits())
	switch v := value.(type) {
	case uint32:
		rst := getUint32WithOfs(v, start, length)
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, rst)
		return data
	case uint64:
		rst := getUint64WithOfs(v, start, length)
		data := make([]byte, 8)
		binary.BigEndian.PutUint64(data, rst)
		return data
	case []byte:
		return v
	}
	return nil
}

func getUint32WithOfs(data uint32, start, length int) uint32 {
	return data << (32 - length) >> (32 - length - start)
}

func getUint64WithOfs(data uint64, start, length int) uint64 {
	return data << (64 - length) >> (64 - length - start)
}

func getMaskBytes(start, length int) []byte {
	end := start + length - 1
	if end < 32 {
		data := make([]byte, 4)
		mask := getUint32WithOfs(^uint32(0), start, length)
		binary.BigEndian.PutUint32(data, mask)
		return data
	}
	if end < 64 {
		data := make([]byte, 8)
		mask := getUint64WithOfs(^uint64(0), start, length)
		binary.BigEndian.PutUint64(data, mask)
		return data
	}
	i := 0
	bytesLength := 8 * ((end + 63) / 64)
	data := make([]byte, bytesLength)
	for i < bytesLength {
		subStart := i * 64
		subEnd := i*64 + 63
		if start > subEnd {
			binary.BigEndian.PutUint64(data[i:], uint64(0))
			i += 8
			continue
		}
		var rngStart, rngLength int
		if start < subStart {
			rngStart = 0
		} else {
			rngStart = start - subStart
		}
		if end > subEnd {
			rngLength = 64 - rngStart
		} else {
			rngLength = (end - subStart) - rngStart + 1
		}
		data = append(data, getMaskBytes(rngStart, rngLength)...)
		i += 8
	}
	return data
}

// Install all flow Actions
func (self *Flow) installFlowActions(flowMod *openflow13.FlowMod,
	instr openflow13.Instruction) error {
	var actInstr openflow13.Instruction
	var addActn bool = false
	var err error

	// Create a apply_action instruction to be used if its not already created
	switch instr.(type) {
	case *openflow13.InstrActions:
		actInstr = instr
	default:
		actInstr = openflow13.NewInstrApplyActions()
	}

	// Loop thru all Actions in reversed order, and prepend the action into instruction, so that the Actions is in the
	// order as it is added by the client.
	for i := len(self.flowActions) - 1; i >= 0; i-- {
		flowAction := self.flowActions[i]
		switch flowAction.ActionType {
		case ActTypeSetVlan:
			// Push Vlan Tag action
			pushVlanAction := openflow13.NewActionPushVlan(0x8100)

			// Set Outer vlan tag field
			vlanField := openflow13.NewVlanIdField(flowAction.vlanId, nil)
			setVlanAction := openflow13.NewActionSetField(*vlanField)

			// Prepend push vlan & setvlan Actions to existing instruction
			err = actInstr.AddAction(setVlanAction, true)
			if err != nil {
				return err
			}
			err = actInstr.AddAction(pushVlanAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added pushvlan action: %+v, setVlan Actions: %+v",
				pushVlanAction, setVlanAction)

		case ActTypePopVlan:
			// Create pop vln action
			popVlan := openflow13.NewActionPopVlan()

			// Add it to instruction
			err = actInstr.AddAction(popVlan, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added popVlan action: %+v", popVlan)

		case ActTypeSetDstMac:
			// Set Outer MacDA field
			macDaField := openflow13.NewEthDstField(flowAction.macAddr, nil)
			setMacDaAction := openflow13.NewActionSetField(*macDaField)

			// Add set macDa action to the instruction
			err = actInstr.AddAction(setMacDaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setMacDa action: %+v", setMacDaAction)

		case ActTypeSetSrcMac:
			// Set Outer MacSA field
			macSaField := openflow13.NewEthSrcField(flowAction.macAddr, nil)
			setMacSaAction := openflow13.NewActionSetField(*macSaField)

			// Add set macDa action to the instruction
			err = actInstr.AddAction(setMacSaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setMacSa Action: %+v", setMacSaAction)

		case ActTypeSetTunnelID:
			// Set tunnelId field
			tunnelIdField := openflow13.NewTunnelIdField(flowAction.tunnelId)
			setTunnelAction := openflow13.NewActionSetField(*tunnelIdField)

			// Add set tunnel action to the instruction
			err = actInstr.AddAction(setTunnelAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setTunnelId Action: %+v", setTunnelAction)

		case "setMetadata":
			// Set Metadata instruction
			metadataInstr := openflow13.NewInstrWriteMetadata(flowAction.metadata, flowAction.metadataMask)

			// Add the instruction to flowmod
			flowMod.AddInstruction(metadataInstr)

		case ActTypeSetSrcIP:
			// Set IP src
			ipSaField := openflow13.NewIpv4SrcField(flowAction.ipAddr, nil)
			setIPSaAction := openflow13.NewActionSetField(*ipSaField)

			// Add set action to the instruction
			err = actInstr.AddAction(setIPSaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setIPSa Action: %+v", setIPSaAction)

		case ActTypeSetDstIP:
			// Set IP dst
			ipDaField := openflow13.NewIpv4DstField(flowAction.ipAddr, nil)
			setIPDaAction := openflow13.NewActionSetField(*ipDaField)

			// Add set action to the instruction
			err = actInstr.AddAction(setIPDaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setIPDa Action: %+v", setIPDaAction)

		case ActTypeSetTunnelSrcIP:
			// Set tunnel src addr field
			tunnelSrcField := openflow13.NewTunnelIpv4SrcField(flowAction.ipAddr, nil)
			setTunnelSrcAction := openflow13.NewActionSetField(*tunnelSrcField)

			// Add set tunnel action to the instruction
			err = actInstr.AddAction(setTunnelSrcAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setTunSa Action: %+v", setTunnelSrcAction)

		case ActTypeSetTunnelDstIP:
			// Set tunnel dst addr field
			tunnelDstField := openflow13.NewTunnelIpv4DstField(flowAction.ipAddr, nil)
			setTunnelAction := openflow13.NewActionSetField(*tunnelDstField)

			// Add set tunnel action to the instruction
			err = actInstr.AddAction(setTunnelAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setTunDa Action: %+v", setTunnelAction)

		case ActTypeSetDSCP:
			// Set DSCP field
			ipDscpField := openflow13.NewIpDscpField(flowAction.dscp)
			setIPDscpAction := openflow13.NewActionSetField(*ipDscpField)

			// Add set action to the instruction
			err = actInstr.AddAction(setIPDscpAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setDscp Action: %+v", setIPDscpAction)

		case ActTypeSetARPOper:
			// Set ARP operation type field
			arpOpField := openflow13.NewArpOperField(flowAction.arpOper)
			setARPOpAction := openflow13.NewActionSetField(*arpOpField)

			// Add set ARP operation type action to the instruction
			err = actInstr.AddAction(setARPOpAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setArpOper Action: %+v", setARPOpAction)

		case ActTypeSetARPSHA:
			// Set ARP_SHA field
			arpShaField := openflow13.NewArpShaField(flowAction.macAddr)
			setARPShaAction := openflow13.NewActionSetField(*arpShaField)

			// Append set ARP_SHA action to the instruction
			err = actInstr.AddAction(setARPShaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setARPSha Action: %+v", setARPShaAction)

		case ActTypeSetARPTHA:
			// Set ARP_THA field
			arpThaField := openflow13.NewArpThaField(flowAction.macAddr)
			setARPThaAction := openflow13.NewActionSetField(*arpThaField)

			// Add set ARP_THA action to the instruction
			err = actInstr.AddAction(setARPThaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setARPTha Action: %+v", setARPThaAction)

		case ActTypeSetARPSPA:
			// Set ARP_SPA field
			arpSpaField := openflow13.NewArpSpaField(flowAction.ipAddr)
			setARPSpaAction := openflow13.NewActionSetField(*arpSpaField)

			// Add set ARP_SPA action to the instruction
			err = actInstr.AddAction(setARPSpaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setARPSpa Action: %+v", setARPSpaAction)
		case ActTypeSetARPTPA:
			// Set ARP_TPA field
			arpTpaField := openflow13.NewArpTpaField(flowAction.ipAddr)
			setARPTpaAction := openflow13.NewActionSetField(*arpTpaField)

			// Add set ARP_SPA action to the instruction
			err = actInstr.AddAction(setARPTpaAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setARPTpa Action: %+v", setARPTpaAction)
		case ActTypeSetTCPsPort:
			// Set TCP src
			tcpSrcField := openflow13.NewTcpSrcField(flowAction.l4Port)
			setTCPSrcAction := openflow13.NewActionSetField(*tcpSrcField)

			// Add set action to the instruction
			err = actInstr.AddAction(setTCPSrcAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setTCPSrc Action: %+v", setTCPSrcAction)

		case ActTypeSetTCPdPort:
			// Set TCP dst
			tcpDstField := openflow13.NewTcpDstField(flowAction.l4Port)
			setTCPDstAction := openflow13.NewActionSetField(*tcpDstField)

			// Add set action to the instruction
			err = actInstr.AddAction(setTCPDstAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setTCPDst Action: %+v", setTCPDstAction)

		case ActTypeSetUDPsPort:
			// Set UDP src
			udpSrcField := openflow13.NewUdpSrcField(flowAction.l4Port)
			setUDPSrcAction := openflow13.NewActionSetField(*udpSrcField)

			// Add set action to the instruction
			err = actInstr.AddAction(setUDPSrcAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setUDPSrc Action: %+v", setUDPSrcAction)

		case ActTypeSetUDPdPort:
			// Set UDP dst
			udpDstField := openflow13.NewUdpDstField(flowAction.l4Port)
			setUDPDstAction := openflow13.NewActionSetField(*udpDstField)

			// Add set action to the instruction
			err = actInstr.AddAction(setUDPDstAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow install. Added setUDPDst Action: %+v", setUDPDstAction)
		case ActTypeSetSCTPsPort:
			// Set SCTP src
			sctpSrcField := openflow13.NewSctpSrcField(flowAction.l4Port)
			setSCTPSrcAction := openflow13.NewActionSetField(*sctpSrcField)

			// Add set action to the instruction
			err = actInstr.AddAction(setSCTPSrcAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setSCTPSrc Action: %+v", setSCTPSrcAction)

		case ActTypeSetSCTPdPort:
			// Set SCTP dst
			sctpDstField := openflow13.NewSctpSrcField(flowAction.l4Port)
			setSCTPDstAction := openflow13.NewActionSetField(*sctpDstField)

			// Add set action to the instruction
			err = actInstr.AddAction(setSCTPDstAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added setSCTPSrc Action: %+v", setSCTPDstAction)

		case ActTypeNXLoad:
			// Create NX load action
			loadAct := flowAction.loadAct
			loadRegAction := loadAct.GetActionMessage()

			// Add load action to the instruction
			err = actInstr.AddAction(loadRegAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added loadReg Action: %+v", loadRegAction)

		case ActTypeNXMove:
			// Create NX move action
			moveRegAction := flowAction.moveAct.GetActionMessage()

			// Add move action to the instruction
			err = actInstr.AddAction(moveRegAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added moveReg Action: %+v", moveRegAction)

		case ActTypeNXCT:
			ctAction := flowAction.connTrack.GetActionMessage()

			// Add conn_track action to the instruction
			err = actInstr.AddAction(ctAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added ct Action: %+v", ctAction)

		case ActTypeNXConjunction:
			// Create NX conjunction action
			conjAction := flowAction.conjunction.GetActionMessage()

			// Add conn_track action to the instruction
			err = actInstr.AddAction(conjAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added conjunction Action: %+v", conjAction)

		case ActTypeDecTTL:
			decTtlAction := openflow13.NewActionDecNwTtl()
			// Add dec_ttl action to the instruction
			err = actInstr.AddAction(decTtlAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added decTTL Action: %+v", decTtlAction)
		case ActTypeNXResubmit:
			resubmitAction := flowAction.resubmit
			// Add resubmit action to the instruction
			err = actInstr.AddAction(resubmitAction.GetActionMessage(), true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added resubmit Action: %+v", resubmitAction)
		case ActTypeNXLearn:
			learnAction := flowAction.learn
			// Add learn action to the instruction
			err = actInstr.AddAction(learnAction.GetActionMessage(), true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added learn Action: %+v", learnAction)
		case ActTypeNXNote:
			notes := flowAction.notes
			noteAction := openflow13.NewNXActionNote()
			noteAction.Note = notes
			// Add note action to the instruction
			err = actInstr.AddAction(noteAction, true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added note Action: %+v", noteAction)
		case ActTypeNXOutput:
			nxOutput := flowAction.nxOutput
			// Add NXOutput action to the instruction
			err = actInstr.AddAction(nxOutput.GetActionMessage(), true)
			if err != nil {
				return err
			}
			addActn = true

			log.Debugf("flow action: Added nxOutput Action: %+v", nxOutput)
		case ActTypeController:
			act := flowAction.controller
			err = actInstr.AddAction(act.GetActionMessage(), true)
			if err != nil {
				return err
			}
			addActn = true
			log.Debugf("flow action: Added controller Action: %+v", act)
		default:
			log.Fatalf("Unknown action type %s", flowAction.ActionType)
			return UnknownActionTypeError
		}
	}

	// Add the instruction to flow if its not already added
	if (addActn) && (actInstr != instr) {
		// Add the instruction to flowmod
		flowMod.AddInstruction(actInstr)
	}

	return nil
}

// GenerateFlowModMessage translates the Flow a FlowMod message according to the commandType.
func (self *Flow) GenerateFlowModMessage(commandType int) (flowMod *openflow13.FlowMod, err error) {
	// Create a flowmode entry
	flowMod = openflow13.NewFlowMod()
	flowMod.TableId = self.Table.TableId
	flowMod.Priority = self.Match.Priority
	// Cookie ID could be set by client, using globalFlowID if not set
	if self.CookieID == 0 {
		self.CookieID = globalFlowID // FIXME: need a better id allocation
		globalFlowID += 1
	}
	flowMod.Cookie = self.CookieID
	if self.CookieMask > 0 {
		flowMod.CookieMask = self.CookieMask
	}
	if self.HardTimeout > 0 {
		flowMod.HardTimeout = self.HardTimeout
	}
	if self.IdleTimeout > 0 {
		flowMod.IdleTimeout = self.IdleTimeout
	}
	flowMod.Command = uint8(commandType)

	// convert match fields to openflow 1.3 format
	flowMod.Match = self.xlateMatch()
	log.Debugf("flow install: Match: %+v", flowMod.Match)
	if commandType != openflow13.FC_DELETE && commandType != openflow13.FC_DELETE_STRICT {

		// Based on the next elem, decide what to install
		switch self.NextElem.Type() {
		case "table":
			// Get the instruction set from the element
			instr := self.NextElem.GetFlowInstr()

			// Check if there are any flow actions to perform
			err = self.installFlowActions(flowMod, instr)
			if err != nil {
				return
			}

			// Add the instruction to flowmod
			flowMod.AddInstruction(instr)

			log.Debugf("flow install: added goto table instr: %+v", instr)

		case "flood":
			fallthrough
		case "output":
			// Get the instruction set from the element
			instr := self.NextElem.GetFlowInstr()

			// Add the instruction to flowmod if its not nil
			// a nil instruction means drop action
			if instr != nil {

				// Check if there are any flow actions to perform
				err = self.installFlowActions(flowMod, instr)
				if err != nil {
					return
				}

				flowMod.AddInstruction(instr)

				log.Debugf("flow install: added next instr: %+v", instr)
			}
		case "group":
			fallthrough
		case "Resubmit":
			// Get the instruction set from the element
			instr := self.NextElem.GetFlowInstr()

			// Add the instruction to flowmod if its not nil
			// a nil instruction means drop action
			if instr != nil {

				// Check if there are any flow actions to perform
				err = self.installFlowActions(flowMod, instr)
				if err != nil {
					return
				}

				flowMod.AddInstruction(instr)

				log.Debugf("flow install: added next instr: %+v", instr)
			}
		case "empty":
			// Get the instruction set from the element. This instruction is InstrActions with no actions
			instr := self.NextElem.GetFlowInstr()
			if instr != nil {

				// Check if there are any flow actions to perform
				err = self.installFlowActions(flowMod, instr)
				if err != nil {
					return
				}
				if len(instr.(*openflow13.InstrActions).Actions) > 0 {
					flowMod.AddInstruction(instr)
				}

				log.Debugf("flow install: added next instr: %+v", instr)
			}

		default:
			log.Fatalf("Unknown Fgraph element type %s", self.NextElem.Type())
			err = UnknownElementTypeError
			return
		}
	}
	return
}

// Install a flow entry
func (self *Flow) install() error {
	command := openflow13.FC_MODIFY_STRICT
	// Add or modify
	if !self.isInstalled {
		command = openflow13.FC_ADD
	}
	flowMod, err := self.GenerateFlowModMessage(command)
	if err != nil {
		return err
	}
	log.Debugf("Sending flowmod: %+v", flowMod)

	// Send the message
	if err := self.Table.Switch.Send(flowMod); err != nil {
		return err
	}

	// Mark it as installed
	self.isInstalled = true

	return nil
}

// updateInstallStatus changes isInstalled value.
func (self *Flow) UpdateInstallStatus(installed bool) {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.isInstalled = installed
}

// Set Next element in the Fgraph. This determines what actions will be
// part of the flow's instruction set
func (self *Flow) Next(elem FgraphElem) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	// Set the next element in the graph
	self.NextElem = elem

	// Install the flow entry
	return self.install()
}

// Special action on the flow to set vlan id
func (self *Flow) SetVlan(vlanId uint16) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetVlan
	action.vlanId = vlanId

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special action on the flow to set vlan id
func (self *Flow) PopVlan() error {
	action := new(FlowAction)
	action.ActionType = ActTypePopVlan

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special action on the flow to set mac dest addr
func (self *Flow) SetMacDa(macDa net.HardwareAddr) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetDstMac
	action.macAddr = macDa

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special action on the flow to set mac source addr
func (self *Flow) SetMacSa(macSa net.HardwareAddr) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetSrcMac
	action.macAddr = macSa

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special action on the flow to set an ip field
func (self *Flow) SetIPField(ip net.IP, field string) error {
	action := new(FlowAction)
	action.ipAddr = ip
	if field == "Src" {
		action.ActionType = ActTypeSetSrcIP
	} else if field == "Dst" {
		action.ActionType = ActTypeSetDstIP
	} else if field == "TunSrc" {
		action.ActionType = ActTypeSetTunnelSrcIP
	} else if field == "TunDst" {
		action.ActionType = ActTypeSetTunnelDstIP
	} else {
		return errors.New("field not supported")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special action on the flow to set arp_spa field
func (self *Flow) SetARPSpa(ip net.IP) error {
	action := new(FlowAction)
	action.ipAddr = ip
	action.ActionType = ActTypeSetARPSPA

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special action on the flow to set arp_spa field
func (self *Flow) SetARPTpa(ip net.IP) error {
	action := new(FlowAction)
	action.ipAddr = ip
	action.ActionType = ActTypeSetARPTPA

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special action on the flow to set a L4 field
func (self *Flow) SetL4Field(port uint16, field string) error {
	action := new(FlowAction)
	action.l4Port = port

	switch field {
	case "TCPSrc":
		action.ActionType = ActTypeSetTCPsPort
		break
	case "TCPDst":
		action.ActionType = ActTypeSetTCPdPort
		break
	case "UDPSrc":
		action.ActionType = ActTypeSetUDPsPort
		break
	case "UDPDst":
		action.ActionType = ActTypeSetUDPdPort
		break
	case "SCTPSrc":
		action.ActionType = ActTypeSetSCTPsPort
		break
	case "SCTPDst":
		action.ActionType = ActTypeSetSCTPdPort
		break
	default:
		return errors.New("field not supported")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special actions on the flow to set metadata
func (self *Flow) SetMetadata(metadata, metadataMask uint64) error {
	action := new(FlowAction)
	action.ActionType = "setMetadata"
	action.metadata = metadata
	action.metadataMask = metadataMask

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special actions on the flow to set vlan id
func (self *Flow) SetTunnelId(tunnelId uint64) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetTunnelID
	action.tunnelId = tunnelId

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special actions on the flow to set dscp field
func (self *Flow) SetDscp(dscp uint8) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetDSCP
	action.dscp = dscp

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// unset dscp field
func (self *Flow) UnsetDscp() error {
	self.lock.Lock()
	defer self.lock.Unlock()

	// Delete to the action from db
	for idx, act := range self.flowActions {
		if act.ActionType == ActTypeSetDSCP {
			self.flowActions = append(self.flowActions[:idx], self.flowActions[idx+1:]...)
		}
	}

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

func (self *Flow) SetARPOper(arpOp uint16) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetARPOper
	action.arpOper = arpOp

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special action on the flow to set ARP source host addr
func (self *Flow) SetARPSha(arpSha net.HardwareAddr) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetARPSHA
	action.macAddr = arpSha

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special action on the flow to set ARP target host addr
func (self *Flow) SetARPTha(arpTha net.HardwareAddr) error {
	action := new(FlowAction)
	action.ActionType = ActTypeSetARPTHA
	action.macAddr = arpTha

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)

	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special Actions on the flow to load data into OXM/NXM field
func (self *Flow) LoadReg(fieldName string, data uint64, dataRange *openflow13.NXRange) error {
	loadAct, err := NewNXLoadAction(fieldName, data, dataRange)
	if err != nil {
		return err
	}
	if self.Table != nil && self.Table.Switch != nil {
		loadAct.ResetFieldLength(self.Table.Switch)
	}
	action := new(FlowAction)
	action.ActionType = loadAct.GetActionType()
	action.loadAct = loadAct
	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special Actions on the flow to move data from src_field[rng] to dst_field[rng]
func (self *Flow) MoveRegs(srcName string, dstName string, srcRange *openflow13.NXRange, dstRange *openflow13.NXRange) error {
	moveAct, err := NewNXMoveAction(srcName, dstName, srcRange, dstRange)
	if err != nil {
		return err
	}
	if self.Table != nil && self.Table.Switch != nil {
		moveAct.ResetFieldsLength(self.Table.Switch)
	}

	action := new(FlowAction)
	action.ActionType = moveAct.GetActionType()
	action.moveAct = moveAct
	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

func (self *Flow) Resubmit(ofPort uint16, tableID uint8) error {
	action := new(FlowAction)
	action.resubmit = NewResubmit(&ofPort, &tableID)
	action.ActionType = action.resubmit.GetActionType()
	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special actions on the flow for connection trackng
func (self *Flow) ConnTrack(commit bool, force bool, tableID *uint8, zoneID *uint16, execActions ...openflow13.Action) error {
	connTrack := &NXConnTrackAction{
		commit:  commit,
		force:   force,
		table:   tableID,
		zone:    zoneID,
		actions: execActions,
	}
	action := new(FlowAction)
	action.ActionType = connTrack.GetActionType()
	action.connTrack = connTrack
	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special Actions to to the flow to set conjunctions
// Note:
//   1) nclause should be in [2, 64].
//   2) clause value should be less than or equals to ncluase, and its value should be started from 1.
//      actual clause in libopenflow messages is started from 0, here would decrement 1 to keep the display
//      value is consistent with expected configuration
func (self *Flow) AddConjunction(conjID uint32, clause uint8, nClause uint8) error {
	conjunction, err := NewNXConjunctionAction(conjID, clause, nClause)
	if err != nil {
		return nil
	}

	action := new(FlowAction)
	action.ActionType = conjunction.GetActionType()
	action.conjunction = conjunction
	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

func (self *Flow) DelConjunction(conjID uint32) error {
	found := false

	self.lock.Lock()
	defer self.lock.Unlock()

	// Remove conjunction from the action db
	for i, act := range self.flowActions {
		if act.ActionType == ActTypeNXConjunction {
			conjuncAct := act.conjunction
			if conjID == conjuncAct.ID {
				self.flowActions = append(self.flowActions[:i], self.flowActions[i+1:]...)
				found = true
			}
		}
	}

	if !found {
		return nil
	}

	// Return EmptyFlowActionError if there is no Actions left in flow
	if len(self.flowActions) == 0 {
		return EmptyFlowActionError
	}
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special Actions to the flow to dec TTL
func (self *Flow) DecTTL() error {
	action := new(FlowAction)
	action.ActionType = ActTypeDecTTL
	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Special Actions to the flow to learn from the current packet and generate a new flow entry.
func (self *Flow) Learn(learn *FlowLearn) error {
	action := new(FlowAction)
	action.ActionType = ActTypeNXLearn
	action.learn = learn
	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

func (self *Flow) Note(data []byte) error {
	action := new(FlowAction)
	action.ActionType = ActTypeNXNote
	action.notes = data
	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}
func (self *Flow) OutputReg(name string, start int, end int) error {
	action := new(FlowAction)
	var err error
	action.nxOutput, err = NewNXOutput(name, start, end)
	if err != nil {
		return err
	}
	action.ActionType = action.nxOutput.GetActionType()

	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

func (self *Flow) Controller(reason uint8) error {
	action := new(FlowAction)
	action.controller = &NXController{
		ControllerID: self.Table.Switch.ctrlID,
		Reason:       reason,
	}
	action.ActionType = action.controller.GetActionType()
	self.lock.Lock()
	defer self.lock.Unlock()

	// Add to the action db
	self.flowActions = append(self.flowActions, action)
	// If the flow entry was already installed, re-install it
	if self.isInstalled {
		return self.install()
	}

	return nil
}

// Delete the flow
func (self *Flow) Delete() error {
	self.lock.Lock()
	defer self.lock.Unlock()

	// Delete from ofswitch
	if self.isInstalled {
		// Create a flowmode entry
		flowMod := openflow13.NewFlowMod()
		flowMod.Command = openflow13.FC_DELETE_STRICT
		flowMod.TableId = self.Table.TableId
		flowMod.Priority = self.Match.Priority
		flowMod.Cookie = self.CookieID
		if self.CookieMask > 0 {
			flowMod.CookieMask = self.CookieMask
		} else {
			flowMod.CookieMask = 0xffffffffffffffff
		}
		flowMod.OutPort = openflow13.P_ANY
		flowMod.OutGroup = openflow13.OFPG_ANY
		flowMod.Match = self.xlateMatch()

		log.Debugf("Sending DELETE flowmod: %+v", flowMod)

		// Send the message
		if err := self.Table.Switch.Send(flowMod); err != nil {
			return err
		}
	}

	// Delete it from the Table
	flowKey := self.flowKey()
	return self.Table.DeleteFlow(flowKey)
}

func (self *Flow) SetRealized() {
	self.statusLock.Lock()
	defer self.statusLock.Unlock()
	self.realized = true
}

// IsRealized gets flow realized status
func (self *Flow) IsRealized() bool {
	self.statusLock.Lock()
	defer self.statusLock.Unlock()
	return self.realized
}

// MonitorRealizeStatus sends MultipartRequest to get current flow status, it is calling if needs to check
// flow's realized status
func (self *Flow) MonitorRealizeStatus() {
	stats, err := self.Table.Switch.DumpFlowStats(self.CookieID, self.CookieMask, &self.Match, &self.Table.TableId)
	if err != nil {
		self.realized = false
	}
	if stats != nil {
		self.realized = true
	}
}

func (self *Flow) GetBundleMessage(command int) (*FlowBundleMessage, error) {
	var flowMod *openflow13.FlowMod
	var err error
	if self.NextElem != nil {
		flowMod, err = self.GenerateFlowModMessage(command)
	} else {
		flowMod, err = self.generateFlowMessage(command)
	}
	if err != nil {
		return nil, err
	}
	return &FlowBundleMessage{flowMod}, nil
}

func (self *Flow) ApplyAction(action OFAction) {
	self.appliedActions = append(self.appliedActions, action)
}

func (self *Flow) ApplyActions(actions []OFAction) {
	self.appliedActions = append(self.appliedActions, actions...)
}

func (self *Flow) ResetApplyActions(actions []OFAction) {
	self.appliedActions = nil
	self.ApplyActions(actions)
}

func (self *Flow) WriteAction(action OFAction) {
	self.writeActions = append(self.writeActions, action)
}

func (self *Flow) WriteActions(actions []OFAction) {
	self.writeActions = append(self.writeActions, actions...)
}

func (self *Flow) ResetWriteActions(actions []OFAction) {
	self.writeActions = nil
	self.WriteActions(actions)
}

func (self *Flow) WriteMetadata(metadata uint64, metadataMask uint64) {
	self.metadata = &writeMetadata{metadata, metadataMask}
}

func (self *Flow) Goto(tableID uint8) {
	self.gotoTable = &tableID
}

func (self *Flow) ClearActions() {
	self.clearActions = true
}

func (self *Flow) Drop() {
	self.appliedActions = nil
	self.metadata = nil
	self.writeActions = nil
	self.clearActions = false
	self.gotoTable = nil
}

func (self *Flow) generateFlowMessage(commandType int) (flowMod *openflow13.FlowMod, err error) {
	flowMod = openflow13.NewFlowMod()
	flowMod.TableId = self.Table.TableId
	flowMod.Priority = self.Match.Priority
	// Cookie ID could be set by client, using globalFlowID if not set
	if self.CookieID == 0 {
		self.CookieID = globalFlowID // FIXME: need a better id allocation
		globalFlowID += 1
	}
	flowMod.Cookie = self.CookieID
	if self.CookieMask > 0 {
		flowMod.CookieMask = self.CookieMask
	}
	if self.HardTimeout > 0 {
		flowMod.HardTimeout = self.HardTimeout
	}
	if self.IdleTimeout > 0 {
		flowMod.IdleTimeout = self.IdleTimeout
	}
	flowMod.Command = uint8(commandType)

	// convert match fields to openflow 1.3 format
	flowMod.Match = self.xlateMatch()
	log.Debugf("flow install: Match: %+v", flowMod.Match)
	if commandType != openflow13.FC_DELETE && commandType != openflow13.FC_DELETE_STRICT {
		if self.metadata != nil {
			openflow13.NewInstrWriteMetadata(self.metadata.data, self.metadata.mask)
		}
		if len(self.appliedActions) > 0 {
			appiedInstruction := openflow13.NewInstrApplyActions()
			for _, act := range self.appliedActions {
				err := appiedInstruction.AddAction(act.GetActionMessage(), false)
				if err != nil {
					return nil, err
				}
			}
			flowMod.AddInstruction(appiedInstruction)
		}
		if self.clearActions {
			clearInstruction := new(openflow13.InstrActions)
			clearInstruction.InstrHeader = openflow13.InstrHeader{
				Type:   openflow13.InstrType_CLEAR_ACTIONS,
				Length: 8,
			}
			flowMod.AddInstruction(clearInstruction)
		}
		if self.gotoTable != nil {
			gotoTableInstruction := openflow13.NewInstrGotoTable(*self.gotoTable)
			flowMod.AddInstruction(gotoTableInstruction)
		}
		if len(self.writeActions) > 0 {
			writeInstruction := openflow13.NewInstrWriteActions()
			for _, act := range self.writeActions {
				if err := writeInstruction.AddAction(act.GetActionMessage(), false); err != nil {
					return nil, err
				}
			}
			flowMod.AddInstruction(writeInstruction)
		}
	}
	return flowMod, nil
}

// Send generates a FlowMod message according the operationType, and then sends it to the OFSwitch.
func (self *Flow) Send(operationType int) error {
	flowMod, err := self.generateFlowMessage(operationType)
	if err != nil {
		return err
	}
	// Send the message
	return self.Table.Switch.Send(flowMod)
}
