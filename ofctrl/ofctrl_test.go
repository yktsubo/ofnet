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

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ovsdbDriver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type OfActor struct {
	Switch            *OFSwitch
	isSwitchConnected bool

	inputTable     *Table
	nextTable      *Table
	connectedCount int
}

func (o *OfActor) PacketRcvd(sw *OFSwitch, packet *PacketIn) {
	log.Printf("App: Received packet: %+v", packet)
}

func (o *OfActor) SwitchConnected(sw *OFSwitch) {
	log.Printf("App: Switch connected: %v", sw.DPID())

	// Store switch for later use
	o.Switch = sw

	o.isSwitchConnected = true
	o.connectedCount += 1
}

func (o *OfActor) MultipartReply(sw *OFSwitch, rep *openflow13.MultipartReply) {
}

func (o *OfActor) SwitchDisconnected(sw *OFSwitch) {
	log.Printf("App: Switch disconnected: %v", sw.DPID())
	o.isSwitchConnected = false
}

var ofActor OfActor
var ctrler *Controller
var ovsDriver *ovsdbDriver.OvsDriver

// Controller/Application/ovsBr work on clientMode
var ofActor2 OfActor
var ctrler2 *Controller
var ovsDriver2 *ovsdbDriver.OvsDriver

// Run an ovs-ofctl command
func runOfctlCmd(cmd, brName string) ([]byte, error) {
	cmdStr := fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 %s %s", cmd, brName)
	out, err := exec.Command("/bin/sh", "-c", cmdStr).Output()
	if err != nil {
		log.Errorf("error running ovs-ofctl %s %s. Error: %v", cmd, brName, err)
		return nil, err
	}

	return out, nil
}

// dump the flows and parse the Output
func ofctlFlowDump(brName string) ([]string, error) {
	flowDump, err := runOfctlCmd("dump-flows", brName)
	if err != nil {
		log.Errorf("Error running dump-flows on %s. Err: %v", brName, err)
		return nil, err
	}

	log.Debugf("Flow dump: %s", flowDump)
	flowOutStr := string(flowDump)
	flowDb := strings.Split(flowOutStr, "\n")[1:]

	log.Debugf("flowDb: %+v", flowDb)

	var flowList []string
	for _, flow := range flowDb {
		felem := strings.Fields(flow)
		if len(felem) > 2 {
			felem = append(felem[:1], felem[2:]...)
			felem = append(felem[:2], felem[4:]...)
			fstr := strings.Join(felem, " ")
			flowList = append(flowList, fstr)
		}
	}

	log.Infof("flowList: %+v", flowList)

	return flowList, nil
}

// Find a flow in flow list and match its action
func ofctlFlowMatch(flowList []string, tableId int, matchStr, actStr string) bool {
	mtStr := fmt.Sprintf("table=%d, %s ", tableId, matchStr)
	aStr := fmt.Sprintf("actions=%s", actStr)
	for _, flowEntry := range flowList {
		log.Debugf("Looking for %s %s in %s", mtStr, aStr, flowEntry)
		if strings.Contains(flowEntry, mtStr) && strings.Contains(flowEntry, aStr) {
			return true
		}
	}

	return false
}

// ofctlDumpFlowMatch dumps flows and finds a match
func ofctlDumpFlowMatch(brName string, tableId int, matchStr, actStr string) bool {
	// dump flows
	flowList, err := ofctlFlowDump(brName)
	if err != nil {
		log.Errorf("Error dumping flows: Err %v", err)
		return false
	}

	return ofctlFlowMatch(flowList, tableId, matchStr, actStr)
}

// Test if OVS switch connects successfully
func TestMain(m *testing.M) {
	// Create a controller
	ctrler = NewController(&ofActor)
	ofActor2 = OfActor{}
	ctrler2 = NewController(&ofActor2)

	// start listening
	go ctrler.Listen(":6733")

	// Connect to ovsdb and add the controller
	ovsDriver = ovsdbDriver.NewOvsDriver("ovsbr11")
	err := ovsDriver.AddController("127.0.0.1", 6733)
	if err != nil {
		log.Fatalf("Error adding controller to ovs")
	}

	// Create ovs bridge and connect clientMode Controller to it
	ovsDriver2 = ovsdbDriver.NewOvsDriver("ovsbr12")
	//wait for 2sec and see if ovs br created
	time.Sleep(2 * time.Second)
	go ctrler2.Connect("/var/run/openvswitch/ovsbr12.mgmt")

	//wait for 10sec and see if switch connects
	time.Sleep(8 * time.Second)
	if !ofActor.isSwitchConnected {
		log.Fatalf("ovsbr0 switch did not connect within 20sec")
		return
	}
	if !ofActor2.isSwitchConnected {
		log.Fatalf("ovsbr12 switch did not connect within 20sec")
		return
	}

	log.Infof("Switch connected. Creating tables..")

	// Create initial tables
	ofActor.inputTable = ofActor.Switch.DefaultTable()
	if ofActor.inputTable == nil {
		log.Fatalf("Failed to get input table")
		return
	}

	ofActor.nextTable, err = ofActor.Switch.NewTable(1)
	if err != nil {
		log.Fatalf("Error creating next table. Err: %v", err)
		return
	}

	ofActor2.inputTable = ofActor2.Switch.DefaultTable()
	if ofActor2.inputTable == nil {
		log.Fatalf("Failed to get input table")
		return
	}

	ofActor2.nextTable, err = ofActor2.Switch.NewTable(1)
	if err != nil {
		log.Fatalf("Error creating next table. Err: %v", err)
		return
	}
	log.Infof("Openflow tables created successfully")

	// run the test
	exitCode := m.Run()

	// delete the bridge
	err = ovsDriver.DeleteBridge("ovsbr11")
	if err != nil {
		log.Fatalf("Error deleting the bridge. Err: %v", err)
	}

	err = ovsDriver2.DeleteBridge("ovsbr12")
	if err != nil {
		log.Fatalf("Error deleting the bridge. Err: %v", err)
	}

	os.Exit(exitCode)
}

// test create/delete table
func TestTableCreateDelete(t *testing.T) {
	var tables [12]*Table

	log.Infof("Creating tables..")
	// create the tables
	for i := 2; i < 12; i++ {
		var err error
		tables[i], err = ofActor.Switch.NewTable(uint8(i))
		if err != nil {
			t.Errorf("Error creating table: %d", i)
		}
	}

	log.Infof("Deleting tables..")

	// delete the tables
	for i := 2; i < 12; i++ {
		err := tables[i].Delete()
		if err != nil {
			t.Errorf("Error deleting table: %d", i)
		}
	}
}

func TestCreateDeleteFlow(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set vlan and install it
	inPortFlow.SetVlan(1)
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// create an output
	output, err := ofActor.Switch.OutputPort(1)
	if err != nil {
		t.Errorf("Error creating an output port. Err: %v", err)
	}

	// create mac flow
	macAddr, _ := net.ParseMAC("02:01:01:01:01:01")
	macFlow, err := ofActor.nextTable.NewFlow(FlowMatch{
		Priority: 100,
		VlanId:   1,
		MacDa:    &macAddr,
	})
	if err != nil {
		t.Errorf("Error creating mac flow. Err: %v", err)
	}

	// Remove vlan and send out on a port
	macFlow.PopVlan()
	err = macFlow.Next(output)
	if err != nil {
		t.Errorf("Error installing the mac flow")
	}

	// Install ip flow
	ipAddr := net.ParseIP("10.10.10.10")
	ipFlow, err := ofActor.nextTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		IpDa:      &ipAddr,
	})
	if err != nil {
		t.Errorf("Error installing ip flow. Err: %v", err)
	}

	err = ipFlow.Next(output)
	if err != nil {
		t.Errorf("Error installing the ip flow")
	}

	// install tcp Flow
	tcpFlag := uint16(0x2)
	tcpFlow, err := ofActor.nextTable.NewFlow(FlowMatch{
		Priority:     100,
		Ethertype:    0x0800,
		IpProto:      6,
		TcpDstPort:   80,
		TcpFlags:     &tcpFlag,
		TcpFlagsMask: &tcpFlag,
	})
	if err != nil {
		t.Errorf("Error creating tcp flow. Err: %v", err)
	}

	log.Infof("Creating tcp flow: %+v", tcpFlow)
	err = tcpFlow.Next(output)
	if err != nil {
		t.Errorf("Error installing the tcp flow")
	}

	// verify it got installed
	flowList, err := ofctlFlowDump("ovsbr11")
	if err != nil {
		t.Errorf("Error getting flow entry")
	}

	// Match inport flow
	if !ofctlFlowMatch(flowList, 0, "priority=100,in_port=1",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// match ip flow
	if !ofctlFlowMatch(flowList, 1, "priority=100,ip,nw_dst=10.10.10.10",
		"output:1") {
		t.Errorf("IP flow not found in OVS.")
	}

	// match mac flow
	if !ofctlFlowMatch(flowList, 1, "priority=100,dl_vlan=1,dl_dst=02:01:01:01:01:01",
		"pop_vlan,output:1") {
		t.Errorf("Mac flow not found in OVS.")
		return
	}

	// match tcp flow
	if !ofctlFlowMatch(flowList, 1, "priority=100,tcp,tp_dst=80,tcp_flags=+syn",
		"output:1") {
		t.Errorf("IP flow not found in OVS.")
	}

	// Delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Delete the flow
	err = macFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the mac flow. Err: %v", err)
	}

	// Delete the flow
	err = ipFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the ip flow. Err: %v", err)
	}

	// Delete the flow
	err = tcpFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the tcp flow. Err: %v", err)
	}

	// Make sure they are really gone
	flowList, err = ofctlFlowDump("ovsbr11")
	if err != nil {
		t.Errorf("Error getting flow entry")
	}

	// Match inport flow and see if its still there..
	if ofctlFlowMatch(flowList, 0, "priority=100,in_port=1",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}

	// match ip flow
	if ofctlFlowMatch(flowList, 1, "priority=100,ip,nw_dst=10.10.10.10",
		"output:1") {
		t.Errorf("IP flow not found in OVS.")
	}

	// match mac flow
	if ofctlFlowMatch(flowList, 1, "priority=100,dl_vlan=1,dl_dst=02:01:01:01:01:01",
		"pop_vlan,output:1") {
		t.Errorf("Mac flow not found in OVS.")
	}

	// match tcp flow
	if ofctlFlowMatch(flowList, 1, "priority=100,tcp,tp_dst=80,tcp_flags=+syn",
		"output:1") {
		t.Errorf("IP flow not found in OVS.")
	}
}

// TestSetUnsetDscp verifies dscp set/unset action
func TestSetUnsetDscp(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		Ethertype: 0x0800,
		IpDscp:    46,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set vlan and dscp
	inPortFlow.SetDscp(23)
	inPortFlow.SetVlan(1)

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify dscp action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,ip,in_port=1,nw_tos=184",
		"set_field:23->ip_dscp,push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// unset dscp
	inPortFlow.UnsetDscp()

	// verify dscp action is gone
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,ip,in_port=1,nw_tos=184",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,in_port=1",
		"push_vlan:0x8100,set_field:4097->vlan_vid,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchSetMetadata verifies metadata match & set metedata
func TestMatchSetMetadata(t *testing.T) {
	metadata := uint64(0x1100)
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:     100,
		InputPort:    1,
		Metadata:     &metadata,
		MetadataMask: &metadata,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set Metadata
	inPortFlow.SetMetadata(uint64(0x8800), uint64(0x8800))

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,metadata=0x1100/0x1100,in_port=1",
		"write_metadata:0x8800/0x8800,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,metadata=0x1100/0x1100,in_port=1",
		"write_metadata:0x8800/0x8800,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchSetTunnelId verifies tunnelId match & set
func TestMatchSetTunnelId(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		TunnelId:  10,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set tunnelId
	inPortFlow.SetTunnelId(20)

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tun_id=0xa,in_port=1",
		"set_field:0x14->tun_id,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tun_id=0xa,in_port=1",
		"set_field:0x14->tun_id,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchSetIpFields verifies match & set for ip fields
func TestMatchSetIpFields(t *testing.T) {
	ipSa := net.ParseIP("10.1.1.0")
	ipDa := net.ParseIP("10.2.1.0")
	ipAddrMask := net.ParseIP("255.255.255.0")
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: 1,
		Ethertype: 0x0800,
		IpSa:      &ipSa,
		IpSaMask:  &ipAddrMask,
		IpDa:      &ipDa,
		IpDaMask:  &ipAddrMask,
		IpProto:   IP_PROTO_TCP,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set ip src/dst
	inPortFlow.SetIPField(net.ParseIP("20.2.1.1"), "Dst")
	inPortFlow.SetIPField(net.ParseIP("20.1.1.1"), "Src")

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp,in_port=1,nw_src=10.1.1.0/24,nw_dst=10.2.1.0/24",
		"set_field:20.2.1.1->ip_dst,set_field:20.1.1.1->ip_src,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp,in_port=1,nw_src=10.1.1.0/24,nw_dst=10.2.1.0/24",
		"set_field:20.2.1.1->ip_dst,set_field:20.1.1.1->ip_src,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchIpv6Fields verifies match ipv6 fields
func TestMatchIpv6Fields(t *testing.T) {
	ipv6Sa, ipv6Net, _ := net.ParseCIDR("2016:0616::/100")
	ipv6Da, _, _ := net.ParseCIDR("2016:0617::/100")
	ipv6Mask := net.IP(ipv6Net.Mask)
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:   100,
		InputPort:  1,
		Ethertype:  0x86DD,
		Ipv6Sa:     &ipv6Sa,
		Ipv6SaMask: &ipv6Mask,
		Ipv6Da:     &ipv6Da,
		Ipv6DaMask: &ipv6Mask,
		IpProto:    IP_PROTO_TCP,
		IpDscp:     23,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set Metadata
	inPortFlow.SetDscp(46)

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp6,in_port=1,ipv6_src=2016:616::/100,ipv6_dst=2016:617::/100,nw_tos=92",
		"set_field:46->ip_dscp,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp6,in_port=1,ipv6_src=2016:616::/100,ipv6_dst=2016:617::/100,nw_tos=92",
		"set_field:46->ip_dscp,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchSetTcpFields verifies match & set for tcp fields
func TestMatchSetTcpFields(t *testing.T) {
	tcpFlag := uint16(0x12)
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:     100,
		InputPort:    1,
		Ethertype:    0x0800,
		IpProto:      IP_PROTO_TCP,
		TcpSrcPort:   8000,
		TcpDstPort:   9000,
		TcpFlags:     &tcpFlag,
		TcpFlagsMask: &tcpFlag,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set TCP src/dst
	inPortFlow.SetL4Field(5000, "TCPDst")
	inPortFlow.SetL4Field(4000, "TCPSrc")

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp,in_port=1,tp_src=8000,tp_dst=9000,tcp_flags=+syn+ack",
		"set_field:5000->tcp_dst,set_field:4000->tcp_src,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,tcp,in_port=1,tp_src=8000,tp_dst=9000,tcp_flags=+syn+ack",
		"set_field:5000->tcp_dst,set_field:4000->tcp_src,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

// TestMatchSetUdpFields verifies match & set for udp fields
func TestMatchSetUdpFields(t *testing.T) {
	inPortFlow, err := ofActor.inputTable.NewFlow(FlowMatch{
		Priority:   100,
		InputPort:  1,
		Ethertype:  0x0800,
		IpProto:    IP_PROTO_UDP,
		UdpSrcPort: 8000,
		UdpDstPort: 9000,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}

	// Set TCP src/dst
	inPortFlow.SetL4Field(5000, "UDPDst")
	inPortFlow.SetL4Field(4000, "UDPSrc")

	// install it
	err = inPortFlow.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	// verify metadata action exists
	if !ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,udp,in_port=1,tp_src=8000,tp_dst=9000",
		"set_field:5000->udp_dst,set_field:4000->udp_src,goto_table:1") {
		t.Errorf("in port flow not found in OVS.")
	}

	// delete the flow
	err = inPortFlow.Delete()
	if err != nil {
		t.Errorf("Error deleting the inPort flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch("ovsbr11", 0, "priority=100,udp,in_port=1,tp_src=8000,tp_dst=9000",
		"set_field:5000->udp_dst,set_field:4000->udp_src,goto_table:1") {
		t.Errorf("in port flow still found in OVS after deleting it.")
	}
}

func TestOFSwitch_DumpFlowStats(t *testing.T) {
	ofActor2.Switch.EnableMonitor()
	roundID := uint64(1001)
	categoryID := uint64(1) << 16

	tcpFlag := uint16(0x12)
	flow1, err := ofActor2.inputTable.NewFlow(FlowMatch{
		Priority:     100,
		InputPort:    1,
		Ethertype:    0x0800,
		IpProto:      IP_PROTO_TCP,
		TcpSrcPort:   8000,
		TcpDstPort:   9000,
		TcpFlags:     &tcpFlag,
		TcpFlagsMask: &tcpFlag,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	}
	flow1.SetL4Field(4000, "TCPSrc")
	f1 := roundID | categoryID | uint64(1)<<24
	flow1.CookieID = f1
	err = flow1.Next(ofActor.nextTable)

	flow2, err := ofActor2.inputTable.NewFlow(FlowMatch{
		Priority:   100,
		InputPort:  1,
		Ethertype:  0x0800,
		IpProto:    IP_PROTO_UDP,
		UdpSrcPort: 8000,
		UdpDstPort: 9000,
	})
	if err != nil {
		t.Errorf("Error creating inport flow. Err: %v", err)
	} // Set TCP src/dst
	flow2.SetL4Field(4000, "UDPSrc")
	flow2.SetL4Field(5000, "UDPDst")
	f2 := roundID | categoryID | uint64(2)<<24
	flow2.CookieID = f2

	// install it
	err = flow2.Next(ofActor.nextTable)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}

	cookieID := roundID | categoryID
	cookieMask := uint64(0xffffff)
	stats := ofActor2.Switch.DumpFlowStats(cookieID, cookieMask, nil, nil)
	if stats == nil {
		t.Fatalf("Failed to dump flows")
	}
	if len(stats) != 2 {
		t.Errorf("Flow count in dump result is incorrect, expecte: 2, actual: %d", len(stats))
	}
	for _, stat := range stats {
		fid := stat.Cookie
		if fid != f1 && fid != f2 {
			t.Errorf("Flow in dump result has incorrect cookieID: %d", fid)
		}
	}
}

func TestReconnectOFSwitch(t *testing.T) {
	app := new(OfActor)
	ctrl := NewController(app)
	brName := "br4reconn"
	ovsBr := prepareContollerAndSwitch(t, app, ctrl, brName)
	defer func() {
		// Wait for flow entries flush
		time.Sleep(1 * time.Second)
		if err := ovsBr.DeleteBridge(brName); err != nil {
			t.Errorf("Failed to delete br %s: %v", brName, err)
		}
		ctrl.Delete()
	}()
	assert.Equal(t, ofActor2.connectedCount, 1)
	go func() {
		ovsBr.DeleteBridge(brName)
		time.Sleep(2 * time.Second)
		ovsBr = ovsdbDriver.NewOvsDriver(brName)
	}()
	ch := make(chan struct{})
	go func() {
		time.Sleep(5 * time.Second)
		ch <- struct{}{}
	}()

	<-ch
	assert.Equal(t, 2, app.connectedCount)
}

func prepareContollerAndSwitch(t *testing.T, app *OfActor, ctrl *Controller, brName string) (ovsBr *ovsdbDriver.OvsDriver) {
	// Create ovs bridge and connect clientMode Controller to it
	ovsBr = ovsdbDriver.NewOvsDriver(brName)
	go ctrl.Connect(fmt.Sprintf("/var/run/openvswitch/%s.mgmt", brName))

	time.Sleep(2 * time.Second)
	setOfTables(t, app, brName)
	return
}

func setOfTables(t *testing.T, ofApp *OfActor, brName string) {
	if !ofApp.isSwitchConnected {
		t.Fatalf("%s switch did not connect within 8s", brName)
		return
	}
	ofApp.inputTable = ofApp.Switch.DefaultTable()
	if ofApp.inputTable == nil {
		t.Fatalf("Failed to get input table")
		return
	}
	var err error
	ofApp.nextTable, err = ofApp.Switch.NewTable(1)
	if err != nil {
		t.Fatalf("Error creating next table. Err: %v", err)
		return
	}
}

func TestBundles(t *testing.T) {
	brName := ovsDriver2.OvsBridgeName
	// Test transaction complete workflow
	tx := ofActor2.Switch.NewTransaction(Atomic)
	err := tx.Begin()
	require.Nil(t, err, fmt.Sprintf("Failed to create transaction: %v", err))
	_, found := ofActor2.Switch.txChans[tx.ID]
	assert.True(t, found, fmt.Sprintf("Failed to add transaction with ID %d from switch queues", tx.ID))
	flow1 := createFlow(t, "22:11:11:11:11:11", "192.168.2.11")
	flow2 := createFlow(t, "22:11:11:11:11:12", "192.168.2.12")
	for _, f := range []*Flow{flow1, flow2} {
		err = tx.AddFlow(f)
		require.Nil(t, err, fmt.Sprintf("Failed to add flowMod into transaction: %v", err))
	}
	count, err := tx.Complete()
	require.Nil(t, err, fmt.Sprintf("Failed to complete transaction: %v", err))
	assert.Equal(t, 2, count)
	assert.True(t, tx.closed)
	err = tx.Commit()
	require.Nil(t, err, fmt.Sprintf("Failed to commit transaction: %v", err))
	actionStr := "goto_table:1"
	for _, matchStr := range []string{
		"priority=100,ip,dl_src=22:11:11:11:11:11,nw_src=192.168.2.11",
		"priority=100,ip,dl_src=22:11:11:11:11:12,nw_src=192.168.2.12",
	} {
		if !ofctlDumpFlowMatch(brName, int(ofActor2.inputTable.TableId), matchStr, actionStr) {
			t.Errorf("ovsDriver2: %s, target flow not found on OVS, match: %s, actions: %s", brName, matchStr, actionStr)
		}
	}
	_, found = ofActor2.Switch.txChans[tx.ID]
	assert.False(t, found)

	// Test transaction abort workflow
	tx2 := ofActor2.Switch.NewTransaction(Atomic)
	err = tx2.Begin()
	require.Nil(t, err, fmt.Sprintf("Failed to create transaction: %v", err))
	flow3 := createFlow(t, "22:11:11:11:11:13", "192.168.2.13")
	err = tx2.AddFlow(flow3)
	require.Nil(t, err, fmt.Sprintf("Failed to add flowMod into transaction: %v", err))
	count, err = tx2.Complete()
	require.Nil(t, err, fmt.Sprintf("Failed to complete transaction: %v", err))
	assert.True(t, tx2.closed)
	assert.Equal(t, 1, count)
	err = tx2.Abort()
	require.Nil(t, err, fmt.Sprintf("Failed to abort transaction: %v", err))
	matchStr := "priority=100,ip,dl_src=22:11:11:11:11:13,nw_src=192.168.2.13"
	if ofctlDumpFlowMatch(brName, int(ofActor2.inputTable.TableId), matchStr, actionStr) {
		t.Errorf("ovsDriver2: %s, target flow not found on OVS, match: %s, actions: %s", brName, matchStr, actionStr)
	}
	_, found = ofActor2.Switch.txChans[tx2.ID]
	assert.False(t, found)

	// Test failure in AddMessage
	tx3 := ofActor2.Switch.NewTransaction(Atomic)
	err = tx3.Begin()
	require.Nil(t, err, fmt.Sprintf("Failed to create transaction: %v", err))
	flow4 := createFlow(t, "33:11:11:11:11:14", "192.168.3.14")
	message, _ := tx3.createBundleAddMessage(flow4)
	message.Xid = uint32(100001)
	tx3.ofSwitch.Send(message)
	count, err = tx3.Complete()
	require.Nil(t, err, fmt.Sprintf("Failed to find addMesssage errors transaction: %v", err))
	assert.True(t, tx3.closed)
	assert.Equal(t, 0, count)
}

func createFlow(t *testing.T, mac, ip string) *Flow {
	srcMac1, _ := net.ParseMAC(mac)
	srcIP1 := net.ParseIP(ip)
	flow1, err := ofActor2.inputTable.NewFlow(
		FlowMatch{
			Priority:  100,
			Ethertype: 0x0800,
			MacSa:     &srcMac1,
			IpSa:      &srcIP1,
		})
	if err != nil {
		t.Fatalf("Failed to create flow")
	}
	flow1.NextElem = ofActor2.nextTable
	return flow1
}

// Test Nicira extensions for match field and actions
func TestNXExtension(t *testing.T) {
	testNXExtensionsWithOFApplication(ofActor, ovsDriver, t)
	testNXExtensionsWithOFApplication(ofActor2, ovsDriver2, t)
}

func testNXExtensionsWithOFApplication(ofApp OfActor, ovsBr *ovsdbDriver.OvsDriver, t *testing.T) {
	// Test action: load mac to src mac
	brName := ovsBr.OvsBridgeName
	log.Infof("Enable monitor flows on table %d in bridge %s", ofApp.inputTable.TableId, brName)
	ofApp.Switch.EnableMonitor()

	srcMac1, _ := net.ParseMAC("11:11:11:11:11:11")
	srcIP1 := net.ParseIP("192.168.1.10")
	flow1, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		MacSa:     &srcMac1,
		IpSa:      &srcIP1,
	})
	if err != nil {
		t.Fatalf("Failed to generate flow: %+v", flow1)
	}
	newSrcMac := uint64(0x111111222222)
	rng1 := openflow13.NewNXRange(0, 47)
	err = flow1.LoadReg("OXM_OF_ETH_SRC", newSrcMac, rng1)
	if err != nil {
		t.Errorf("Failed to load data into field OXM_OF_ETH_SRC: %+v", err)
	}
	verifyFlowInstallAndDelete(t, flow1, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,dl_src=11:11:11:11:11:11,nw_src=192.168.1.10",
		"load:0x111111222222->NXM_OF_ETH_SRC[],goto_table:1")

	// Test action: move src mac to dst mac
	srcMac2, _ := net.ParseMAC("11:11:11:11:11:22")
	flow2, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		MacSa:     &srcMac2,
		IpSa:      &srcIP1,
	})
	if err != nil {
		t.Fatalf("Failed to generate flow: %+v", flow2)
	}
	rng2 := openflow13.NewNXRange(0, 47)
	err = flow2.MoveRegs("NXM_OF_ETH_SRC", "NXM_OF_ETH_DST", rng2, rng2)
	if err != nil {
		t.Errorf("Failed to move data from NXM_OF_ETH_SRC to NXM_OF_ETH_DST: %+v", err)
	}
	verifyFlowInstallAndDelete(t, flow2, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,dl_src=11:11:11:11:11:22,nw_src=192.168.1.10",
		"move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],goto_table:1")

	// Test action: output in_port
	inPort1 := uint32(3)
	flow3, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: inPort1,
	})
	if err != nil {
		t.Fatalf("Failed to generate flow: %+v", flow3)
	}
	verifyFlowInstallAndDelete(t, flow3, NewOutputInPort(), brName, ofApp.inputTable.TableId,
		"priority=100,in_port=3",
		"IN_PORT")

	//Test action: output to register
	inPort2 := uint32(4)
	flow4, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: inPort2,
	})
	if err != nil {
		t.Fatalf("Failed to generate flow: %+v", flow4)
	}
	nxRegOutput, _ := NewNXOutput("NXM_NX_REG1", 5, 10)
	verifyFlowInstallAndDelete(t, flow4, nxRegOutput, brName, ofApp.inputTable.TableId,
		"priority=100,in_port=4",
		"output:NXM_NX_REG1[5..10]")

	// Test action: conjunction
	inPort3 := uint32(5)
	flow5, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: inPort3,
	})
	if err != nil {
		t.Fatalf("Failed to generate flow: %+v", flow5)
	}

	_ = flow5.AddConjunction(uint32(100), uint8(2), uint8(5))
	_ = flow5.AddConjunction(uint32(101), uint8(2), uint8(3))
	// install it
	err = flow5.Next(NewEmptyElem())
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}
	matchStr := "priority=100,in_port=5"
	actionStr := "conjunction(100,2/5),conjunction(101,2/3)"
	tableID := int(ofApp.inputTable.TableId)
	// verify metadata action exists
	if !ofctlDumpFlowMatch(brName, tableID, matchStr, actionStr) {
		t.Errorf("conjunction flow match: %s, actions: %s not found in OVS", matchStr, actionStr)
	}
	flow5.MonitorRealizeStatus()
	time.Sleep(1 * time.Second)
	log.Info("Flow realize status is ", flow5.IsRealized())

	_ = flow5.DelConjunction(uint32(101))
	actionStr = "conjunction(100,2/5)"
	// verify metadata action exists
	if !ofctlDumpFlowMatch(brName, tableID, matchStr, actionStr) {
		t.Errorf("conjunction flow match: %s, actions: %s not found in OVS", matchStr, actionStr)
	}

	err = flow5.DelConjunction(uint32(100))
	if err != EmptyFlowActionError {
		t.Errorf("Failed to find no action left in flow actions")
	}

	// delete the flow
	err = flow5.Delete()
	if err != nil {
		t.Errorf("Error deleting the flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch(brName, tableID, matchStr, actionStr) {
		t.Errorf("br: %s, target flow still found in OVS after deleting it", brName)
	}

	// Test action: set tun dst addr
	inPort4 := uint32(6)
	flow6, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		InputPort: inPort4,
	})
	if err != nil {
		t.Fatalf("Failed to generate flow: %+v", flow6)
	}
	tunDstAddr := net.ParseIP("192.168.1.100")
	err = flow6.SetIPField(tunDstAddr, "TunDst")
	verifyFlowInstallAndDelete(t, flow6, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,in_port=6",
		"set_field:192.168.1.100->tun_dst,goto_table:1")

	// Test action: move eth_src->dst_dst, move arp_sha->arp_tha, move arp_spa->arp_tpa,
	// set_field: arp_op=2, eth_src, arp_sha, arp_spa,
	// output:IN_PORT
	inPort5 := uint32(7)
	flow7, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0806,
		InputPort: inPort5,
		ArpOper:   1,
	})
	if err != nil {
		t.Fatalf("Failed to generate flow: %+v", flow7)
	}
	rng4 := openflow13.NewNXRange(0, 31)
	sMAC, _ := net.ParseMAC("11:11:11:11:11:22")
	sIP := net.ParseIP("192.168.1.100")
	_ = flow7.MoveRegs("NXM_OF_ETH_SRC", "NXM_OF_ETH_DST", rng2, rng2)
	_ = flow7.MoveRegs("NXM_NX_ARP_SHA", "NXM_NX_ARP_THA", rng2, rng2)
	_ = flow7.MoveRegs("NXM_OF_ARP_SPA", "NXM_OF_ARP_TPA", rng4, rng4)
	_ = flow7.SetARPOper(2)
	_ = flow7.SetMacSa(sMAC)
	_ = flow7.SetARPSha(sMAC)
	_ = flow7.SetARPSpa(sIP)
	verifyFlowInstallAndDelete(t, flow7, NewOutputInPort(), brName, ofApp.inputTable.TableId,
		"priority=100,arp,in_port=7,arp_op=1",
		"move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:2->arp_op,set_field:11:11:11:11:11:22->eth_src,set_field:11:11:11:11:11:22->arp_sha,set_field:192.168.1.100->arp_spa,IN_PORT")

	// Test action: ct(commit, table=1, zone=0xff01,exec(load:0xf009->NXM_NX_CT_MARK[]))
	inPort6 := uint32(8)
	flow8, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		InputPort: inPort6,
	})
	if err != nil {
		t.Fatalf("Failed to generate flow: %+v", flow8)
	}
	ctTable := uint8(1)
	ctZone := uint16(0xff01)
	dstField, _ := openflow13.FindFieldHeaderByName("NXM_NX_CT_MARK", false)
	loadData := uint64(0xf009)

	ctLoadAction := openflow13.NewNXActionRegLoad(rng4.ToOfsBits(), dstField, loadData)
	err = flow8.ConnTrack(true, false, &ctTable, &ctZone, ctLoadAction)
	if err != nil {
		t.Errorf("Failed to apply ct action: %+v", err)
	}
	verifyFlowInstallAndDelete(t, flow8, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,in_port=8",
		"ct(commit,table=1,zone=65281,exec(load:0xf009->NXM_NX_CT_MARK[])),goto_table:1")

	// Test action: dec_ttl
	inPort7 := uint32(9)
	flow9, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		InputPort: inPort7,
	})
	if err != nil {
		t.Fatalf("Failed to generate flow: %+v", flow9)
	}
	err = flow9.DecTTL()
	if err != nil {
		t.Errorf("Failed to apply dec_ttl action: %+v", err)
	}
	verifyFlowInstallAndDelete(t, flow9, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,in_port=9",
		"dec_ttl,goto_table:1")

	// Test action: ct(commit, exec(move:NXM_OF_ETH_SRC[]->NXM_NX_CT_LABEL, load:0xf009->NXM_NX_CT_MARK[]))
	// Test match: ct_state=+new-trk
	ctStates := openflow13.NewCTStates()
	ctStates.SetNew()
	ctStates.UnsetTrk()
	flow10, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		CtStates:  ctStates,
	})
	if err != nil {
		t.Fatalf("Failed to generate flow: %+v", flow10)
	}

	ctMoveSrc, _ := openflow13.FindFieldHeaderByName("NXM_OF_ETH_SRC", false)
	ctMoveDst, _ := openflow13.FindFieldHeaderByName("NXM_NX_CT_LABEL", false)
	ctMoveAction := openflow13.NewNXActionRegMove(48, 0, 0, ctMoveSrc, ctMoveDst)
	err = flow10.ConnTrack(true, false, nil, nil, ctMoveAction, ctLoadAction)
	if err != nil {
		t.Errorf("Failed to apply dec_ttl action: %+v", err)
	}
	verifyFlowInstallAndDelete(t, flow10, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ct_state=+new-trk,ip",
		"ct(commit,exec(move:NXM_OF_ETH_SRC[]->NXM_NX_CT_LABEL[0..47],load:0xf009->NXM_NX_CT_MARK[])),goto_table:1")

	status := ofApp.Switch.CheckStatus(1)
	if !status {
		t.Errorf("Failed to check Switch status.")
	}
	//Test match: reg1=0x12/0xffff
	reg1 := &NXRegister{
		ID:    1,
		Data:  uint32(0x12),
		Range: openflow13.NewNXRange(0, 15),
	}
	var regs = []*NXRegister{reg1}
	flow11, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		NxRegs:    regs,
	})
	err = flow11.ConnTrack(true, false, nil, nil)
	if err != nil {
		t.Errorf("Failed to apply dec_ttl action: %+v", err)
	}
	verifyFlowInstallAndDelete(t, flow11, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ip,reg1=0x12/0xffff",
		"ct(commit),goto_table:1")

	//Test match: ct_mark=0x20/0x20
	var mask = uint32(0x20)
	flow12, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:   100,
		Ethertype:  0x0800,
		CtMark:     uint32(0x20),
		CtMarkMask: &mask,
	})
	verifyFlowInstallAndDelete(t, flow12, ofApp.nextTable, brName, ofApp.inputTable.TableId,
		"priority=100,ct_mark=0x20/0x20,ip",
		"goto_table:1")

	// Test group
	groupId := uint32(1)

	group1 := newGroup(groupId, GroupSelect, ofApp.Switch)

	natAction := openflow13.NewNXActionCTNAT()
	if err := natAction.SetSNAT(); err != nil {
		t.Errorf("Failed to set SNAT action: %v", err)
	} else if err := natAction.SetRandom(); err != nil {
		t.Errorf("Failed to set random action: %v", err)
	} else {
		natAction.SetRangeIPv4Min(net.ParseIP("10.0.0.240"))
	}
	ctAction := openflow13.NewNXActionConnTrack()
	ctAction.Commit()
	ctAction.AddAction(natAction)
	bkt := openflow13.NewBucket()
	bkt.Weight = 50
	bkt.AddAction(ctAction)
	group1.AddBuckets(bkt)
	err = group1.Install()
	if err != nil {
		t.Errorf("Failed to install group entry: %v", err)
	}

	verifyGroup(t, brName, group1, "select", "bucket=weight:50,actions=ct(commit,nat(src=10.0.0.240,random))", true)

	// Install flow and refer to group
	inPort8 := uint32(10)
	flow13, err := ofApp.inputTable.NewFlow(FlowMatch{
		Priority:  100,
		Ethertype: 0x0800,
		InputPort: inPort8,
	})
	verifyFlowInstallAndDelete(t, flow13, group1, brName, ofApp.inputTable.TableId,
		"priority=100,ip,in_port=10",
		"group:1")
	group1.Delete()
	verifyGroup(t, brName, group1, "select", "bucket=weight:50,actions=ct(commit,nat(src=10.0.0.240,random))", false)
}

func verifyFlowInstallAndDelete(t *testing.T, flow *Flow, nextElem FgraphElem, br string, tableID uint8, matchStr string, actionStr string) {
	// install it
	err := flow.Next(nextElem)
	if err != nil {
		t.Errorf("Error installing inport flow. Err: %v", err)
	}
	flow.MonitorRealizeStatus()
	// verify metadata action exists
	if !ofctlDumpFlowMatch(br, int(tableID), matchStr, actionStr) {
		t.Errorf("br: %s, target flow not found on OVS, match: %s, actions: %s", br, matchStr, actionStr)
	}
	if !flow.IsRealized() {
		t.Errorf("Failed to realize flow status, match: %s, actions: %s", matchStr, actionStr)
	}

	// delete the flow
	err = flow.Delete()
	if err != nil {
		t.Errorf("Error deleting the flow. Err: %v", err)
	}

	// Make sure they are really gone
	if ofctlDumpFlowMatch(br, int(tableID), matchStr, actionStr) {
		t.Errorf("br: %s, target flow still found on OVS after deleting it: match: %s, actions: %s", br, matchStr, actionStr)
	}
}

func verifyGroup(t *testing.T, br string, group *Group, groupType string, buckets string, expectExists bool) {
	// dump groups
	groupList, err := ofctlGroupDump(br)
	if err != nil {
		log.Errorf("Error dumping flows: Err %v", err)
	}
	groupStr := fmt.Sprintf("group_id=%d,type=%s,%s", group.ID, groupType, buckets)
	found := false
	for _, groupEntry := range groupList {
		log.Debugf("Looking for %s in %s", groupStr, groupEntry)
		if strings.Contains(groupEntry, groupStr) {
			found = true
			break
		}
	}
	if found != expectExists {
		t.Errorf("br %s, failed to find group entry %s", br, groupStr)
	}
}

// dump the groups and parse the Output
func ofctlGroupDump(brName string) ([]string, error) {
	groupDump, err := runOfctlCmd("dump-groups", brName)
	if err != nil {
		log.Errorf("Error running dump-groups on %s. Err: %v", brName, err)
		return nil, err
	}

	log.Debugf("Group dump: %s", groupDump)
	groupOutStr := string(groupDump)
	groupDb := strings.Split(groupOutStr, "\n")[1:]

	log.Debugf("groupList: %+v", groupDb)

	return groupDb, nil
}
