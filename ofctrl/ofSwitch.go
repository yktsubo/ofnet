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
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/contiv/libOpenflow/common"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/util"

	log "github.com/Sirupsen/logrus"
	cmap "github.com/streamrail/concurrent-map"
)

var (
	heartbeatInterval, _ = time.ParseDuration("3s")
)

type OFSwitch struct {
	stream *util.MessageStream
	dpid   net.HardwareAddr
	app    AppInterface
	// Following are fgraph state for the switch
	tableDb        map[uint8]*Table
	dropAction     *Output
	sendToCtrler   *Output
	normalLookup   *Output
	ready          bool
	portMux        sync.Mutex
	statusMux      sync.Mutex
	outputPorts    map[uint32]*Output
	groupDb        map[uint32]*Group
	connCh         chan int // Channel to notify controller connection status is changed
	mQueue         chan *openflow13.MultipartRequest
	monitorEnabled bool
	lastUpdate     time.Time // time at that receiving the last EchoReply
	heartbeatCh    chan struct{}
	// map for receiving reply messages from OFSwitch. Key is Xid, and value is a chan created by request message sender.
	txChans map[uint32]chan MessageResult
	txLock  sync.Mutex // lock for txChans
}

var switchDb cmap.ConcurrentMap
var monitoredFlows cmap.ConcurrentMap

func init() {
	switchDb = cmap.New()
	monitoredFlows = cmap.New()
}

// Builds and populates a Switch struct then starts listening
// for OpenFlow messages on conn.
func NewSwitch(stream *util.MessageStream, dpid net.HardwareAddr, app AppInterface, connCh chan int) *OFSwitch {
	var s *OFSwitch
	if getSwitch(dpid) == nil {
		log.Infoln("Openflow Connection for new switch:", dpid)

		s = new(OFSwitch)
		s.app = app
		s.stream = stream
		s.dpid = dpid
		s.connCh = connCh
		s.txChans = make(map[uint32]chan MessageResult)

		// Initialize the fgraph elements
		s.initFgraph()

		// Save it
		switchDb.Set(dpid.String(), s)

		// Main receive loop for the switch
		go s.receive()

	} else {
		log.Infoln("Openflow Connection for switch:", dpid)

		s = getSwitch(dpid)
		s.stream = stream
		s.dpid = dpid
	}

	// send Switch connected callback
	s.switchConnected()

	// Return the new switch
	return s
}

// Returns a pointer to the Switch mapped to dpid.
func getSwitch(dpid net.HardwareAddr) *OFSwitch {
	sw, _ := switchDb.Get(dpid.String())
	if sw == nil {
		return nil
	}
	return sw.(*OFSwitch)
}

// Returns the dpid of Switch s.
func (self *OFSwitch) DPID() net.HardwareAddr {
	return self.dpid
}

// Sends an OpenFlow message to this Switch.
func (self *OFSwitch) Send(req util.Message) {
	self.stream.Outbound <- req
}

func (self *OFSwitch) Disconnect() {
	self.stream.Shutdown <- true
	self.switchDisconnected()
}

func (self *OFSwitch) changeStatus(status bool) {
	self.statusMux.Lock()
	defer self.statusMux.Unlock()
	self.ready = status
}

func (self *OFSwitch) IsReady() bool {
	self.statusMux.Lock()
	defer self.statusMux.Unlock()
	return self.ready
}

// Handle switch connected event
func (self *OFSwitch) switchConnected() {
	self.changeStatus(true)
	self.app.SwitchConnected(self)

	// Send new feature request
	self.Send(openflow13.NewFeaturesRequest())

	self.Send(openflow13.NewEchoRequest())

	self.heartbeatCh = make(chan struct{})
	go func() {
		timer := time.NewTicker(heartbeatInterval)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				self.Send(openflow13.NewEchoRequest())
			case <-self.heartbeatCh:
				break
			}
		}
	}()

}

// Handle switch disconnected event
func (self *OFSwitch) switchDisconnected() {
	self.changeStatus(false)
	self.heartbeatCh <- struct{}{}
	switchDb.Remove(self.DPID().String())
	self.app.SwitchDisconnected(self)
	if self.connCh != nil {
		self.connCh <- ReConnection
	}
}

// Receive loop for each Switch.
func (self *OFSwitch) receive() {
	for {
		select {
		case msg := <-self.stream.Inbound:
			// New message has been received from message
			// stream.
			self.handleMessages(self.dpid, msg)
		case err := <-self.stream.Error:
			log.Warnf("Received ERROR message from switch %v. Err: %v", self.dpid, err)

			// send Switch disconnected callback
			self.switchDisconnected()
			return
		}
	}
}

// Handle openflow messages from the switch
func (self *OFSwitch) handleMessages(dpid net.HardwareAddr, msg util.Message) {
	log.Debugf("Received message: %+v, on switch: %s", msg, dpid.String())

	switch t := msg.(type) {
	case *common.Header:
		switch t.Header().Type {
		case openflow13.Type_Hello:
			// Send Hello response
			h, err := common.NewHello(4)
			if err != nil {
				log.Errorf("Error creating hello message")
			}
			self.Send(h)

		case openflow13.Type_EchoRequest:
			// Send echo reply
			res := openflow13.NewEchoReply()
			self.Send(res)

		case openflow13.Type_EchoReply:
			self.lastUpdate = time.Now()

		case openflow13.Type_FeaturesRequest:

		case openflow13.Type_GetConfigRequest:

		case openflow13.Type_BarrierRequest:

		case openflow13.Type_BarrierReply:

		}
	case *openflow13.ErrorMsg:
		log.Errorf("Received ofp1.3 error msg: %+v", *t)
		result := MessageResult{
			succeed: false,
			errType: t.Type,
			errCode: t.Code,
			xID:     t.Xid,
		}
		self.publishMessage(t.Xid, result)

	case *openflow13.VendorHeader:
		log.Infof("Received Experimenter message: %+v", t)

	case *openflow13.SwitchFeatures:

	case *openflow13.SwitchConfig:
		switch t.Header.Type {
		case openflow13.Type_GetConfigReply:

		case openflow13.Type_SetConfig:

		}
	case *openflow13.PacketIn:
		log.Debugf("Received packet(ofctrl): %+v", t)
		// send packet rcvd callback
		self.app.PacketRcvd(self, (*PacketIn)(t))

	case *openflow13.FlowRemoved:

	case *openflow13.PortStatus:
		// FIXME: This needs to propagated to the app.
	case *openflow13.PacketOut:

	case *openflow13.FlowMod:

	case *openflow13.PortMod:

	case *openflow13.MultipartRequest:

	case *openflow13.MultipartReply:
		log.Debugf("Received MultipartReply")
		rep := (*openflow13.MultipartReply)(t)
		if self.monitorEnabled {
			key := fmt.Sprintf("%d", rep.Xid)
			ch, found := monitoredFlows.Get(key)
			if found {
				replyChan := ch.(chan *openflow13.MultipartReply)
				replyChan <- rep
			}
		}
		// send packet rcvd callback
		self.app.MultipartReply(self, rep)
	case *openflow13.BundleControl:
		result := MessageResult{
			xID:     t.Xid,
			succeed: true,
		}
		self.publishMessage(t.Xid, result)
	case *openflow13.BundleError:
		errData := t.ErrorMsg.Data.Bytes()
		log.Errorf("Received bundle error msg: %+v", errData)
		result := MessageResult{
			succeed:      false,
			errType:      t.Type,
			errCode:      t.Code,
			experimenter: int32(t.ExperimenterID),
			xID:          t.Xid,
		}
		experimenterID := binary.BigEndian.Uint32(errData[8:12])
		if experimenterID == openflow13.ONF_EXPERIMENTER_ID {
			experimenterType := binary.BigEndian.Uint32(errData[12:16])
			switch experimenterType {
			case openflow13.Type_BundleCtrl:
				self.publishMessage(t.Xid, result)
			case openflow13.Type_BundleAdd:
				bundleID := binary.BigEndian.Uint32(errData[20:24])
				self.publishMessage(bundleID, result)
			}
		}
	}
}

func (self *OFSwitch) getMPReq() *openflow13.MultipartRequest {
	mp := &openflow13.MultipartRequest{}
	mp.Type = openflow13.MultipartType_Flow
	mp.Header = openflow13.NewOfp13Header()
	mp.Header.Type = openflow13.Type_MultiPartRequest
	return mp
}

func (self *OFSwitch) EnableMonitor() {
	if self.monitorEnabled {
		return
	}

	if self.mQueue == nil {
		self.mQueue = make(chan *openflow13.MultipartRequest)
	}

	go func() {
		for {
			mp := <-self.mQueue
			self.Send(mp)
			log.Debugf("Send flow stats request")
		}
	}()
	self.monitorEnabled = true
}

func (self *OFSwitch) DumpFlowStats(cookieID, cookieMask uint64, flowMatch *FlowMatch, tableID *uint8) []*openflow13.FlowStats {
	mp := self.getMPReq()
	replyChan := make(chan *openflow13.MultipartReply)
	go func() {
		log.Debug("Add flow into monitor queue")
		flowMonitorReq := openflow13.NewFlowStatsRequest()
		if tableID != nil {
			flowMonitorReq.TableId = *tableID
		} else {
			flowMonitorReq.TableId = 0xff
		}
		flowMonitorReq.Cookie = cookieID
		if cookieMask > 0 {
			flowMonitorReq.CookieMask = cookieMask
		} else {
			flowMonitorReq.CookieMask = ^uint64(0)
		}
		if flowMatch != nil {
			f := &Flow{Match: *flowMatch}
			flowMonitorReq.Match = f.xlateMatch()
		}
		mp.Body = flowMonitorReq
		monitoredFlows.Set(fmt.Sprintf("%d", mp.Xid), replyChan)
		self.mQueue <- mp
	}()

	reply := <-replyChan
	flowStates := make([]*openflow13.FlowStats, 0)
	if reply.Type == openflow13.MultipartType_Flow {
		flowArr := reply.Body
		for _, entry := range flowArr {
			flowStates = append(flowStates, entry.(*openflow13.FlowStats))
		}
		return flowStates
	}
	return nil
}

func (self *OFSwitch) CheckStatus(timeout time.Duration) bool {
	return self.lastUpdate.Add(heartbeatInterval).After(time.Now())
}

func (self *OFSwitch) subscribeMessage(xID uint32, msgChan chan MessageResult) {
	self.txLock.Lock()
	self.txChans[xID] = msgChan
	self.txLock.Unlock()
}

func (self *OFSwitch) publishMessage(xID uint32, result MessageResult) {
	self.txLock.Lock()
	defer self.txLock.Unlock()
	ch, found := self.txChans[xID]
	if found {
		go func() {
			ch <- result
		}()
	}
}

func (self *OFSwitch) unSubscribeMessage(xID uint32) {
	_, found := self.txChans[xID]
	if found {
		delete(self.txChans, xID)
	}
}
