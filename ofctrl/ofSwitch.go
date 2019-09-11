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
	"sync"
	"time"

	"github.com/contiv/libOpenflow/common"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/util"

	log "github.com/Sirupsen/logrus"
	cmap "github.com/streamrail/concurrent-map"
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
	retry          chan bool // Channel to notify controller reconnect switch
	mQueue         chan *openflow13.MultipartRequest
	monitorEnabled bool
}

var switchDb cmap.ConcurrentMap
var monitoredFlows cmap.ConcurrentMap

func init() {
	switchDb = cmap.New()
	monitoredFlows = cmap.New()
}

// Builds and populates a Switch struct then starts listening
// for OpenFlow messages on conn.
func NewSwitch(stream *util.MessageStream, dpid net.HardwareAddr, app AppInterface, retryChan chan bool) *OFSwitch {
	var s *OFSwitch

	if getSwitch(dpid) == nil {
		log.Infoln("Openflow Connection for new switch:", dpid)

		s = new(OFSwitch)
		s.app = app
		s.stream = stream
		s.dpid = dpid
		s.retry = retryChan

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

	// FIXME: This is too fragile. Create a periodic timer
	// Start the periodic echo request loop
	self.Send(openflow13.NewEchoRequest())
}

// Handle switch disconnected event
func (self *OFSwitch) switchDisconnected() {
	self.changeStatus(false)
	self.app.SwitchDisconnected(self)
	switchDb.Remove(self.DPID().String())
	if self.retry != nil {
		self.retry <- true
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

			// FIXME: This is too fragile. Create a periodic timer
			// Wait three seconds then send an echo_request message.
			go func() {
				<-time.After(time.Second * 3)

				// Send echo request
				res := openflow13.NewEchoRequest()
				self.Send(res)
			}()
			self.changeStatus(true)

		case openflow13.Type_FeaturesRequest:

		case openflow13.Type_GetConfigRequest:

		case openflow13.Type_BarrierRequest:

		case openflow13.Type_BarrierReply:

		}
	case *openflow13.ErrorMsg:
		log.Errorf("Received ofp1.3 error msg: %+v", *t)
	case *openflow13.VendorHeader:

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
	start := time.Now()
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
			flowMonitorReq.CookieMask = uint64(0xffffffffffffffff)
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
	delta := time.Now().Sub(start).Nanoseconds()
	log.Infof("time diff: %d", (delta / 1000))
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
	// Send echo request
	self.changeStatus(false)
	ch := make(chan bool)
	go func() {
		res := openflow13.NewEchoRequest()
		self.Send(res)
		for {
			if self.IsReady() {
				ch <- true
				return
			} else {
				time.Sleep(50 * time.Millisecond)
			}
		}
	}()
	select {
	case status := <-ch:
		log.Info("Connection status is ", status)
		return status
	case <-time.After(timeout * time.Second):
		return false
	}
}
