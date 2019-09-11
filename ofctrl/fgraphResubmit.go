package ofctrl

import "github.com/wenyingd/libOpenflow/openflow13"

// This file implements the forwarding graph API for the resubmit element

type Resubmit struct {
	ofport    uint16 // target ofport to resubmit
	nextTable uint8  // target table to resubmit
}

// Fgraph element type for the Resubmit
func (self *Resubmit) Type() string {
	return "Resubmit"
}

// instruction set for resubmit element
func (self *Resubmit) GetFlowInstr() openflow13.Instruction {
	outputInstr := openflow13.NewInstrApplyActions()
	resubmitAct := self.GetResubmitAction()
	outputInstr.AddAction(resubmitAct, false)
	return outputInstr
}

// Return a resubmit action (Used as a last action by flows in the table pipeline)
func (self *Resubmit) GetResubmitAction() openflow13.Action {
	if self.ofport == 0 {
		self.ofport = openflow13.OFPP_IN_PORT
	}
	if self.nextTable == 0 {
		self.nextTable = openflow13.OFPTT_ALL
	}
	return openflow13.NewNXActionResubmitTableAction(self.ofport, self.nextTable)
}

func NewResubmit(inPort uint16, table uint8) *Resubmit {
	return &Resubmit{
		ofport:    inPort,
		nextTable: table,
	}
}
