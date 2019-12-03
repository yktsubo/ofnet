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
	return openflow13.NewNXActionResubmitTableAction(self.ofport, self.nextTable)
}

func NewResubmit(inPort *uint16, table *uint8) *Resubmit {
	resubmit := new(Resubmit)
	if inPort == nil {
		resubmit.ofport = openflow13.OFPP_IN_PORT
	} else {
		resubmit.ofport = *inPort
	}
	if table == nil {
		resubmit.nextTable = openflow13.OFPTT_ALL
	} else {
		resubmit.nextTable = *table
	}
	return resubmit
}
