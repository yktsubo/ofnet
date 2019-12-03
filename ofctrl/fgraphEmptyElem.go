package ofctrl

import (
	"github.com/wenyingd/libOpenflow/openflow13"
)

// This file implements the forwarding graph API for empty element. It will return
// InstrActions as the value of GetFlowInstr, but without any reserved actions.

type EmptyElem struct {
}

// Fgraph element type for the NXOutput
func (self *EmptyElem) Type() string {
	return "empty"
}

// instruction set for NXOutput element
func (self *EmptyElem) GetFlowInstr() openflow13.Instruction {
	instr := openflow13.NewInstrApplyActions()
	return instr
}

func NewEmptyElem() *EmptyElem {
	return new(EmptyElem)
}
