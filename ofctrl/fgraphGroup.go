package ofctrl

import (
	"github.com/contiv/libOpenflow/openflow13"
)

type GroupType int

const (
	GroupAll GroupType = iota
	GroupSelect
	GroupIndirect
	GroupFF
)

type Group struct {
	Switch      *OFSwitch
	ID          uint32
	GroupType   GroupType
	Buckets     []*openflow13.Bucket
	isInstalled bool
}

func (self *Group) Type() string {
	return "group"
}

func (self *Group) GetFlowInstr() openflow13.Instruction {
	groupInstr := openflow13.NewInstrApplyActions()
	groupAct := openflow13.NewActionGroup(self.ID)
	// Add group action to the instruction
	groupInstr.AddAction(groupAct, false)
	return groupInstr
}

func (self *Group) AddBuckets(buckets ...*openflow13.Bucket) {
	if self.Buckets == nil {
		self.Buckets = make([]*openflow13.Bucket, 0)
	}
	self.Buckets = append(self.Buckets, buckets...)
	if self.isInstalled {
		self.Install()
	}
}

func (self *Group) ResetBuckets(buckets ...*openflow13.Bucket) {
	self.Buckets = make([]*openflow13.Bucket, 0)
	self.Buckets = append(self.Buckets, buckets...)
	if self.isInstalled {
		self.Install()
	}
}

func (self *Group) Install() error {
	groupMod := openflow13.NewGroupMod()
	groupMod.GroupId = self.ID

	switch self.GroupType {
	case GroupAll:
		groupMod.Type = openflow13.OFPGT_ALL
	case GroupSelect:
		groupMod.Type = openflow13.OFPGT_SELECT
	case GroupIndirect:
		groupMod.Type = openflow13.OFPGT_INDIRECT
	case GroupFF:
		groupMod.Type = openflow13.OFPGT_FF
	}

	for _, bkt := range self.Buckets {
		// Add the bucket to group
		groupMod.AddBucket(*bkt)
	}

	if self.isInstalled {
		groupMod.Command = openflow13.OFPGC_MODIFY
	}
	self.Switch.Send(groupMod)

	// Mark it as installed
	self.isInstalled = true

	return nil
}

func (self *Group) Delete() error {
	if self.isInstalled {
		groupMod := openflow13.NewGroupMod()
		groupMod.GroupId = self.ID
		groupMod.Command = openflow13.OFPGC_DELETE
		self.Switch.Send(groupMod)
		// Mark it as unInstalled
		self.isInstalled = false
	}

	// Delete group from switch cache
	return self.Switch.DeleteGroup(self.ID)
}

func newGroup(id uint32, groupType GroupType, ofSwitch *OFSwitch) *Group {
	return &Group{
		ID:        id,
		GroupType: groupType,
		Switch:    ofSwitch,
	}
}
