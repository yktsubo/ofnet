package ofctrl

// The work flow to use transaction for sending multiple Openflow messages should be:
// NewTransaction->Begin->AddFlow->Complete->Commit. Client could cancel the messages by calling Abort after the
// transaction is complete and not commit.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/libOpenflow/util"
)

type TransactionType uint16

func (t TransactionType) getValue() uint16 {
	return uint16(t)
}

const (
	Atomic  = TransactionType(openflow13.OFPBCT_ATOMIC)
	Ordered = TransactionType(openflow13.OFPBCT_ORDERED)
)

var uid uint32

type Transaction struct {
	ofSwitch       *OFSwitch
	ID             uint32
	flag           TransactionType
	closed         bool
	lock           sync.Mutex
	successAdd     map[uint32]bool
	controlReplyCh chan MessageResult
	addErrorCh     chan MessageResult
}

// NewTransaction creates a transaction on the switch. It will assign a bundle ID, and sets the bundle flags.
func (self *OFSwitch) NewTransaction(flag TransactionType) *Transaction {
	tx := new(Transaction)
	tx.ID = atomic.AddUint32(&uid, 1)
	if flag == 0 {
		tx.flag = Atomic
	} else {
		tx.flag = flag
	}
	tx.ofSwitch = self
	tx.controlReplyCh = make(chan MessageResult)
	return tx
}

func (tx *Transaction) getError(reply MessageResult) error {
	errType := reply.GetErrorType()
	errCode := reply.GetErrorCode()
	if errType == openflow13.ET_EXPERIMENTER && errCode >= openflow13.BFC_UNKNOWN && errCode <= openflow13.BFC_BUNDLE_IN_PROCESS {
		return openflow13.ParseBundleError(reply.GetErrorCode())
	}
	return fmt.Errorf("unsupported bundle error with type %d and code %d", errType, errCode)
}

func (tx *Transaction) sendControlRequest(xID uint32, msg util.Message) error {
	tx.ofSwitch.subscribeMessage(xID, tx.controlReplyCh)
	defer tx.ofSwitch.unSubscribeMessage(xID)
	if err := tx.ofSwitch.Send(msg); err != nil {
		return err
	}

	select {
	case reply := <-tx.controlReplyCh:
		if reply.IsSucceed() {
			return nil
		} else {
			return tx.getError(reply)
		}
	case <-time.After(messageTimeout):
		return fmt.Errorf("bundle reply is timeout")
	case <-tx.ofSwitch.ctx.Done():
		return fmt.Errorf("bundle reply is canceled because of disconnection from the Switch")
	}
}

func (tx *Transaction) newBundleControlMessage(msgType uint16) *openflow13.BundleControl {
	message := openflow13.NewBundleControl()
	message.Type = msgType
	message.Flags = tx.flag.getValue()
	message.BundleID = tx.ID
	return message
}

func (tx *Transaction) createBundleAddMessage(flowMod *openflow13.FlowMod) (*openflow13.BundleAdd, error) {
	message := openflow13.NewBundleAdd()
	message.BundleID = tx.ID
	message.Flags = tx.flag.getValue()
	flowMod.Xid = message.Xid
	message.Message = flowMod
	return message, nil
}

// Begin opens a bundle configuration.
func (tx *Transaction) Begin() error {
	message := tx.newBundleControlMessage(openflow13.OFPBCT_OPEN_REQUEST)
	err := tx.sendControlRequest(message.Xid, message)
	if err != nil {
		return err
	}
	tx.addErrorCh = make(chan MessageResult, 10)
	tx.successAdd = make(map[uint32]bool)
	tx.ofSwitch.subscribeMessage(tx.ID, tx.addErrorCh)
	// Start a new goroutine to listen add error messages if received from OFSwitch.
	go func() {
		for {
			select {
			case reply := <-tx.addErrorCh:
				if reply.xID == 0 {
					// Remove add message error channel when the bundle is closed.
					tx.ofSwitch.unSubscribeMessage(tx.ID)
					return
				} else if !reply.succeed {
					// Remove failed add message from successAdd.
					tx.lock.Lock()
					delete(tx.successAdd, reply.xID)
					tx.lock.Unlock()
				}
			}
		}
	}()
	return nil
}

// AddFlow adds messages in the bundle.
func (tx *Transaction) AddFlow(flowMod *openflow13.FlowMod) error {
	message, err := tx.createBundleAddMessage(flowMod)
	if err != nil {
		return err
	}
	tx.lock.Lock()
	tx.successAdd[message.Xid] = true
	tx.lock.Unlock()
	return tx.ofSwitch.Send(message)
}

// Complete closes the bundle configuration. It returns the number of successful messages added in the bundle.
func (tx *Transaction) Complete() (int, error) {
	if !tx.closed {
		msg1 := tx.newBundleControlMessage(openflow13.OFPBCT_CLOSE_REQUEST)
		if err := tx.sendControlRequest(msg1.Xid, msg1); err != nil {
			return 0, err
		}
		close(tx.addErrorCh)
		tx.closed = true
	}
	return len(tx.successAdd), nil
}

// Commit commits the bundle configuration. If transaction is not closed, it sends OFPBCT_CLOSE_REQUEST in advance.
func (tx *Transaction) Commit() error {
	if !tx.closed {
		return fmt.Errorf("transaction %d is not complete", tx.ID)
	}
	msg := tx.newBundleControlMessage(openflow13.OFPBCT_COMMIT_REQUEST)
	if err := tx.sendControlRequest(msg.Xid, msg); err != nil {
		return err
	}
	return nil
}

// Abort discards the bundle configuration. If transaction is not closed, it sends OFPBCT_CLOSE_REQUEST in advance.
func (tx *Transaction) Abort() error {
	if !tx.closed {
		return fmt.Errorf("transaction %d is not complete", tx.ID)
	}
	msg := tx.newBundleControlMessage(openflow13.OFPBCT_DISCARD_REQUEST)
	if err := tx.sendControlRequest(msg.Xid, msg); err != nil {
		return err
	}
	return nil
}
