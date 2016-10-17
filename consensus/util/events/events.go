/*
Copyright IBM Corp. 2016 All Rights Reserved.

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

package events

import (
	"time"

	"github.com/op/go-logging"
)

var logger *logging.Logger // package-level logger

func init() {
	logger = logging.MustGetLogger("consensus/util/events")
}

// Event is a type meant to clearly convey that the return type or parameter to a function will be supplied to/from an events.Manager
//@@ Event는 event.Manager와 통신하는 기능(함수)를 구현할 I/F
type Event interface{}

// Receiver is a consumer of events, ProcessEvent will be called serially
// as events arrive
//@@ Receiver : 이벤트 컨수머, 이벤트가 도착할때마다, 그 순서대로 ProcessEvent가 호출된다.
type Receiver interface {
	// ProcessEvent delivers an event to the Receiver, if it returns non-nil, the return is the next processed event
	ProcessEvent(e Event) Event
}

// ------------------------------------------------------------
//
// Threaded object
//
// ------------------------------------------------------------

// threaded holds an exit channel to allow threads to break from a select
//@@ threaded :
type threaded struct {
	exit chan struct{}
}

// halt tells the threaded object's thread to exit
//@@ halt : 쓰레드 객체에 종료를 알림.
func (t *threaded) Halt() {
	select {
	case <-t.exit:
		logger.Warning("Attempted to halt a threaded object twice")
	default:
		close(t.exit)
	}
}

// ------------------------------------------------------------
//
// Event Manager
//
// ------------------------------------------------------------

// Manager provides a serialized interface for submitting events to
// a Receiver on the other side of the queue
//@@ Manager는 발생 이벤트에 대하여 큐의 수신자 쪽에 직렬화된 인터페이스를 제공
type Manager interface {
	Inject(Event) // A temporary interface to allow the event manager thread to skip the queue
	//@@ 이벤트 매니저 쓰레드가 큐를 스킵하는 것을 허용하는 임시 인터페이스
	Queue() chan<- Event // Get a write-only reference to the queue, to submit events
	//@@ 이벤트를 제출하기 위해 쓰기만 가능한 큐 레퍼런스를 구함
	SetReceiver(Receiver) // Set the target to route events to
	//@@ 이벤트를 보낼 타겟, 즉 리시버를 셋
	Start() // Starts the Manager thread TODO, these thread management things should probably go away
	//@@ 이벤트 매니저 쓰레드를 시작함, 이 쓰레드 관리자는 추후 삭제 되어야 함?
	Halt() // Stops the Manager thread
	//@@ 매니저 쓰레드를 중지.
}

// managerImpl is an implementation of Manger
// Manager I/F의 구현체
type managerImpl struct {
	threaded
	receiver Receiver
	events   chan Event
}

// NewManagerImpl creates an instance of managerImpl
//@@ NewManagerImpl 새로운 managerImpl 인스턴스를 생성하고 리턴.
func NewManagerImpl() Manager {
	return &managerImpl{
		events:   make(chan Event),
		threaded: threaded{make(chan struct{})},
	}
}

// SetReceiver sets the destination for events
func (em *managerImpl) SetReceiver(receiver Receiver) {
	em.receiver = receiver
}

// Start creates the go routine necessary to deliver events
func (em *managerImpl) Start() {
	go em.eventLoop()
}

// queue returns a write only reference to the event queue
func (em *managerImpl) Queue() chan<- Event {
	return em.events
}

// SendEvent performs the event loop on a receiver to completion
func SendEvent(receiver Receiver, event Event) {
	next := event
	for {
		// If an event returns something non-nil, then process it as a new event
		next = receiver.ProcessEvent(next)
		if next == nil {
			break
		}
	}
}

// Inject can only safely be called by the managerImpl thread itself, it skips the queue
//@@ 큐를 제외한 나머지 펑션만으로 구성된 매니저 구현체 쓰레드를 호출
func (em *managerImpl) Inject(event Event) {
	if em.receiver != nil {
		SendEvent(em.receiver, event)
	}
}

// eventLoop is where the event thread loops, delivering events
//@@ eventLoop : 이벤트 쓰레드 loop, 이벤트를 전달.
func (em *managerImpl) eventLoop() {
	for {
		select {
		case next := <-em.events:
			em.Inject(next)
		case <-em.exit:
			logger.Debug("eventLoop told to exit")
			return
		}
	}
}

// ------------------------------------------------------------
//
// Event Timer
//
// ------------------------------------------------------------

// Timer is an interface for managing time driven events
// the special contract Timer gives which a traditional golang
// timer does not, is that if the event thread calls stop, or reset
// then even if the timer has already fired, the event will not be
// delivered to the event queue
//@@ Timer : 시간을 이용한 이벤트를 관리하기 위한 인터페이스
//@@ 전통적인 고 언어가 제공하지 않는 특별한 타입의 계약 타이머는,
//@@ 이벤트 쓰레드가 stop 또는 reset을 호출하면, 시간이 이미 만료되었다고 하더라도,
//@@ 이 이벤트는 이벤트 큐에 전달되지 않음.
type Timer interface {
	SoftReset(duration time.Duration, event Event) // start a new countdown, only if one is not already started
	Reset(duration time.Duration, event Event)     // start a new countdown, clear any pending events
	Stop()                                         // stop the countdown, clear any pending events
	Halt()                                         // Stops the Timer thread
}

// TimerFactory abstracts the creation of Timers, as they may
// need to be mocked for testing
type TimerFactory interface {
	CreateTimer() Timer // Creates an Timer which is stopped
}

// TimerFactoryImpl implements the TimerFactory
type timerFactoryImpl struct {
	manager Manager // The Manager to use in constructing the event timers
}

// NewTimerFactoryImpl creates a new TimerFactory for the given Manager
func NewTimerFactoryImpl(manager Manager) TimerFactory {
	return &timerFactoryImpl{manager}
}

// CreateTimer creates a new timer which deliver events to the Manager for this factory
func (etf *timerFactoryImpl) CreateTimer() Timer {
	return newTimerImpl(etf.manager)
}

// timerStart is used to deliver the start request to the eventTimer thread
//@@ timerStart : 이벤트 타이머 쓰레드에 요청을 시작하기 위함.
type timerStart struct {
	hard     bool          // Whether to reset the timer if it is running //@@ 타이머가 이미 돌고 있다면, 리셋할지 여부
	event    Event         // What event to push onto the event queue //@@ 이벤트 큐에 넣어질 이벤트
	duration time.Duration // How long to wait before sending the event //@@ 이벤트 송신 대기 시간.
}

// timerImpl is an implementation of Timer
//@@ timerImpl : Timer의 구현체
type timerImpl struct {
	threaded                   // Gives us the exit chan //@@ 종료 채널???
	timerChan <-chan time.Time // When non-nil, counts down to preparing to do the event //@@ 이벤트 타이머 실행 채널(카운트 다운)
	startChan chan *timerStart // Channel to deliver the timer start events to the service go routine //@@ 타이머 스타트 이벤트를 전달할 채널
	stopChan  chan struct{}    // Channel to deliver the timer stop events to the service go routine //@@ 타이머 종료 이벤트를 전달할 채널
	manager   Manager          // The event manager to deliver the event to after timer expiration //@@ 타이머가 만료된 후, 이벤트를 전달할 이벤트 매니저
}

// newTimer creates a new instance of timerImpl
//@@ 새로운 timerImpl 인스턴스를 생성.
func newTimerImpl(manager Manager) Timer {
	et := &timerImpl{
		startChan: make(chan *timerStart),
		stopChan:  make(chan struct{}),
		threaded:  threaded{make(chan struct{})},
		manager:   manager,
	}
	go et.loop()
	return et
}

// softReset tells the timer to start a new countdown, only if it is not currently counting down
// this will not clear any pending events
//@@ softReset : 타이머가 새로운 카운트다운을 시작하도록 알림, (현재, 타이머가 동작중이 아닐 경우에만.)
//@@ 아직 지연 이벤트들을 클리어하지 않음
func (et *timerImpl) SoftReset(timeout time.Duration, event Event) {
	et.startChan <- &timerStart{
		duration: timeout,
		event:    event,
		hard:     false,
	}
}

// reset tells the timer to start counting down from a new timeout, this also clears any pending events
//@@ reset : 새로운 타임아웃 기준으로 카운트 다운을 실행하도록 함, 이 함수의 경우엔 지연 이벤트들을 모두 클리어함.
func (et *timerImpl) Reset(timeout time.Duration, event Event) {
	et.startChan <- &timerStart{
		duration: timeout,
		event:    event,
		hard:     true,
	}
}

// stop tells the timer to stop, and not to deliver any pending events
//@@ stop : 타이머가 정지하도록 함. 이벤트 전달은 없음
func (et *timerImpl) Stop() {
	et.stopChan <- struct{}{}
}

// loop is where the timer thread lives, looping
// loop는 타이머 쓰레드가 살아있을 때 looping을 구현
func (et *timerImpl) loop() {
	var eventDestChan chan<- Event
	var event Event

	for {
		// A little state machine, relying on the fact that nil channels will block on read/write indefinitely
		//@@ 작은 상태 머신, nil 채널은 읽기와 쓰기가 모두 제한되도록 함.

		select {
		case start := <-et.startChan: // 타이머를 시작하는 경우,
			if et.timerChan != nil {
				if start.hard {
					logger.Debug("Resetting a running timer")
				} else {
					continue
				}
			}
			logger.Debug("Starting timer")
			et.timerChan = time.After(start.duration)
			if eventDestChan != nil {
				logger.Debug("Timer cleared pending event")
			}
			event = start.event
			eventDestChan = nil
		case <-et.stopChan: // 타이머를 종료하는 경우,
			if et.timerChan == nil && eventDestChan == nil {
				logger.Debug("Attempting to stop an unfired idle timer")
			}
			et.timerChan = nil
			logger.Debug("Stopping timer")
			if eventDestChan != nil {
				logger.Debug("Timer cleared pending event")
			}
			eventDestChan = nil
			event = nil
		case <-et.timerChan: // 타이머가 만료되었을 경우,
			logger.Debug("Event timer fired")
			et.timerChan = nil
			eventDestChan = et.manager.Queue()
		case eventDestChan <- event: // 타이머가 적용된 이벤트가 전달되었을 경우,
			logger.Debug("Timer event delivered")
			eventDestChan = nil
		case <-et.exit: // 타이머가 종료, 중지 되었을 경우
			logger.Debug("Halting timer")
			return
		}
	}
}
