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

package producer

import (
	"fmt"
	"sync"
	"time"

	pb "github.com/hyperledger/fabric/protos"
)

//---- event hub framework ----

//handlerListi uses map to implement a set of handlers. use mutex to access
//the map. Note that we don't have lock/unlock wrapper methods as the lock
//of handler list has to be done under the eventProcessor lock. See
//registerHandler, deRegisterHandler. register/deRegister methods
//will be called only when a new consumer chat starts/ends respectively
//and the big lock should have no performance impact
//
type handlerList interface {
	add(ie *pb.Interest, h *handler) (bool, error)
	del(ie *pb.Interest, h *handler) (bool, error)
	foreach(ie *pb.Event, action func(h *handler))
}

//블록과 트랜잭션 거부 타입의 이벤트에 적용되는 구조체
type genericHandlerList struct {
	sync.RWMutex
	handlers map[*handler]bool
}

//체인코드 이벤트 타입의 이벤트에 적용되는 구조체
type chaincodeHandlerList struct {
	sync.RWMutex
	handlers map[string]map[string]map[*handler]bool
}

//체인코드 핸들러 리스트에 새로운 핸들러를 추가
func (hl *chaincodeHandlerList) add(ie *pb.Interest, h *handler) (bool, error) {
	hl.Lock()
	defer hl.Unlock()

	//chaincode registration info must be non-nil
	if ie.GetChaincodeRegInfo() == nil {
		return false, fmt.Errorf("chaincode information not provided for registering")
	}
	//chaincode registration info must be for a non-empty chaincode ID (even if the chaincode does not exist)
	if ie.GetChaincodeRegInfo().ChaincodeID == "" {
		return false, fmt.Errorf("chaincode ID not provided for registering")
	}
	//is there a event type map for the chaincode
	//해당 체인코드의 이벤트 맵이 없다면, 생성. (chaincodeid - eventname) == emap
	emap, ok := hl.handlers[ie.GetChaincodeRegInfo().ChaincodeID]
	if !ok {
		emap = make(map[string]map[*handler]bool)
		hl.handlers[ie.GetChaincodeRegInfo().ChaincodeID] = emap
	}

	//create handler map if this is the first handler for the type
	//해당 타입에 대한 첫번째 핸들러라면, 핸들러 맵을 생성.
	// (chaincodeid - eventname)emap, handler == handlermap
	var handlerMap map[*handler]bool
	if handlerMap, _ = emap[ie.GetChaincodeRegInfo().EventName]; handlerMap == nil {
		handlerMap = make(map[*handler]bool)
		emap[ie.GetChaincodeRegInfo().EventName] = handlerMap
	} else if _, ok = handlerMap[h]; ok {
		return false, fmt.Errorf("handler exists for event type")
	}

	//the handler is added to the map
	handlerMap[h] = true

	return true, nil
}

//체인코드 핸들러 리스트에서 핸들러를 삭제
func (hl *chaincodeHandlerList) del(ie *pb.Interest, h *handler) (bool, error) {
	hl.Lock()
	defer hl.Unlock()

	//chaincode registration info must be non-nil
	if ie.GetChaincodeRegInfo() == nil {
		return false, fmt.Errorf("chaincode information not provided for de-registering")
	}

	//chaincode registration info must be for a non-empty chaincode ID (even if the chaincode does not exist)
	if ie.GetChaincodeRegInfo().ChaincodeID == "" {
		return false, fmt.Errorf("chaincode ID not provided for de-registering")
	}

	//if there's no event type map, nothing to do
	emap, ok := hl.handlers[ie.GetChaincodeRegInfo().ChaincodeID]
	if !ok {
		return false, fmt.Errorf("chaincode ID not registered")
	}

	//if there are no handlers for the event type, nothing to do
	var handlerMap map[*handler]bool
	if handlerMap, _ = emap[ie.GetChaincodeRegInfo().EventName]; handlerMap == nil {
		return false, fmt.Errorf("event name %s not registered for chaincode ID %s", ie.GetChaincodeRegInfo().EventName, ie.GetChaincodeRegInfo().ChaincodeID)
	} else if _, ok = handlerMap[h]; !ok {
		//the handler is not registered for the event type
		return false, fmt.Errorf("handler not registered for event name %s for chaincode ID %s", ie.GetChaincodeRegInfo().EventName, ie.GetChaincodeRegInfo().ChaincodeID)
	}
	//remove the handler from the map
	delete(handlerMap, h)

	//if the last handler has been removed from handler map for a chaincode's event,
	//remove the event map.
	//if the last map of events have been removed for the chaincode UUID
	//remove the chaincode UUID map
	//체인코드 이벤트를 위한 랜들러 맵으로부터 마지막 핸들러가 삭제되면, 이벤트 맵도 삭제 된다.
	//(핸들러리스트, event)(event, chaincode id)
	if len(handlerMap) == 0 {
		delete(emap, ie.GetChaincodeRegInfo().EventName)
		if len(emap) == 0 {
			delete(hl.handlers, ie.GetChaincodeRegInfo().ChaincodeID)
		}
	}

	return true, nil
}

//체인코드 이벤트의 경우,
func (hl *chaincodeHandlerList) foreach(e *pb.Event, action func(h *handler)) {
	hl.Lock()
	defer hl.Unlock()

	//if there's no chaincode event in the event... nothing to do (why was this event sent ?)
	if e.GetChaincodeEvent() == nil || e.GetChaincodeEvent().ChaincodeID == "" {
		return
	}

	//get the event map for the chaincode
	if emap := hl.handlers[e.GetChaincodeEvent().ChaincodeID]; emap != nil {
		//get the handler map for the event
		if handlerMap := emap[e.GetChaincodeEvent().EventName]; handlerMap != nil {
			for h := range handlerMap {
				action(h)
			}
		}
		//send to handlers who want all events from the chaincode, but only if
		//EventName is not already "" (chaincode should NOT send nameless events though)
		if e.GetChaincodeEvent().EventName != "" {
			if handlerMap := emap[""]; handlerMap != nil {
				for h := range handlerMap {
					action(h)
				}
			}
		}
	}
}

//체인코드가 아닌 제네릭 핸들러 리스트에 핸들러 추가
func (hl *genericHandlerList) add(ie *pb.Interest, h *handler) (bool, error) {
	hl.Lock()
	if _, ok := hl.handlers[h]; ok {
		hl.Unlock()
		return false, fmt.Errorf("handler exists for event type")
	}
	hl.handlers[h] = true
	hl.Unlock()
	return true, nil
}

//체인코드가 아닌 제네릭 핸들러 리스트에 핸들러 삭제
func (hl *genericHandlerList) del(ie *pb.Interest, h *handler) (bool, error) {
	hl.Lock()
	if _, ok := hl.handlers[h]; !ok {
		hl.Unlock()
		return false, fmt.Errorf("handler does not exist for event type")
	}
	delete(hl.handlers, h)
	hl.Unlock()
	return true, nil
}

//체인코드가 아닌 제네릭 핸들러 리스트를 loop도는 함수.
func (hl *genericHandlerList) foreach(e *pb.Event, action func(h *handler)) {
	hl.Lock()
	for h := range hl.handlers {
		action(h)
	}
	hl.Unlock()
}

//eventProcessor has a map of event type to handlers interested in that
//event type. start() kicks of the event processor where it waits for Events
//from producers. We could easily generalize the one event handling loop to one
//per handlerMap if necessary.
//이벤트 프로세서는 이벤트 타입과 해당 이벤트 타입을 관심 이벤트로 가진 핸들러 맵을 가지고 있다.
//start()는 이 이벤트 프로세서를 기동킨다.
type eventProcessor struct {
	sync.RWMutex
	eventConsumers map[pb.EventType]handlerList

	//we could generalize this with mutiple channels each with its own size
	//이벤트를 수신하는 채널.
	eventChannel chan *pb.Event

	//milliseconds timeout for producer to send an event.
	//if < 0, if buffer full, unblocks immediately and not send
	//if 0, if buffer full, will block and guarantee the event will be sent out
	//if > 0, if buffer full, blocks till timeout
	timeout int
}

//어플리케이션 전 영역의 걸쳐 하나의 클래스의 단 하나의 인스턴스만을 생성하는 것 -> 싱글톤
//global eventProcessor singleton created by initializeEvents. Openchain producers
//send events simply over a reentrant static method
//이벤트 프로세서는 싱글톤으로 선언됨.
var gEventProcessor *eventProcessor

func (ep *eventProcessor) start() {
	producerLogger.Info("event processor started")
	for {
		//wait for event
		//이벤트 채널이 이벤트 수신 대기
		e := <-ep.eventChannel

		var hl handlerList
		eType := getMessageType(e) //이벤트 타입 확인
		ep.Lock()
		//해당 이벤트 타입을 수신하기로한 이벤트 컨수머들을 담당하는 핸들러
		if hl, _ = ep.eventConsumers[eType]; hl == nil {
			producerLogger.Errorf("Event of type %s does not exist", eType)
			ep.Unlock()
			continue
		}
		//lock the handler map lock

		ep.Unlock()
		//loop를 돌면서 핸들러가 이벤트를 송신
		hl.foreach(e, func(h *handler) {
			if e.Event != nil {
				h.SendMessage(e)
			}
		})

	}
}

//initialize and start
//이벤트 프로세서 시작
func initializeEvents(bufferSize uint, tout int) {
	if gEventProcessor != nil {
		panic("should not be called twice")
	}
	//(event consumer, channel, timeout set)
	gEventProcessor = &eventProcessor{eventConsumers: make(map[pb.EventType]handlerList), eventChannel: make(chan *pb.Event, bufferSize), timeout: tout}

	addInternalEventTypes()

	//start the event processor
	go gEventProcessor.start()
}

//AddEventType supported event
//이벤트 프로세서가 처리할 이벤트 타입(기정의된 블록, 체인코드이벤트, 트랜잭션rejection)을 정의
func AddEventType(eventType pb.EventType) error {
	gEventProcessor.Lock()
	producerLogger.Debugf("registering %s", pb.EventType_name[int32(eventType)])
	if _, ok := gEventProcessor.eventConsumers[eventType]; ok {
		gEventProcessor.Unlock()
		return fmt.Errorf("event type exists %s", pb.EventType_name[int32(eventType)])
	}

	switch eventType {
	case pb.EventType_BLOCK:
		//블록 이벤트를 수신할 컨수머 리스트 = 각 피어별로 할당할 핸들러 리스트의 참조 링크
		gEventProcessor.eventConsumers[eventType] = &genericHandlerList{handlers: make(map[*handler]bool)}
	case pb.EventType_CHAINCODE:
		gEventProcessor.eventConsumers[eventType] = &chaincodeHandlerList{handlers: make(map[string]map[string]map[*handler]bool)}
	case pb.EventType_REJECTION:
		gEventProcessor.eventConsumers[eventType] = &genericHandlerList{handlers: make(map[*handler]bool)}
	}
	gEventProcessor.Unlock()

	return nil
}

//이벤트 프로세서에 이벤트 핸들러를 등록. -> 이벤트 타입별 핸들러 리스트에 추가.
func registerHandler(ie *pb.Interest, h *handler) error {
	producerLogger.Debugf("registerHandler %s", ie.EventType)

	gEventProcessor.Lock()
	defer gEventProcessor.Unlock()
	if hl, ok := gEventProcessor.eventConsumers[ie.EventType]; !ok {
		return fmt.Errorf("event type %s does not exist", ie.EventType)
	} else if _, err := hl.add(ie, h); err != nil {
		return fmt.Errorf("error registering handler for  %s: %s", ie.EventType, err)
	}

	return nil
}

// 이벤트 프로세서에 등록된 이벤트 핸들러를 해제 -> 이벤트 타입별 핸들러 리스트에서 삭제
func deRegisterHandler(ie *pb.Interest, h *handler) error {
	producerLogger.Debugf("deRegisterHandler %s", ie.EventType)

	gEventProcessor.Lock()
	defer gEventProcessor.Unlock()
	if hl, ok := gEventProcessor.eventConsumers[ie.EventType]; !ok {
		return fmt.Errorf("event type %s does not exist", ie.EventType)
	} else if _, err := hl.del(ie, h); err != nil {
		return fmt.Errorf("error deregistering handler for %s: %s", ie.EventType, err)
	}

	return nil
}

//------------- producer API's -------------------------------

//Send sends the event to interested consumers
//이벤트 수신자에게 이벤트를 송신, 송신 시간 타임아웃이 적용되어 있음
func Send(e *pb.Event) error {
	if e.Event == nil {
		producerLogger.Error("event not set")
		return fmt.Errorf("event not set")
	}

	if gEventProcessor == nil {
		return nil
	}

	if gEventProcessor.timeout < 0 {
		select {
		case gEventProcessor.eventChannel <- e:
		default:
			return fmt.Errorf("could not send the blocking event")
		}
	} else if gEventProcessor.timeout == 0 {
		gEventProcessor.eventChannel <- e
	} else {
		select {
		case gEventProcessor.eventChannel <- e:
		case <-time.After(time.Duration(gEventProcessor.timeout) * time.Millisecond):
			return fmt.Errorf("could not send the blocking event")
		}
	}

	return nil
}
