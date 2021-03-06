/*
 *
 * Copyright 2014, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

package grpc

import (
	"bytes"
	"io"
	"time"

	"golang.org/x/net/context"
	"golang.org/x/net/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/transport"
)

// recvResponse receives and parses an RPC response.
// On error, it returns the error and indicates whether the call should be retried.
//
// TODO(zhaoq): Check whether the received message sequence is valid.
func recvResponse(dopts dialOptions, t transport.ClientTransport, c *callInfo, stream *transport.Stream, reply interface{}) error {
	// Try to acquire header metadata from the server if there is any.
	var err error
	c.headerMD, err = stream.Header()
	if err != nil {
		return err
	}
	p := &parser{r: stream}
	for {
		if err = recv(p, dopts.codec, stream, dopts.dc, reply); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	c.trailerMD = stream.Trailer()
	return nil
}

// sendRequest writes out various information of an RPC such as Context and Message.
func sendRequest(ctx context.Context, codec Codec, compressor Compressor, callHdr *transport.CallHdr, t transport.ClientTransport, args interface{}, opts *transport.Options) (_ *transport.Stream, err error) {
	stream, err := t.NewStream(ctx, callHdr)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if _, ok := err.(transport.ConnectionError); !ok {
				t.CloseStream(stream, err)
			}
		}
	}()
	var cbuf *bytes.Buffer
	if compressor != nil {
		cbuf = new(bytes.Buffer)
	}
	outBuf, err := encode(codec, args, compressor, cbuf)
	if err != nil {
		return nil, transport.StreamErrorf(codes.Internal, "grpc: %v", err)
	}
	err = t.Write(stream, outBuf, opts)
	// t.NewStream(...) could lead to an early rejection of the RPC (e.g., the service/method
	// does not exist.) so that t.Write could get io.EOF from wait(...). Leave the following
	// recvResponse to get the final status.
	if err != nil && err != io.EOF {
		return nil, err
	}
	// Sent successfully.
	return stream, nil
}

// Invoke sends the RPC request on the wire and returns after response is received.
// Invoke is called by generated code. Also users can call Invoke directly when it
// is really needed in their use cases.
//@@ RPC 요청을 보내고 응답 수신 (sync 모드, connection close/error 인 경우 retry)
//@@ 함수 인자 설명
//@@ ctx : 이거는...
//@@ method : 호출할 method 명
//@@ reply : 응답 버퍼 (interface {} --> 형지정을 하지 않을 때)
//@@ cc : gRPC ClientConn
//@@ opts : 콤마(,)로 여러 CallOption 넣을 수 있음
func Invoke(ctx context.Context, method string, args, reply interface{}, cc *ClientConn, opts ...CallOption) (err error) {
	c := defaultCallInfo
	for _, o := range opts {
		if err := o.before(&c); err != nil {
			return toRPCErr(err)
		}
	}
	defer func() {
		for _, o := range opts {
			o.after(&c)
		}
	}()
	
	//@@ EnableTracing == true : Trace Log 쌓는거 같음
	//@@ 파일시스템에서 찾아봐라.. : "grpc.Sent." + <method Family명>
	if EnableTracing {
		c.traceInfo.tr = trace.New("grpc.Sent."+methodFamily(method), method)
		defer c.traceInfo.tr.Finish()
		c.traceInfo.firstLine.client = true
		if deadline, ok := ctx.Deadline(); ok {
			c.traceInfo.firstLine.deadline = deadline.Sub(time.Now())
		}
		c.traceInfo.tr.LazyLog(&c.traceInfo.firstLine, false)
		// TODO(dsymonds): Arrange for c.traceInfo.firstLine.remoteAddr to be set.
		defer func() {
			if err != nil {
				c.traceInfo.tr.LazyLog(&fmtStringer{"%v", []interface{}{err}}, true)
				c.traceInfo.tr.SetError()
			}
		}()
	}
	topts := &transport.Options{
		Last:  true,
		Delay: false,
	}
	
	// retry 를 위한 for loop : connection close/error 인 경우 retry
	for {
		var (
			err    error
			t      transport.ClientTransport
			stream *transport.Stream
			// Record the put handler from Balancer.Get(...). It is called once the
			// RPC has completed or failed.
			put func()
		)
		// TODO(zhaoq): Need a formal spec of fail-fast.
		callHdr := &transport.CallHdr{
			Host:   cc.authority,
			Method: method,
		}
		if cc.dopts.cp != nil {
			callHdr.SendCompress = cc.dopts.cp.Type()
		}
		gopts := BalancerGetOptions{
			BlockingWait: !c.failFast,
		}
		t, put, err = cc.getTransport(ctx, gopts)
		if err != nil {
			// TODO(zhaoq): Probably revisit the error handling.
			if _, ok := err.(*rpcError); ok {
				return err
			}
			if err == errConnClosing {
				if c.failFast {
					return Errorf(codes.Unavailable, "%v", errConnClosing)
				}
				continue
			}
			// All the other errors are treated as Internal errors.
			return Errorf(codes.Internal, "%v", err)
		}
		if c.traceInfo.tr != nil {
			c.traceInfo.tr.LazyLog(&payload{sent: true, msg: args}, true)
		}
		stream, err = sendRequest(ctx, cc.dopts.codec, cc.dopts.cp, callHdr, t, args, topts)
		if err != nil {
			if put != nil {
				put()
				put = nil
			}
			if _, ok := err.(transport.ConnectionError); ok {
				if c.failFast {
					return toRPCErr(err)
				}
				continue
			}
			return toRPCErr(err)
		}
		// Receive the response
		err = recvResponse(cc.dopts, t, &c, stream, reply)
		if err != nil {
			if put != nil {
				put()
				put = nil
			}
			if _, ok := err.(transport.ConnectionError); ok {
				if c.failFast {
					return toRPCErr(err)
				}
				continue
			}
			t.CloseStream(stream, err)
			return toRPCErr(err)
		}
		if c.traceInfo.tr != nil {
			c.traceInfo.tr.LazyLog(&payload{sent: false, msg: reply}, true)
		}
		t.CloseStream(stream, nil)
		if put != nil {
			put()
			put = nil
		}
		return Errorf(stream.StatusCode(), "%s", stream.StatusDesc())
	}
}
