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

package dockercontroller

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/fsouza/go-dockerclient"
	"github.com/hyperledger/fabric/core/container/ccintf"
	cutil "github.com/hyperledger/fabric/core/container/util"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
)

var (
	dockerLogger = logging.MustGetLogger("dockercontroller")
	hostConfig   *docker.HostConfig
)

//DockerVM is a vm. It is identified by an image id
//
//DockerVM 구조체 :  image id로 구별되는 vm임
type DockerVM struct {
	id string
}

// getDockerHostConfig() : 도커 호스트 config 가져오기
func getDockerHostConfig() *docker.HostConfig {
	if hostConfig != nil {
		return hostConfig
	}
	dockerKey := func(key string) string {
		return "vm.docker.hostConfig." + key
	}
	getInt64 := func(key string) int64 {
		defer func() {
			if err := recover(); err != nil {
				dockerLogger.Warningf("load vm.docker.hostConfig.%s failed, error: %v", key, err)
			}
		}()
		n := viper.GetInt(dockerKey(key))
		return int64(n)
	}

	var logConfig docker.LogConfig
	err := viper.UnmarshalKey(dockerKey("LogConfig"), &logConfig)
	if err != nil {
		dockerLogger.Warningf("load docker HostConfig.LogConfig failed, error: %s", err.Error())
	}
	networkMode := viper.GetString(dockerKey("NetworkMode"))
	if networkMode == "" {
		networkMode = "host"
	}
	dockerLogger.Debugf("docker container hostconfig NetworkMode: %s", networkMode)

	hostConfig = &docker.HostConfig{
		CapAdd:  viper.GetStringSlice(dockerKey("CapAdd")),
		CapDrop: viper.GetStringSlice(dockerKey("CapDrop")),

		DNS:         viper.GetStringSlice(dockerKey("Dns")),
		DNSSearch:   viper.GetStringSlice(dockerKey("DnsSearch")),
		ExtraHosts:  viper.GetStringSlice(dockerKey("ExtraHosts")),
		NetworkMode: networkMode,
		IpcMode:     viper.GetString(dockerKey("IpcMode")),
		PidMode:     viper.GetString(dockerKey("PidMode")),
		UTSMode:     viper.GetString(dockerKey("UTSMode")),
		LogConfig:   logConfig,

		ReadonlyRootfs:   viper.GetBool(dockerKey("ReadonlyRootfs")),
		SecurityOpt:      viper.GetStringSlice(dockerKey("SecurityOpt")),
		CgroupParent:     viper.GetString(dockerKey("CgroupParent")),
		Memory:           getInt64("Memory"),
		MemorySwap:       getInt64("MemorySwap"),
		MemorySwappiness: getInt64("MemorySwappiness"),
		OOMKillDisable:   viper.GetBool(dockerKey("OomKillDisable")),
		CPUShares:        getInt64("CpuShares"),
		CPUSet:           viper.GetString(dockerKey("Cpuset")),
		CPUSetCPUs:       viper.GetString(dockerKey("CpusetCPUs")),
		CPUSetMEMs:       viper.GetString(dockerKey("CpusetMEMs")),
		CPUQuota:         getInt64("CpuQuota"),
		CPUPeriod:        getInt64("CpuPeriod"),
		BlkioWeight:      getInt64("BlkioWeight"),
	}

	return hostConfig
}

//@@ docker config 생성
//@@ docker option 생성
//@@ CreateContainer() 호출
//@@		docker HTTP 에 container 생성 요청송신/응답수신
func (vm *DockerVM) createContainer(ctxt context.Context, client *docker.Client, imageID string, containerID string, args []string, env []string, attachstdin bool, attachstdout bool) error {
	config := docker.Config{Cmd: args, Image: imageID, Env: env, AttachStdin: attachstdin, AttachStdout: attachstdout}
	copts := docker.CreateContainerOptions{Name: containerID, Config: &config, HostConfig: getDockerHostConfig()}
	dockerLogger.Debugf("Create container: %s", containerID)
	_, err := client.CreateContainer(copts)
	if err != nil {
		return err
	}
	dockerLogger.Debugf("Created container: %s", imageID)
	return nil
}

//@@ Image Build Option 생성
//@@ BuildImage() 호출
//@@		docker HTTP 에 Image 생성 요청송신/응답처리
func (vm *DockerVM) deployImage(client *docker.Client, ccid ccintf.CCID, args []string, env []string, attachstdin bool, attachstdout bool, reader io.Reader) error {
	id, _ := vm.GetVMName(ccid)
	outputbuf := bytes.NewBuffer(nil)
	opts := docker.BuildImageOptions{
		Name:         id,
		Pull:         false,
		InputStream:  reader,
		OutputStream: outputbuf,
	}

	if err := client.BuildImage(opts); err != nil {
		dockerLogger.Errorf("Error building images: %s", err)
		dockerLogger.Errorf("Image Output:\n********************\n%s\n********************", outputbuf.String())
		return err
	}

	dockerLogger.Debugf("Created image: %s", id)

	return nil
}

//Deploy use the reader containing targz to create a docker image
//for docker inputbuf is tar reader ready for use by docker.Client
//the stream from end client to peer could directly be this tar stream
//talk to docker daemon using docker Client and build the image
//
//vm.Deploy() : tar.gz파일 내부의 Dockerfile을 기초로 도커 이미지를 생성
//@@ NewDockerClient() 호출
//@@		docker 로 요청보내는 Client 생성 ( session 연결 포함 )
//@@ vm.deployImage() 호출
//@@		Image Build Option 생성
//@@		BuildImage() 호출
//@@			docker HTTP 에 Image 생성 요청송신/응답처리
//@@		에러 리턴 ( 정상이면 nil )
func (vm *DockerVM) Deploy(ctxt context.Context, ccid ccintf.CCID, args []string, env []string, attachstdin bool, attachstdout bool, reader io.Reader) error {
	client, err := cutil.NewDockerClient()
	switch err {
	case nil:
		//@@ Image Build Option 생성
		//@@ BuildImage() 호출
		//@@		docker HTTP 에 Image 생성 요청송신/응답처리
		if err = vm.deployImage(client, ccid, args, env, attachstdin, attachstdout, reader); err != nil {
			return err
		}
	default:
		return fmt.Errorf("Error creating docker client: %s", err)
	}
	return nil
}

//Start starts a container using a previously created docker image
//
// vm.Start() : 사전에 생성한 docker image로 컨테이너를 구동시킴.
//@@ NewDockerClient() 호출
//@@		docker 로 요청보내는 Client 생성 ( session 연결 포함 )
//@@ stopInternal() 호출
//@@		StopContainer() 호출
//@@			docker HTTP 에 Container 중지 요청전송/응답에러리턴 (정상이면 nil)
//@@		dontkill == false : KillContainer() 호출
//@@			docker HTTP 에 Container Kill 요청전송/응답에러리턴 (정상이면 nil)
//@@		dontremove == false : RemoveContainer() 호출
//@@			docker HTTP 에 Container 삭제 요청전송/응답에러리턴 (정상이면 nil)
//@@		에러 리턴
//@@ createContainer() 호출
//@@		docker config 생성
//@@		docker option 생성
//@@		CreateContainer() 호출
//@@			docker HTTP 에 container 생성 요청송신/응답수신
//@@ Image 가 없어서 실패할 경우 deployImage() 호출 ( 다시 createContainer() 호출 )
//@@		Image Build Option 생성
//@@		BuildImage() 호출
//@@			docker HTTP 에 Image 생성 요청송신/응답처리
//@@ StartContainer() 호출
//@@		docker HTTP 에 Container 시작 요청전송/응답에러리턴 (정상이면 nil)
func (vm *DockerVM) Start(ctxt context.Context, ccid ccintf.CCID, args []string, env []string, attachstdin bool, attachstdout bool, reader io.Reader) error {
	imageID, _ := vm.GetVMName(ccid)
	client, err := cutil.NewDockerClient()
	if err != nil {
		dockerLogger.Debugf("start - cannot create client %s", err)
		return err
	}

	containerID := strings.Replace(imageID, ":", "_", -1)

	//stop,force remove if necessary
	//컨테이너를 강제로 종료시킴, 필요시 삭제할것.
	dockerLogger.Debugf("Cleanup container %s", containerID)
	//@@ StopContainer() 호출
	//@@		docker HTTP 에 Container 중지 요청전송/응답에러리턴 (정상이면 nil)
	//@@ dontkill == false : KillContainer() 호출
	//@@		docker HTTP 에 Container Kill 요청전송/응답에러리턴 (정상이면 nil)
	//@@ dontremove == false : RemoveContainer() 호출
	//@@		docker HTTP 에 Container 삭제 요청전송/응답에러리턴 (정상이면 nil)
	//@@ 에러 리턴
	vm.stopInternal(ctxt, client, containerID, 0, false, false)

	dockerLogger.Debugf("Start container %s", containerID)
	//@@ docker config 생성
	//@@ docker option 생성
	//@@ CreateContainer() 호출
	//@@		docker REST 에 container 생성 요청송신/응답수신
	err = vm.createContainer(ctxt, client, imageID, containerID, args, env, attachstdin, attachstdout)
	if err != nil {
		//if image not found try to create image and retry
		//image가 없을 경우 신규 생성해서 retry
		if err == docker.ErrNoSuchImage {
			if reader != nil {
				dockerLogger.Debugf("start-could not find image ...attempt to recreate image %s", err)
				//@@ Image Build Option 생성
				//@@ BuildImage() 호출
				//@@		docker HTTP 에 Image 생성 요청송신/응답처리
				if err = vm.deployImage(client, ccid, args, env, attachstdin, attachstdout, reader); err != nil {
					return err
				}

				dockerLogger.Debug("start-recreated image successfully")
				//@@ docker config 생성
				//@@ docker option 생성
				//@@ CreateContainer() 호출
				//@@		docker REST 에 container 생성 요청송신/응답수신
				if err = vm.createContainer(ctxt, client, imageID, containerID, args, env, attachstdin, attachstdout); err != nil {
					dockerLogger.Errorf("start-could not recreate container post recreate image: %s", err)
					return err
				}
			} else {
				dockerLogger.Errorf("start-could not find image: %s", err)
				return err
			}
		} else {
			dockerLogger.Errorf("start-could not recreate container %s", err)
			return err
		}
	}

	// start container with HostConfig was deprecated since v1.10 and removed in v1.2
	// HostConfig을 통한 컨테이너 구동은 v1.2에서 삭제됨
	err = client.StartContainer(containerID, nil)
	if err != nil {
		dockerLogger.Errorf("start-could not start container %s", err)
		return err
	}

	dockerLogger.Debugf("Started container %s", containerID)
	return nil
}

//Stop stops a running chaincode
//
// vm.Stop() : 실행중인 체인코드를 정지시킴
//@@ NewDockerClient() 호출
//@@		docker 로 요청보내는 Client 생성 ( session 연결 포함 )
//@@ stopInternal() 호출
//@@		StopContainer() 호출
//@@			docker HTTP 에 Container 중지 요청전송/응답에러리턴 (정상이면 nil)
//@@		dontkill == false : KillContainer() 호출
//@@			docker HTTP 에 Container Kill 요청전송/응답에러리턴 (정상이면 nil)
//@@		dontremove == false : RemoveContainer() 호출
//@@			docker HTTP 에 Container 삭제 요청전송/응답에러리턴 (정상이면 nil)
//@@		에러 리턴
func (vm *DockerVM) Stop(ctxt context.Context, ccid ccintf.CCID, timeout uint, dontkill bool, dontremove bool) error {
	id, _ := vm.GetVMName(ccid)
	client, err := cutil.NewDockerClient()
	if err != nil {
		dockerLogger.Debugf("stop - cannot create client %s", err)
		return err
	}
	id = strings.Replace(id, ":", "_", -1)

	//@@ StopContainer() 호출
	//@@		docker HTTP 에 Container 중지 요청전송/응답에러리턴 (정상이면 nil)
	//@@ dontkill == false : KillContainer() 호출
	//@@		docker HTTP 에 Container Kill 요청전송/응답에러리턴 (정상이면 nil)
	//@@ dontremove == false : RemoveContainer() 호출
	//@@		docker HTTP 에 Container 삭제 요청전송/응답에러리턴 (정상이면 nil)
	//@@ 에러 리턴
	err = vm.stopInternal(ctxt, client, id, timeout, dontkill, dontremove)

	return err
}

//@@ StopContainer() 호출
//@@		docker HTTP 에 Container 중지 요청전송/응답에러리턴 (정상이면 nil)
//@@ dontkill == false : KillContainer() 호출
//@@		docker HTTP 에 Container Kill 요청전송/응답에러리턴 (정상이면 nil)
//@@ dontremove == false : RemoveContainer() 호출
//@@		docker HTTP 에 Container 삭제 요청전송/응답에러리턴 (정상이면 nil)
//@@ 에러 리턴
func (vm *DockerVM) stopInternal(ctxt context.Context, client *docker.Client, id string, timeout uint, dontkill bool, dontremove bool) error {
	err := client.StopContainer(id, timeout)
	if err != nil {
		dockerLogger.Debugf("Stop container %s(%s)", id, err)
	} else {
		dockerLogger.Debugf("Stopped container %s", id)
	}
	if !dontkill {
		err = client.KillContainer(docker.KillContainerOptions{ID: id})
		if err != nil {
			dockerLogger.Debugf("Kill container %s (%s)", id, err)
		} else {
			dockerLogger.Debugf("Killed container %s", id)
		}
	}
	if !dontremove {
		err = client.RemoveContainer(docker.RemoveContainerOptions{ID: id, Force: true})
		if err != nil {
			dockerLogger.Debugf("Remove container %s (%s)", id, err)
		} else {
			dockerLogger.Debugf("Removed container %s", id)
		}
	}
	return err
}

//Destroy destroys an image
//
// vm.Destroy() : 도커 이미지를 삭제
//@@ NewDockerClient() 호출
//@@		docker 로 요청보내는 Client 생성 ( session 연결 포함 )
//@@ RemoveImageExtended() 호출
//@@		docker HTTP 에 Container 삭제 요청전송/응답에러리턴 (정상이면 nil)
func (vm *DockerVM) Destroy(ctxt context.Context, ccid ccintf.CCID, force bool, noprune bool) error {
	id, _ := vm.GetVMName(ccid)
	client, err := cutil.NewDockerClient()
	if err != nil {
		dockerLogger.Errorf("destroy-cannot create client %s", err)
		return err
	}
	id = strings.Replace(id, ":", "_", -1)

	err = client.RemoveImageExtended(id, docker.RemoveImageOptions{Force: force, NoPrune: noprune})

	if err != nil {
		dockerLogger.Errorf("error while destroying image: %s", err)
	} else {
		dockerLogger.Debug("Destroyed image %s", id)
	}

	return err
}

//GetVMName generates the docker image from peer information given the hashcode. This is needed to
//keep image name's unique in a single host, multi-peer environment (such as a development environment)
//
// vm.GetVMName() : 피어 정보의 해쉬코드값으로 도커 이미지를 생성함.
// single host, multi-peer 환경에서 이미지 이름을 유니크하게 유지하기 위해 필요함.(e.g. 개발환경)
func (vm *DockerVM) GetVMName(ccid ccintf.CCID) (string, error) {
	if ccid.NetworkID != "" {
		return fmt.Sprintf("%s-%s-%s", ccid.NetworkID, ccid.PeerID, ccid.ChaincodeSpec.ChaincodeID.Name), nil
	} else if ccid.PeerID != "" {
		return fmt.Sprintf("%s-%s", ccid.PeerID, ccid.ChaincodeSpec.ChaincodeID.Name), nil
	} else {
		return ccid.ChaincodeSpec.ChaincodeID.Name, nil
	}
}
