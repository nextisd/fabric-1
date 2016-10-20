## PBFT 알고리즘 정리(2016.10)##
#####링크 참조 :
[1] PBFT Paper PDF(osdi99) : http://pmg.csail.mit.edu/papers/osdi99.pdf

[2] PBFT PPT #1 : https://people.eecs.berkeley.edu/~istoica/classes/cs268/06/notes/BFT-osdi99x6.pdf

[3] PBFT PPT #2 : http://www.cs.utexas.edu/users/lorenzo/corsi/cs371d/07F/notes/week14.pdf

[4] Tendermint : https://atrium.lib.uoguelph.ca/xmlui/bitstream/handle/10214/9769/Buchman_Ethan_201606_MAsc.pdf?sequence=7

[5] Zyzzyba : http://disi.unitn.it/~montreso/ds/handouts/17-pbft2.pdf

[6] Fault-Tolerence 종합 : http://slideplayer.com/slide/4158355/
- - -

- **PBFT(Practical Byzantine Fault-Torelence)**
	+ R개의 Replica는 f개의 Byzantine Fault를 견딘다.

	+ 강력한 암호화 (비위조 서명, 해시 충돌 방지)

	+ 약한 동기화(sync) 환경을 가정


- - -

- **Request 처리 요청**
	- 프로토콜은 뷰(view) 내부에서 실행됨

	- 현재의 뷰는 Primary를 지정한다.

	- Primary는 'sequence number'를 할당하여 request를 ordering.
	- Backup(not a primary replica)들은 Primary의 올바른 동작을 보장한다.
		1. Primary가 올바르게 ordering 했는가?
		2. Primary Fault 발생시 View Change를 트리거 한다.

	- result `r`에 대해 accept 하기 전에 클라이언트는 f+1개의 (동일한 `t`, 동일한 `r`, 다른 `i`로 만들어진) REPLY를 기다린다.

        ---
            < REQUEST, o, t, c >@c
                o : state machine operation
                t : timestamp
                c : client id
                @c : client c's signature

        ---
            < REPLY, v, t, c, i, r >@i
                v : view Number
                t : timestamp
                c : client ID
                i : replica Number
                r : operation result
                @i : replica i's signature
        ---

- **Troubleshooting**
	- REPLY를 기다리던 `c`(client)에 타임아웃 발생시, REQUEST를 모든 Replica에게 Broadcast 한다.

	- 만약, Replica가 이미 Response 계산이 완료되어 있다면 그대로 리턴하면 된다.

	- 그게 아니라면, Replica들은 REQUEST를 Primary에게 포워딩 한다.

	- **Praimary가 Multicast하지 않는다면 faulty를 의심할 수 있다.**

- - -

- ** Quorum(정족수) and Certificate**
	- **Quorum은 최소한 2f+1개의 Replica가 필요**
		+ 2개 이상의 quorum은 하나 이상의 정상 replica에서 교차함
		+ Faulty replica가 없는 한개의 quorum은 항상 존재함

	- **Certificate** : Quorum 구성원으로 부터 발행된 특정한 속성을 보장하거나 인증하는 메시지 셋
		+ 두가지 Certificate 알고리즘을 정의할수 있다.
			1. **Strong Certificate** : *2f+1 message*
			2. **Weak Certificate** : *f+1 message*
- - -

- ** Algorithm Components **
	- Normal case operation
		+ 3-phase algorithm
			1. **Pre-prepare phase** : REQUEST 순서 지정
			2. **Prepare phase** : 뷰 내에서의 REQUEST의 순서 보장(확정)
			3. **Commit phase** : 뷰와 뷰간의 오더링 보장

		+ 각각의 replica(`i`)는 아래의 state를 관리한다(메모리 상에서 관리/저장 가능)
			1. Service State
			2. Message Log(모든 송수신 메시지)
			3. Replica(`i`)의 current view를 나타내는 integer(`v`)

- - -

- ** PRE-PREPARE**
        Primary는 <<PRE-PREPARE, v, n, d>@p, m> 메시지를 Broadcast 처리.
            v : view no.
            n : seq. no.
            d : digest of m
            @p : Primary's signature
            m : client's request
 	- 정상(not faulty) backup(replica, not primary) `i`는 아래 조건들을 충족한다면 `PRE-PREPARE`를 Accept 한다.

        1. `PRE-PREPARE`는 well-formed(적격)
        2. `i`는 뷰(`v`) 내에 포함
        3. `i`는 동일한 `v`(view no), 동일한 `n`(seq no.), 다른 `d`(digest of m)를 가진 `PRE-PREPARE`를 accept 한적이 없어야 한다.
        4. `n`은 두개의 워터마크(watermark) `H`와 `L` 사이의 숫자여야 함(++seq no. 고갈 방지++)

    - 각각의 Accepted된 `PRE-PREPARE` 메시지는 replica의 메시지로그에 저장된다(Primary도 동일)
- - -

- ** PREPARE **
      Backup(i)는 `<PREPARE, v, n, d, i>@i` 를 Broadcast 처리.
    	v : view no.
        n : seq no.
        d : digest of m
        i : replica no.
        @i : replica i's signature

	- 정상적인 backup(`i`)는 아래 조건을 충족한다면 `PREPARE`를 Accept 한다.

        1. `PREPARE` is well formed.
        2. `i`는 뷰(`v`)에 포함
        3. `n`은 두개의 워터마크 `L`~`H` 사이에 위치

    - `PREPARE`를 전송한 Replica들은 뷰(`v`) 내에서 REQUEST(`m`)에 대한 seq no(`n`)을 Accept 한다.
    - 각각의 Accepted `PREPARE` 메시지는 replica의 메시지 로그에 저장된다.

- - -

- ** Prepare Certificate**

    - *P-Certificate*는 view내의 모든 처리 순서(order)를 보증한다.

    - 로그에 아래 내용들이 포함되어 있다면, Replica는 P-Certificate(m,v,n)을 생성한다.
        1. REQUEST(`m`)
        2. 뷰(`v`) 내에서 REQUEST(`m`)에 해당하고 seq no(`n`)인 `PRE-PREPARE` 메시지
        3. `PRE-PREPARE`를 만족하는 각각의 다른 backup으로 부터 온 2f개의 `PREPARE` 메시지

    -  *P-Certificate(m,v,n)*은
        - 뷰(`v`) 내에서 REQUEST(`m`)에 seq no(`n`)을 할당하는 것에 대한 ++Quorum(정족수)의 합의를 의미함++

        - *P-Certificate(m1,v,n)*, *P-Certificate(m2,v,n)*을 갖는 두개의 정상(non-faulty) Replica는 존재할 수 없음.

- - -

- **Are we done?**
    - Replica는 뷰(`v`)내에서 REQUEST(`m`)에 seq no(`n`)을 할당하는 것을 보증하는 *P-Certificate*를 모음(collect)

    - 어떤 문제가 있을 수 있나?
        - `v`에 대한 Primary faulty => 뷰체인지 할것
        - 새로운 Primary는 새로운 뷰(`v'`)에서 REQUEST(`m`)에 대한 동일한 seq no(`n`)을 보장해야 한다.
            - 새로운 Primary는 *P-Certificate*가 없을 수도 있다.
            - Quorum을 맞출 수 있을까?

- - -

- ** COMMIT **
  	replica(i)는 P-Certificate를 collecting 한 뒤 `<COMMIT, v, n, d, i>@i` 를 Multicast 처리.
    	v : view no.
        n : seq no.
        d : digest of m
        i : replica no.
        @i : i's signature

- - -

- ** Commit Certificate**
    - Replica는 아래조건 충족시 *C-Certificate(m,v,n)*를 갖는다.
        1. *P-Certificate(m,v,n)* 보유시.
        2. 각각의 다른(자신 포함) replica들로부터 받은 2f+1개의 commit 메시지가 로그에 있을때.

    - 어떤 Replica가 *C-Certificate(m,v,n)*을 갖고 있다는 것은 f+1개의 정상 replica가 *P-Certificate(m,v,n)*를 갖고 있다는 뜻임, 이러한 정의는 아래의 속성들을 보장함.
        1. 정상(non-faulty) Replica는 ++뷰체인지 시에도 commit 된 REQUEST의 seq no.를 그대로 사용한다.++
        2. 정상 Replica가 *C-Certificate* 생성시 결국 f+1개의 정상 Replica도 동일 작업이 수행된다(*C-Certificate* 생성)
- - -

- ** REPLY **
    - REQUEST 실행 완료 후 replica들은 클라이언트에게 REPLY 처리.
- - -

- ** Garbage Collection**
    - Replica는 "old" Request들의 로그 정보를 삭제해야만 함

    - 언제를 "old"로 볼수 있을까?
        - Request가 실행된 직후?
        - 로깅된 데이터가 앞으로 사용될 일이 없다는 것을 Replica가 증명할 수 있을때.
- - -

- ** Stable Certificate**
    - Certificate로 로그를 Truncate 처리

        - 각각의 Replica는 주기적으로(K개의 request를 처리 후) state의 Checkpoint를 만들고 해당 state(체크포인트된)의 correct 여부를 증명하기 위한 Certificate를 생성한다.
        - `<CHECKPOINT, n, d, i >@i` 를 Multicast 처리.
        - `Stable Certificate` : 약한 인증서(weak certificate)로서 동일한 n과 d를 가진 f+1개의 다른 replica로 부터 온 메시지들로 구성됨.
            - 최소한 1개의 정상 Replica가 seq no(`n`)에 대한 *C-Certification*을 보유하고 있다는 것을 보증해줌
            - f+1개의 정상 Replica가 *P-Certification*을 가짐
            - seq no(`n`) is locked!
- - -

- ** Checkpoint and Watermarks **

    - Watermark `L`과 `H`는 Byzantine Primary가 모든 Seq no.를 소진하는 것을 방지함.

    - Replica가 체크포인트 `<CHECKPOINT, n, d, *>`를 위해 Stable Certificate를 모을때,
        - 워터마크 `L`에 `n` 할당
        - 워터마크 `H`에는 `L + O(K)`를 할당
            - 노드가 체크포인트가 stable 되기까지 대기하는 것을 멈추지 않는다는 것을 보장하는 작은 상수값

- - -

- ** Primary Fault 발생시 처리 **

    - 비잔틴 Primary는 safety를 위반하고 request 처리를 방해할 수도 있다.

    - safety 위반 방지를 위해, backup 들은 언제나 primary의 "proof" 메시지를 요구할 수 있다.

    - Request 처리를 보장하기 위해 slow/faulty Primary는 뷰체인지를 통해 컨센서스에서 제거할 수 있다.
- - -

- ** View Change**

    - 유효한 REQUEST를 수신하고 그 실행을 대기하고 있는 backup들로 부터 트리거 된다.

    - 2f+1개의 replica들이 지원하는 *"new-view certificate"*를 새로운 Primary가 모으게 되면 뷰체인지는 성공함
    - 만약 뷰체인지 성공시, 새로운 Primary는...
        1. Quorum으로부터 이미 만들어진 stable한 *certificate*를 읽는다.
        2. 가장 최근의 stable checkpoint를 계산하고, 준비된 명령들 순서대로 갭을 채운다.(Paxos와 동일)
        3. 이 정보들을 입증할 수 있는 backup들에게 위 정보들을 전송한다.

    - 뷰(v)의 Primary에 대해서 Replica(i)의 요청이 타임아웃 발생시,
        - `CHECKPOINT`, `VIEW-CHANGE`, `NEW-VIEW-CHANGE`를 제외한 나머지 메시지들의 수신을 정지.
        - `VIEW-CHANGE` 메시지를 Multicast 처리
        - `<VIEW-CHANGE, v+1, n, s, C, P, i>@i`
            - `v+1` : view no++
            - `n` : seq no. of last stable checkpoint
            - `s` : last stable checkpoint
            - `C` : stable certificate for s
            - `P` : set of P-Certificate for requests prepared at i with seq no# > n
- - -

- ** New View로 이동 : Primary 관점 **
    - "primary elect" `j` (replica v+1 mod R)가 2f+1개의 유효한 뷰체인지 메시지를 모으게 되면 `V`(*new-view certificate*)를 획득하게 된다.
    - `j`는 아래 데이터 들을 계산한다. (`L`,`H`,`O`,`N`)
        - Watermark `L` : `V`에서  latest stable checkpoint의 seq no.
        - Watermark `H` : `V`에서 준비된 certificate들 중에서 가장 높은 seq no
        - `L < n <=H` 에 해당하는 seq no를 가진 `PRE-PREPARE` 메시지.
        - 만약 `V`에 `n`, `m`에 해당하는 *certificate*가 준비되어 있다면,
            - `O = O Union <PRE-PREPARE, v+1, n, m>@j`
        - 준비되어 있지 않다면,
            - `N = N Union <PRE-PREPARE, v+1, n, null>@j`
    - `j`는 `<NEW-VIEW, v+1, n, V, O, N>@j`를 Multicast 처리

    - `j`는 자신의 로그에 `O`, `N`을 추가한다. 필요한 경우 `j`는 seq no(`L`)을 가리키는 state checkpoint를 로그에 추가하고, 자신의 state를 update 한다.
- - -

- ** New View로 이동 : Backup 관점 **
    - Backup(replica, not primary)들은 아래를 만족할 경우 v+1을 가리키는 `NEW-VIEW` 메시지를 Accept한다.
        1. 서명이 유효한지
        2. `V`(*NEW-VIEW Certificate*)내부에 v+1에 대한 `VIEW-CHANGE` 메시지가 포함되어 있는지
        3. `O`가 정상(correct)이라는 것을 내부적으로 검증할 수 있는지

    - Backup은 Primary처럼 로그를 업데이트 한다.
        - `O`내부의 모든 메시지들에 대한 `PREPARE` 메시지를 Multicast 한다.

    - `PREPARE` 메시지를 로그에 추가하고 View에 참여한다.
- - -

- ** Safety : Request의 처리 순서에 대한 Replica들의 합의 **
    - **Within a view**
        - 만약 정상(correct)인 replica가 `(m,v,n)`에 대한 *C-Certificate*를 생성한다면, 2f+1개의 Replica들이 *P-Certification*을 생성했다는 의미임.
        - 만약 정상 Replica가 `(m',v,n),m'!=m`,에 대한 *C-Certificate*를 생성한다면, 최소한 1개의 Replica는 m과 m'의 모순 상태의 메시지 대신에 반드시 `PREPARE` 메시지를 전송해야 한다.

    - **Across views**
        - 정상인 Replica가 `(m,v,n)`에 대한 *C-Certificate*를 생성한다고 가정
        - 정상인 Replica는 `v'`에 대한 `NEW-VIEW` 메시지를 받았을때만 `v'>v` 인 `PRE-PREPARE`를 Accept한다.
        - 하지만, NEW-VIEW 메시지가 2f+1개의 replica의 `VIEW-CHANGE` 메시지를 포함했을 경우 : 최소한 1개의 메시지는 `(m,v,n)`에 대한 *P-Certificate*를 포함한 상태로 다른 노드로 부터 전송되었다는 것을 의미함.

    - 두가지 가능성...
        1. `NEW-VIEW` 내의 `O`는 `(m,v+1,n)`에 대한 `PRE-PREPARE`를 포함하고 있다.
        2. `NEW-VIEW`는 seq no `n'>n`인 stable checkpoint를 알려준다.

    - 어느 경우에서나 `m`은 `v'`에서 `n`과 다른 seq no.를 할당받지는 않음
- - -

- ** Livenesss(유효화) **
    - 두가지 요구사항의 균형을 맞출 필요가 있음
        1. request가 실행(execute)되지 않았을때 뷰체인지를 트리거.
        2. 어떠한 Request를 실행하기에 충분한 시간을 가진, 최소한 2f+1개의 이상의 정상(non-faulty) replica가 같은 view 안에 있어야 한다.

    - `VIEW-CHANGE` 전송 후, 2f+1 개의 `VIEW-CHANGE`를 수신한 후에 timeout 타이머를 시작한다.

    - Timeout 길이는 exponentially 늘어나도록 한다.

    - 자기자신의 뷰보다 큰 f+1개의 `VIEW-CHANGE`를 수신하게 되면, 바로 `VIEW-CHANGE`를 전송한다.

    - Faulty Replica는 영원히 `VIEW-CHANGE`를 요청할 수 없다.
- - -

- ** 통신 최적화 **
    - 하나의 Replica는 response를 전송, 나머지는 digest를 전송

    - Replica들은 *P-Certificate*를 보유한 Request들을 적극적으로 실행할 수 있다.
        - 임시 응답 리턴 리턴
        - 클라이언트는 2f+1개의 임시 응답을 처리완료로 판단

    - Read Only Request
        - Replica는 현재 state에서 Request 실행
        - 클라이언트는 2f+1개의 응답을 받으면 처리완료로 판단
        - 그렇지 않다면, 보통의 R/W Request 전송
- - -

- ** 빠른 인증 **

    - Digital Signature 대신 MAC 사용

    - MAC 사용시 PK Signature 보다 1000배 빠름
    - 공개키 암호화 : MAC Key 셋업, `VIEW-CHANGE`, `NEW-VIEW` 메시지 생성시 사용됨

















