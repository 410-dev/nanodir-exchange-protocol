# NanoDirectory File Exchange Infrastructure

## 개요

한 조직 내 여러 컴퓨터가 파일을 교환해야 할 경우, 상당히 많은 양의 코드를 새로 짜야 한다. 이를 간편하게 하기 위해 조직 내의 서버에 의존하여 파일 전송을 할 수 있도록 하는 라이브러리 혹은 프레임워크를 구상한다.

## 궁극적으로 달성하고자 하는 목표

최종적으로는 이 라이브러리가 코드의 단순화를 목적으로 하기에, 개발자가 다음과 같은 코드만으로 파일을 쉽게 공유할 수 있도록 하고자 한다.

송신 예시:

```python
from osext.libaqnetutil.EdgeMachine import EdgeMachine, Network

# 현재 장치 인스턴스 가져오기
current_machine: EdgeMachine = EdgeMachine.get_current_machine("master")  # 현재 장치 인스턴스 가져오기
current_network: Network = current_machine.get_network_instance("master") # 현재 장치에 등록된 네트워크 인스턴스 가져오기 (네트워크 실존 여부 체크 안함)

# Check if network is not enrolled.
# If so, the code should not work.

if not current_network.is_machine_enrolled(current_machine): raise Exception("Not enrolled to network!")

# Get machine ID of machine name for john@mycompany.com
multiple_target_machines: list[EdgeMachine] = current_network.get_machines_of(current_machine, "Engineering/Developers", "john@mycompany.com")

# Send to all machines
is_successful: dict[str, bool] = current_network.send_to_machines(current_network, multiple_target_machines, 8080, "/home/user/Desktop/my-file.txt")

```

## 경고
본 저장소에 작성된 코드는 아래 서술한 메커니즘과 100% 동일하지는 않으며, 실제 구현에서 고려 가능한 확장성과 유연성을 위해 일부 변경되었다.

## 네트워크 모델 - 구성 요소

- CentralServer 
  - Relay 
  - Authorization 
  - Hold
- EdgeMachine

해당 네트워크는 크게 두가지 종류가 있다: CentralServer 와 EdgeMachine 이다. EdgeMachine 은 일반적으로 사용하는 컴퓨터이고, CentralServer 는 EdgeMachine 이 다른 EdgeMachine 과 통신하기 위해 반드시 한번 이상 통신하는 서버이다.

## CentralServer

CentralServer 는 세가지 역할을 수행한다. Relay, Authorization, Hold 이며, 한 머신은 여러가지 역할을 동시에 수행할 수 있다.

### Relay

- EdgeMachine 의 주소 및 상태를 반환하거나, 파일 전달을 위한 용도이다.

### Authorization

- EdgeMachine 의 장치 정보를 저장한다. 
- 전송하는 장치와 수신할 장치의 자격 검증을 한다. 
- KMS 의 역할을 수행한다. 
- 장치의 최초 등록 및 등록 정보 저장 역할을 수행한다. 
- 장치 등록시, Relay 와 Hold 서버의 주소를 반환하거나, 무작위 생성 시스템에 관한 정보를 반환한다.

### Hold
- 만약 Relay 를 사용한 파일 전송 시도시 실패할 경우, 임시로 파일을 저장할 서버이다. 이 서버는 필수가 아니며, 그러할 경우 임시 파일 저장을 위한 기능은 사용할 수 없다.

## EdgeMachine

최종 사용자가 사용하는 장치이며, 이는 CentralServer 에 연결하여 파일 송수신을 준비할 수 있다.\
아래 설명에서 사용자는 각각 김철수, 김영희로 설정한다.

철수를 `DomainA/Group1` 에, 영희를 `DomainA/Group2` 에 지정한다.

철수의 로그온 아이디는 `bob@mynetwork.com` 이며, 사용중인 장치의 아이디는 다음과 같다:
업무용 랩탑: `DomainA/Group1/bob@mynetwork.com/My-Laptop`\
업무용 데스크탑: `DomainA/Group1/bob@mynetwork.com/My-Desktop`

영희의 로그온 아이디는 `alice@mynetwork.com` 이며, 사용중인 장치의 아이디는 다음과 같다:\
업무용 랩탑: `DomainA/Group2/alice@mynetwork.com/My-Laptop`\
업무용 데스크탑: `DomainA/Group2/alice@mynetwork.com/My-Desktop`

CentralServer 정책 모델 예시

Relay
```json
{
    "RelayWhitelist": {
    	"DomainA/Group1/SubGroup1": {
	    	"P2PConnection.GeneralAllow": false,
    		"P2PConnection.Whitelist": [
    			"DomainA/Group2/SubGroup1/*"
    		]
    	},
    	"DomainA/Group2": {
    		"P2PConnection.GeneralAllow": false,
    		"P2PConnection.Whitelist": [
    			"DomainA/Group1/*"
    		]
    	}
    }
}
```

## 파일 전송 모델


모델 A 는 직접 전송 모델이다. 파일 전송시에 서버를 거치지 않는다. 이는 보안이 중요한 파일을 전송할 때 사용할 수 있다.

모델 B 는 서버 중계 전송 모델이다. 파일 전송시 서버에 저장되며, 감사의 목적이 필요할 때 사용할 수 있다.

철수가 영희에게 파일을 전송하려 할 경우, 작동 메커니즘은 다음과 같다:

1. 철수의 컴퓨터가 Authorization 서버에 등록될 때 저장한 각 분담 서버의 주소를 불러온다.

    예시: `auth.mynetwork.com`, `relay.mynetwork.com`

2. 철수가 Authorization 서버에 영희의 장치 정보를 요청한다. 이 때, 서버 측에서는 정책에 따라 전송 모델 A 혹은 모델 B 를 결정한다. 만약 모델 A로 연결이 된다면 영희의 공개 암호화 키를 반환하고, 모델 B로 연결 된다면 정책과 수신자 장치 온라인 여부에 따라 Relay 혹은 Hold 서버의 공개 암호화 키를 반환한다.

    요청 구조: 

     `REQ:<현재 장치 인증 JWT 문자열>:pk:<로그온 ID>, <로그온 ID>, .... :<파일 유형>:<확장자>:<파일 크기 in bytes>:EOD`

    요청 예시: 

     `REQ:2413fb3709b05939f04cf2e92f7d0897fc2596f9ad0b8a9ea855c7bfebaae892:pk:alice@mynetwork.com:plain-text:txt:32768:EOD`

    반환 구조:

     `RES:{"machines":{"name":{"pk":"xxx", ... }, ... }}:EOD`
    
    반환 예시:

    `RES:{"machines":{"DomainA/Group2/alice@mynetwork.com/My-Laptop":{"pk":"421c76d77563afa1914846b010bd164f395bd34c2102e5e99e0cb9cf173c1d87"},"DomainA/Group2/alice@mynetwork.com/My-Desktop":{"pk":"92ff90719d49bc974b12c2dfa6bf319c28f1d59419878e9148c9c472d5d9f599"}}}:EOD`


3. 철수가 보내고자 하는 장치를 고른 후 (예: My-Desktop) 이것의 장치 이름을 Relay 서버에 전송하여 커넥션에 필요한 정보를 반환받는다. 이 때, 서버 측에서는 정책에 따라 전송 모델 A 혹은 모델 B 를 결정한다. 만약 모델 A 가 되었을 경우 NAT Traversal 및 STUN/TURN 을 활용하기 위한 정보를 담은 후 영희의 장치 주소를 전송하고, 모델 B 가 되었을 경우, 정책과 수신자 장치 온라인 여부에 따라 Relay 혹은 Hold 서버의 해당 정보를 반환한다. Relay 서버에는 Session ID 와 바인딩 된 체크섬 및 수신 발신인의 정보를 포함한다.

    요청 구조: `REQ:<현재 장치 인증 JWT 문자열>:<장치 이름>,<장치 이름>, ...:<파일 유형>:<확장자>:<파일 크기 in bytes>:<SHA-256 체크섬>:EOD`

    요청 예시: `REQ:2413fb3709b05939f04cf2e92f7d0897fc2596f9ad0b8a9ea855c7bfebaae892:DomainA/Group2/alice@mynetwork.com/My-Desktop:plain-text:txt:32768:0c0e36f8c9580a11bb72906e973b81be37c1d0ab0ef4812a990069bfac142df7:EOD`

    반환 구조: `RES:{"장치 이름":{"session-id":"xxx","phys-addr":"","stun":{},"turn":{},"nat":{}}}:EOD`

    반환 예시: `RES:{"DomainA/Group2/alice@mynetwork.com/My-Desktop":{"session-id":"12341234","phys-addr":"14.250.xxx.xxx","stun":{},"turn":{},"nat":{}}}:EOD`

4. 철수는 이제 저 주소로 전송 요청을 시도한다. 이 때, 2번 단계에서 불러온 PK 로 비대칭 암호화를 하고, 3번 단계에서 받아온 연결 정보로 파일 전송을 시도한다.


## 파일 수신 모델

파일 수신은 서버 정책 및 그룹 정책에 따라 Polling, Reverse (검증 필요) 가 있다. 이 때, Polling 모드로 파일을 수신할 경우, Relay 서버는 송신인에게 반드시 Hold 서버의 정보를 전송해야 한다.

- Polling: 영희의 컴퓨터는 백그라운드에서 매 n 초 마다 Hold 서버에 현재 장치로 수신 예약된 파일이 있는지 확인한다. 만약 파일이 있다면 해당 파일을 자동으로 다운로드 한 후, 성공시 Hold 서버에서 해당 파일을 삭제한다.

- Reverse: 영희의 컴퓨터는 Relay 서버로 무기한 요청을 연다. Relay 서버에서 전달할 파일이 들어오면 해당 파일을 해당 무기한 요청의 응답으로 반환한다. 이는 Reverse shell 과 비슷한 원리이다.

## 저장 위치에 관하여

파일이 백그라운드에서 들어온다면, 파일이 자동으로 저장될 위치를 판단해야 한다. 이는 장치 내에서 설정 가능하며, 위에서 요청한 파일 유형 혹은 파일 확장자를 기반으로 판단한다.

만약 매핑이 없을 경우, 사용자에게 저장할 위치를 묻거나 Downloads 에 저장할 의사를 팝업으로 묻고 응답을 받을 때 까지 대기 시키거나, /tmp 에 저장 후 사용자에게 알린다 (설정에 따라 다름)

예: image-userphoto 를 /home/?/Pictures/ 로 매핑 설정하면 수신 에이전트는 받은 파일을 해당 위치에 자동 저장한다.

## 파일 전송 이어받기

네트워크 단절이나 시스템 종료 등 모종의 이유로 파일 전송이 중단될 경우를 대비해 식별자 기반의 이어받기를 지원한다.

최초 전송 요청 시, 송신자는 해당 파일 전송 세션에 대한 고유 식별자를 서버로부터 발급받아 헤더에 포함한다.

전송이 중간에 끊긴 후 다시 연결될 때, 송신자 혹은 수신자는 이 고유식별자와 함께 현재까지 성공적으로 송수신된 파일의 바이트 위치(Offset, 예: 2147483648)를 명시하여 요청한다.

연결이 재개되면 해당 Offset 지점부터 청크(Chunk) 단위로 파일 업로드 및 다운로드가 진행되며, 메모리 부하를 방지하기 위해 디스크에 스트리밍 방식으로 직접 기록한다.

## 초기 구상
[블로그 글](https://dev.lks410.me/groupnetwork-file-exchange-idea)