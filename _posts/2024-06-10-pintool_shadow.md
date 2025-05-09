---
title: Packer 분석 1 [VMProtect]
categories: [Project, HSPACE]
tags: [Packer, Themida, VMProtect, Debugger, Window]
image: ../assets/img/3S/shad.jpg
---



## 실습 진행

---

[VMProtect Software](https://vmpsoft.com/files)

간단한 코드에 VMProtect Demo를 적용시켜 분석해보고자 한다.

```c
#include <stdio.h>
void helloWorld() {
    printf("Hello World!");
}

void main(int argc, char *argv[])
{
    printf("Main Function");
    helloWorld();
}
```

해당 파일을 위에 Build 자료 참고하여 exe파일로 만들어준다.

그 후 VMProtect에 들어가서 해당 .exe파일을 선택해준 후,

![alt text](image.png)

우선 Add Function 버튼을 눌러 helloWorld라는 function을 추가해준다.

![alt text](image-1.png)

option들도 디버깅에 용이하게 변경해준다.

그 후 컴파일 버튼(재생 플레이어처럼 생긴 버튼)을 눌러서 파일을 생성해준다.

실행시키면 다음과 같은 창이 뜨긴 하지만 잘 출력된다.

![image.png](attachment:2fe996d1-325d-45f5-a87b-78ea20913961:image.png)

![image.png](attachment:6dcc9a86-978d-4f9f-ac21-649021579977:image.png)

(터미널이 아니라 직접 실행시키니 출력문이 안 보일 정도로 빨리 꺼짐 → 따로 추가적인 함수를 넣어줘야 바로 안 꺼지고 보인다는 자료를 확인한 적 있음. 하지만 최대한 자료와 같은 환경 구성하기 위해 추가하지 않음.)

*참고) IDA로 까려고 할 때 자꾸 .exe.id2에서 권한 거부 문제가 발생했는데 바탕화면에서 여니까 되었음. (IDA 권한 줘서 했었는데도 왜 안 됐지..)

![image.png](attachment:10ffe815-b086-4896-8fa1-e5af63f95f20:image.png)

IDA 화면. 왼쪽에 보면 분명히 나는 함수 하나만 짰는데 어마무시하게 많은 서브루틴 함수들이 존재함을 확인할 수 있다.

## 분석

우선 VMProtect가 적용되지 않은 바이너리를 확인해보자.

![image.png](attachment:0e337cbf-0a08-4d2c-aede-c33b76bcd8e1:image.png)

심볼도 다 살아있다.

이제 String 찾기로 VMProtect에서 Main Fuction이라는 문자열을 찾아보자.

*참고2)

- IDA가 웃긴게, Main이라고 치면 아무것도 안 나오고 Full Text로 쳐야 확인이 된다. Main Functio 도 안 됨,,

![image.png](attachment:7d1544f2-08bd-447c-9256-747fad86151a:image.png)

적용된 바이너리는 다음과 같다.

![main이라는 함수명은 직접 변경한 것이다.](attachment:51579aa9-5cd1-48cc-9b55-fa15d8ab1d96:image.png)

main이라는 함수명은 직접 변경한 것이다.

![Non VMProtect](attachment:06ed73fa-139e-4b5e-81b0-06f0433d791d:image.png)

Non VMProtect

![VMProtect](attachment:59ed6405-3e92-4ea7-b596-367f634e8ba1:image.png)

VMProtect

PE파일에서는 외부 함수를 호출하기 위해서 Import Address Table(IAT)를 이용하여 실제 주소들을 채워넣는다.

`__imp_printf` 는 External symbol에 존재하며, 이는 프로그램이 외부에서 가져와 사용하는 함수나 변수를 의미하며 IAT에 존재하는 외부 함수 주소를 가리킨다.

하지만 VMProtect가 적용된 printf함수는 함수 포인터로만 존재한다. 런타임 시에 동적으로 해당 함수의 주소가 채워질 가능성이 존재한다. 이는 동적 분석을 통해 확인해보아야 한다.

이렇게 가상화가 적용되지 않은 부분들도 변경된다. 하지만 기본적인 함수 틀은 모두 살아있는 모습이다.

Main으로 추정되는 함수를 찾았다. 하지만 문제가 발생했는데,

![image.png](attachment:d45616da-2380-472f-af09-46dc498e47f7:image.png)

JUMPOUT 오류가 발생했다.

[IDA "sp-analysis failed" 에러 해결 방법](https://keyme2003.tistory.com/entry/test)

![image.png](attachment:51673962-1335-4e0b-a73d-2ea785f1837f:image.png)

![image.png](attachment:53f88a38-56ae-49e9-b717-969d34faae22:image.png)

---

이 밑에 내용들은 정리 필요

## VMProtect 동작 원리

## VMProtect의 핵심 실행 메커니즘

VMProtect는 **인터프리터 방식의 가상 머신**으로 동작합니다. 가상화된 명령어는 즉시 실행되지만, 원래 x86 명령어와는 전혀 다른 방식으로 처리됩니다:

1. **바이트코드 실시간 해석**:
    - 각 바이트코드 명령어는 읽혀지는 즉시 해당 핸들러에 의해 실행됩니다
    - 이는 JIT(Just-In-Time) 컴파일이 아닌, 순수 인터프리터 방식입니다
2. **가상 컨텍스트 유지**:
    - RSP 기반 메모리 영역에 가상 레지스터 상태가 유지됩니다
    - RBP를 통해 접근하는 가상 스택은 연산 중간값을 저장합니다

### 디스패처

디스패처(Dispatcher)는 가상 머신 보호 체계의 핵심 구성요소로, 다음과 같은 중요 기능을 수행합니다:

1. **명령어 해석**: 암호화된 바이트코드를 하나씩 읽어 어떤 VM 핸들러를 실행할지 결정합니다.
2. **제어 흐름 관리**: 각 바이트코드 명령어 실행 후 다음 명령어로 제어를 전달합니다.
3. **컨텍스트 유지**: 가상 레지스터, 가상 플래그 등 VM의 상태를 유지합니다.

![image.png](attachment:73d19240-48dc-424b-b014-c93a770c99e4:image.png)

해당 코드에서 `add rsi,1` 까지 실행시켰을 때, RSI 레지스터 값을 확인해보면 `0x4a7a3d` 이다.

![image.png](attachment:6ced6a75-d47d-4c85-8e4c-2d83731367ce:image.png)

해당 위치를 IDA로 확인해보면 암호화 되어있는 부분임을 확인할 수 있다.

switch문

![image.png](attachment:8733c448-e1a6-459b-9fcd-8c0662e4c6bc:image.png)

실질적으론 계산된 R8 레지스터에 있는 위치로 이동한다.

**(Claude.ai)**

```mermaid
flowchart TB
    subgraph "VMProtect 디스패처 아키텍처"
        Fetch["바이트코드 인출\n(RSI 사용)"] --> Decode["핸들러 주소 결정\n(R11+RCX*4 참조)"]
        Decode --> Execute["핸들러 실행\n(해당 명령어 처리)"]
        Execute --> Fetch
    end

    subgraph "레지스터 역할"
        RSI["RSI: 바이트코드 포인터\n(명령어 스트림 위치)"]
        RBP["RBP: 가상 스택 포인터\n(연산 스택 관리)"]
        R11["R11: 베이스 주소\n(핸들러 테이블 기준점)"]
        RSP["RSP: 가상 레지스터 기반 주소\n(VM 상태 저장소)"]
        RCX["RCX/R10: 현재 바이트코드\n(핸들러 인덱스)"]
        R8["R8: 계산된 핸들러 주소\n(실행 대상)"]
    end

    subgraph "가상 스택 구조"
        direction TB
        Stack["가상 스택 (RBP 기반)"] --- VStack
        
        subgraph VStack
            direction TB
            StackTop["상위 주소 (이전 값들)"]
            StackRBP["RBP → 현재 스택 최상단"]
            StackRBP8["RBP+8 (다음 팝 위치)"]
            StackRBP16["RBP+16..."]
            
            StackTop --- StackRBP --- StackRBP8 --- StackRBP16
        end
    end

    subgraph "가상 레지스터 파일"
        VRegs["가상 레지스터 (RSP+인덱스)"] --- RegFile
        
        subgraph RegFile
            Reg0["RSP+0: 가상 레지스터 0"]
            Reg1["RSP+8: 가상 레지스터 1"]
            RegN["RSP+N*8: 가상 레지스터 N"]
            
            Reg0 --- Reg1 --- RegN
        end
    end

    subgraph "핸들러 테이블 구조"
        HTable["핸들러 테이블 (R11 기반)"] --- Handlers
        
        subgraph Handlers
            H0["R11+0: 핸들러 0 오프셋"]
            H1["R11+4: 핸들러 1 오프셋"]
            HN["R11+N*4: 핸들러 N 오프셋"]
            
            H0 --- H1 --- HN
        end
    end

    Fetch -.-> RSI
    Decode -.-> R11
    Decode -.-> RCX
    Execute -.-> R8
    Execute -.-> RBP
    Execute -.-> RSP
```

- RSI: 현재 실행 중인 바이트코드 위치를 가리키는 명령어 포인터
- RBP: 가상 연산을 위한 스택 관리
- R11: 핸들러 테이블과 코드의 기준점
- RSP: 가상 레지스터 파일의 기반 주소
- RCX/R10: 현재 해석 중인 바이트코드 값
- R8: 실행할 핸들러의 계산된 주소