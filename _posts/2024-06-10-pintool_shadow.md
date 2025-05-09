---
title: Packer 분석 1 [VMProtect - 코드 가상화 ]
categories: [Project, HSPACE]
tags: [Packer, Themida, VMProtect, Debugger, Window]
image: ../assets/img/Packer/VM_banner.png
published: false
---

해당 프로젝트 전, Android Mobile Hacking 프로젝트를 진행한 경험이 있다. 프로젝트 막바지에 버그헌팅을 목표로 삼았기에 버그헌팅 프로그램에 참여하여 상용앱을 분석해보았는데 이때가 첫 리얼월드에 대한 경험이였다. 하지만 가장 처음으로 가로막히게 된 부분은 디버거 탐지와 난독화였고, 이를 계기로 해당 보호 기법들에 대해 분석해보게 되었다.

<br />
상용 프로그램들에는 자신들의 프로그램의 소스코드, 취약점 등을 보호하기 위한 목적으로 'Packer'라는 것을 사용한다.
<br />

## Packer

실행 파일 패커는 원본 프로그램의 코드와 데이터를 압축하거나 암호화하는 도구이다. 패커는 원본 실행 파일을 래핑하여 새로운 실행 파일을 생성하며, 프로그램 실행 시 원본 코드를 메모리에서 동적으로 복원한다. 이는 파일 크기 감소, 로딩 시간 단축, 코드 보호 등 다양한 목적으로 사용된다.

<br />
Packer들이 가진 기능은 다양한데, 해당 분석에서는 코드 가상화 및 디버거 탐지에 대해 분석해본다.
<br />

## VMProtect 코드 가상화 분석

---

[VMProtect Software](https://vmpsoft.com/files)
<br />
VMProtect에서는 Demo버전을 배포하고 있다. 해당 버전을 이용하여 예제 코드를 작성하여 실제 적용시켰을 때 어떤 식으로 코드 가상화가 이루어지는지 분석해보자.


<br />

**예제 코드**
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
예제 코드를 작성한 이후, visual studio를 이용하여 exe 파일을 만들어준다. 버전은 2022를 사용한다.

간단히 기술하면 
<br />
[빌드에서 '솔루션 정리' -> 프로젝트 -> '프로젝트명' 속성 -> 구성에서 Release 선택 -> 저장 -> 빌드 에서 '솔루션 다시 빌드' -> 일괄 빌드 (Release 적힌 구성 둘 다 체크)]
<br />
이렇게 진행해준 후, Release 혹은 x64 파일에 들어가보면 exe 파일이 있다.

그 후 VMProtect에 들어가서 해당 .exe파일을 선택해준 후,

![Image](https://github.com/user-attachments/assets/b765d475-ab06-4ced-8171-d1f3ab404420)

우선 Add Function 버튼을 눌러 helloWorld라는 function을 추가해준다.

![Image](https://github.com/user-attachments/assets/1cbcd489-196c-4b1d-bbc5-33f2a9376d80)

option들도 디버깅에 용이하게 변경해준다.

그 후 컴파일 버튼(재생 플레이어처럼 생긴 버튼)을 눌러서 파일을 생성해준다.

실행시키면 다음과 같은 창이 뜨긴 하지만 잘 출력된다.

![Image](https://github.com/user-attachments/assets/d58334f1-41ba-4895-8285-4c7356d7880b)

![Image](https://github.com/user-attachments/assets/6c3a5756-9c5c-4c7c-9988-bf572eec38fb)

(터미널이 아니라 직접 실행시키니 출력문이 안 보일 정도로 빨리 꺼짐 → 따로 추가적인 함수를 넣어줘야 바로 안 꺼지고 보인다는 자료를 확인한 적 있음. 하지만 최대한 자료와 같은 환경 구성하기 위해 추가하지 않음.)

*참고) IDA로 까려고 할 때 자꾸 .exe.id2에서 권한 거부 문제가 발생했는데 바탕화면에서 여니까 되었음. (IDA 권한 줘서 했었는데도 왜 안 됐지..)

![Image](https://github.com/user-attachments/assets/0f0ec54b-6b5a-41e6-90ca-e46373d7a684)

IDA 화면. 왼쪽에 보면 분명히 나는 함수 하나만 짰는데 어마무시하게 많은 서브루틴 함수들이 존재함을 확인할 수 있다.

## 분석

우선 VMProtect가 적용되지 않은 바이너리를 확인해보자.

![Image](https://github.com/user-attachments/assets/9c6b09a5-95f2-4c10-a43f-470451dd5c3f)

심볼도 다 살아있다.

이제 String 찾기로 VMProtect에서 Main Fuction이라는 문자열을 찾아보자.

*참고2)

- IDA가 웃긴게, Main이라고 치면 아무것도 안 나오고 Full Text로 쳐야 확인이 된다. Main Functio 도 안 됨,,

![Image](https://github.com/user-attachments/assets/bb4617e3-aca6-4575-9236-c12aa888c636)

적용된 바이너리는 다음과 같다.

![Image](https://github.com/user-attachments/assets/387333bc-46f0-4fad-a5dc-f66876d44a4e)

main이라는 함수명은 직접 변경한 것이다.

![Non VMProtect](https://github.com/user-attachments/assets/17718a85-9a04-4e0d-bae9-1b866300ffc2) | ![VMProtect](https://github.com/user-attachments/assets/89e44b64-5b98-4123-a17f-9be8fda4eae7)
Non VMProtect
<p align="center">
  <img src="![Non VMProtect](https://github.com/user-attachments/assets/17718a85-9a04-4e0d-bae9-1b866300ffc2)" align="center" width="32%">
  <img src="![VMProtect](https://github.com/user-attachments/assets/89e44b64-5b98-4123-a17f-9be8fda4eae7)" align="center" width="32%">
  <figcaption align="center">3개 이미지 띄우기</figcaption>
</p>

VMProtect

PE파일에서는 외부 함수를 호출하기 위해서 Import Address Table(IAT)를 이용하여 실제 주소들을 채워넣는다.

`__imp_printf` 는 External symbol에 존재하며, 이는 프로그램이 외부에서 가져와 사용하는 함수나 변수를 의미하며 IAT에 존재하는 외부 함수 주소를 가리킨다.

하지만 VMProtect가 적용된 printf함수는 함수 포인터로만 존재한다. 런타임 시에 동적으로 해당 함수의 주소가 채워질 가능성이 존재한다. 이는 동적 분석을 통해 확인해보아야 한다.

이렇게 가상화가 적용되지 않은 부분들도 변경된다. 하지만 기본적인 함수 틀은 모두 살아있는 모습이다.

Main으로 추정되는 함수를 찾았다. 하지만 문제가 발생했는데,

![Image](https://github.com/user-attachments/assets/2604fd32-0e84-4b90-a554-c6556b9620f4)

JUMPOUT 오류가 발생했다.