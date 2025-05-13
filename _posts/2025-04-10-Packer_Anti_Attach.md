---
title: Packer 분석 2 [Anti Anti Attach]
categories: [Project, HSPACE]
tags: [Packer, Themida, VMProtect, Debugger, Window, Anti, Anti-Attach, Anti-Debugging]
image: ../assets/img/Packer/VM_banner.png
published: false
---

이전 포스팅에서는 VMProtect를 적용한 파일에서 이루어지는 코드 가상화에 대해서 분석해보았다. Packer들은 이같은Anti Debugging기법들을 많이 사용하는데, 이번 포스팅에서는 그 중에서 Anti Attach에 대해 분석해보자 한다.

## Anti Attach

---

**Anti-Attach**는 디버거가 실행 중인 프로세스에 **attach** 하는 것을 사전에 **차단하는 기술**이다.  
이는 **안티 디버깅(Anti-Debugging)** 기법의 하위 범주로, 분석 도구가 프로세스 내부 상태를 관찰하거나 조작하지 못하도록 설계된다.

해당 기술에는 굉장히 많은 기법들이 존재하는데, 이번에도 직접 Anti Attach 실습 자료를 만들어서 우회해보는 방식으로 진행할 것이다.

## Build

---

### exe 파일 생성

우선 Anti Attach 실습을 진행하기 이전에 실습할 프로그램 및 실제 Anti Attach가 일어나면 어떻게 감지되는지 확인해보기 위해 exe파일을 제작해준다.

필자는 Visual studio 2022를 이용하여 빌드하였으며, 프로젝트 생성 후 exe 파일 빌드 과정을 요약하자면 다음과 같다. 

**VS 설치 → 프로젝트 생성 → test 코드 제작 → ctrl + f5 → x64에 exe 파일 생성**

### Themida 적용 (Demo)

1. Input Filename 설정

![Image](https://github.com/user-attachments/assets/4d7fdcad-a725-4394-8d84-149f2c3aba5c)

2. option 설정

![Image](https://github.com/user-attachments/assets/b5cd2c97-0567-4711-925f-c78d19c1947f)

그리고 Protect 버튼을 눌러주면 용량이 약 100배 커진 파일 생성이 생성된다.

![Image](https://github.com/user-attachments/assets/a1c27e77-87bf-46ba-8b19-a00714e71890)

해당 파일을 실행시키려고 하면 백신이 악성 파일로 인식해 격리시켜버리니 실시간 검사를 잠깐 꺼두어야 한다.

그리고 x64dbg를 붙여서 실행시켜보면

![Image](https://github.com/user-attachments/assets/00290005-2a10-454a-9da4-987caabf626d)

이렇게 Debugger가 존재한다고 뜨며, 프로그램이 종료된다. 참고로 말하지만 x64dbg를 사용해서 디버깅을 해볼 땐 스킬라하이드 같은 옵션을 뜨고 해야한다. 필자는 아무 생각 없이 켜두고 하다 안 떠서 더미다가 제대로 작동 안 되는줄 알았다.

또한 이렇게 실행파일이 패킹되어 있는지 확인하는 패킹 확인 툴도 여러가지 존재한다. 대표적으로 Exeinfo PE라는 Tool이 존재한다.

![Image](https://github.com/user-attachments/assets/7b209d1b-f9a3-45f0-8d37-08a6bfa2e3f5)

이런 식으로 해당 파일에 무슨 버전의 어떤 패커가 적용되어있는지 파악해준다.

확인해 보고 싶은 사람들을 위해 다운로드 링크를 가져와봤다.

[Exeinfo PE 0.0.8.8을 위한 Windows을 다운로드하세요 Uptodown.com](https://exeinfo-pe.kr.uptodown.com/windows/download)

## Anti Attach

대표적인 아래 기법들을 우회하는 방향으로 진행해보고자 한다.

Themida 자체에는 너무 많은 기능이 존재하기 때문에, 예제 프로그램을 제작하여 특정 기능들을 하나씩 우회해보자. 

**Static**

1. PEB
2. NtQueryInformationProcess()
3. NtQuerySystemInformation()
4. NtQueryObject()
5. ZwSetInformationThread()
6. TLS 콜백 함수
7. ETC…

**Dymamic**

1. 예외 처리
2. Timing Check
3. Trap Flag
4. 0xCC Detection

이번 포스팅은 Static 기법을 중점으로 우회해볼 것이다.
## Anti Anti Attach

---

**예제 코드**

```cpp
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// 직접 enum 정의 (Visual Studio에서 필요)
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7
} PROCESSINFOCLASS;

// Native API 함수 포인터 typedef
typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* NtQueryInfoProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
    );

void check_IsDebuggerPresent() {
    if (IsDebuggerPresent())
        printf("[!] IsDebuggerPresent: 디버거 감지됨\\n");
    else
        printf("[*] IsDebuggerPresent: 디버거 없음\\n");
}

void check_CheckRemoteDebuggerPresent() {
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);

    if (debuggerPresent)
        printf("[!] CheckRemoteDebuggerPresent: 디버거 감지됨\\n");
    else
        printf("[*] CheckRemoteDebuggerPresent: 디버거 없음\\n");
}

void check_NtQueryInformationProcess() {
    NtQueryInfoProcess NtQueryInformationProcess =
        (NtQueryInfoProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQueryInformationProcess"
        );

    if (!NtQueryInformationProcess) {
        printf("[-] NtQueryInformationProcess 로딩 실패\\n");
        return;
    }

    ULONG_PTR debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        (PROCESSINFOCLASS)7,  // 또는 ProcessDebugPort
        &debugPort,
        sizeof(debugPort),
        NULL
    );

    if (status == 0 && debugPort != 0)
        printf("[!] NtQueryInformationProcess(ProcessDebugPort): 디버거 감지됨\\n");
    else
        printf("[*] NtQueryInformationProcess(ProcessDebugPort): 디버거 없음\\n");
}

void check_PEB() { // _M_IX86 : x86 프로세서 대상으로 하는 컴파일 = 600 정의. x64/ARM 컴파일 정의 X
#ifdef _M_IX86
    PVOID peb = (PVOID)__readfsdword(0x30); 
#else
    PVOID peb = (PVOID)__readgsqword(0x60);
#endif

    BYTE beingDebugged = *((PBYTE)((PBYTE)peb + 2));
    DWORD ntGlobalFlag = *((PDWORD)((PBYTE)peb + 0x68));

    printf("[*] PEB.BeingDebugged: %s (%d)\\n",
        beingDebugged ? "디버거 감지됨" : "없음", beingDebugged);

    printf("[*] PEB.NtGlobalFlag:  0x%x %s\\n", ntGlobalFlag,
        (ntGlobalFlag & 0x70) ? "(디버거 감지됨)" : "(정상)");
}

int main() {
    printf("==== 디버거 탐지 테스트 시작 ====\\n\\n");

    check_IsDebuggerPresent();
    check_CheckRemoteDebuggerPresent();
    check_NtQueryInformationProcess();
    check_PEB();

    printf("\\n[!] frida attach 대기 중... attach 후 아무 키나 입력하세요.\\n");
    getchar();  // 사용자가 키 입력할 때까지 대기

    check_IsDebuggerPresent();
    check_CheckRemoteDebuggerPresent();
    check_NtQueryInformationProcess();
    check_PEB();

    printf("\\n==== 테스트 완료. 엔터를 누르면 종료 ====\\n");
    getchar();
    return 0;
}
```

## IsDebuggerPresent 함수 (debugapi.h)

[IsDebuggerPresent - Win32 apps](https://learn.microsoft.com/ko-kr/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent)

호출 프로세스가 사용자 모드 디버거에 의해 디버깅되고 있는지 여부를 확인한다.

```cpp
BOOL IsDebuggerPresent();
```

해당 함수는 다음과 같이 어셈블리 코드로 구현되어 있다.

```
mov eax, fs:[0x30]            ; TEB의 주소를 EAX에 로드
movzx eax, byte ptr [eax+0x2] ; PEB의 BeingDebugged 플래그 값을 EAX에 로드
ret
```

어떻게 구현되어서 실행되는지 하나씩 따라가 본다.

---

### 1. TEB

각 스레드마다 존재하는 구조체이며, 스레드 자체 정보와 PEB의 정보를 포함하고 있다.

위 어셈블리 코드에서 `fs:[0x30]`에 접근하고 있는데, 이는 TEB의 주소에서 `ProcessEnvironmentBlock` 필드에 해당한다.

```cpp
typedef struct _TEB {
  PVOID Reserved1[12];           // 32bit 기준 0x30 offset
  PPEB  ProcessEnvironmentBlock; // @ offset 0x30
  ...
} TEB, *PTEB;
```

---

### 2. PEB

[PEB 구조체 문서 - Win32 apps](https://learn.microsoft.com/ko-kr/windows/win32/api/winternl/ns-winternl-peb)

PEB(Process Environment Block)은 프로세스마다 존재하며, 모듈 정보, 환경 변수, 디버깅 플래그 등을 포함하는 구조체이다.

```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged; // offset +0x02
  ...
  ULONG                         NtGlobalFlag;  // offset +0x68 (x86 기준)
  ...
} PEB, *PPEB;
```

PEB + 0x02 위치에 `BeingDebugged` 플래그가 존재하며, `IsDebuggerPresent()` 함수는 이 값을 통해 디버깅 여부를 판단한다.

---

### 3. BeingDebugged는 누가 설정하는가?

이제 해당 플래그가 어떻게 설정되는지 커널 수준에서 확인해본다.

#### 유저 모드 ↔ 커널 모드

| 구분          | 설명               | 예시                          |
| ----------- | ---------------- | --------------------------- |
| User Mode   | 일반 애플리케이션 실행 영역  | `chrome.exe`, `notepad.exe` |
| Kernel Mode | 운영체제 핵심 코드 실행 영역 | `ntoskrnl.exe`, 드라이버 등      |

#### 프로세스 생성 흐름

`CreateProcessA()` 호출 시 흐름은 다음과 같다:

```
User Code
   ↓
kernel32.dll → ntdll.dll → NtCreateUserProcess(syscall)
   ↓
ntoskrnl.exe → 실제 프로세스 생성
```

커널에서 프로세스를 표현하는 구조체는 `EPROCESS`이며, 이 안에서 `DebugPort` 값이 설정된다.

| 구조체      | 설명                       |
| -------- | ------------------------ |
| EPROCESS | 커널 내부에서 하나의 프로세스를 표현함    |
| PEB      | 유저 모드에서 접근 가능한 프로세스 메타정보 |
| TEB      | 스레드 단위 구조체. PEB를 참조함     |

---

### 4. 디버거가 붙을 때의 흐름

디버거가 `DEBUG_PROCESS` 옵션으로 `CreateProcess()`를 호출하면 커널에서 이를 감지하여 다음과 같은 처리를 한다:

- `EPROCESS.DebugPort ≠ NULL`인 경우
- `PEB->BeingDebugged = 1`로 설정됨

#### 호출 예시

```cpp
CreateProcess(
  "C:\\target.exe",  // ← 디버깅 대상
  NULL,
  NULL,
  NULL,
  FALSE,
  DEBUG_PROCESS,    // ← 디버깅 모드로 프로세스 생성
  NULL,
  NULL,
  &si,
  &pi
);
```

#### 참고: Attach 방식 디버깅

| 구분                    | 설명        | API 함수                    |
| --------------------- | --------- | ------------------------- |
| 이미 실행 중인 프로세스에 디버깅 연결 | Attach 방식 | `DebugActiveProcess(pid)` |

#### x86 vs x64 구조

| 구분         | x86       | x64       |
| ---------- | --------- | --------- |
| 세그먼트 레지스터  | fs        | gs        |
| TEB 접근 오프셋 | fs:[0x30] | gs:[0x60] |
| 주소 크기      | 4바이트      | 8바이트      |

### 5. 우회

단순히 BOOL 을 반환값으로 주는 함수이기 때문에, Frida로 반환값만 변조하면 우회가 가능하다.

```javascript
// === Themida Anti-Debugging Bypass Script (Frida) ===

function overrideReturn(mod, name, fakeRetval) {
    const addr = Module.findExportByName(mod, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                console.log("[Bypass] " + name + " intercepted");
            },
            onLeave: function (retval) {
                console.log("    -> Original return: " + retval + ", overriding with: " + fakeRetval);
                retval.replace(ptr(fakeRetval));
            }
        });
    }
}

// API 호출 우회
overrideReturn("kernel32.dll", "IsDebuggerPresent", 0);
```

**Developer Command Prompt for VS**

![Image](https://github.com/user-attachments/assets/bef03a9e-a6fe-428f-abac-58dde073426a)

`IsDebuggerPresent()` 함수는 `kernel32.dll`에 익스포트된 함수이기 때문에 해당 DLL에서 가져온다.

![Image](https://github.com/user-attachments/assets/a0152c4b-c9b0-4395-8e95-150f33db5ed3)

---

## CheckRemoteDebuggerPresent()

[CheckRemoteDebuggerPresent 함수(debugapi.h) - Win32 apps](https://learn.microsoft.com/ko-kr/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent)

```cpp
BOOL CheckRemoteDebuggerPresent(
  [in]      HANDLE hProcess,
  [in, out] PBOOL  pbDebuggerPresent
);
```

함수가 성공적으로 동작하였을 때 반환값은 0이 아닌 값이며, 실패하는 경우 0을 반환 및 `GetLastError()`를 호출한다.

해당 함수의 `pbDebuggerPresent`는 디버거가 별도의 병렬 프로세스에 있음을 나타낸다. 때문에 해당 함수의 반환값은 디버거 존재의 직접적인 영향을 끼치지 않으며, 내부의 포인터를 후킹하여 수정해주어야 한다.

![Image](https://github.com/user-attachments/assets/2466d17a-46a0-4952-abd5-b403222831bb)

### 1차 시도

```javascript
// === Themida Anti-Debugging Bypass Script (Frida) ===

function overrideReturn(mod, name, fakeRetval) {
    const addr = Module.findExportByName(mod, name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                console.log("[Bypass] " + name + " intercepted");
                this.flagPtr = args[1];  // 안전하게 저장
            },
            onLeave: function (retval) {
                console.log("    -> Original return: " + retval + ", overriding with: " + fakeRetval);
                retval.replace(ptr(fakeRetval));
                try {
                    Memory.writeU8(this.flagPtr, 0); // write safely
                } catch (e) {
                    console.error("Write failed:", e);
                }
            }
        });
    }
}

// API 호출 우회
overrideReturn("kernel32.dll", "CheckRemoteDebuggerPresent", 1);
```

### 안 됨

- 이유

**Interceptor.attach**

- 원래 함수의 **시작과 끝**에 후킹 코드를 삽입
- 함수의 **원래 코드가 그대로 실행**됨
- `onEnter`와 `onLeave` 콜백을 통해 함수 실행 전후를 제어함

---

### 무한 루프가 발생한 이유

어셈블리 코드를 보면:

```
0147052B | FF55 8B                  | call dword ptr ss:[ebp-75]
0147052E | EC                       | in al,dx
0147052F | E9 31F02675              | jmp kernel32.766DF565
```

무한 루프가 발생한 가능성 있는 시나리오는 다음과 같다.

1. **후킹 중첩**
   
   - attach 후 원래 함수의 내부 코드 실행 중 `jmp`가 다시 해당 API를 호출
   - attach → 원래 함수 실행 → 내부에서 다시 attach → 무한 반복

2. **Frida 트랩 후킹 충돌**
   
   - Frida는 함수 시작 부분에 트랩(trap)을 설치
   - 내부 점프가 이 트랩을 우회하거나 다시 트랩으로 돌아오면 이상한 동작 발생

3. **콜백 실행 문제**
   
   - onLeave에서 `retval.replace(ptr(...))`로 반환값 조작 시 예상 제어 흐름이 깨짐
   - `Memory.writeU8()` 호출 중 예외 발생 시 전체 흐름이 망가질 수 있음

---

### Interceptor.replace 사용

**Interceptor.replace**

- 원래 함수를 **완전히 대체**
- 원래 함수의 코드는 **전혀 실행되지 않음**
- 제공한 `NativeCallback`이 원래 함수 대신 실행됨

```javascript
// === Themida Anti-Debugging Bypass Script (Frida) ===

function overrideReturn(mod, name, fakeRetval) {
    const addr = Module.findExportByName(mod, name);
    if (addr) {
        Interceptor.replace(addr, new NativeCallback(function (hProcess, pDebuggerPresent) {
            console.log("[Bypass] " + name + " completely replaced");

            // 인수 검증 후 안전하게 쓰기
            if (pDebuggerPresent !== null && !pDebuggerPresent.isNull()) {
                try {
                    Memory.writeU8(pDebuggerPresent, 0);
                    console.log("    -> Wrote 0 to debugger flag");
                } catch (e) {
                    console.error("    -> Write failed:", e.message);
                }
            }
            return fakeRetval;
        }, 'int', ['pointer', 'pointer']));

        console.log("[+] Successfully hooked " + name);
    }
}

// API 호출 우회
overrideReturn("kernel32.dll", "CheckRemoteDebuggerPresent", 1);
```

![Image](https://github.com/user-attachments/assets/ba5693d3-fdae-4c8c-ac39-667c589b795b)

## NtQueryInformationProcess()

[NtQueryInformationProcess 함수(winternl.h) - Win32 apps](https://learn.microsoft.com/ko-kr/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)

```cpp
__kernel_entry NTSTATUS NtQueryInformationProcess(
  [in]            HANDLE           ProcessHandle,
  [in]            PROCESSINFOCLASS ProcessInformationClass,
  [out]           PVOID            ProcessInformation,
  [in]            ULONG            ProcessInformationLength,
  [out, optional] PULONG           ReturnLength
);
```

지정된 프로세스에 대한 정보를 검색한다.

| 항목  | 설명                                                 |
| --- | -------------------------------------------------- |
| 위치  | `ntdll.dll`                                        |
| 역할  | 프로세스의 다양한 정보 구조(Process ID, 디버깅 상태, 이미지 경로 등)를 가져옴 |
| 용도  | 디버깅 탐지, 실행 환경 확인, 내부 상태 추적 등                       |

### [in] ProcessInformationClass

매개변수는 **PROCESSINFOCLASS** 열거형의 값 중 하나로 존재할 수 있다.

| 정보 클래스                                | 탐지 방식                           | 우회 방법              |
| ------------------------------------- | ------------------------------- | ------------------ |
| `7` `ProcessDebugPort`                | 디버거 연결 여부 (`DebugPort != NULL`) | Frida 후킹 or PEB 패치 |
| `31` `ProcessDebugFlags`              | 디버깅 중이면 0 반환됨                   | 반환값을 1로 후킹         |
| `30` `ProcessInstrumentationCallback` | 샌드박스 탐지용 악용                     | 후킹/패치 필요           |

`ProcessInformation`로 준 리턴 버퍼의 값으로 탐지 여부를 판단하므로, 해당 버퍼를 후킹해야 한다.

![Image](https://github.com/user-attachments/assets/db84233a-beea-4e18-b044-498b12791eb0)

| 이름                          | 실제 존재 여부             | 의미                         |
| --------------------------- | -------------------- | -------------------------- |
| `NtQueryInformationProcess` | export됨              | 유저 모드에서 syscall 진입 stub    |
| `ZwQueryInformationProcess` | 없음 (ntdll export 기준) | 커널 모드 함수 또는 리버싱 도구의 명명 컨벤션 |

> IDA는 심볼 이름 없이도 system call stub의 시그니처를 분석해서 `Zw*`로 자동으로 이름을 붙여줌

---

```javascript
function overrideReturn() {
    Interceptor.attach(Module.getExportByName("ntdll.dll", "NtQueryInformationProcess"), {
        onEnter: function (args) {
            // NtQ의 인자들
            // this 객체에 데이터를 저장 시, onEnter와 onLeave 사이에 상태 공유 가능
            this.infoClass = args[1].toInt32();
            this.outBuf = args[2];
        },
        onLeave: function (retval) {
            if (this.infoClass === 7 || this.infoClass === 31) { // ProcessDebugPort, ProcessDebugFlags
                console.log("우회: ProcessDebugPort 또는 DebugFlags");
                Memory.writePointer(this.outBuf, ptr(0));  // 디버거 없음처럼
            }
        }
    });
}

// API 호출 우회
overrideReturn();
```

---

### Frida API 설명

```javascript
onEnter: function(args) {
    // args는 인터셉트된 함수의 인자들을 담은 배열
}
```

- 항상 단일 매개변수 `args`만 받는다.
- `args`는 인터셉트된 함수의 모든 인자를 담은 배열이다.
- `args[0]`, `args[1]` 등으로 각 인자에 접근 가능하다.

```javascript
onLeave: function(retval) {
    // retval은 인터셉트된 함수의 반환값
}
```

- `retval`은 `NativePointer` 객체이다.
- `Memory.writePointer()`는 포인터 크기의 값을 쓰는 데 적합하다.

```javascript
Interceptor.attach(targetFunction, {
    onEnter: function(args) {
        // Frida가 이 함수 호출 시 특별한 컨텍스트 객체를 this에 바인딩
        this.someValue = args[0];
    }
});
```

Frida는 표준 JavaScript의 `this` 바인딩 특성을 활용하여 인터셉터 API를 설계하였다.

## PEB

---

이 스크립트는:

- 현재 프로세스의 **TEB → PEB 구조체**를 자동으로 추적하고,
- `BeingDebugged` 값을 **0으로 덮어쓰기**
- `NtGlobalFlag` 값을 **0으로 초기화**
- 아키텍처(`x86`/`x64`)를 자동 감지함

```javascript
// === Anti-Debug Bypass: PEB.BeingDebugged & NtGlobalFlag ===

(function () {
    const is64 = Process.pointerSize === 8;
    const tebOffset = is64 ? 0x60 : 0x30;
    const ntGlobalFlagOffset = is64 ? 0xBC : 0x68;

    // NtCurrentTeb()로 TEB 가져오기
    const NtCurrentTeb = new NativeFunction(
        Module.findExportByName('ntdll.dll', 'NtCurrentTeb'),
        'pointer',
        []
    );

    const teb = NtCurrentTeb();
    console.log('[*] TEB:', teb);

    // TEB + offset → PEB
    const peb = Memory.readPointer(teb.add(tebOffset));
    console.log('[*] PEB:', peb);

    // ──────── 1. BeingDebugged 우회 ────────
    const beingDebugged = Memory.readU8(peb.add(0x2));
    console.log('[*] Before: PEB->BeingDebugged =', beingDebugged);
    Memory.writeU8(peb.add(0x2), 0);
    console.log('[+] PEB->BeingDebugged patched to 0');

    // ──────── 2. NtGlobalFlag 우회 ────────
    const ntGlobalFlag = Memory.readU32(peb.add(ntGlobalFlagOffset));
    console.log('[*] Before: PEB->NtGlobalFlag =', ntGlobalFlag.toString(16));
    Memory.writeU32(peb.add(ntGlobalFlagOffset), 0);
    console.log('[+] PEB->NtGlobalFlag patched to 0');
})();
```

- `Process.pointerSize`: 포인터 크기를 바이트 단위로 반환함. 스크립트의 아키텍처 독립성을 위해 사용
- `NativeFunction`: 주소를 함수처럼 사용할 수 있도록 래핑
- `NtCurrentTeb`는 인자 없이 TEB 주소를 반환하므로, 인자 없이 정의
- `Memory.writeU8`, `writeU32`: 각각 1바이트, 4바이트 쓰기
- `toString(16)`: 숫자를 16진수 문자열로 변환

![Image](https://github.com/user-attachments/assets/5ff71bf1-937a-468d-a1b9-fe295b95a3c6)

## TLS

---

TLS는 사실 attach말고 실행할 때 같이 실행해주면 이전 우회 기법들을 이용해서 모두 가능하고, 실행 중에도 `g_debugDetected`(감지된 디버깅 기법 수) 변수의 값만 바꾸면 된다.

`g_debugDetected`의 심볼 정보가 있으면 여느 우회법과 동일하게 새로 write 해서 우회해주면 되고, 없는 경우 메모리 스캔을 통해 예측 및 수정을 해주는 방법을 통해 수정해주면 된다.

---

## 

## Total Static Bypass

---

따라서 모든 기능들을 합쳐보면 다음과 같다:

```javascript
// === Anti-Debug Bypass: PEB.BeingDebugged & NtGlobalFlag ===

(function () {
    const is64 = Process.pointerSize === 8;
    const tebOffset = is64 ? 0x60 : 0x30;
    const ntGlobalFlagOffset = is64 ? 0xBC : 0x68;

    const NtCurrentTeb = new NativeFunction(
        Module.findExportByName('ntdll.dll', 'NtCurrentTeb'),
        'pointer',
        []
    );

    const teb = NtCurrentTeb();
    const peb = Memory.readPointer(teb.add(tebOffset));

    Memory.writeU8(peb.add(0x2), 0); // BeingDebugged
    Memory.writeU32(peb.add(ntGlobalFlagOffset), 0); // NtGlobalFlag
})();

function NTQ_Bypass() {
    Interceptor.attach(Module.getExportByName("ntdll.dll", "NtQueryInformationProcess"), {
        onEnter: function (args) {
            this.infoClass = args[1].toInt32();
            this.outBuf = args[2];
        },
        onLeave: function (retval) {
            if (this.infoClass === 7 || this.infoClass === 31) {
                console.log("우회: ProcessDebugPort");
                Memory.writePointer(this.outBuf, ptr(0));
            }
        }
    });
}
NTQ_Bypass();

function overrideReturn(mod, name, fakeRetval) {
    const addr = Module.findExportByName(mod, name);
    if (addr) {
        Interceptor.replace(addr, new NativeCallback(function (hProcess, pDebuggerPresent) {
            if (pDebuggerPresent !== null && !pDebuggerPresent.isNull()) {
                try {
                    Memory.writeU8(pDebuggerPresent, 0);
                } catch (e) {}
            }
            return fakeRetval;
        }, 'int', ['pointer', 'pointer']));
    }
}
overrideReturn("kernel32.dll", "CheckRemoteDebuggerPresent", 1);
```

모두 우회되는 것을 확인할 수 있다.

하지만 이게 Static의 모든 기술들은 아니다. Heap 관련해서 값을 확인하여 디버거 여부를 판단하는 것도 있고, 굉장히 다양한 탐지 기법들이 존재한다. 