---
title: Packer 분석 2 [Anti Anti-Attach]
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

용량이 약 100배 커진 파일 생성

해당 파일을 실행시키려고 하면 백신이 악성 파일로 인식해 격리시켜버리니 실시간 검사를 잠깐 꺼두자

실행시키면 이렇게 데모버전이라고 뜬다.

그리고 실제로 x64dbg를 붙여서 실행시켜보면

이렇게 뜬다. (처음엔 안 돼서 진짜 더미다 3.x.x.x는 이상한가? 했는데 그냥 스킬라하이드가 켜져있었다.

패킹 확인 툴

[Exeinfo PE 0.0.8.8을 위한 Windows을 다운로드하세요 | Uptodown.com](https://exeinfo-pe.kr.uptodown.com/windows/download)

참고로

Yes24도 Themida 3.x.x.x 버전이 적용되어 있다.

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

## Anti Debuging Bypass

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

[IsDebuggerPresent 함수(debugapi.h) - Win32 apps](https://learn.microsoft.com/ko-kr/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent)

호출 프로세스가 사용자 모드 디버거에 의해 디버깅되고 있는지 여부를 확인한다.

```cpp
BOOL IsDebuggerPresent();
```

해당 함수는 다음과 같이 어셈블리 코드로 구현되어 있다.

```cpp
mov eax, fs:[0x30]            ; TEB의 주소를 EAX에 로드
movzx eax, byte ptr [eax+0x2] ; PEB의 BeingDebugged 플래그 값을 EAX에 로드
ret
```

어떻게 구현되어서 실행되는지 하나씩 따라가보자.

### **1. TEB**

각 스레드마다 존재하는 구조체이며, 스레드 자체 정보와 PEB의 정보를 같이 담고 있다.

위의 어셈블리를 확인해보면 fs:[0x30]에 접근하고 있는데, TEB의 주소가 FS:[0x00]에서 시작하며 FS:[0x30]을 통해 PEB에 접근이 가능하다.

```cpp
typedef struct _TEB {
  PVOID Reserved1[12];           // 32bit -> 4byte * 12 = 48 = 0x30
  PPEB  ProcessEnvironmentBlock; // @ offset 0x30
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;
```

### **2. PEB**

[PEB(winternl.h) - Win32 apps](https://learn.microsoft.com/ko-kr/windows/win32/api/winternl/ns-winternl-peb)

그럼 자연스럽게 PEB로 넘어가는데, PEB(Process Environment Block)이란, 하나의 프로세스마다 존재하는 구조체이며 프로세스에 대한 메타정보 (로드된 모듈, 환경 변수, 디버깅 플래그 등등)을 포함하고 있는 구조체이다.

한마디로 프로세스 정보를 포함한다.

```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged; // offset +0x02
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

PEB + 0x02 위치에 BeingDebugged flag가 존재하며, IsDebuggerPresent는 이걸 읽어와서 디버깅 중인지 판단하는 것이다.

```cpp
mov eax, fs:[0x30]            ; TEB의 주소를 EAX에 로드
movzx eax, byte ptr [eax+0x2] ; PEB의 BeingDebugged 플래그 값을 EAX에 로드
ret
```

### **3. 그렇다면 BeingDebugged는 누가 세팅하는가?**

해당 부분에 대해 이해하기 위해선 커널까지 내려가야 한다.

커널 개념에 대해 간단히 설명보면 유지 모드와 커널 모드로 나뉘는데,

| 구분              | 설명                         | 예시                                        |
| --------------- | -------------------------- | ----------------------------------------- |
| **User Mode**   | 일반 앱이 실행되는 영역              | `notepad.exe`, `chrome.exe`, 내가 만든 프로그램 등 |
| **Kernel Mode** | Windows OS의 핵심 코드가 실행되는 영역 | `ntoskrnl.exe`, 드라이버, 시스템 콜 등             |

으로 나뉜다. 실제 프로세스가 생성될 때는 다음과 같은 방식을 동작한다.

CreateProcessA() 호출 시,

```
내 코드 (User mode)
    ↓
Windows API: CreateProcessA
    ↓
kernel32.dll → ntdll.dll → NtCreateUserProcess (syscall)
    ↓
ntoskrnl.exe (Kernel mode) → 실제 프로세스 생성
```

이런 호출을 위해선 커널도 커널만의 프로세스에 대한 구조체를 가져야하며, 이를 `EPROCESS`라고 한다.

| 구조체        | 설명                                               |
| ---------- | ------------------------------------------------ |
| `EPROCESS` | 커널 내부에서 하나의 프로세스를 표현하는 구조체 (메모리, 핸들 테이블 등 보유)    |
| `PEB`      | 사용자 모드에서 접근 가능한 프로세스 메타정보 구조체 (BeingDebugged 포함) |
| `TEB`      | 각 스레드마다 생성되는 구조체 (PEB를 참조함)                      |

그리고, BeingDebugged은 `ntoskrnl.exe` 가 설정한다.

| 함수                                  | 역할                                  |
| ----------------------------------- | ----------------------------------- |
| `DbgkInitialize()`                  | 디버거 연결 초기화                          |
| `DbgkCreateThread()`                | 디버거와 연동된 상태로 새 스레드 생성               |
| `DbgkProcessDebugPortSet()`         | 디버거 연결된 상태 반영                       |
| `PsSetCreateProcessNotifyRoutine()` | 프로세스 생성 시 알림 등록 (드라이버/보안 툴도 여기 후킹함) |

중 일부가 EPROCESS.DebugPort를 설정하며,

```
EPROCESS.DebugPort ≠ NULL
      ↓
PEB->BeingDebugged = 1
```

로 설정된다.

```
[User Mode]
  CreateProcess() ←—— 디버거가 호출, 디버깅 옵션 설정됨 (DEBUG_PROCESS 등)
        ↓
[ntdll → syscall] NtCreateUserProcess()
        ↓
[Kernel Mode: ntoskrnl.exe]
  → EPROCESS 구조체 생성
  → PEB 할당 (BeingDebugged = 0 기본값)
  → 디버깅 옵션 감지 시:
       ↳ EPROCESS.DebugPort 설정
       ↳ PEB->BeingDebugged = 1 로 설정
```

즉, 디버거가 디버깅 대상을 직접 실행할 때 새 프로세스를 띄우기 위해 CreateProcess() 함수를 호출하며

```c
CreateProcess(
  "C:\\\\target.exe",     // ← 디버깅 대상
  NULL,
  NULL,
  NULL,
  FALSE,
  DEBUG_PROCESS,        // ← 디버깅 모드로 프로세스 생성
  NULL,
  NULL,
  &si,
  &pi);
```

위와 같이 디버깅 모드로 프로세스를 생성하고, 이를 확인하고 커널이 EPROCESS.DebugPort을 설정, PEB->BeingDebugged = 1 로 세팅이 되는 방식이다.

*참고1) attach로 디버깅 시작

| **미 실행 중인 프로세스에 붙기** | Attach 방식 | `DebugActiveProcess(pid)` |
| -------------------- | --------- | ------------------------- |

*참고2) x86 vs x64

| 구분         | x86                                  | x64                         |
| ---------- | ------------------------------------ | --------------------------- |
| 세그먼트 레지스터  | `fs`                                 | `gs`                        |
| TEB 접근 오프셋 | `fs:[0x30]`                          | `gs:[0x60]`                 |
| 의미         | TEB 구조체 내의 `ProcessEnvironmentBlock` | 동일한 역할이지만 오프셋이 다름 (64bit니까) |
| 주소 크기      | 4바이트 (32bit)                         | 8바이트 (64bit)                |

### **4. 우회**

단순히 BOOL 을 반환값으로 주는 함수이기 때문에, Frida로 반환값만 변조하면 우회가 가능하다.

```c
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

IsDebuggerPresent() 함수는 kernel32.dll 에 익스포트된(dll이 외부에서 사용할 수 있도록 공개적으로 내보낸) 함수이기 때문에 해당 dll에서 가져온다.

**Developer Command Prompt for VS**

## CheckRemoteDebuggerPresent()

---

[CheckRemoteDebuggerPresent 함수(debugapi.h) - Win32 apps](https://learn.microsoft.com/ko-kr/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent)

```c
BOOL CheckRemoteDebuggerPresent(
  [in]      HANDLE hProcess,
  [in, out] PBOOL  pbDebuggerPresent
);
```

함수가 성공적으로 동작하였을 때 반환값은 0이 아닌 값이며, 실패하는 경우 0을 반환 및 GetLastError를 호출한다.

해당 함수의 pbDebuggerPresent는 디버거가 별도의 병렬 프로세스에 있음을 나타낸다.

때문에 해당 함수의 반환값은 디버거 존재의 직접적인 영향을 끼치지 않으며, 내부의 포인터를 후킹하여 수정해주어야 한다.

1차 시도

```jsx
// === Themida Anti-Debugging Bypass Script (Frida) ===
ㅂ
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

안 됨

- Claude : 이유
  
  두 코드의 핵심적인 차이점은 함수 후킹 방식에 있습니다:
  
  1. **원래 보내신 코드**: `Interceptor.attach()`를 사용
     
     ```jsx
     javascript
     Interceptor.attach(addr, {
        onEnter: function (args) { ... },
        onLeave: function (retval) { ... }
     });
     ```
  
  2. **작동하는 코드**: `Interceptor.replace()`를 사용
     
     ```jsx
     javascript
     Interceptor.replace(addr, new NativeCallback(function (hProcess, pDebuggerPresent) { ... }, 'int', ['pointer', 'pointer']));
     ```
  
  이 두 방식의 차이는:
1. **Interceptor.attach**:
   
   - 원래 함수의 **시작과 끝**에 후킹 코드를 삽입합니다
   - 함수의 **원래 코드가 그대로 실행**됩니다
   - `onEnter`와 `onLeave` 콜백을 통해 함수 실행 전후를 제어합니다

2. **Interceptor.replace**:
   
   - 원래 함수를 **완전히 대체**합니다
   - 원래 함수의 코드는 **전혀 실행되지 않습니다**
   - 제공한 NativeCallback이 원래 함수 대신 실행됩니다
   
   무한 루프가 발생한 이유:
- `Interceptor.attach`를 사용할 경우, 함수의 원래 코드가 실행됩니다

- 이때 원래 코드 내부에 `jmp kernel32.766DF565` 같은 점프 명령이 포함되어 있으면 제어 흐름이 예상과 다르게 변경됩니다

- 이로 인해 후킹 로직이 반복적으로 트리거되거나 함수 내부에서 무한 루프가 발생할 수 있습니다
  
  `Interceptor.replace`는 원래 함수의 코드를 실행하지 않고 완전히 새로운 코드로 대체하기 때문에, 원래 함수의 내부 점프나 복잡한 흐름을 우회하여 무한 루프 문제를 해결합니다.
  
  무한 루프가 발생한 이유를 자세히 분석해 보겠습니다.
  
  어셈블리 코드를 보면:
  
  ```
  0147052B | FF55 8B                  | call dword ptr ss:[ebp-75]              |
  0147052E | EC                       | in al,dx                                |
  0147052F | E9 31F02675              | jmp kernel32.766DF565                   |
  ```
  
  무한 루프가 발생한 가능성 있는 시나리오는:
1. **후킹 중첩**:
   
   - `Interceptor.attach`로 `CheckRemoteDebuggerPresent` 함수를 후킹했습니다
   - 후킹된 함수가 호출되면 `onEnter` 콜백이 실행됩니다
   - 원래 함수 코드가 실행되면서 `jmp kernel32.766DF565` 명령으로 kernel32.dll 내부 코드로 점프합니다
   - 이 내부 코드가 다시 `CheckRemoteDebuggerPresent` 또는 관련 함수를 호출하면 후킹이 다시 트리거됩니다
   - 이런 식으로 후킹 → 원래 함수 → 다시 후킹의 순환이 형성됩니다

2. **Frida 트랩 후킹 충돌**:
   
   - Frida는 함수 시작 부분에 트랩(trap)을 설치합니다
   - 함수 내부의 점프가 이 트랩을 우회하거나 다시 트랩으로 돌아오게 하면 이상한 동작이 발생할 수 있습니다
   - 특히 내부 함수 호출과 반환 과정에서 예상치 못한 제어 흐름 변경이 발생할 수 있습니다

3. **콜백 실행 문제**:
   
   - `onLeave` 콜백에서 `retval.replace(ptr(fakeRetval))` 명령으로 반환값을 변경합니다
   - 이 변경이 커널 레벨에서 예상대로 작동하지 않으면, 반환 과정에서 제어 흐름이 깨질 수 있습니다
   - `Memory.writeU8(this.flagPtr, 0)` 실행 시 예외가 발생하면 반환 처리에 문제가 생깁니다
   
   `Interceptor.replace`는 이런 문제를 피할 수 있는 이유는:
- 함수 전체를 대체하므로 원래 함수의 코드(점프 명령 포함)가 아예 실행되지 않습니다
- 순환 참조나 재귀적 호출 가능성이 크게 줄어듭니다
- 반환값 처리가 더 직접적이고 명확합니다

다른 API 이용 (`Interceptor.replace()`)

---

**Frida API**

`Interceptor.replace(target, replacement[, data])`: replace function at `target` with implementation at `replacement`. This is typically used if you want to fully or partially replace an existing function’s implementation.

Use [`NativeCallback`](https://frida.re/docs/javascript-api/#nativecallback) to implement a `replacement` in JavaScript.

---

```jsx
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

## **NtQueryInformation**Process()

---

[NtQueryInformationProcess 함수(winternl.h) - Win32 apps](https://learn.microsoft.com/ko-kr/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)

```cpp
__kernel_entry NTSTATUS NtQueryInformationProcess(
  [in]            HANDLE           ProcessHandle,       //정보를 검색할 프로세스에 대한 핸들
  [in]            PROCESSINFOCLASS ProcessInformationClass,//검색할 프로세스 정보의 유형
  [out]           PVOID            ProcessInformation,
  [in]            ULONG            ProcessInformationLength,
  [out, optional] PULONG           ReturnLength
);
```

지정된 프로세스에 대한 정보를 검색한다.

| **항목** | **설명**                                             |
| ------ | -------------------------------------------------- |
| 위치     | `ntdll.dll`                                        |
| 역할     | 프로세스의 다양한 정보 구조(Process ID, 디버깅 상태, 이미지 경로 등)를 가져옴 |
| 용도     | 디버깅 탐지, 실행 환경 확인, 내부 상태 추적                         |

`[in] ProcessInformationClass`

매개 변수는 **PROCESSINFOCLASS** 열거형의 값 중 하나로 존재할 수 있다.

| **정보 클래스**                            | **탐지 방식**                       | **우회 방법**          |
| ------------------------------------- | ------------------------------- | ------------------ |
| `7` `ProcessDebugPort`                | 디버거 연결 여부 (`DebugPort != NULL`) | Frida 후킹 or PEB 패치 |
| `31` `ProcessDebugFlags`              | 디버깅 중이면 0 반환됨                   | 반환값을 1로 후킹         |
| `30` `ProcessInstrumentationCallback` | 샌드박스 탐지용 악용                     | 후킹/패치 필요           |

`ProcessInformation` 로 준 리턴 버퍼의 값으로 탐지 여부를 판단하기 때문에, 해당 버퍼를 후킹해야한다.

| 이름                          | 실제로 존재? (ntdll.dll)         | 의미                                |
| --------------------------- | --------------------------- | --------------------------------- |
| `NtQueryInformationProcess` | ✅ export됨                   | 유저 모드에서 syscall 진입 stub           |
| `ZwQueryInformationProcess` | ❌ 존재하지 않음 (ntdll export 기준) | 커널 모드 이름이거나 리버싱 도구의 명명 convention |

- IDA는 **심볼 이름 없이도 system call stub의 시그니처를 분석해서 `Zw*`로 자동으로 이름을 붙여줌**

```jsx
function overrideReturn() {
    Interceptor.attach(Module.getExportByName("ntdll.dll", "NtQueryInformationProcess"), {
        onEnter: function (args) {//NtQ의 인자들
                //this 객체에 데이터를 저장 시, onEnter와 onLeave 사이에 상태 공유 가능
            this.infoClass = args[1].toInt32();
            this.outBuf = args[2];
        },
        onLeave: function (retval) {//NtQ의 반환값
            if (this.infoClass === 7 || this.infoClass === 31) { // ProcessDebugPort
                console.log("우회: ProcessDebugPort");
                Memory.writePointer(this.outBuf, ptr(0));  // 디버거 없음처럼
            }
        }
    });
}

// API 호출 우회
overrideReturn();
```

- API 설명
  
  ```jsx
  onEnter: function(args) {
  // args는 인터셉트된 함수의 인자들을 담은 배열
  }
  ```
  
  - **항상 단일 매개변수 `args`만 받습니다.**
  - `args`는 인터셉트된 함수의 모든 인자를 담은 배열입니다.
  - `args[0]`, `args[1]` 등으로 인터셉트된 함수의 각 인자에 접근합니다.
  
  ### onLeave 함수
  
  ```jsx
  javascript
  onLeave: function(retval) {
  // retval은 인터셉트된 함수의 반환값
  }
  ```
  
  - **항상 단일 매개변수 `retval`만 받습니다.**
  - `retval`은 인터셉트된 함수의 반환값을 담은 `NativePointer` 객체입니다.
  
  `Memory.writePointer()`는 포인터 크기의 값(32비트 시스템에서 4바이트, 64비트 시스템에서 8바이트)을 쓰는 데 적합합니다.
  
  Frida는 표준 JavaScript의 `this` 바인딩 특성을 활용하여 인터셉터 API를 설계했습니다:
  
  ```jsx
  javascript
  Interceptor.attach(targetFunction, {
      onEnter: function(args) {
  // Frida가 이 함수 호출 시 특별한 컨텍스트 객체를 this에 바인딩
          this.someValue = args[0];
      }
  });
  ```

## PEB

---

제대로 정리하기

좋아, 너가 요청한 대로 **`PEB->BeingDebugged`와 `PEB->NtGlobalFlag`를 자동으로 우회하는 Frida 스크립트**를 작성해줄게.

이 스크립트는:

- 현재 프로세스의 **TEB → PEB 구조체**를 자동으로 추적하고,
- `BeingDebugged` 값을 **0으로 덮어쓰기**
- `NtGlobalFlag` 값을 **0으로 초기화**
- 아키텍처(`x86`/`x64`)를 자동 감지함

```jsx
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

- `Process.pointerSize`: property containing the size of a pointer (in bytes) as a number. This is used to make your scripts more portable.

- `NativeFunction`
  
  ```jsx
  new NativeFunction(address, returnType, argTypes[, abi])
  ```
  
  - 코드에서 지정한 주소를 실제 함수처럼 사용할 수 있는 객체. 인자로 함수의 주소와 반환 타입, 그리고 인자의 타입을 지정하면 해당 함수 호출 가능. 보편적으로 Frida 코드 내에서 라이브러리 함수를 직접 호출해야 하는 경우 Native Function을 사용함
  - NtCurrentTeb는 인자 없이 TEB 주소를 반환하는 함수라서 저렇게 인자를 구성함.

- `BeingDebugged`는 불리언 플래그로 1바이트 크기, `NtGlobalFlag`는 32비트 플래그 필드라서 각각 쓰는 U8, U32가 다름

- `toString(16)`은 숫자를 16진수 문자열로 변환합니다:

PEB 값을 변경해버리면 당연히 `IsDebuggerPresent`는 우회된다.

## Total Static Bypass

---

따라서 모든 기능들을 합쳐보면

```jsx
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

function NTQ_Bypass() {
    Interceptor.attach(Module.getExportByName("ntdll.dll", "NtQueryInformationProcess"), {
        onEnter: function (args) {
            this.infoClass = args[1].toInt32();
            this.outBuf = args[2];
        },
        onLeave: function (retval) {
            if (this.infoClass === 7 || this.infoClass === 31) { // ProcessDebugPort
                console.log("우회: ProcessDebugPort");
                Memory.writePointer(this.outBuf, ptr(0));  // 디버거 없음처럼
            }
        }
    });
}

// API 호출 우회
NTQ_Bypass();

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

모두 우회되는 것을 확인할 수 있다.

하지만 이게 Static의 모든 기술들은 아니다. Heap관련해서 값을 확인하여 디버거 여부를 판단하는 것도 있고.. 굉장히 다양한 탐지 기법들이 존재한다.

## TLS

---

TLS는 사실 attach말고 실행할 때 같이 실행해주면 이전 우회 기법들을 이용해서 모두 가능하고, 실행 중에도 g_debugDetected(감지된 디버깅 기법 수) 변수의 값만 바꾸면 된다.

g_debugDetected 의 심볼 정보가 있으면 여느 우회법과 동일하게 새로 wirte 해서 우회해주면 되고, 없는 경우 메모리 스캔을 통해 예측 및 수정을 해주는 방법을 통해 수정해주면 된다.
