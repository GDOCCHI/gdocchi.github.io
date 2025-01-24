---
title: Pintool로 구현한 Shadow Stack
categories: [Project, 3S]
tags: [intel, cet, shadowstack, stack, ibt, indirectbranchtracking]
image: ../assets/img/3S/shad.png
---



## 기본 개념

---

### **1. 스레드 (Thread)**

스레드는 프로그램이 작업을 수행하는데 사용하는 실행의 경로이다. 일반적으로 하나의 프로세스 내에서 여러 스레드를 실행할 수 있으며, 이를 멀티스레딩이라고 한다. 각 스레드는 프로세스의 자원을 공유하면서 독립적인 실행 흐름을 가질 수 있다. 이는 프로그램이 여러 작업을 동시에 처리하게 하여 효율성을 증가시킨다.

- **예시**: 웹 브라우저에서 하나의 스레드가 사용자 인터페이스를 관리하고, 다른 스레드가 네트워크 요청을 처리하며, 또 다른 스레드가 파일 I/O를 담당할 수 있다.

### **2. 트레이스 (Trace)**

트레이스는 프로그램 실행 중 발생하는 일련의 이벤트나 작업들을 순차적으로 기록한 것을 말한다. 프로그램의 성능 분석이나 디버깅을 할 때, 어떤 함수가 호출되었는지, 어떤 변수가 어떻게 변경되었는지 등의 정보를 포함할 수 있다. 트레이스 정보는 프로그램의 실행 경로를 추적하고 문제를 진단하는 데 유용하다.

### **3. 블록 (Block)**

블록은 프로그래밍에서 사용되는 기본적인 구조 단위로, 여러 문장을 하나의 그룹으로 묶는 역할을 한다. 일반적으로 블록은 중괄호 **`{}`**로 정의된다. 특히, 프로그래밍에서는 코드 블록, 기본 블록 등 다양한 형태의 블록이 사용된다.

- **코드 블록**: 함수나 조건문, 반복문 등에서 사용되는 코드의 집합이다.

- **기본 블록 (Basic Block)**: 컴파일러 최적화에서 사용하는 용어로, 제어가 입력되는 지점과 떠나는 지점 사이에 있는 중간 지점 없이 실행되는 명령어 시퀀스를 말한다. 즉, 분기(조건) 없이 순차적으로 실행되는 코드의 집합이다.
  
  - 기본 블록과 분기
    
    ### 기본 블록
    
    기본 블록(Basic Block)이란 프로그램에서 순차적으로 실행되는 명령어들의 시퀀스를 말하며, 이 블록은 제어가 그 블록의 첫 명령어에 입력되어 순차적으로 실행된 후, 블록의 마지막 명령어에서 다른 블록으로 제어가 이동하게 된다. 기본 블록은 내부에 분기(조건문)나 점프(무조건적 이동), 함수 호출과 같은 제어 흐름을 변경하는 명령어가 없어야 한다.
    
    ### **함수 호출과 기본 블록**
    
    함수 호출은 기본적으로 제어 흐름을 변경한다. 함수로 제어가 이동했다가 함수 실행이 끝나면 원래의 코드 흐름으로 돌아와야 하기 때문에, 일반적으로 함수 호출은 기본 블록의 끝을 의미하고 새로운 기본 블록의 시작을 알린다. 따라서, 함수 호출 포인트 직후는 새로운 기본 블록의 시작점이 된다.
    
    ### **분기의 종류**
    
    프로그래밍에서 분기는 제어 흐름을 변경하는 여러 방식을 포함한다. 대표적인 분기의 종류는 다음과 같다:
    
    1. **조건 분기(Conditional Branch)**
       - 조건문(if, switch 등)에 의해 결정되는 분기로, 조건의 평가 결과(true 또는 false)에 따라 다른 코드 섹션을 실행한다.
    2. **무조건적 분기(Unconditional Branch)**
       - goto문이나 루프의 종료 등, 조건 없이 특정 위치로 점프하는 분기이다. 프로그램 카운터(Program Counter)를 특정 주소로 강제로 변경하여 실행 흐름을 이동시킨다.
    3. **함수 호출(Function Call)**
       - 다른 함수로 제어를 이동시키며, 호출된 함수의 실행이 완료된 후에는 원래의 위치로 제어가 돌아온다. 이는 호출 스택(Call Stack)을 사용하여 관리된다.
    4. **반환(Return)**
       - 함수의 실행이 종료되고, 함수를 호출한 지점으로 제어가 돌아가는 분기이다. 이는 함수 내에서 발생하며, 보통 **`return`** 명령어에 의해 처리된다.
    5. **예외 처리(Exception Handling)**
       - 실행 중에 예외 상황이 발생했을 때, 정상적인 실행 흐름에서 벗어나 예외를 처리하는 코드로 제어를 이동시키는 분기이다. 이는 예외가 발생할 가능성이 있는 코드 블록을 try 블록으로 감싸고, catch 블록에서 예외를 처리함으로써 구현된다.

### 4. IPOINT

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/57749aec-4422-4d95-b493-aa606e04dfbb/64589bea-f6ce-4ee1-94c8-bad0588018d3/Untitled.png)

## Detection BOF Code (Final)

---

```cpp
#include <iostream>
#include <stack>
#include "pin.H"

std::stack<ADDRINT> shadowStack;

VOID BeforeCall(ADDRINT sp)
{
    shadowStack.push(sp);
}

VOID AfterCall(ADDRINT sp)
{
    if (sp != shadowStack.top())
    {
        std::cout << "Buffer Overflow Detected!" << std::endl;
        PIN_ExitProcess(1);
    }
    shadowStack.pop();
}

VOID Instruction(INS ins, VOID* v)
{
    if (INS_IsCall(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeCall,
                       IARG_REG_VALUE, REG_STACK_PTR, IARG_END);

        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)AfterCall,
                       IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    }
}

int main(int argc, char* argv[])
{
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();

    return 0;
}
```

## Instruction Func

### 1차 (실패)

```cpp
VOID Instruction(INS ins, VOID* v)
{
    if (INS_IsCall(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeCall,
                       IARG_REG_VALUE, REG_STACK_PTR, IARG_END);

        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)AfterCall,
                       IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    }
}
/*
INS_IsCall에서 ins가 Call명령어가 맞으면, InserCall함수를 통해 우리가 넣고자 하는 계측함수를 삽입한다.
우선, 분석 호출을 명령 바로 앞에 삽입하여 shadowstack에 해당 
*/
```

1. `INS_InsertCall(INS ins, IPOINT action, AFUNPTR funpter, ...)`
   
   - 명령어 입력과 관련하여 funptr에 대한 호출을 삽입합니다.
   
   - 매개 변수
     
     - `INS` : Instruction to instrument
     
     - `action` : 이전, 이후 등을 지정한다.
       
       IPOINT_BEFORE는 모든 명령어에 대해 항상 유효합니다.
       
       IPOINT_AFTER는 fall-through가 존재할 때만 유효합니다(즉, 호출 및 무조건 분기가 실패합니다). INS_IsValidForIpointAfter(ins)가 true인 경우에만 허용됩니다.
       
       IPOINT_TAKEN_BRANCH는 지점이 아닌 경우 유효하지 않습니다. INS_IsValidForIpointTakenBranch가 true인 경우에만 허용됩니다.
     
     - `funptr` : funptr에 대한 호출 삽입
     
     - `…` : funptr에 전달하는 인수 목록입니다. [**IARG_TYPE을**](https://software.intel.com/sites/landingpage/pintool/docs/98830/Pin/doc/html/group__INST__ARGS.html#ga089c27ca15e9ff139dd3a3f8a6f8451d) 참조하세요 . IARG_END로 종료됩니다.
       
       - `IARG_TYPE` : 정수 레지스터의 경우 ADDRINT이다. 레지스터 값을 가져오며 추가 레지스터 인수가 필요하다. → [**REG: 레지스터 개체**](https://software.intel.com/sites/landingpage/pintool/docs/98830/Pin/doc/html/group__REG.html)

### 2차 (실패)

```cpp
#include <iostream>
#include <stack>
#include "pin.H"

using namespace std;

stack<ADDRINT> shadowStack; // 스택 포인터를 저장할 스택

// 함수 호출 전에 호출될 콜백 함수
VOID BeforeCall(ADDRINT sp)
{
    shadowStack.push(sp); // 현재 스택 포인터를 저장
}

// 함수 반환 전에 호출될 콜백 함수
VOID AfterReturn(ADDRINT sp)
{
    if (!shadowStack.empty())
    {
        ADDRINT savedSp = shadowStack.top(); // 저장된 스택 포인터를 가져옴
        shadowStack.pop();

        // 스택 포인터가 단순히 다른 것을 기반으로 오버플로우 감지를 조정
        if (sp != savedSp - 0x8)
        {
            cout << "Potential BOF detected: SP at call: " << savedSp << ", SP at return: " << sp << endl;
            // PIN_ExitProcess(1);  // 감지 시 프로그램 종료를 비활성화하여 관찰만 수행
        }
    }
}

VOID Instruction(INS ins, VOID *v)
{
    if (INS_IsCall(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeCall, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    }
    if (INS_IsRet(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AfterReturn, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    } // 이걸로
}

int main(int argc, char *argv[])
{
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram(); // This function will not return

    return 0;
}
```

호출과 리턴된 주소가 8바이트 차이난다는 것을 알아내고 수정. 하지만 오버플로우가 일어나도 반응 x

```cpp
#include <iostream>
#include <stack>
#include "pin.H"

using namespace std;

stack<ADDRINT> shadowStack; // 스택 포인터를 저장할 스택

// 함수 호출 전에 호출될 콜백 함수
VOID BeforeCall(ADDRINT sp)
{
    shadowStack.push(sp); // 현재 스택 포인터를 저장
}

// 함수 반환 전에 호출될 콜백 함수
VOID AfterReturn(ADDRINT sp)
{
    if (!shadowStack.empty())
    {
        ADDRINT savedSp = shadowStack.top(); // 저장된 스택 포인터를 가져옴
        shadowStack.pop();

        // 스택 포인터가 단순히 다른 것을 기반으로 오버플로우 감지를 조정
        if (sp != savedSp)
        {
            cout << "Potential BOF detected: SP at call: " << savedSp << ", SP at return: " << sp << endl;
            // PIN_ExitProcess(1);  // 감지 시 프로그램 종료를 비활성화하여 관찰만 수행
        }
    }
}

VOID Instruction(INS ins, VOID *v)
{
    if (INS_IsCall(ins))
    {
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)BeforeCall, IARG_RETURN_IP, IARG_END);
    } //이걸로
    if (INS_IsRet(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AfterReturn, IARG_MEMORYREAD_EA, IARG_END);
    }
}

int main(int argc, char *argv[])
{
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram(); // This function will not return

    return 0;
}
```

### 3차 (성공. 이유 알아냄)

**3_1차 실패작 → but, 이유 찾아냄**

```bash
#include <iostream>
#include <stack>
#include "pin.H"

using namespace std;

std::stack<ADDRINT> shadowStack;
std::stack<ADDRINT> testStack;

VOID BeforeCall(ADDRINT sp)
{
    shadowStack.push(sp);
}

VOID BeforeCall_test(ADDRINT sp)
{
    testStack.push(sp);
}

VOID AfterCall(ADDRINT sp)
{
    if (sp != testStack.top())
    {
        ADDRINT save = shadowStack.top();
        ADDRINT test = testStack.top();
        std::cout << "Buffer Overflow Detected!" << std::endl;
        if (save != test)
            std::cout << "Return : " << save << ", Test : "<< test << endl;
        //PIN_ExitProcess(1);
    }
    shadowStack.pop();
    testStack.pop();
}

VOID Instruction(INS ins, VOID* v)
{

    if (INS_IsCall(ins))
    {
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)BeforeCall, IARG_RETURN_IP, IARG_END);
        ADDRINT nextAddr = INS_Address(ins) + INS_Size(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeCall_test, IARG_ADDRINT, nextAddr, IARG_END);
    }
    if (INS_IsRet(ins))
    {    
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AfterCall, IARG_REG_VALUE, REG_RSP, IARG_END);
    }


}

int main(int argc, char* argv[])
{
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();

    return 0;
}
```

동아리 osori님이 보내주신 코드를 참고하여 내 코드와 비교. 구현 원리 자체는 동일한데 내껀 계속 실패.

그래서 IARG_RETURN_IP가 내가 생각하는 주소를 안 주나? 해서 osori님 코드에서 도출되는 ret주소와 비교해봄. 결과적으로 동일함. 돌렸을 때 `save != test` 조건문 안의 출력문이 출력되지 않음.

확인한 결과,

`REG_STACK_PTR` 은 `REG_RSP`와 달리 32/64 비트에 따라서 알맞은 레지스터의 값 (esp, rsp)를 구별해주는 더 정확한 인자임. 여기서 생각하지 못 했던 부분은 RSP → 함수 에필로그 leave이후 rsp는 ret를 가르키게 된다. 즉, 현재 stack의 ret을 가리키는 주소이다. ret안의 돌아갈 주소가 아닌 ret자체의 주소이다.

따라서 해당 주소 자체와 비교하는 게 아니라 해당 주소안에 있는 주소와 비교를 해주어야한다.

즉, 포인터를 이용하여 구현해주어야 하는 것이다.

완성된 최종본을 살펴보면,

**3-2 최종본.**

```cpp
#include <iostream>
#include <stack>
#include "pin.H"

using namespace std;

std::stack<ADDRINT> shadowStack;

VOID BeforeCall(ADDRINT sp)
{
    shadowStack.push(sp);
}

VOID AfterCall(ADDRINT *sp)
{
    if (*sp != shadowStack.top())
    {
        ADDRINT save = shadowStack.top();
        std::cout << "Buffer Overflow Detected!" << std::endl;
        PIN_ExitProcess(1);
    }
    shadowStack.pop();
}

VOID Instruction(INS ins, VOID* v)
{
    if (INS_IsCall(ins))
    {
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)BeforeCall, IARG_RETURN_IP, IARG_END);
    }
    if (INS_IsRet(ins))
    {    
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AfterCall, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    }
}

int main(int argc, char* argv[])
{
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();

    return 0;
}
```
