---
title: XSS Bypass Advance
categories: [Hacking, Web]
tags: [xss, bypass, dreamhack]
---

## XSS Bypass

XSS 취약점을 우회할 수 있는 방법엔 여러가지가 있다. 각 상황에 대한 우회법들을 정리해보자.





#### XSS Allowlist 필터링

> 안전하다고 알려진 마크업만 허용하는 필터링 방식





### 이벤트 핸들러

> 특정 요소에서 발생하는 이벤트를 처리하기 위해 존재하는 콜백 형태의 핸들러 함수





### Javascript 스키마

> URL 로드 시, 자바스크립트 코드를 실행할 수 있도록 해주는 활성 하이퍼링크





### Unicode escape sequence

> 문자열에서 유니코드 문자를 코드포인트로 나타낼 수 있는 표기법





### Computed member access

> 객체의 특정 속성에 접근할 때 속성 이름을 동적으로 계산하는 기능





### 템플릿 리터럴 (Template Literals)

> 내장된 표현식을 허용하는 문자열 리터럴이며, 여러 줄로 이뤄진 문자열과 문자 보간기능을 사용







```c
#include <stdio.h>
#include <stdlib.h>
int main()
{
    int *ptr;
    int N;
    ptr = (int *)malloc(sizeof(int));
    scanf("%d", &N);
}
```
