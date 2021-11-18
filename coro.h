// MIT License

// Copyright (c) 2021 Zeta

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Coroutines are fun
// But only work with gcc/clang, because MSVC does not support inline assembly for x64?

#ifndef _CORO_H_
#define _CORO_H_

typedef union coro_value {
  int i;
  long long l;
  float f;
  double d;
  void *p;
} coro_value_t;

#define coro_null                                                              \
  (coro_value_t) { 0 }

typedef struct coro {
  void (*fun)();
  void *stack;
  void *cur_stack;
  void *prev_stack;

  void *last_stopped;
  void *return_to;
} coro_t;

void coro_init(coro_t *coro, void (*fun)(coro_value_t value));
coro_value_t coro_call(coro_t *coro, coro_value_t value);
coro_value_t coro_yield(coro_t *coro, coro_value_t value);

#ifdef CORO_IMPLEMENTATION

#ifndef CORO_ALLOC
#include <malloc.h>
#define CORO_ALLOC(size) malloc(size)
#endif
#ifndef CORO_FREE
#define CORO_FREE(ptr, size) free(ptr)
#endif

// 128 kilobytes
#ifndef CORO_STACK_SIZE
#define CORO_STACK_SIZE 128 * 1024
#endif

#if defined(__x86_64__) || defined(_M_X64)
#define AMD64
#endif

#if defined(__arm64) || defined(__arm64__) || defined(__aarch64) ||            \
    defined(__aarch64__)
#define ARM64
#endif

#ifdef AMD64
#define CLOBBERED_REGS                                                         \
  /*"rax", "rcx", "rdx", "rbx"*/ /*"rsp", "rbp",*/ "rsi", "rdi", "r8", "r9",   \
      "r10", "r11", "r12", "r13", "r14", "r15"
#elif defined(ARM64)
#define CLOBBERED_REGS                                                         \
  "x4", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25",  \
      "r26", "r27", "r28", "r29", "r30"
#else
#error "Unsupported architecture"
#endif
void coro_init(coro_t *coro, void (*fun)(coro_value_t value)) {
  *coro = (coro_t){0};
  coro->stack = CORO_ALLOC(CORO_STACK_SIZE);
  coro->cur_stack = coro->stack + (CORO_STACK_SIZE);
  coro->last_stopped = fun;
}

coro_value_t coro_call(coro_t *coro, coro_value_t value) {
  coro->return_to = &&ret_label;
  register coro_value_t r;
#ifdef AMD64
  asm("movq %%rsp, (%[prev_stack]);"
      "movq %[new_stack], %%rsp;"
      "movq %[value], %%rdi;"
      "jmpq *%[where_to];" ::[prev_stack] "r"(&coro->prev_stack),
      [new_stack] "r"(coro->cur_stack), [where_to] "r"(coro->last_stopped),
      [value] "r"(value)
      : CLOBBERED_REGS);
#elif defined(ARM64)
  asm("mov x4, sp;"
      "str x4, [%[prev_stack]];"
      "mov sp, %[new_stack];"
      "mov x0, %[value];"
      "br %[where_to];" ::[prev_stack] "r"(&coro->prev_stack),
      [new_stack] "r"(coro->cur_stack), [where_to] "r"(coro->last_stopped),
      [value] "r"(value)
      : CLOBBERED_REGS);
#endif
ret_label:
#ifdef AMD64
  asm("movq %%rdi, %[r]" : [r] "=r"(r));
#elif defined(ARM64)
  asm("mov %[r], x0" : [r] "=r"(r));
#endif
  return r;
}

coro_value_t coro_yield(coro_t *coro, coro_value_t value) {
  coro->last_stopped = &&ret_label;
  register coro_value_t r;
#ifdef AMD64
  asm("movq %%rsp, (%[prev_stack]);"
      "movq %[cur_stack], %%rsp;"
      "movq %[value], %%rdi;"
      "jmpq *%[where_to];" ::[prev_stack] "r"(&coro->cur_stack),
      [cur_stack] "r"(coro->prev_stack), [where_to] "r"(coro->return_to),
      [value] "r"(value)
      : CLOBBERED_REGS);
#elif defined(ARM64)
  asm("mov x4, sp;"
      "str x4, [%[prev_stack]];"
      "mov sp, %[cur_stack];"
      "mov x0, %[value];"
      "br %[where_to];" ::[prev_stack] "r"(&coro->cur_stack),
      [cur_stack] "r"(coro->prev_stack), [where_to] "r"(coro->return_to),
      [value] "r"(value)
      : CLOBBERED_REGS);
#endif
ret_label:
#ifdef AMD64
  asm("movq %%rdi, %[r]" : [r] "=r"(r));
#elif defined(ARM64)
  asm("mov %[r], x0" : [r] "=r"(r));
#endif
  return r;
}

void coro_destroy(coro_t *coro) {
  if (coro->stack) {
    CORO_FREE(coro->stack, CORO_STACK_SIZE);
  }
}
#endif
#endif
