; RUN: llc                             < %s | FileCheck %s
; RUN: llc -fast-isel -fast-isel-abort < %s | FileCheck %s
target datalayout = "E-m:e-i64:64-n32:64"
target triple = "powerpc64-unknown-linux-gnu"

; Trivial patchpoint codegen
;
define i64 @trivial_patchpoint_codegen(i64 %p1, i64 %p2, i64 %p3, i64 %p4) {
entry:
; CHECK-LABEL: trivial_patchpoint_codegen:

; CHECK: li 11, -8531
; CHECK-NEXT: rldic 11, 11, 32, 16
; CHECK-NEXT: oris 11, 11, 48879
; CHECK-NEXT: ori 11, 11, 51966
; CHECK-NEXT: mtctr 11
; CHECK-NEXT: bctrl

; CHECK: li 11, -8531
; CHECK-NEXT: rldic 11, 11, 32, 16
; CHECK-NEXT: oris 11, 11, 48879
; CHECK-NEXT: ori 11, 11, 51967
; CHECK-NEXT: mtctr 11
; CHECK-NEXT: bctrl

; CHECK: blr

  %resolveCall2 = inttoptr i64 244837814094590 to i8*
  %result = tail call i64 (i64, i32, i8*, i32, ...)* @llvm.experimental.patchpoint.i64(i64 2, i32 24, i8* %resolveCall2, i32 4, i64 %p1, i64 %p2, i64 %p3, i64 %p4)
  %resolveCall3 = inttoptr i64 244837814094591 to i8*
  tail call void (i64, i32, i8*, i32, ...)* @llvm.experimental.patchpoint.void(i64 3, i32 24, i8* %resolveCall3, i32 2, i64 %p1, i64 %result)
  ret i64 %result
}

; Caller frame metadata with stackmaps. This should not be optimized
; as a leaf function.
;
; CHECK-LABEL: caller_meta_leaf
; CHECK: stdu 1, -80(1)
; CHECK: Ltmp
; CHECK: addi 1, 1, 80
; CHECK: blr

define void @caller_meta_leaf() {
entry:
  %metadata = alloca i64, i32 3, align 8
  store i64 11, i64* %metadata
  store i64 12, i64* %metadata
  store i64 13, i64* %metadata
  call void (i64, i32, ...)* @llvm.experimental.stackmap(i64 4, i32 0, i64* %metadata)
  ret void
}

; Test patchpoints reusing the same TargetConstant.
; <rdar:15390785> Assertion failed: (CI.getNumArgOperands() >= NumArgs + 4)
; There is no way to verify this, since it depends on memory allocation.
; But I think it's useful to include as a working example.
define i64 @testLowerConstant(i64 %arg, i64 %tmp2, i64 %tmp10, i64* %tmp33, i64 %tmp79) {
entry:
  %tmp80 = add i64 %tmp79, -16
  %tmp81 = inttoptr i64 %tmp80 to i64*
  %tmp82 = load i64* %tmp81, align 8
  tail call void (i64, i32, ...)* @llvm.experimental.stackmap(i64 14, i32 8, i64 %arg, i64 %tmp2, i64 %tmp10, i64 %tmp82)
  tail call void (i64, i32, i8*, i32, ...)* @llvm.experimental.patchpoint.void(i64 15, i32 32, i8* null, i32 3, i64 %arg, i64 %tmp10, i64 %tmp82)
  %tmp83 = load i64* %tmp33, align 8
  %tmp84 = add i64 %tmp83, -24
  %tmp85 = inttoptr i64 %tmp84 to i64*
  %tmp86 = load i64* %tmp85, align 8
  tail call void (i64, i32, ...)* @llvm.experimental.stackmap(i64 17, i32 8, i64 %arg, i64 %tmp10, i64 %tmp86)
  tail call void (i64, i32, i8*, i32, ...)* @llvm.experimental.patchpoint.void(i64 18, i32 32, i8* null, i32 3, i64 %arg, i64 %tmp10, i64 %tmp86)
  ret i64 10
}

; Test small patchpoints that don't emit calls.
define void @small_patchpoint_codegen(i64 %p1, i64 %p2, i64 %p3, i64 %p4) {
entry:
; CHECK-LABEL: small_patchpoint_codegen:
; CHECK:      Ltmp
; CHECK:      nop
; CHECK-NEXT: nop
; CHECK-NEXT: nop
; CHECK-NEXT: nop
; CHECK-NEXT: nop
; CHECK-NOT:  nop
; CHECK: blr
  %result = tail call i64 (i64, i32, i8*, i32, ...)* @llvm.experimental.patchpoint.i64(i64 5, i32 20, i8* null, i32 2, i64 %p1, i64 %p2)
  ret void
}

declare void @llvm.experimental.stackmap(i64, i32, ...)
declare void @llvm.experimental.patchpoint.void(i64, i32, i8*, i32, ...)
declare i64 @llvm.experimental.patchpoint.i64(i64, i32, i8*, i32, ...)

