; ml64.exe /c /Fo suicide.obj .\suicide.asm

; Define a segment that you want the linker to recognize as part of ".stub"
_STUB SEGMENT PARA 'CODE' ALIAS('.stub') 
_STUB ENDS

; Tell MASM to assemble subsequent code into this _STUB segment
_STUB SEGMENT

    ; PUBLIC AddTwoNumbers ; Make it callable from C++
    AddTwoNumbers PROC

        ; RCX will hold the first argument (a)
        ; RDX will hold the second argument (b)
        ; RAX will hold the return value
        mov rax, rcx            ; Move the first argument (a) from RCX to RAX
        add rax, rdx            ; Add the second argument (b) from RDX to RAX
        ; int 3
        ret                     ; Return to the caller (result is in RAX)
    AddTwoNumbers ENDP

    Suicide PROC

        ; On entry (x64 __fastcall from C++):
        ; RCX = pBaseAddressToFree
        ; RDX = resolved_pfnNtFreeVirtualMemory
        ; R8  = resolved_pfnRtlExitUserThread

        ; int 3

        push rbp                            ; epilog
        mov rbp, rsp                        ; epilog
        
        ; Preserve stuff
        push r11
        push r12
        push r13
        push r14
        ; rbp is already pushed in the epilog

        sub rsp, 40h

        mov r12, rcx                        ; r12 = pBaseAddressToFree
        mov r13, rdx                        ; r13 = pfnNtFreeVirtualMemory
        mov r14, r8                         ; r14 = pfnRtlExitUserThread
        

        mov byte ptr [rbp - 40h], 48h       ; Micro-stub byte 0
        mov byte ptr [rbp - 3Fh], 31h       ; Micro-stub byte 1
        mov byte ptr [rbp - 3Eh], 0C9h      ; Micro-stub byte 2
        mov byte ptr [rbp - 3Dh], 41h       ; Micro-stub byte 3
        mov byte ptr [rbp - 3Ch], 0FFh      ; Micro-stub byte 4
        mov byte ptr [rbp - 3Bh], 0E6h      ; Micro-stub byte 5
        lea r11, [rbp - 40h]                ; R11 = Address of micro-stub on stack

        int 3

    Suicide ENDP

_STUB ENDS ; End of this segment definition

END