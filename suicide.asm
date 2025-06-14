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

        and rsp, -16            ; Align RSP to 16-byte boundary
        mov rbp, rsp
        sub rsp, 16
        xor rax, rax            ; RAX = 0
        

        int 3
        ; Store parameters for NtFreeVirtualMemory on the stack, to be pointed to by RDX and R8

        mov [rbp - 8], rcx      ; [RBP-8] = BaseAddress (RCX passed from C++ caller, e.g., pResources->Injected_Shellcode_base)


    Suicide ENDP

_STUB ENDS ; End of this segment definition

END