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
        ; R9  = resolved_pfnVirtualProtect

        ; int 3

        push rbp                            ; epilog
        mov rbp, rsp                        ; epilog
        
        ; Preserve stuff
        push r11
        push r12
        push r13
        push r14
        push r15
        ; rbp is already pushed in the epilog

        sub rsp, 40h

        ; int 3
        mov r12, rcx                        ; r12 = pBaseAddressToFree
        mov r13, rdx                        ; r13 = pfnNtFreeVirtualMemory
        mov r14, r8                         ; r14 = pfnRtlExitUserThread
        mov r15, r9                         ; r15 = pfnVirtualProtect
        

        mov byte ptr [rbp - 40h], 48h       ; Micro-stub byte 0     ---
        mov byte ptr [rbp - 3Fh], 31h       ; Micro-stub byte 1        |- xor rcx, rcx
        mov byte ptr [rbp - 3Eh], 0C9h      ; Micro-stub byte 2     ---    
        mov byte ptr [rbp - 3Dh], 41h       ; Micro-stub byte 3     ---
        mov byte ptr [rbp - 3Ch], 0FFh      ; Micro-stub byte 4        |- jmp r14
        mov byte ptr [rbp - 3Bh], 0E6h      ; Micro-stub byte 5     ---
        lea r11, [rbp - 40h]                ; R11 = Address of micro-stub on stack
        ; int 3

        ; --- Attempt to Call VirtualProtect ---
        ; Args for VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
        ; RCX = lpAddress
        ; RDX = dwSize
        ; R8  = flNewProtect
        ; R9  = lpflOldProtect (pointer to a DWORD on stack)
        ; int 3
        ; mov rcx, r11
        ; and rcx, -1000h                     ; Page-align downwards
        ; mov rdx, 1000h                      ; RDX = dwSize = one page
        ; mov r8d, 20h                        ; R8D = flNewProtect = PAGE_EXECUTE_READ (0x20)
        ; lea r9, [rbp - 38h]                 ; lpflOldProtect
        ; call r15                            ; Call pfnVirtualProtect
        ; int 3
        ; jmp r11
        ; ;-----------------------------------------------------------------------------------------------

        ; --- Attempt to Call NtProtectVirtualMemory ---
        ; Args for NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
        ; RCX = ProcessHandle
        ; RDX = BaseAddress
        ; R8  = NumberOfBytesToProtect
        ; R9  = NewAccessProtection (pointer to a DWORD on stack)
        ; on stack OldAccessProtection
        ; int 3
        ; Set up arguments for NtProtectVirtualMemory
        xor rcx, rcx
        dec rcx                             ; RCX = -1 (HANDLE hProcess = NtCurrentProcess)

        mov rax, r11
        and rax, -1000h                     ; Page-align it downwards
        mov [rbp - 48h], rax                ; Store base address (micro-stub) at [rbp - 48h]
        lea rdx, [rbp - 48h]                ; RDX = &BaseAddress (pointer to base address)

        mov dword ptr [rbp - 4Ch], 1000h    ; RegionSize = 0x1000 (one page)
        lea r8, [rbp - 4Ch]                 ; R8 = &RegionSize (pointer to region size)

        mov r9d, 20h                        ; R9D = NewAccessProtection = PAGE_EXECUTE_READ (0x20)

        lea rax, [rbp - 50h]                ; RAX = pointer to where OldAccessProtection will be stored
        mov dword ptr [rbp - 50h], 0        ; Zero out OldProtect space

        sub rsp, 20h                        ; shadow space for Win64 calling convention
        mov [rsp + 20h], rax                ; 5th argument (OldAccessProtection) on stack
        int 3
        call r15                            ; Call pfnNtProtectVirtualMemory
        
        int 3
        add rsp, 20h                        ; clean up shadow space
        ;-----------------------------------------------------------------------------------------------

        ; ; ; --- Set up Arguments for NtFreeVirtualMemory(hProcess, &BaseAddress, &RegionSize, FreeType) ---
        
        ; mov qword ptr [rbp - 50h], r12      ; Store BaseAddressToFree value
        ; mov qword ptr [rbp - 58h], 0        ; Store RegionSize value (0)


        ; xor rcx, rcx
        ; dec rcx                             ; rcx = -1 (hProcess = NtCurrentProcess)
        ; lea rdx, [rbp - 50h]                ; RDX = address of [rbp - 10h] (where BaseAddressToFree value is)
        ; lea r8, [rbp - 58h]                 ; R8  = address of [rbp - 18h] (where RegionSize=0 value is)
        ; mov r9d, 08000h                     ; R9d = FreeType = MEM_RELEASE (0x8000)
        ; ; int 3

        ; ; ;-----------------------------------------------------------------------------------------------

        ; and rsp, -10h
        ; sub rsp, 8
        ; push r11

        ; jmp r13                             ; jump to NtfreeVirtualMemory

        ; and rsp, -16
        ; mov rbp, rsp

        ; sub rsp, 16
        ; xor rax, rax
    
        ; mov [rbp - 8], rcx
        ; mov [rbp - 16], rax
    
        ; sub rsp, 40
        ; mov rax, r8
        ; push rax
    
        ; mov r9d, 08000h     ; FreeType
        ; lea r8, [rbp - 16]  ; RegionSize
        ; lea rdx, [rbp - 8]  ; BaseAddress
        ; xor rcx, rcx
        ; dec rcx             ; ProcessHandle
        ; mov rax, rdx

        ; int 3
        ; jmp rax

    Suicide ENDP

_STUB ENDS ; End of this segment definition

END