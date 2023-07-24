.text

.pool
.set EXEC_MAGIC,     0x65786563
.set MEMC_MAGIC,     0x6d656d63
.set DONE_MAGIC,     0x646f6e65

.syntax unified
.code 16
.global _main
_main:
    PUSH {R4-R7,LR}
    SUB  SP, SP, #0x10

    MOV  R5, R0
    MOV  R4, R1

    LDR  R0, [R5]
    LDR  R1, [R5,4]

    LDR  R2, =EXEC_MAGIC
    CMP  R0, R2
    BNE  not_exec
    CMP  R1, R2
    BNE  not_exec

    MOVS  R1, #0
    STR R1, [R5]
    STR R1, [R5,4]

    LDR R0, [R5, #0x20]
    LDR R1, [R5, #0x24]
    LDR R2, [R5, #0x28]
    LDR R3, [R5, #0x2c]

    STR R0, [SP, #0x00]
    STR R1, [SP, #0x04]
    STR R2, [SP, #0x08]
    STR R3, [SP, #0x0C]

    LDR R0, [R5, #0x10]
    LDR R1, [R5, #0x14]
    LDR R2, [R5, #0x18]
    LDR R3, [R5, #0x1c]

    LDR  R6, [R5, #0x8]
    BLX  R6

    LDR  R2, =DONE_MAGIC
    STR R0, [R5,#0x8]
    STR R1, [R5,#0xC]

    STR R2, [R5]
    STR R2, [R5,4]
    B request_done

not_exec:
    LDR  R2, =MEMC_MAGIC
    CMP  R0, R2
    BNE  request_done
    CMP  R1, R2
    BNE  request_done

    MOVS R1, #0
    STR R1, [R5]
    STR R1, [R5,4]

    LDR R0, [R5, #0x10]
    LDR R1, [R5, #0x14]
    LDR  R2, [R5, #0x18]
    BL   memcpy

    LDR  R2, =DONE_MAGIC
    STR R2, [R5]
    STR R2, [R5,4]
    B    request_done

request_done:
    MOV R0, R4
    MOV R1, R5
    MOVS R2, 0x10
    BL memcpy
    MOVS R0, 0x10
    ADD  SP, SP, #0x10
    POP  {R4-R7,PC}

memcpy:
    CMP  R2, #4
    BCC  memcpy_2

    LDR  R3, [R1]
    STR  R3, [R0]
    ADDS R0, R0, #4
    ADDS R1, R1, #4
    SUBS R2, R2, #4
    B    memcpy

memcpy_2:
    CMP  R2, #2
    BCC  memcpy_1

    LDRH R3, [R1]
    STRH R3, [R0]
    ADDS R0, R0, #2
    ADDS R1, R1, #2
    SUBS R2, R2, #2

memcpy_1:
    CMP R2, 0
    BEQ memcpy_done

    LDRB R3, [R1]
    STRB R3, [R0]
    ADDS R0, R0, #1
    ADDS R1, R1, #1
    SUBS R2, R2, #1

memcpy_done:
    BX   LR

    memset:
    MOVS R3, #0xFF
    ANDS R1, R1, R3
    LSLS R3, R1, #8
    ORRS R1, R1, R3
    LSLS R3, R1, #16
    ORRS R1, R1, R3

memset_4:
    CMP  R2, #4
    BCC  memset_2

    STR  R1, [R0]
    ADDS R0, R0, #4
    SUBS R2, R2, #4
    B    memset_4

memset_2:
    CMP  R2, #2
    BCC  memset_1

    STRH R1, [R0]
    ADDS R0, R0, #2
    SUBS R2, R2, #2

memset_1:
    CMP R2, 0
    BEQ memcpy_done

    STRB R1, [R0]
    ADDS R0, R0, #1
    SUBS R2, R2, #1

memset_done:
    BX   LR
