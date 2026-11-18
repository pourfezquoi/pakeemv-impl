



Stack_Size      EQU     0x0000A000
;Stack_Size      EQU     0x00000600	
                AREA    STACK, NOINIT, READWRITE, ALIGN=3
Stack_Mem       SPACE   Stack_Size
__initial_sp


; <h> Heap Configuration
;   <o>  Heap Size (in Bytes) <0x0-0xFFFFFFFF:8>
; </h>

Heap_Size       EQU     0x00000100

                AREA    HEAP, NOINIT, READWRITE, ALIGN=3
__heap_base
Heap_Mem        SPACE   Heap_Size
__heap_limit


                PRESERVE8
                THUMB


; Vector Table Mapped to Address 0 at Reset

                AREA    RESET, DATA, READONLY
                EXPORT  __Vectors
                EXPORT  __Vectors_End
                EXPORT  __Vectors_Size

__Vectors       DCD     __initial_sp              ; Top of Stack
                DCD     Reset_Handler             ; Reset Handler
                DCD     NMI_Handler               ; NMI Handler
                DCD     HardFault_Handler         ; Hard Fault Handler
                DCD     MemManage_Handler         ; MPU Fault Handler
                DCD     BusFault_Handler          ; Bus Fault Handler
                DCD     UsageFault_Handler        ; Usage Fault Handler
                DCD     0                         ; Reserved
                DCD     0                         ; Reserved
                DCD     0                         ; Reserved
                DCD     0                         ; Reserved
                DCD     SVC_Handler               ; SVCall Handler
                DCD     DebugMon_Handler          ; Debug Monitor Handler
                DCD     0                         ; Reserved
                DCD     PendSV_Handler            ; PendSV Handler
                DCD     SysTick_Handler           ; SysTick Handler
                DCD     WDT_Handler               ; WDT Handler
                DCD     GPIOA_Handler             ; GPIOL Handler
                DCD     GPIOB_Handler             ; GPIOH Handlerv
                DCD     USBI_Handler              ; USBI Handler
                DCD     TIMER0_Handler            ; TIMER1 Handler
                DCD     TIMER1_Handler            ; TIMER2 Handler
                DCD     TIMER2_Handler            ; TIMER3 Handler
                DCD     DMAC_Handler              ; DMAC Handler
                DCD     I2CI_Handler              ; I2CI Handler
                DCD     SPI0_Handler              ; SPI1 Handler
                DCD     SPI1_Handler              ; SPI2 Handler
                DCD     EMMCI_Handler             ; EMMCI Handler
                DCD     0                         ; Reserved
                DCD     0                         ; Reserved
                DCD     PWM1_Handler              ; PWM1 handler
                DCD     PWM2_Handler              ; PWM2 handler
                DCD     USI0_Handler              ; USI1 Handler
                DCD     USI1_Handler              ; USI2 Handler
                DCD     USI2_Handler              ; USI3 Handler
                DCD     SCI_Handler               ; SCI Handler
                DCD     REAE_Handler              ; REAE Handler
                DCD     BEAE_Handler              ; BEAE Handler
                DCD     FPAE_Handler              ; FPAE Handler
                DCD     BCAE_Handler              ; BCAE Handler
                DCD     SHAE_Handler              ; SHAE Handler
                DCD     RNG_Handler               ; RNG Handler
                DCD     SCM_TD_Handler            ; SCMTD Handler
                DCD     SCM_VD_Handler            ; SCMVD Handler
                DCD     SCM_SD_Handler            ; SCMSD Handler
                DCD     WAKEUP0_Handler           ; WAKEUP0 Handler
                DCD     WAKEUP1_Handler           ; WAKEUP1 Handler
                
__Vectors_End

__Vectors_Size  EQU     __Vectors_End - __Vectors

                AREA    |.text|, CODE, READONLY


; Reset Handler
Reset_Handler   PROC
                EXPORT  Reset_Handler             [WEAK]
                IMPORT  __main
                LDR     R0, = 0x40000000    ;
                LDR     R1, = 0x00          ;
                STR     R1, [R0]            ;
                LDR     R0, =__main
                BX      R0
                ENDP

; Dummy Exception Handlers (infinite loops which can be modified)

NMI_Handler     PROC
                EXPORT  NMI_Handler               [WEAK]
                B       .
                ENDP
HardFault_Handler\
                PROC
                EXPORT  HardFault_Handler         [WEAK]
                B       .
                ENDP
MemManage_Handler\
                PROC
                EXPORT  MemManage_Handler         [WEAK]
                B       .
                ENDP
BusFault_Handler\
                PROC
                EXPORT  BusFault_Handler          [WEAK]
                B       .
                ENDP
UsageFault_Handler\
                PROC
                EXPORT  UsageFault_Handler        [WEAK]
                B       .
                ENDP
SVC_Handler     PROC
                EXPORT  SVC_Handler               [WEAK]
                B       .
                ENDP
DebugMon_Handler\
                PROC
                EXPORT  DebugMon_Handler          [WEAK]
                B       .
                ENDP
PendSV_Handler\
                PROC
                EXPORT  PendSV_Handler            [WEAK]
                B       .
                ENDP
SysTick_Handler\
                PROC
                EXPORT  SysTick_Handler           [WEAK]
                B       .
                ENDP

Default_Handler PROC                                    
                EXPORT WDT_Handler                   [WEAK]
                EXPORT GPIOA_Handler                 [WEAK]
                EXPORT GPIOB_Handler                 [WEAK]
                EXPORT USBI_Handler                  [WEAK]
                EXPORT TIMER0_Handler                [WEAK]
                EXPORT TIMER1_Handler                [WEAK]
                EXPORT TIMER2_Handler                [WEAK]
                EXPORT DMAC_Handler                  [WEAK]
                EXPORT I2CI_Handler                  [WEAK]
                EXPORT SPI0_Handler                  [WEAK]
                EXPORT SPI1_Handler                  [WEAK]
                EXPORT EMMCI_Handler                 [WEAK]
                EXPORT PWM1_Handler                  [WEAK]
                EXPORT PWM2_Handler                  [WEAK]
                EXPORT USI0_Handler                  [WEAK]
                EXPORT USI1_Handler                  [WEAK]
                EXPORT USI2_Handler                  [WEAK]
                EXPORT SCI_Handler                   [WEAK]
                EXPORT REAE_Handler                  [WEAK]
                EXPORT BEAE_Handler                  [WEAK]
                EXPORT FPAE_Handler                  [WEAK]
                EXPORT BCAE_Handler                  [WEAK]
                EXPORT SHAE_Handler                  [WEAK]
                EXPORT RNG_Handler                   [WEAK]
                EXPORT SCM_TD_Handler                [WEAK]
                EXPORT SCM_VD_Handler                [WEAK]
                EXPORT SCM_SD_Handler                [WEAK]
                EXPORT WAKEUP0_Handler               [WEAK]
                EXPORT WAKEUP1_Handler               [WEAK]
WDT_Handler               
GPIOA_Handler       
GPIOB_Handler          
USBI_Handler        
TIMER0_Handler      
TIMER1_Handler      
TIMER2_Handler      
DMAC_Handler        
I2CI_Handler                                             
SPI0_Handler        
SPI1_Handler        
EMMCI_Handler             
PWM1_Handler        
PWM2_Handler        
USI0_Handler        
USI1_Handler        
USI2_Handler        
SCI_Handler         
REAE_Handler        
BEAE_Handler        
FPAE_Handler        
BCAE_Handler        
SHAE_Handler        
RNG_Handler         
PCI_Handler    
SCM_TD_Handler
SCM_VD_Handler
SCM_SD_Handler
WAKEUP0_Handler
WAKEUP1_Handler
                B       .
                ENDP


                ALIGN


; User Initial Stack & Heap

                IF      :DEF:__MICROLIB

                EXPORT  __initial_sp
                EXPORT  __heap_base
                EXPORT  __heap_limit

                ELSE

                IMPORT  __use_two_region_memory
                EXPORT  __user_initial_stackheap

__user_initial_stackheap PROC
                LDR     R0, =  Heap_Mem
                LDR     R1, =(Stack_Mem + Stack_Size)
                LDR     R2, = (Heap_Mem +  Heap_Size)
                LDR     R3, = Stack_Mem
                BX      LR
                ENDP

                ALIGN

                ENDIF


                END

