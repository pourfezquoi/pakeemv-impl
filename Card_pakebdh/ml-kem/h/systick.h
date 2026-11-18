#ifndef		__SYSTICK_H__ 
#define		__SYSTICK_H__




//SYSTCSR
#define		SYSTICK_COUNTFLAG				0x00010000	//Read-only overflow flag
#define		SYSTICK_CLKSOURCE				0x00000004	//Clock source selection bit; only the system clock is currently supported
#define		SYSTICK_TICKINT					0x00000002	//Interrupt enable bit
#define		SYSTICK_ENABLE					0x00000001	//SysTick enable bit






void systick_int_init(void);
void enable_systick(void);
void disable_systick(void);

#endif

