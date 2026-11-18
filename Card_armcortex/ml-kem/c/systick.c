#include "HSCTU_Registers.h"
#include "systick.h"
#include "gpio.h"
#include "types.h"


T_U32 g_systick_count = 0;

#if defined(PAKE_EMV_BENCHMARK) && PAKE_EMV_BENCHMARK && \
    defined(PAKE_EMV_SYSTICK_BENCHMARK) && PAKE_EMV_SYSTICK_BENCHMARK
/* The benchmark's state has one owner in smartcard_demo.c. */
extern unsigned char pake_benchmark_systick_irq(void);
#endif



void systick_int_init(void)
{
	SYSTRVR = 0xffffff;//105 MHz system clock; maximum 24-bit reload
	
	SYSTCSR = SYSTICK_CLKSOURCE | SYSTICK_TICKINT;//Enable the core (system) clock and interrupts
}


void enable_systick(void)//Enable the timer
{
	SYSTCSR |= SYSTICK_ENABLE;
}


void disable_systick(void)//Disable the timer
{
	SYSTCSR &= ~SYSTICK_ENABLE;
}




void SysTick_Handler(void)//SysTick interrupt handler
{
#if defined(PAKE_EMV_BENCHMARK) && PAKE_EMV_BENCHMARK && \
    defined(PAKE_EMV_SYSTICK_BENCHMARK) && PAKE_EMV_SYSTICK_BENCHMARK
    if (pake_benchmark_systick_irq()) return;
#endif
	if(SYSTCSR & SYSTICK_COUNTFLAG)
	{
		g_systick_count++;
	}
	if(g_systick_count >= 10)//Legacy ten-interrupt indicator interval
	{
		gpio_out(GPIO_GP0_SPI0SCK, 2);//Blink the indicator LED
		g_systick_count = 0;
	}
}


