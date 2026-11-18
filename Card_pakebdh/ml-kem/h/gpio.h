#ifndef     __GPIO_H__
#define     __GPIO_H__

#include "HSCTU_Registers.h"
#include "interrupt_conf.h"
#include "types.h"



//GPIO pin macro definitions
#define GPIO_GP0_SPI0SCK                    (0)
#define GPIO_GP1_SPI0SS0                    (1)
#define GPIO_GP2_SPI0SS1                    (2)
#define GPIO_GP3_SPI0MISO                   (3)
#define GPIO_GP4_SPI0MOSI                   (4)
#define GPIO_GP5_SPI0SPIO2                  (5)
#define GPIO_GP6_SPI0SPIO3                  (6)
#define GPIO_GP7_SPI1SS1                    (7)

#define GPIO_GP8_SPI1SCK_SDSICLK            (8)
#define GPIO_GP9_SPI1SS0_SDSIDIO3           (9)
#define GPIO_GP10_SPI1MOSI_SDSICMD          (10)
#define GPIO_GP11_SPI1MISO_SDSIDIO0         (11)
#define GPIO_GP12_SPI1SPIIO2_SDSIDIO1       (12)
#define GPIO_GP13_SPI1SPIO3_SDSIDIO2        (13)
#define GPIO_GP14_UART0TXD_TIMPC2           (14)
#define GPIO_GP15_UART1RXD_TIMPC3           (15)

#define GPIO_GP16_I2CSCL_UART1RXD           (16)
#define GPIO_GP17_I2CSDA_UART1TXD           (17)
#define GPIO_GP18_UART0CTS_UART2CTS_TIMPC5  (18)
#define GPIO_GP19_UART0RTS_UART2RTS_TIMPC4  (19)
#define GPIO_GP20_TIMPC0_UART1RTS_CLKOUT    (20)
#define GPIO_GP21_TIMPC1_UART1CTS_SCIRSTO   (21)
#define GPIO_GP22_SCICLK_UART2RXD_TIMPC7    (22)
#define GPIO_GP23_SCIDIO_UART2TXD_TIMPC6    (23)

#define GPIO_GP24_EMMCDIO0_SDDIO0           (24)
#define GPIO_GP25_EMMCDIO1_SDDIO1           (25)
#define GPIO_GP26_EMMCDIO2_SDDIO2           (26)
#define GPIO_GP27_EMMCDIO3_SDDIO3           (27)
#define GPIO_GP28_EMMCDIO4                  (28)
#define GPIO_GP29_EMMCDIO5                  (29)
#define GPIO_GP30_EMMCDIO6                  (30)
#define GPIO_GP31_EMMCDIO7                  (31)

#define GPIO_GP32_EMMCCMD_SDCMD             (32)
#define GPIO_GP33_EMMCCLK_SDCLK             (33)
#define GPIO_GP34_EMMCRST                   (34)
#define GPIO_GP35_TIMPC8            (35)
#define GPIO_GP36_TIMPC9            (36)



//Interrupt modes
#define     INTERRUPT_NO_EDGE               (0)//No interrupt is generated
#define     INTERRUPT_UP_EDGE               (1)//Generate an interrupt on the rising edge
#define     INTERRUPT_DOWN_EDGE             (2)//Generate an interrupt on the falling edge
#define     INTERRUPT_UP_AND_DOWN_EDGE      (3)//Generate interrupts on both rising and falling edges

void gpio_init(U8 GPIO, U8 Dir);
void gpio_out(U8 GPIO, U8 value);
unsigned char gpio_get(U8 GPIO);
void gpio_int_init(U8 GPIO, U8 intrrupt_mode, NVIC_PRIORITY_Type priority);
unsigned char  gpio_intrrupt_state_detec(U8 GPIO);
void gpio_intrrupt_state_clear(U8 GPIO);
void gpio_intrrupt_disable(U8 GPIO);
void gpio_int_clksel(U8 value);

#endif
