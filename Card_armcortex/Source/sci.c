#include "sci.h"
#include <string.h>

unsigned short etu_clk[256] =
{
    0,  372,    186,    93,     0,      0,      0,      0,  31,     0,  0, 0, 0, 0, 0, 0,
    0,  372,    186,    93,     0,      0,      0,      0,  31,     0,  0, 0, 0, 0, 0, 0,
    0,  558,    279,    0,      0,      0,      0,      0,  0,      0,  0, 0, 0, 0, 0, 0,
    0,  744,    372,    186,    93,     0,      0,      0,  62,     0,  0, 0, 0, 0, 0, 0,
    0,  1116,   558,    279,    0,      0,      0,      0,  93,     0,  0, 0, 0, 0, 0, 0,
    0,  1488,   744,    372,    186,    93,     0,      0,  124,    0,  0, 0, 0, 0, 0, 0,
    0,  1860,   930,    465,    0,      0,      0,      0,  155,    93, 0, 0, 0, 0, 0, 0,
    0,  0,      0,      0,      0,      0,      0,      0,  0,      0,  0, 0, 0, 0, 0, 0,
    0,  0,      0,      0,      0,      0,      0,      0,  0,      0,  0, 0, 0, 0, 0, 0,
    0,  512,    256,    128,    64,     32,     16,     8,  0,      0,  0, 0, 0, 0, 0, 0,
    0,  768,    384,    192,    96,     48,     24,     12, 64,     0,  0, 0, 0, 0, 0, 0,
    0,  1024,   512,    256,    128,    64,     32,     16, 0,      0,  0, 0, 0, 0, 0, 0,
    0,  1536,   768,    384,    192,    96,     48,     24, 128,    0,  0, 0, 0, 0, 0, 0,
    0,  2048,   1024,   512,    256,    128,    64,     32, 0,      0,  0, 0, 0, 0, 0, 0,
    0,  0,      0,      0,      0,      0,      0,      0,  0,      0,  0, 0, 0, 0, 0, 0,
    0,  0,      0,      0,      0,      0,      0,      0,  0,      0,  0, 0, 0, 0, 0, 0
};


void send_time_out(unsigned short clks)
{
    SCI_SNDCR = SCI_SNDCR_SND | (1344 * clks);  // assume CLK in 1 MHz
}

void disnable_send_time_out(void)
{
    SCI_SNDCR = 0;
}

unsigned char receive_data(unsigned char *buff, unsigned short len)
{
    unsigned char i;

    SCI_CR1 &= ~SCI_CR1_TRE;

    for(i = 0; i < len; i++)
    {
        while(!(SCI_SR & SCI_SR_RDRF));
        buff[i] = SCI_DR;
    }

    return len;
}

void send_byte(unsigned char x)
{
    SCI_CR1 |= SCI_CR1_TRE;
    while(!(SCI_SR & SCI_SR_TRDE));

    SCI_DR = x;

    while(!(SCI_SR & SCI_SR_TC));
    SCI_SR = SCI_SR_TC;

    SCI_CR1 &= ~SCI_CR1_TRE;
}

void send_data(unsigned char *buff, unsigned short len)
{
    unsigned char i;

    SCI_CR1 |= SCI_CR1_TRE;
    for(i = 0; i < len; i++)
    {
        while(!(SCI_SR & SCI_SR_TRDE));
        SCI_DR = buff[i];
    }

    while(!(SCI_SR & SCI_SR_TC));
    SCI_SR = SCI_SR_TC;

    SCI_CR1 &= ~SCI_CR1_TRE;
}
