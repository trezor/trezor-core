/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include STM32_HAL_H

#ifndef DISPLAY_ILI9341V
#define DISPLAY_ILI9341V 0
#endif

#ifndef DISPLAY_ST7789V
#define DISPLAY_ST7789V  1
#endif

// FSMC/FMC Bank 1 - NOR/PSRAM 1
#define DISPLAY_MEMORY_BASE  0x60000000
#define DISPLAY_MEMORY_PIN   16

#define CMD(X)          (*((__IO uint8_t *)((uint32_t)(DISPLAY_MEMORY_BASE))) = (X))
#define DATA(X)         (*((__IO uint8_t *)((uint32_t)(DISPLAY_MEMORY_BASE | (1 << DISPLAY_MEMORY_PIN)))) = (X))

#define DOUBLE_BUFFER 1

#if DOUBLE_BUFFER
__IO uint8_t *DBUF = (__IO uint8_t *)CCMDATARAM_BASE;

secbool DBUF_DIRTY = sectrue;

static struct {
    struct {
        uint16_t x, y;
    } start;
    struct {
        uint16_t x, y;
    } end;
    struct {
        uint16_t x, y;
    } pos;
} PIXELWINDOW;

static void PIXELDATA(uint16_t c)
{
    // convert from 16-bit depth to 8-bit depth
    // (RBB: 5-6-5 bits to 3-3-2 bits: rrrrrggg gggbbbbb -> rrrgggbb)
    if (PIXELWINDOW.pos.x <= PIXELWINDOW.end.x && PIXELWINDOW.pos.y <= PIXELWINDOW.end.y) {
        const int i = PIXELWINDOW.pos.x + PIXELWINDOW.pos.y * DISPLAY_RESX;
        if (i < DISPLAY_RESX * DISPLAY_RESY) {
            const uint8_t d = ((c & 0xE000) >> 8) | ((c & 0x700) >> 6) | ((c & 0x18) >> 3);
            DBUF[i] = d;
            DBUF_DIRTY = sectrue;
        }
    }
    PIXELWINDOW.pos.x++;
    if (PIXELWINDOW.pos.x > PIXELWINDOW.end.x) {
        PIXELWINDOW.pos.x = PIXELWINDOW.start.x;
        PIXELWINDOW.pos.y++;
    }
}
#else
#define PIXELDATA(X) DATA((X) >> 8); DATA((X) & 0xFF)
#endif

static void display_set_window(uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1);

void display_clear(void)
{
    const int saved_orientation = DISPLAY_ORIENTATION;
    display_orientation(0); // set MADCTL first so that we can set the window correctly next
    display_set_window(0, 0, MAX_DISPLAY_RESX - 1, MAX_DISPLAY_RESY - 1); // address the complete frame memory
    for (uint32_t i = 0; i < MAX_DISPLAY_RESX * MAX_DISPLAY_RESY; i++) {
        DATA(0x00); DATA(0x00);  // 2 bytes per pixel because we're using RGB 5-6-5 format
    }
    display_set_window(0, 0, DISPLAY_RESX - 1, DISPLAY_RESY - 1); // go back to restricted window
    display_orientation(saved_orientation); // if valid, go back to the saved orientation
#if DOUBLE_BUFFER
    for (int i = 0; i < DISPLAY_RESX * DISPLAY_RESY; i++) {
        PIXELDATA(0x0000);
    }
#endif
}

static void __attribute__((unused)) display_sleep(void)
{
#if DISPLAY_ILI9341V || DISPLAY_ST7789V
    CMD(0x28); // DISPOFF: Display Off
    CMD(0x10); // SLPIN: Sleep in
    HAL_Delay(5); // need to wait 5 milliseconds after "sleep in" before sending any new commands
#endif
}

static void display_unsleep(void)
{
#if DISPLAY_ILI9341V || DISPLAY_ST7789V
    CMD(0x11); // SLPOUT: Sleep Out
    HAL_Delay(5); // need to wait 5 milliseconds after "sleep out" before sending any new commands
    CMD(0x29); // DISPON: Display On
#endif
}

static struct {
    uint16_t x, y;
} BUFFER_OFFSET;

static void display_set_window(uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1)
{
    x0 += BUFFER_OFFSET.x; x1 += BUFFER_OFFSET.x;
    y0 += BUFFER_OFFSET.y; y1 += BUFFER_OFFSET.y;

#if DOUBLE_BUFFER
    PIXELWINDOW.start.x = x0; PIXELWINDOW.start.y = y0;
    PIXELWINDOW.end.x = x1; PIXELWINDOW.end.y = y1;
    PIXELWINDOW.pos.x = x0; PIXELWINDOW.pos.y = y0;
#else

#if DISPLAY_ILI9341V || DISPLAY_ST7789V
    CMD(0x2A); DATA(x0 >> 8); DATA(x0 & 0xFF); DATA(x1 >> 8); DATA(x1 & 0xFF); // column addr set
    CMD(0x2B); DATA(y0 >> 8); DATA(y0 & 0xFF); DATA(y1 >> 8); DATA(y1 & 0xFF); // row addr set
    CMD(0x2C);
#endif

#endif
}

void display_set_orientation(int degrees)
{
#if DOUBLE_BUFFER

#else

#if DISPLAY_ILI9341V || DISPLAY_ST7789V
    #define MV  (1 << 5)
    #define MX  (1 << 6)
    #define MY  (1 << 7)
    // MADCTL: Memory Data Access Control
    // reference section 9.3 in the ILI9341 manual; 8.12 in the ST7789V manual
    BUFFER_OFFSET.x = 0;
    BUFFER_OFFSET.y = 0;
    uint8_t display_command_parameter = 0;
    switch (degrees) {
        case 0:
            display_command_parameter = 0;
            break;
        case 90:
            display_command_parameter = MV | MX;
            break;
        case 180:
            display_command_parameter = MX | MY;
            BUFFER_OFFSET.y = MAX_DISPLAY_RESY - DISPLAY_RESY;
            break;
        case 270:
            display_command_parameter = MV | MY;
            BUFFER_OFFSET.x = MAX_DISPLAY_RESY - DISPLAY_RESX;
            break;
    }
    CMD(0x36); DATA(display_command_parameter);
    display_set_window(0, 0, DISPLAY_RESX - 1, DISPLAY_RESY - 1); // reset the column and page extents
#endif

#endif
}

#define LED_PWM_TIM_PERIOD (10000)

void display_set_backlight(int val)
{
    TIM1->CCR1 = LED_PWM_TIM_PERIOD * val / 255;
}

void display_hardware_reset(void)
{
    HAL_GPIO_WritePin(GPIOC, GPIO_PIN_14, GPIO_PIN_RESET); // LCD_RST/PC14
    // wait 10 milliseconds. only needs to be low for 10 microseconds.
    // my dev display module ties display reset and touch panel reset together.
    // keeping this low for max(display_reset_time, ctpm_reset_time) aids development and does not hurt.
    HAL_Delay(10);
    HAL_GPIO_WritePin(GPIOC, GPIO_PIN_14, GPIO_PIN_SET); // LCD_RST/PC14
    HAL_Delay(120); // max wait time for hardware reset is 120 milliseconds (experienced display flakiness using only 5ms wait before sending commands)
}

void display_init(void)
{
    // init peripherials
    __HAL_RCC_GPIOE_CLK_ENABLE();
    __HAL_RCC_TIM1_CLK_ENABLE();
    __HAL_RCC_FMC_CLK_ENABLE();

    GPIO_InitTypeDef GPIO_InitStructure;

    // LCD_PWM/PA7 (backlight control)
    GPIO_InitStructure.Mode      = GPIO_MODE_AF_PP;
    GPIO_InitStructure.Pull      = GPIO_NOPULL;
    GPIO_InitStructure.Speed     = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStructure.Alternate = GPIO_AF1_TIM1;
    GPIO_InitStructure.Pin       = GPIO_PIN_7;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStructure);

    // enable PWM timer
    TIM_HandleTypeDef TIM1_Handle;
    TIM1_Handle.Instance = TIM1;
    TIM1_Handle.Init.Period = LED_PWM_TIM_PERIOD - 1;
    // TIM1/APB2 source frequency equals to SystemCoreClock in our configuration, we want 1 MHz
    TIM1_Handle.Init.Prescaler = SystemCoreClock / 1000000 - 1;
    TIM1_Handle.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;
    TIM1_Handle.Init.CounterMode = TIM_COUNTERMODE_UP;
    TIM1_Handle.Init.RepetitionCounter = 0;
    HAL_TIM_PWM_Init(&TIM1_Handle);

    TIM_OC_InitTypeDef TIM_OC_InitStructure;
    TIM_OC_InitStructure.Pulse = 0;
    TIM_OC_InitStructure.OCMode = TIM_OCMODE_PWM2;
    TIM_OC_InitStructure.OCPolarity = TIM_OCPOLARITY_HIGH;
    TIM_OC_InitStructure.OCFastMode = TIM_OCFAST_DISABLE;
    TIM_OC_InitStructure.OCNPolarity = TIM_OCNPOLARITY_HIGH;
    TIM_OC_InitStructure.OCIdleState = TIM_OCIDLESTATE_SET;
    TIM_OC_InitStructure.OCNIdleState = TIM_OCNIDLESTATE_SET;
    HAL_TIM_PWM_ConfigChannel(&TIM1_Handle, &TIM_OC_InitStructure, TIM_CHANNEL_1);

    display_backlight(0);

    HAL_TIM_PWM_Start(&TIM1_Handle, TIM_CHANNEL_1);
    HAL_TIMEx_PWMN_Start(&TIM1_Handle, TIM_CHANNEL_1);

    // LCD_RST/PC14
    GPIO_InitStructure.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStructure.Pull = GPIO_NOPULL;
    GPIO_InitStructure.Speed = GPIO_SPEED_FREQ_LOW;
    GPIO_InitStructure.Alternate = 0;
    GPIO_InitStructure.Pin = GPIO_PIN_14;
    HAL_GPIO_WritePin(GPIOC, GPIO_PIN_14, GPIO_PIN_RESET); // default to keeping display in reset
    HAL_GPIO_Init(GPIOC, &GPIO_InitStructure);

    // LCD_FMARK/PD12 (tearing effect)
    GPIO_InitStructure.Mode = GPIO_MODE_INPUT;
    GPIO_InitStructure.Pull = GPIO_NOPULL;
    GPIO_InitStructure.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStructure.Alternate = 0;
    GPIO_InitStructure.Pin = GPIO_PIN_12;
    HAL_GPIO_Init(GPIOD, &GPIO_InitStructure);

    GPIO_InitStructure.Mode      = GPIO_MODE_AF_PP;
    GPIO_InitStructure.Pull      = GPIO_NOPULL;
    GPIO_InitStructure.Speed     = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStructure.Alternate = GPIO_AF12_FMC;
    //                             LCD_CS/PD7   LCD_RS/PD11   LCD_RD/PD4   LCD_WR/PD5
    GPIO_InitStructure.Pin       = GPIO_PIN_7 | GPIO_PIN_11 | GPIO_PIN_4 | GPIO_PIN_5;
    HAL_GPIO_Init(GPIOD, &GPIO_InitStructure);
    //                             LCD_D0/PD14   LCD_D1/PD15   LCD_D2/PD0   LCD_D3/PD1
    GPIO_InitStructure.Pin       = GPIO_PIN_14 | GPIO_PIN_15 | GPIO_PIN_0 | GPIO_PIN_1;
    HAL_GPIO_Init(GPIOD, &GPIO_InitStructure);
    //                             LCD_D4/PE7   LCD_D5/PE8   LCD_D6/PE9   LCD_D7/PE10
    GPIO_InitStructure.Pin       = GPIO_PIN_7 | GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10;
    HAL_GPIO_Init(GPIOE, &GPIO_InitStructure);

    // Reference UM1725 "Description of STM32F4 HAL and LL drivers", section 64.2.1 "How to use this driver"
    SRAM_HandleTypeDef external_display_data_sram;
    external_display_data_sram.Instance = FMC_NORSRAM_DEVICE;
    external_display_data_sram.Init.NSBank = FMC_NORSRAM_BANK1;
    external_display_data_sram.Init.DataAddressMux = FMC_DATA_ADDRESS_MUX_DISABLE;
    external_display_data_sram.Init.MemoryType = FMC_MEMORY_TYPE_SRAM;
    external_display_data_sram.Init.MemoryDataWidth = FMC_NORSRAM_MEM_BUS_WIDTH_8;
    external_display_data_sram.Init.BurstAccessMode = FMC_BURST_ACCESS_MODE_DISABLE;
    external_display_data_sram.Init.WaitSignalPolarity = FMC_WAIT_SIGNAL_POLARITY_LOW;
    external_display_data_sram.Init.WrapMode = FMC_WRAP_MODE_DISABLE;
    external_display_data_sram.Init.WaitSignalActive = FMC_WAIT_TIMING_BEFORE_WS;
    external_display_data_sram.Init.WriteOperation = FMC_WRITE_OPERATION_ENABLE;
    external_display_data_sram.Init.WaitSignal = FMC_WAIT_SIGNAL_DISABLE;
    external_display_data_sram.Init.ExtendedMode = FMC_EXTENDED_MODE_DISABLE;
    external_display_data_sram.Init.AsynchronousWait = FMC_ASYNCHRONOUS_WAIT_DISABLE;
    external_display_data_sram.Init.WriteBurst = FMC_WRITE_BURST_DISABLE;
    external_display_data_sram.Init.ContinuousClock = FMC_CONTINUOUS_CLOCK_SYNC_ONLY;
    external_display_data_sram.Init.PageSize = FMC_PAGE_SIZE_NONE;

    // reference RM0090 section 37.5 Table 259, 37.5.4, Mode 1 SRAM, and 37.5.6
    FMC_NORSRAM_TimingTypeDef normal_mode_timing;
    normal_mode_timing.AddressSetupTime = 4;
    normal_mode_timing.AddressHoldTime = 1;
    normal_mode_timing.DataSetupTime = 4;
    normal_mode_timing.BusTurnAroundDuration = 0;
    normal_mode_timing.CLKDivision = 2;
    normal_mode_timing.DataLatency = 2;
    normal_mode_timing.AccessMode = FMC_ACCESS_MODE_A;

    HAL_SRAM_Init(&external_display_data_sram, &normal_mode_timing, NULL);

    display_hardware_reset();
#if DISPLAY_ILI9341V
    // most recent manual: https://www.newhavendisplay.com/app_notes/ILI9341.pdf
    CMD(0x35); DATA(0x00); // TEON: Tearing Effect Line On; V-blanking only
    CMD(0x3A); DATA(0x55); // COLMOD: Interface Pixel format; 65K color: 16-bit/pixel (RGB 5-6-5 bits input)
    CMD(0xB6); DATA(0x0A); DATA(0xC2); DATA(0x27); DATA(0x00); // Display Function Control: gate scan direction 319 -> 0
    CMD(0xF6); DATA(0x09); DATA(0x30); DATA(0x00); // Interface Control: XOR BGR as ST7789V does
    // the above config is the most important and definitely necessary
    CMD(0xCF); DATA(0x00); DATA(0xC1); DATA(0x30);
    CMD(0xED); DATA(0x64); DATA(0x03); DATA(0x12); DATA(0x81);
    CMD(0xE8); DATA(0x85); DATA(0x10); DATA(0x7A);
    CMD(0xF7); DATA(0x20);
    CMD(0xEA); DATA(0x00); DATA(0x00);
    CMD(0xC0); DATA(0x23);                          // power control   VRH[5:0]
    CMD(0xC1); DATA(0x12);                          // power control   SAP[2:0] BT[3:0]
    CMD(0xC5); DATA(0x60); DATA(0x44);              // vcm control 1
    CMD(0xC7); DATA(0x8A);                          // vcm control 2
    CMD(0xB1); DATA(0x00); DATA(0x18);              // framerate
    CMD(0xF2); DATA(0x00);                          // 3 gamma func disable
    // gamma curve 1
    CMD(0xE0); DATA(0x0F); DATA(0x2F); DATA(0x2C); DATA(0x0B); DATA(0x0F); DATA(0x09); DATA(0x56); DATA(0xD9); DATA(0x4A); DATA(0x0B); DATA(0x14); DATA(0x05); DATA(0x0C); DATA(0x06); DATA(0x00);
    // gamma curve 2
    CMD(0xE1); DATA(0x00); DATA(0x10); DATA(0x13); DATA(0x04); DATA(0x10); DATA(0x06); DATA(0x25); DATA(0x26); DATA(0x3B); DATA(0x04); DATA(0x0B); DATA(0x0A); DATA(0x33); DATA(0x39); DATA(0x0F);
#endif
#if DISPLAY_ST7789V
    CMD(0x35); DATA(0x00); // TEON: Tearing Effect Line On; V-blanking only
    CMD(0x3A); DATA(0x55); // COLMOD: Interface Pixel format; 65K color: 16-bit/pixel (RGB 5-6-5 bits input)
    CMD(0xDF); DATA(0x5A); DATA(0x69); DATA(0x02); DATA(0x01); // CMD2EN: Commands in command table 2 can be executed when EXTC level is Low
    CMD(0xC0); DATA(0x20); // LCMCTRL: LCM Control: XOR RGB setting
    CMD(0xE4); DATA(0x1D); DATA(0x0A); DATA(0x11); // GATECTRL: Gate Control; NL = 240 gate lines, first scan line is gate 80.; gate scan direction 319 -> 0
    // the above config is the most important and definitely necessary
    CMD(0xD0); DATA(0xA4); DATA(0xA1);              // PWCTRL1: Power Control 1
    // gamma curve 1
    // CMD(0xE0); DATA(0x70); DATA(0x2C); DATA(0x2E); DATA(0x15); DATA(0x10); DATA(0x09); DATA(0x48); DATA(0x33); DATA(0x53); DATA(0x0B); DATA(0x19); DATA(0x18); DATA(0x20); DATA(0x25);
    // gamma curve 2
    // CMD(0xE1); DATA(0x70); DATA(0x2C); DATA(0x2E); DATA(0x15); DATA(0x10); DATA(0x09); DATA(0x48); DATA(0x33); DATA(0x53); DATA(0x0B); DATA(0x19); DATA(0x18); DATA(0x20); DATA(0x25);
#endif
    display_clear();
    display_unsleep();
}

void display_refresh(void)
{
    // synchronize with the panel synchronization signal in order to avoid visual tearing effects
    while (GPIO_PIN_RESET == HAL_GPIO_ReadPin(GPIOD, GPIO_PIN_12)) { }
    while (GPIO_PIN_SET == HAL_GPIO_ReadPin(GPIOD, GPIO_PIN_12)) { }

#if DOUBLE_BUFFER

    // don't draw if not dirty
    if (sectrue != DBUF_DIRTY) return;

    // frame limiter = don't redraw frame if older one is younger than 16 ms = 60 fps
    static uint32_t t0 = 0;
    uint32_t t1 = HAL_GetTick();
    if (t1 < t0 + 16) {
        t0 = t1;
        return;
    } else {
        t0 = t1;
    }

    static const uint16_t rgb332to565lut[256] =  {
        0x0000, 0x000a, 0x0015, 0x001f, 0x0120, 0x012a, 0x0135, 0x013f,
        0x0240, 0x024a, 0x0255, 0x025f, 0x0360, 0x036a, 0x0375, 0x037f,
        0x0480, 0x048a, 0x0495, 0x049f, 0x05a0, 0x05aa, 0x05b5, 0x05bf,
        0x06c0, 0x06ca, 0x06d5, 0x06df, 0x07e0, 0x07ea, 0x07f5, 0x07ff,
        0x2000, 0x200a, 0x2015, 0x201f, 0x2120, 0x212a, 0x2135, 0x213f,
        0x2240, 0x224a, 0x2255, 0x225f, 0x2360, 0x236a, 0x2375, 0x237f,
        0x2480, 0x248a, 0x2495, 0x249f, 0x25a0, 0x25aa, 0x25b5, 0x25bf,
        0x26c0, 0x26ca, 0x26d5, 0x26df, 0x27e0, 0x27ea, 0x27f5, 0x27ff,
        0x4800, 0x480a, 0x4815, 0x481f, 0x4920, 0x492a, 0x4935, 0x493f,
        0x4a40, 0x4a4a, 0x4a55, 0x4a5f, 0x4b60, 0x4b6a, 0x4b75, 0x4b7f,
        0x4c80, 0x4c8a, 0x4c95, 0x4c9f, 0x4da0, 0x4daa, 0x4db5, 0x4dbf,
        0x4ec0, 0x4eca, 0x4ed5, 0x4edf, 0x4fe0, 0x4fea, 0x4ff5, 0x4fff,
        0x6800, 0x680a, 0x6815, 0x681f, 0x6920, 0x692a, 0x6935, 0x693f,
        0x6a40, 0x6a4a, 0x6a55, 0x6a5f, 0x6b60, 0x6b6a, 0x6b75, 0x6b7f,
        0x6c80, 0x6c8a, 0x6c95, 0x6c9f, 0x6da0, 0x6daa, 0x6db5, 0x6dbf,
        0x6ec0, 0x6eca, 0x6ed5, 0x6edf, 0x6fe0, 0x6fea, 0x6ff5, 0x6fff,
        0x9000, 0x900a, 0x9015, 0x901f, 0x9120, 0x912a, 0x9135, 0x913f,
        0x9240, 0x924a, 0x9255, 0x925f, 0x9360, 0x936a, 0x9375, 0x937f,
        0x9480, 0x948a, 0x9495, 0x949f, 0x95a0, 0x95aa, 0x95b5, 0x95bf,
        0x96c0, 0x96ca, 0x96d5, 0x96df, 0x97e0, 0x97ea, 0x97f5, 0x97ff,
        0xb000, 0xb00a, 0xb015, 0xb01f, 0xb120, 0xb12a, 0xb135, 0xb13f,
        0xb240, 0xb24a, 0xb255, 0xb25f, 0xb360, 0xb36a, 0xb375, 0xb37f,
        0xb480, 0xb48a, 0xb495, 0xb49f, 0xb5a0, 0xb5aa, 0xb5b5, 0xb5bf,
        0xb6c0, 0xb6ca, 0xb6d5, 0xb6df, 0xb7e0, 0xb7ea, 0xb7f5, 0xb7ff,
        0xd800, 0xd80a, 0xd815, 0xd81f, 0xd920, 0xd92a, 0xd935, 0xd93f,
        0xda40, 0xda4a, 0xda55, 0xda5f, 0xdb60, 0xdb6a, 0xdb75, 0xdb7f,
        0xdc80, 0xdc8a, 0xdc95, 0xdc9f, 0xdda0, 0xddaa, 0xddb5, 0xddbf,
        0xdec0, 0xdeca, 0xded5, 0xdedf, 0xdfe0, 0xdfea, 0xdff5, 0xdfff,
        0xf800, 0xf80a, 0xf815, 0xf81f, 0xf920, 0xf92a, 0xf935, 0xf93f,
        0xfa40, 0xfa4a, 0xfa55, 0xfa5f, 0xfb60, 0xfb6a, 0xfb75, 0xfb7f,
        0xfc80, 0xfc8a, 0xfc95, 0xfc9f, 0xfda0, 0xfdaa, 0xfdb5, 0xfdbf,
        0xfec0, 0xfeca, 0xfed5, 0xfedf, 0xffe0, 0xffea, 0xfff5, 0xffff,
    };
    // set full window
    const uint16_t x0 = 0, y0 = 0, x1 = DISPLAY_RESX - 1, y1 = DISPLAY_RESY - 1;
    CMD(0x2A); DATA(x0 >> 8); DATA(x0 & 0xFF); DATA(x1 >> 8); DATA(x1 & 0xFF); // column addr set
    CMD(0x2B); DATA(y0 >> 8); DATA(y0 & 0xFF); DATA(y1 >> 8); DATA(y1 & 0xFF); // row addr set
    CMD(0x2C);

    // flush double buffer according to orientation
    // also convert from 8-bit depth to 16-bit depth
    // (RBB: 3-3-2 bits to 5-6-5 bits: rrrgggbb -> rrrrrggg gggbbbbb)
    switch (DISPLAY_ORIENTATION) {
        case 0:
            for (int i = 0; i < DISPLAY_RESX * DISPLAY_RESY; i++) {
                const uint16_t d = rgb332to565lut[DBUF[i]];
                DATA(d >> 8); DATA(d & 0xFF);
            }
            break;
        case 90:
            for (int j = 0; j < DISPLAY_RESY; j++) {
                for (int i = 0; i < DISPLAY_RESX; i++) {
                    const int o = (DISPLAY_RESX - 1 - i) * DISPLAY_RESY + j;
                    const uint16_t d = rgb332to565lut[DBUF[o]];
                    DATA(d >> 8); DATA(d & 0xFF);
                }
            }
            break;
        case 180:
            for (int i = 0; i < DISPLAY_RESX * DISPLAY_RESY; i++) {
                const int o = DISPLAY_RESX * DISPLAY_RESY - 1 - i;
                const uint16_t d = rgb332to565lut[DBUF[o]];
                DATA(d >> 8); DATA(d & 0xFF);
            }
            break;
        case 270:
            for (int j = 0; j < DISPLAY_RESY; j++) {
                for (int i = 0; i < DISPLAY_RESX; i++) {
                    const int o = i * DISPLAY_RESY + (DISPLAY_RESY - 1 - j);
                    const uint16_t d = rgb332to565lut[DBUF[o]];
                    DATA(d >> 8); DATA(d & 0xFF);
                }
            }
            break;
    }

    DBUF_DIRTY = secfalse;
#endif
}

void display_save(const char *prefix)
{
}
