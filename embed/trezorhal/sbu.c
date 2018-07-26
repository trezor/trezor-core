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

#include "common.h"
#include "sbu.h"

static UART_HandleTypeDef uart_handle;

static inline void sbu_default_pin_state(void) {
    // SBU1/PA2 SBU2/PA3
    HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, GPIO_PIN_RESET);
    HAL_GPIO_WritePin(GPIOA, GPIO_PIN_3, GPIO_PIN_RESET);

    // set above pins to OUTPUT / NOPULL
    GPIO_InitTypeDef GPIO_InitStructure;

    GPIO_InitStructure.Pin = GPIO_PIN_2 | GPIO_PIN_3;
    GPIO_InitStructure.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStructure.Pull = GPIO_NOPULL;
    GPIO_InitStructure.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStructure);
}

static inline void sbu_active_pin_state(void) {
    // set above pins to OUTPUT / NOPULL
    GPIO_InitTypeDef GPIO_InitStructure;

    GPIO_InitStructure.Pin = GPIO_PIN_2;
    GPIO_InitStructure.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStructure.Pull = GPIO_NOPULL;
    GPIO_InitStructure.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStructure.Alternate = GPIO_AF7_USART2;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStructure);

    GPIO_InitStructure.Pin = GPIO_PIN_3;
    GPIO_InitStructure.Mode = GPIO_MODE_AF_OD;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStructure);
}

void sbu_init(void) {
    sbu_default_pin_state();
}

void HAL_UART_MspInit(UART_HandleTypeDef *huart) {
    // enable USART clock
    __HAL_RCC_USART2_CLK_ENABLE();
    // GPIO have already been initialised by sbu_init
}

void HAL_UART_MspDeInit(UART_HandleTypeDef *huart) {
    __HAL_RCC_USART2_CLK_DISABLE();
}

void sbu_uart_on(void) {
    if (uart_handle.Instance) {
        return;
    }

    // turn on USART
    sbu_active_pin_state();
    HAL_Delay(10);

    uart_handle.Instance = USART2;
    uart_handle.Init.BaudRate = 115200;
    uart_handle.Init.WordLength = UART_WORDLENGTH_8B;
    uart_handle.Init.StopBits = UART_STOPBITS_1;
    uart_handle.Init.Parity = UART_PARITY_NONE;
    uart_handle.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    uart_handle.Init.Mode = UART_MODE_TX_RX;

    if (HAL_OK != HAL_UART_Init(&uart_handle)) {
        ensure(secfalse, NULL);
        return;
    }

    HAL_Delay(10);
}

void sbu_uart_off(void) {
    if (uart_handle.Instance) {
        HAL_UART_DeInit(&uart_handle);
        uart_handle.Instance = NULL;
    }
    // turn off UART
    HAL_Delay(10);
    sbu_default_pin_state();
    HAL_Delay(10);
}

int sbu_read(uint8_t *data, uint16_t len) {
    int res = HAL_UART_Receive(&uart_handle, data, len, 10000);
    ensure(sectrue * ((HAL_OK == res) || (HAL_TIMEOUT == res)), NULL);
    if (HAL_OK == res) {
        return len;
    } else {
        return -1;
    }
}

void sbu_write(const uint8_t *data, uint16_t len) {
    ensure(sectrue * (HAL_OK == HAL_UART_Transmit(&uart_handle, (uint8_t *)data, len, 10000)), NULL);
}

void sbu_set_pins(secbool sbu1, secbool sbu2) {
    HAL_GPIO_WritePin(GPIOA, GPIO_PIN_2, sbu1 == sectrue ? GPIO_PIN_SET : GPIO_PIN_RESET);
    HAL_GPIO_WritePin(GPIOA, GPIO_PIN_3, sbu2 == sectrue ? GPIO_PIN_SET : GPIO_PIN_RESET);
}
