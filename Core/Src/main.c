/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2025 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <string.h>
#include <stdio.h>
#include "cmox_crypto.h"
#include "cachel1_armv7.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define PUTCHAR_PROTOTYPE 			int __io_putchar(int ch)
#define UART_PORT_HANDLE_DEBUG		huart2	// Port handle where debug msgs are shown.
#define CRYPTOLIB_TEST_BUF_SIZE		100	// Bytes.
#define CRYPTOLIB_TEST_KEY_SIZE		16	// Bytes.
#define CRYPTOLIB_TEST_BLOCK_SIZE 	16	// Bytes.
#define CRYPTOLIB_TEST_HMAC_ALGO    CMOX_HMAC_SHA256_ALGO
#define CRYPTOLIB_TEST_HMAC_SIZE	4	// Minimum size recommended by NIST SP 800-107
#define CRYPTOLIB_TEST_ERROR		0
#define CRYPTOLIB_TEST_SUCCESS		1
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
CRC_HandleTypeDef hcrc;
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
uint8_t is_data_to_enc = 0; // Flag to start the encryption of data from tx_buf. 
uint8_t is_data_to_dec = 0; // Flag to start the decryption of data from rx_buf_enc.

// For AES:
const uint8_t aes_key[CRYPTOLIB_TEST_KEY_SIZE] =
{
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
const uint8_t aes_iv[CRYPTOLIB_TEST_BLOCK_SIZE] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// For HMAC:
const uint8_t hmac_key[CRYPTOLIB_TEST_KEY_SIZE] = // Minimal size of 16 bytes for SHA-256.
{
	0xcf, 0xd4, 0xa4, 0x49, 0x10, 0xc9, 0xe5, 0x67, 0x50, 0x7a, 0xbb, 0x6c, 0xed, 0xe4, 0xfe, 0x60
};

// Buffers without encryption.
uint8_t tx_buf[CRYPTOLIB_TEST_BUF_SIZE] = {0};
uint8_t rx_buf[CRYPTOLIB_TEST_BUF_SIZE] = {0};

// Should I only encrypt the used portion of the buffer? In that case I would have
// to create a byte with a size only know at runtime.
uint8_t tx_buf_enc[CRYPTOLIB_TEST_BUF_SIZE] = {0};
uint8_t rx_buf_enc[CRYPTOLIB_TEST_BUF_SIZE] = {0};

// For HMAC.
uint8_t hmac_tag[CRYPTOLIB_TEST_HMAC_SIZE] = {0}; // I assume the tag will be truncated by the lib to only use their 4 MSB.

size_t tx_buf_size = 0;     // N° of bytes in tx_buf containing the msg to send.
size_t tx_buf_enc_size = 0; // N° of bytes in tx_buf containing the encrypted msg to send.
size_t rx_buf_enc_size = 0; // N° of bytes in rx_buf_enc containing the received msg to decrypt.
size_t rx_buf_size = 0;     // N° of bytes in rx_buf containing the decrypted msg.
size_t hmac_tag_size = 0;   // Size in bytes of the generated tag.
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_CRC_Init(void);
/* USER CODE BEGIN PFP */
static void CPU_CACHE_Enable(void);
uint8_t EncryptData(void);
uint8_t DecryptData(void);
void TestEncDec(void);
void TestHmac(void);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
  /* USER CODE BEGIN 1 */

	/* Enable the CPU Cache */
	CPU_CACHE_Enable();
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();
  MX_CRC_Init();
  /* USER CODE BEGIN 2 */
	printf("UART initialized.\n");
	printf("CRC initialized.\n");

	cmox_init_arg_t init_target = {CMOX_INIT_TARGET_F4, NULL};

	/* Initialize cryptographic library */
	if (cmox_initialize(&init_target) != CMOX_INIT_SUCCESS)
	{
		Error_Handler();
	}
	printf("CMOX initialized.\n");

	// TestEncDec();
	TestHmac();
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
	if (is_data_to_enc) {
		if (EncryptData() == CRYPTOLIB_TEST_ERROR) {
			Error_Handler();
		}
		// TODO: Calculate and append MAC after encryption.
		is_data_to_enc = 0;
	}

	if (is_data_to_dec) {
		// TODO: Verify MAC before decryption.
		if (DecryptData() == CRYPTOLIB_TEST_ERROR) {
			Error_Handler();
		}
		is_data_to_dec = 0;
	}
	/* USER CODE END WHILE */

	/* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE2);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 16;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV4;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
	Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
							  |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
	Error_Handler();
  }
}

/**
  * @brief CRC Initialization Function
  * @param None
  * @retval None
  */
static void MX_CRC_Init(void)
{

  /* USER CODE BEGIN CRC_Init 0 */

  /* USER CODE END CRC_Init 0 */

  /* USER CODE BEGIN CRC_Init 1 */

  /* USER CODE END CRC_Init 1 */
  hcrc.Instance = CRC;
  if (HAL_CRC_Init(&hcrc) != HAL_OK)
  {
	Error_Handler();
  }
  /* USER CODE BEGIN CRC_Init 2 */

  /* USER CODE END CRC_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
	Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : B1_Pin */
  GPIO_InitStruct.Pin = B1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : LD2_Pin */
  GPIO_InitStruct.Pin = LD2_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(LD2_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
/**
  * @brief  CPU L1-Cache enable.
  * @param  None
  * @retval None
  */
static void CPU_CACHE_Enable(void)
{
  /* Enable I-Cache */
  SCB_EnableICache(); // warning: implicit declaration

  /* Enable D-Cache */
  SCB_EnableDCache(); // warning: implicit declaration
}

/**
 * @brief Encrypts the first tx_buf_size bytes saved in tx_buf using the AES-CBC protocol with the key
 * stored in aes_key and the initialization vector stored in aes_iv.
 * The encrypted tx_buf_enc_size bytes are saved in tx_buf_enc.
 * 
 * @retval uint8_t CRYPTOLIB_TEST_ERROR on error, CRYPTOLIB_TEST_SUCCESS on success.
 */
uint8_t EncryptData()
{
	cmox_cipher_retval_t retval;
	retval = cmox_cipher_encrypt(CMOX_AESFAST_CBC_ENC_ALGO,  	/* Use AES CBC algorithm */
								tx_buf, tx_buf_size,      		/* Plaintext to encrypt */
								aes_key, sizeof(aes_key),    	/* AES key to use */
								aes_iv, sizeof(aes_iv),      	/* Initialization vector */
								tx_buf_enc, &tx_buf_enc_size); 	/* Data buffer to receive generated ciphertext */
	
	// TODO: Clear buffers after use.

	/* Verify API returned value */
	if (retval != CMOX_CIPHER_SUCCESS) {
		return CRYPTOLIB_TEST_ERROR;
	}

	/* Verify generated data size is the expected one */
	if (tx_buf_enc_size != tx_buf_size) {
		return CRYPTOLIB_TEST_ERROR;
	}

	return CRYPTOLIB_TEST_SUCCESS;
}

/**
 * @brief Decrypts the first rx_buf_enc_size bytes saved in rx_buf_enc using the AES-CBC protocol with the key
 * stored in aes_key and the initialization vector stored in aes_iv.
 * 
 * @return uint8_t 
 */
uint8_t DecryptData(void)
{
	cmox_cipher_retval_t retval;
	retval = cmox_cipher_decrypt(CMOX_AES_CBC_DEC_ALGO,			/* Use AES CBC algorithm */
								rx_buf_enc, rx_buf_enc_size,    /* Ciphertext to decrypt */
								aes_key, sizeof(aes_key),       /* AES key to use */
								aes_iv, sizeof(aes_iv),         /* Initialization vector */
								rx_buf, &rx_buf_size);   		/* Data buffer to receive generated plaintext */

	// TODO: Clear buffers after use.
	
	/* Verify API returned value */
	if (retval != CMOX_CIPHER_SUCCESS) {
		return CRYPTOLIB_TEST_ERROR;
	}

	/* Verify generated data size is the expected one */
	if (rx_buf_size != rx_buf_enc_size) {
		return CRYPTOLIB_TEST_ERROR;
	}

	return CRYPTOLIB_TEST_SUCCESS;
}

void TestEncDec(void) 
{
	// TEST: Try to encrypt data that is not a multiple of the AES block size (16 bytes).
	printf("Encryption/decryption test start:\n");
	
	cmox_cipher_retval_t retval;

	// Clear buffers.
	memset(tx_buf, 0, CRYPTOLIB_TEST_BUF_SIZE);
	memset(tx_buf_enc, 0, CRYPTOLIB_TEST_BUF_SIZE);
	memset(rx_buf_enc, 0, CRYPTOLIB_TEST_BUF_SIZE);
	memset(rx_buf, 0, CRYPTOLIB_TEST_BUF_SIZE);

	tx_buf_size = 0;
	tx_buf_enc_size = 0;
	rx_buf_size = 0;
	rx_buf_enc_size = 0;

	uint8_t msg_to_enc[] = "C";
	memcpy(tx_buf, msg_to_enc, sizeof(msg_to_enc));

	printf("msg_to_enc: ");
	printf(msg_to_enc);
	printf("\n");

	printf("tx_buf: ");
	printf(tx_buf);
	printf("\n");

	tx_buf_size = sizeof(msg_to_enc);
	printf("tx_buf_size: ");
	printf("%d", tx_buf_size);
	printf("\n");

	printf("Encrypting tx_buf...\n");

	retval = cmox_cipher_encrypt(CMOX_AESFAST_CBC_ENC_ALGO,  	/* Use AES CBC algorithm */
								tx_buf, tx_buf_size,      		/* Plaintext to encrypt */
								aes_key, sizeof(aes_key),    	/* AES key to use */
								aes_iv, sizeof(aes_iv),      	/* Initialization vector */
								tx_buf_enc, &tx_buf_enc_size); 	/* Data buffer to receive generated ciphertext */

	/* Verify API returned value */
	if (retval != CMOX_CIPHER_SUCCESS) {
		printf("Error: Encryption failed.\n");
	}

	/* Verify generated data size is the expected one */
	if (tx_buf_enc_size != tx_buf_size) {
		printf("Error: Incorrect size of encrypted data.\n");
	}

	printf("tx_buf_enc: ");
	printf(tx_buf_enc);
	printf("\n");

	printf("tx_buf_enc_size: ");
	printf("%d", tx_buf_enc_size);
	printf("\n");

	memcpy(rx_buf_enc, tx_buf_enc, tx_buf_enc_size);
	rx_buf_enc_size = tx_buf_enc_size;

	printf("rx_buf_enc: ");
	printf(rx_buf_enc);
	printf("\n");

	printf("rx_buf_enc_size: ");
	printf("%d", rx_buf_enc_size);
	printf("\n");	

	printf("Decrypting rx_buf_enc...\n");

	retval = cmox_cipher_decrypt(CMOX_AES_CBC_DEC_ALGO,		/* Use AES CBC algorithm */
							rx_buf_enc, rx_buf_enc_size,    /* Ciphertext to decrypt */
							aes_key, sizeof(aes_key),       /* AES key to use */
							aes_iv, sizeof(aes_iv),         /* Initialization vector */
							rx_buf, &rx_buf_size);   		/* Data buffer to receive generated plaintext */
	
	/* Verify API returned value */
	if (retval != CMOX_CIPHER_SUCCESS) {
		printf("Error: Decryption failed.\n");
	}

	/* Verify generated data size is the expected one */
	if (rx_buf_size != rx_buf_enc_size) {
		printf("Error: Incorrect size of decrypted data.\n");
	}

	printf("rx_buf: ");
	printf(rx_buf);
	printf("\n");

	printf("rx_buf_size: ");
	printf("%d", rx_buf_size);
	printf("\n");

	if (strcmp(rx_buf, tx_buf) == 0) {
		printf("Encryption/decryption test successful.\n");
	} else {
		printf("Encryption/decryption test failed.\n");
	}

	printf("Test completed.\n");
}

void TestHmac(void)
{
	printf("HMAC authentication verification test start:\n");
	
	cmox_mac_retval_t retval;

	// Clear buffers.
	memset(tx_buf, 0, CRYPTOLIB_TEST_BUF_SIZE);
	memset(tx_buf_enc, 0, CRYPTOLIB_TEST_BUF_SIZE);
	memset(rx_buf_enc, 0, CRYPTOLIB_TEST_BUF_SIZE);
	memset(rx_buf, 0, CRYPTOLIB_TEST_BUF_SIZE);

	tx_buf_size = 0;
	tx_buf_enc_size = 0;
	rx_buf_size = 0;
	rx_buf_enc_size = 0;

	uint8_t msg_to_hmac[] = "";
	memcpy(tx_buf, msg_to_hmac, sizeof(msg_to_hmac));

	printf("msg_to_hmac: ");
	printf(msg_to_hmac);
	printf("\n");

	printf("tx_buf: ");
	printf(tx_buf);
	printf("\n");

	tx_buf_size = sizeof(msg_to_hmac);
	printf("tx_buf_size: ");
	printf("%d", tx_buf_size);
	printf("\n");

	printf("Generating tag for tx_buf...\n");

	retval = cmox_mac_compute(CRYPTOLIB_TEST_HMAC_ALGO, /* Use HMAC SHA256 algorithm */
							tx_buf, tx_buf_size,        /* Message to authenticate */
							hmac_key, sizeof(hmac_key), /* HMAC Key to use */
							NULL, 0,                    /* Custom data */
							hmac_tag,                   /* Data buffer to receive generated authnetication tag */
							sizeof(hmac_tag),    		/* Expected authentication tag size */
							&hmac_tag_size);            /* Generated tag size */

	/* Verify API returned value */
	if (retval != CMOX_MAC_SUCCESS) {
		printf("Error: Tag generation failed.\n");
	}

	/* Verify generated data size is the expected one */
	if (hmac_tag_size != sizeof(hmac_tag)) {
		printf("Error: Incorrect size of generated tag.\n");
	}

	printf("hmac_tag: ");
	for (int i = 0; i < hmac_tag_size; i++) {
		printf("%02X", hmac_tag[i]);
		printf(":%c", hmac_tag[i]);
		if (i < hmac_tag_size - 1) {
			printf(", ");
		}
	}
	printf("\n");

	printf("hmac_tag_size: ");
	printf("%d", hmac_tag_size);
	printf("\n");

	memcpy(tx_buf_enc, tx_buf, tx_buf_size);
	// Can't use strcat() as this will overwrite the last element of tx_buf_enc if this is '\0' (Null terminated string).
	memcpy(tx_buf_enc + tx_buf_size, hmac_tag, hmac_tag_size);
	tx_buf_enc_size = tx_buf_size + hmac_tag_size;

	memcpy(rx_buf_enc, tx_buf_enc, tx_buf_enc_size);
	rx_buf_enc_size = tx_buf_enc_size;

	printf("rx_buf_enc: ");
	printf(rx_buf_enc);
	printf("\n");

	printf("rx_buf_enc_size: ");
	printf("%d", rx_buf_enc_size);
	printf("\n");	

	uint8_t hmac_tag_extracted[sizeof(hmac_tag)] = {0};

	// WARN: In the receiver the msg structure must be known beforehand to be able to verify it.
	memcpy(hmac_tag_extracted, rx_buf_enc + tx_buf_size, hmac_tag_size);
	memset(rx_buf_enc + tx_buf_size, 0, hmac_tag_size);
	rx_buf_enc_size -= hmac_tag_size;

	printf("Verifying rx_buf_enc's MAC...\n");

	retval = cmox_mac_verify(CRYPTOLIB_TEST_HMAC_ALGO,  /* Use HMAC SHA256 algorithm */
							rx_buf_enc, rx_buf_enc_size,/* Message to verify */
							hmac_key, sizeof(hmac_key), /* HMAC Key to use */
							NULL, 0,              		/* Custom data */
							hmac_tag_extracted,         /* Authentication tag */
							hmac_tag_size);      		/* tag size */

	/* Verify API returned value */
	if (retval != CMOX_MAC_AUTH_SUCCESS) {
		printf("Error: MAC verification failed.\n");
	} else {
		printf("MAC verification successful.\n");
	}

	memcpy(rx_buf, rx_buf_enc, rx_buf_enc_size);
	rx_buf_size = rx_buf_enc_size;

	printf("rx_buf: ");
	printf(rx_buf);
	printf("\n");

	printf("rx_buf_size: ");
	printf("%d", rx_buf_size);
	printf("\n");

	printf("HMAC authentication verification test successful.\n");
	printf("Test completed.\n");
}

/**
  * @brief  Retargets the C library printf function to the USART.
  *   None
  * @retval None
  */
PUTCHAR_PROTOTYPE
{
	/* Place your implementation of fputc here */
	/* e.g. write a character to the USART1 and Loop until the end of transmission */
	HAL_UART_Transmit(&UART_PORT_HANDLE_DEBUG, (uint8_t *)&ch, 1, 0xFFFF);

	return ch;
}

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  printf("Error_Handler() triggered.\n");
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
	 ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
