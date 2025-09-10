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
#define PUTCHAR_PROTOTYPE int __io_putchar(int ch)
#define UART_PORT_HANDLE_DEBUG	huart2	// Port handle where debug msgs are shown.
#define CHUNK_SIZE  48u   /* Chunk size (in bytes) when data to encrypt or decrypt are processed by chunk */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
CRC_HandleTypeDef hcrc;

UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
/* CBC context handle */
cmox_cbc_handle_t Cbc_Ctx;

/* SHA3 context handle */
cmox_sha3_handle_t sha3_ctx;

enum {PASSED, FAILED};
uint8_t glob_status = FAILED;
//__IO TestStatus glob_status = FAILED;

// For AES example:
const uint8_t Key[] =
{
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
const uint8_t IV[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
const uint8_t Plaintext[] =
{
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
const uint8_t Expected_Ciphertext[] =
{
  0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
  0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
  0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
  0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};

// For SHA example:
const uint8_t Message[] =
{
  0x22, 0xe1, 0xdf, 0x25, 0xc3, 0x0d, 0x6e, 0x78, 0x06, 0xca, 0xe3, 0x5c, 0xd4, 0x31, 0x7e, 0x5f,
  0x94, 0xdb, 0x02, 0x87, 0x41, 0xa7, 0x68, 0x38, 0xbf, 0xb7, 0xd5, 0x57, 0x6f, 0xbc, 0xca, 0xb0,
  0x01, 0x74, 0x9a, 0x95, 0x89, 0x71, 0x22, 0xc8, 0xd5, 0x1b, 0xb4, 0x9c, 0xfe, 0xf8, 0x54, 0x56,
  0x3e, 0x2b, 0x27, 0xd9, 0x01, 0x3b, 0x28, 0x83, 0x3f, 0x16, 0x1d, 0x52, 0x08, 0x56, 0xca, 0x4b,
  0x61, 0xc2, 0x64, 0x1c, 0x4e, 0x18, 0x48, 0x00, 0x30, 0x0a, 0xed, 0xe3, 0x51, 0x86, 0x17, 0xc7,
  0xbe, 0x3a, 0x4e, 0x66, 0x55, 0x58, 0x8f, 0x18, 0x1e, 0x96, 0x41, 0xf8, 0xdf, 0x7a, 0x6a, 0x42,
  0xea, 0xd4, 0x23, 0x00, 0x3a, 0x8c, 0x4a, 0xe6, 0xbe, 0x9d, 0x76, 0x7a, 0xf5, 0x62, 0x30, 0x78,
  0xbb, 0x11, 0x60, 0x74, 0x63, 0x85, 0x05, 0xc1, 0x05, 0x40, 0x29, 0x92, 0x19, 0xb0, 0x15, 0x5f,
  0x45, 0xb1, 0xc1, 0x8a, 0x74, 0x54, 0x8e, 0x43, 0x28, 0xde, 0x37, 0xa9, 0x11, 0x14, 0x05, 0x31,
  0xde, 0xb6, 0x43, 0x4c, 0x53, 0x4a, 0xf2, 0x44, 0x9c, 0x1a, 0xbe, 0x67, 0xe1, 0x80, 0x30, 0x68,
  0x1a, 0x61, 0x24, 0x02, 0x25, 0xf8, 0x7e, 0xde, 0x15, 0xd5, 0x19, 0xb7, 0xce, 0x25, 0x00, 0xbc,
  0xcf, 0x33, 0xe1, 0x36, 0x4e, 0x2f, 0xbe, 0x6a, 0x8a, 0x2f, 0xe6, 0xc1, 0x5d, 0x73, 0x24, 0x26,
  0x10, 0xed, 0x36, 0xb0, 0x74, 0x00, 0x80, 0x81, 0x2e, 0x89, 0x02, 0xee, 0x53, 0x1c, 0x88, 0xe0,
  0x35, 0x90, 0x20, 0x79, 0x7c, 0xbd, 0xd1, 0xfb, 0x78, 0x84, 0x8a, 0xe6, 0xb5, 0x10, 0x59, 0x61,
  0xd0, 0x5c, 0xdd, 0xdb, 0x8a, 0xf5, 0xfe, 0xf2, 0x1b, 0x02, 0xdb, 0x94, 0xc9, 0x81, 0x04, 0x64,
  0xb8, 0xd3, 0xea, 0x5f, 0x04, 0x7b, 0x94, 0xbf, 0x0d, 0x23, 0x93, 0x1f, 0x12, 0xdf, 0x37, 0xe1,
  0x02, 0xb6, 0x03, 0xcd, 0x8e, 0x5f, 0x5f, 0xfa, 0x83, 0x48, 0x8d, 0xf2, 0x57, 0xdd, 0xde, 0x11,
  0x01, 0x06, 0x26, 0x2e, 0x0e, 0xf1, 0x6d, 0x7e, 0xf2, 0x13, 0xe7, 0xb4, 0x9c, 0x69, 0x27, 0x6d,
  0x4d, 0x04, 0x8f
};

const uint8_t Expected_Hash[] =
{
  0xa6, 0x37, 0x5f, 0xf0, 0x4a, 0xf0, 0xa1, 0x8f, 0xb4, 0xc8, 0x17, 0x5f, 0x67, 0x11, 0x81, 0xb4,
  0xcf, 0x79, 0x65, 0x3a, 0x3d, 0x70, 0x84, 0x7c, 0x6d, 0x99, 0x69, 0x4b, 0x3f, 0x5d, 0x41, 0x60,
  0x1f, 0x1d, 0xbe, 0xf8, 0x09, 0x67, 0x5c, 0x63, 0xca, 0xc4, 0xec, 0x83, 0x15, 0x3b, 0x1c, 0x78,
  0x13, 0x1a, 0x7b, 0x61, 0x02, 0x4c, 0xe3, 0x62, 0x44, 0xf3, 0x20, 0xab, 0x87, 0x40, 0xcb, 0x7e
};

uint8_t Computed_Ciphertext[sizeof(Expected_Ciphertext)];
uint8_t Computed_Plaintext[sizeof(Plaintext)];
uint8_t computed_hash[CMOX_SHA3_512_SIZE]; // There are smaller sizes too.
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_CRC_Init(void);
/* USER CODE BEGIN PFP */
static void CPU_CACHE_Enable(void);
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
	cmox_cipher_retval_t retval;
	size_t computed_size;
	/* General cipher context */
	cmox_cipher_handle_t *cipher_ctx;
	/* Index for piecemeal processing */
	uint32_t index;

	cmox_hash_retval_t retval_hash;
	/* General hash context */
	cmox_hash_handle_t *hash_ctx;

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

	  /* --------------------------------------------------------------------------
	   * SINGLE CALL USAGE (AES)
	   * --------------------------------------------------------------------------
	   */

	  /* Compute directly the ciphertext passing all the needed parameters */
	  /* Note: CMOX_AES_CBC_ENC_ALGO refer to the default AES implementation
	   * selected in cmox_default_config.h. To use a specific implementation, user can
	   * directly choose:
	   * - CMOX_AESFAST_CBC_ENC_ALGO to select the AES fast implementation
	   * - CMOX_AESSMALL_CBC_ENC_ALGO to select the AES small implementation
	   */
	  retval = cmox_cipher_encrypt(CMOX_AESFAST_CBC_ENC_ALGO,                  /* Use AES CBC algorithm */
	                               Plaintext, sizeof(Plaintext),           /* Plaintext to encrypt */
	                               Key, sizeof(Key),                       /* AES key to use */
	                               IV, sizeof(IV),                         /* Initialization vector */
	                               Computed_Ciphertext, &computed_size);   /* Data buffer to receive generated ciphertext */

	  /* Verify API returned value */
	  if (retval != CMOX_CIPHER_SUCCESS)
	  {
	    Error_Handler();
	  }

	  /* Verify generated data size is the expected one */
	  if (computed_size != sizeof(Expected_Ciphertext))
	  {
	    Error_Handler();
	  }

	  /* Verify generated data are the expected ones */
	  if (memcmp(Expected_Ciphertext, Computed_Ciphertext, computed_size) != 0)
	  {
	    Error_Handler();
	  }

	  /* Compute directly the plaintext passing all the needed parameters */
	  /* Note: CMOX_AES_CBC_DEC_ALGO refer to the default AES implementation
	   * selected in cmox_default_config.h. To use a specific implementation, user can
	   * directly choose:
	   * - CMOX_AESFAST_CBC_DEC_ALGO to select the AES fast implementation
	   * - CMOX_AESSMALL_CBC_DEC_ALGO to select the AES small implementation
	   */
	  retval = cmox_cipher_decrypt(CMOX_AES_CBC_DEC_ALGO,                 /* Use AES CBC algorithm */
	                               Expected_Ciphertext, sizeof(Expected_Ciphertext), /* Ciphertext to decrypt */
	                               Key, sizeof(Key),                      /* AES key to use */
	                               IV, sizeof(IV),                        /* Initialization vector */
	                               Computed_Plaintext, &computed_size);   /* Data buffer to receive generated plaintext */

	  /* Verify API returned value */
	  if (retval != CMOX_CIPHER_SUCCESS)
	  {
	    Error_Handler();
	  }

	  /* Verify generated data size is the expected one */
	  if (computed_size != sizeof(Plaintext))
	  {
	    Error_Handler();
	  }

	  /* Verify generated data are the expected ones */
	  if (memcmp(Plaintext, Computed_Plaintext, computed_size) != 0)
	  {
	    Error_Handler();
	  }

	  /* --------------------------------------------------------------------------
	     * MULTIPLE CALLS USAGE (AES)
	     * --------------------------------------------------------------------------
	     */

	    /* Construct a cipher context that is configured to perform AES CBC encryption operations */
	    /* Note: CMOX_AES_CBC_ENC refer to the default AES implementation
	     * selected in cmox_default_config.h. To use a specific implementation, user can
	     * directly choose:
	     * - CMOX_AESFAST_CBC_ENC to select the AES fast implementation
	     * - CMOX_AESSMALL_CBC_ENC to select the AES small implementation
	     */
	    cipher_ctx = cmox_cbc_construct(&Cbc_Ctx, CMOX_AES_CBC_ENC);
	    if (cipher_ctx == NULL)
	    {
	      Error_Handler();
	    }

	    /* Initialize the cipher context */
	    retval = cmox_cipher_init(cipher_ctx);
	    if (retval != CMOX_CIPHER_SUCCESS)
	    {
	      Error_Handler();
	    }

	    /* Setup of the encryption key into the context */
	    retval = cmox_cipher_setKey(cipher_ctx, Key, sizeof(Key));  /* AES key to use */
	    if (retval != CMOX_CIPHER_SUCCESS)
	    {
	      Error_Handler();
	    }

	    /* Setup of the Initialization Vector (IV) into the context */
	    retval = cmox_cipher_setIV(cipher_ctx, IV, sizeof(IV));     /* Initialization vector */
	    if (retval != CMOX_CIPHER_SUCCESS)
	    {
	      Error_Handler();
	    }

	    /* Encrypt the plaintext in multiple steps by appending chunks of CHUNK_SIZE bytes */
	    for (index = 0; index < (sizeof(Plaintext) - CHUNK_SIZE); index += CHUNK_SIZE)
	    {
	      retval = cmox_cipher_append(cipher_ctx,
	                                  &Plaintext[index], CHUNK_SIZE,        /* Chunk of plaintext to encrypt */
	                                  Computed_Ciphertext, &computed_size); /* Data buffer to receive generated chunk
	                                                                           of ciphertext */

	      /* Verify API returned value */
	      if (retval != CMOX_CIPHER_SUCCESS)
	      {
	        Error_Handler();
	      }

	      /* Verify generated data size is the expected one */
	      if (computed_size != CHUNK_SIZE)
	      {
	        Error_Handler();
	      }

	      /* Verify generated data are the expected ones */
	      if (memcmp(&Expected_Ciphertext[index], Computed_Ciphertext, computed_size) != 0)
	      {
	        Error_Handler();
	      }
	    }
	    /* Process with encryption of the last part if needed */
	    if (index < sizeof(Plaintext))
	    {
	      retval = cmox_cipher_append(cipher_ctx,
	                                  &Plaintext[index],
	                                  sizeof(Plaintext) - index,              /* Last part of plaintext to encrypt */
	                                  Computed_Ciphertext, &computed_size);   /* Data buffer to receive generated last
	                                                                             part of ciphertext */

	      /* Verify API returned value */
	      if (retval != CMOX_CIPHER_SUCCESS)
	      {
	        Error_Handler();
	      }

	      /* Verify generated data size is the expected one */
	      if (computed_size != (sizeof(Plaintext) - index))
	      {
	        Error_Handler();
	      }

	      /* Verify generated data are the expected ones */
	      if (memcmp(&Expected_Ciphertext[index], Computed_Ciphertext, computed_size) != 0)
	      {
	        Error_Handler();
	      }
	    }

	    /* Cleanup the context */
	    retval = cmox_cipher_cleanup(cipher_ctx);
	    if (retval != CMOX_CIPHER_SUCCESS)
	    {
	      Error_Handler();
	    }

	    /* Construct a cipher context that is configured to perform AES CBC decryption operations */
	    /* Note: CMOX_AES_CBC_DEC refer to the default AES implementation
	     * selected in cmox_default_config.h. To use a specific implementation, user can
	     * directly choose:
	     * - CMOX_AESFAST_CBC_DEC to select the AES fast implementation
	     * - CMOX_AESSMALL_CBC_DEC to select the AES small implementation
	     */
	    cipher_ctx = cmox_cbc_construct(&Cbc_Ctx, CMOX_AES_CBC_DEC);
	    if (cipher_ctx == NULL)
	    {
	      Error_Handler();
	    }

	    /* Initialize the cipher context */
	    retval = cmox_cipher_init(cipher_ctx);
	    if (retval != CMOX_CIPHER_SUCCESS)
	    {
	      Error_Handler();
	    }

	    /* Setup of the decryption key into the context */
	    retval = cmox_cipher_setKey(cipher_ctx, Key, sizeof(Key));  /* AES key to use */
	    if (retval != CMOX_CIPHER_SUCCESS)
	    {
	      Error_Handler();
	    }

	    /* Setup of the Initialization Vector (IV) into the context */
	    retval = cmox_cipher_setIV(cipher_ctx, IV, sizeof(IV));     /* Initialization vector */
	    if (retval != CMOX_CIPHER_SUCCESS)
	    {
	      Error_Handler();
	    }

	    /* Decrypt the plaintext in multiple steps by appending chunks of CHUNK_SIZE bytes */
	    for (index = 0; index < (sizeof(Expected_Ciphertext) - CHUNK_SIZE); index += CHUNK_SIZE)
	    {
	      retval = cmox_cipher_append(cipher_ctx,
	                                  &Expected_Ciphertext[index],
	                                  CHUNK_SIZE,                           /* Chunk of ciphertext to decrypt */
	                                  Computed_Plaintext, &computed_size);  /* Data buffer to receive generated
	                                                                           chunk of plaintext */

	      /* Verify API returned value */
	      if (retval != CMOX_CIPHER_SUCCESS)
	      {
	        Error_Handler();
	      }

	      /* Verify generated data size is the expected one */
	      if (computed_size != CHUNK_SIZE)
	      {
	        Error_Handler();
	      }

	      /* Verify generated data are the expected ones */
	      if (memcmp(&Plaintext[index], Computed_Plaintext, computed_size) != 0)
	      {
	        Error_Handler();
	      }
	    }
	    /* Process with encryption of the last part if needed */
	    if (index < sizeof(Expected_Ciphertext))
	    {
	      retval = cmox_cipher_append(cipher_ctx,
	                                  &Expected_Ciphertext[index],
	                                  sizeof(Expected_Ciphertext) - index,    /* Last part of ciphertext to decrypt */
	                                  Computed_Plaintext, &computed_size);    /* Data buffer to receive generated last
	                                                                             part of plaintext */

	      /* Verify API returned value */
	      if (retval != CMOX_CIPHER_SUCCESS)
	      {
	        Error_Handler();
	      }

	      /* Verify generated data size is the expected one */
	      if (computed_size != (sizeof(Expected_Ciphertext) - index))
	      {
	        Error_Handler();
	      }

	      /* Verify generated data are the expected ones */
	      if (memcmp(&Plaintext[index], Computed_Plaintext, computed_size) != 0)
	      {
	        Error_Handler();
	      }
	    }

	    /* Cleanup the handle */
	    retval = cmox_cipher_cleanup(cipher_ctx);
	    if (retval != CMOX_CIPHER_SUCCESS)
	    {
	      Error_Handler();
	    }

	    printf("AES_CBC_EncryptDecrypt completed successfully.\n");

	    /* --------------------------------------------------------------------------
	     * SINGLE CALL USAGE (SHA)
	     * --------------------------------------------------------------------------
	     */
	    /* Compute directly the digest passing all the needed parameters */
	    retval_hash = cmox_hash_compute(CMOX_SHA3_512_ALGO,       /* Use SHA3-512 algorithm */
	                               Message, sizeof(Message), /* Message to digest */
	                               computed_hash,            /* Data buffer to receive digest data */
	                               CMOX_SHA3_512_SIZE,       /* Expected digest size */
	                               &computed_size);          /* Size of computed digest */

	    /* Verify API returned value */
	    if (retval_hash != CMOX_HASH_SUCCESS)
	    {
	      Error_Handler();
	    }

	    /* Verify generated data size is the expected one */
	    if (computed_size != CMOX_SHA3_512_SIZE)
	    {
	      Error_Handler();
	    }

	    /* Verify generated data are the expected ones */
	    if (memcmp(Expected_Hash, computed_hash, computed_size) != 0)
	    {
	      Error_Handler();
	    }

	    /* --------------------------------------------------------------------------
	       * MULTIPLE CALLS USAGE (SHA)
	       * --------------------------------------------------------------------------
	       */

	      /* Construct a hash context that is configured to perform SHA3-512 digest operations */
	      hash_ctx = cmox_sha3_512_construct(&sha3_ctx);
	      if (hash_ctx == NULL)
	      {
	        Error_Handler();
	      }

	      /* Initialize the hash context */
	      retval_hash = cmox_hash_init(hash_ctx);
	      if (retval_hash != CMOX_HASH_SUCCESS)
	      {
	        Error_Handler();
	      }

	      /* Set the desired size for the digest to compute: note that in the case
	         where the size of the digest is the default for the algorithm, it is
	         possible to skip this call. */
	      retval_hash = cmox_hash_setTagLen(hash_ctx, CMOX_SHA3_512_SIZE);
	      if (retval_hash != CMOX_HASH_SUCCESS)
	      {
	        Error_Handler();
	      }

	      /* Append the message to be hashed by chunks of CHUNK_SIZE Bytes */
	      for (index = 0; index < (sizeof(Message) - CHUNK_SIZE); index += CHUNK_SIZE)
	      {
		retval_hash = cmox_hash_append(hash_ctx, &Message[index], CHUNK_SIZE); /* Chunk of data to digest */

	        /* Verify API returned value */
	        if (retval_hash != CMOX_HASH_SUCCESS)
	        {
	          Error_Handler();
	        }
	      }
	      /* Append the last part of the message if needed */
	      if (index < sizeof(Message))
	      {
		retval_hash = cmox_hash_append(hash_ctx, &Message[index], sizeof(Message) - index); /* Last part of data to digest */

	        /* Verify API returned value */
	        if (retval_hash != CMOX_HASH_SUCCESS)
	        {
	          Error_Handler();
	        }
	      }

	      /* Generate the digest data */
	      retval_hash = cmox_hash_generateTag(hash_ctx, computed_hash, &computed_size);

	      /* Verify API returned value */
	      if (retval_hash != CMOX_HASH_SUCCESS)
	      {
	        Error_Handler();
	      }

	      /* Verify generated data size is the expected one */
	      if (computed_size != CMOX_SHA3_512_SIZE)
	      {
	        Error_Handler();
	      }

	      /* Verify generated data are the expected ones */
	      if (memcmp(Expected_Hash, computed_hash, computed_size) != 0)
	      {
	        Error_Handler();
	      }

	      /* Cleanup the context */
	      retval_hash = cmox_hash_cleanup(hash_ctx);
	      if (retval_hash != CMOX_HASH_SUCCESS)
	      {
	        Error_Handler();
	      }

	      printf("Hash SHA3_Digest completed successfully.\n");

	      /* No more need of cryptographic services, finalize cryptographic library */
	      if (cmox_finalize(NULL) != CMOX_INIT_SUCCESS)
	      {
	        Error_Handler();
	      }

	      glob_status = PASSED;

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
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
