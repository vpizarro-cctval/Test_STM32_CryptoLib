
/******************************************************************************
 * @file    Cryptolib.h
 * @author  Víctor Pizarro (victor.pizarroc@usm.cl)
 * @brief   Wrapper library for use of X-CUBE-CRYPTOLIB functions in firmware 
 * communications to achieve confidentiality, authenticity and integrity.
 * @version 0.1
 * @date    15/9/25
 ******************************************************************************
 */

#ifndef CRYPTOLIB_H
#define CRYPTOLIB_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include <string.h>
#include "cmox_crypto.h"

/* Defines -------------------------------------------------------------------*/
#define CRYPTOLIB_KEY_SIZE 		16 	// Bytes
#define CRYPTOLIB_IV_SIZE		16	// Bytes (size of the AES block)
#define CRYPTOLIB_TAG_SIZE 		4	// Bytes
#define CRYPTOLIB_MAX_MSG_SIZE 	69	// Bytes (max expected plaintext size)
#define CRYPTOLIB_ENC_MSG_SIZE	CRYPTOLIB_IV_SIZE + CRYPTOLIB_TAG_SIZE + CRYPTOLIB_MAX_MSG_SIZE
									// Encoded msg: |IV|HMAC Tag|Ciphertext|
#define CRYPTOLIB_AES_ALGO		CMOX_AESFAST_CBC_ENC_ALGO
#define CRYPTOLIB_MAC_ALGO		CMOX_HMAC_SHA256_ALGO

/* Exported types ------------------------------------------------------------*/
typedef enum {
	CRYPTOLIB_NO_ERROR = 0,
	CRYPTOLIB_ENCRYPTION_ERROR,
	CRYPTOLIB_DECRYPTION_ERROR,
	CRYPTOLIB_AUTH_ERROR,
	CRYPTOLIB_MSG_SIZE_ERROR,
	CRYPTOLIB_KEY_ERROR
} Cryptolib_Error_t;

typedef struct {
	uint8_t *_aes_key;
	uint8_t *_hmac_key;
	uint8_t _aes_iv[CRYPTOLIB_IV_SIZE];
	uint8_t _msg[CRYPTOLIB_MAX_MSG_SIZE];		// Not sure if needed
	size_t _msg_size;
	uint8_t _enc_msg[CRYPTOLIB_ENC_MSG_SIZE];	// Not sure if needed
	uint8_t _is_key_set;
} Cryptolib_t;

typedef uint8_t Cryptolib_key_t[CRYPTOLIB_KEY_SIZE];

const Cryptolib_t _cryptolib_default_h = {
	._aes_key = NULL,
	._hmac_key = NULL,
	._msg_size = 0,
	._is_key_set = 0,
};

/* Exported constants --------------------------------------------------------*/

/* Exported functions prototypes ---------------------------------------------*/
// TODO: Move implementations to .c file

uint8_t Cryptolib_Init(Cryptolib_t * crypto_h)
{
	// Default initialization.
	*crypto_h = _cryptolib_default_h;

	// TODO: Initialize arrays.
	memset(crypto_h->_aes_iv, 0, CRYPTOLIB_IV_SIZE);
	memset(crypto_h->_msg, 0, CRYPTOLIB_MAX_MSG_SIZE);
	memset(crypto_h->_enc_msg, 0, CRYPTOLIB_ENC_MSG_SIZE);

	return CRYPTOLIB_NO_ERROR;
}

/**
 * @brief Encrypts a message using AES-CBC protocol, and adds an HMAC code to provide confidentiality,
 * authentication and integrity of the transmited message. For this purpose, two secret keys with lengths 
 * of 16 bytes are required (AES-CBC key and HMAC key).
 * 
 * @param crypto_h 	Pointer to a Cryptolib_t struct containing the encryption configuration.
 * @param msg 		Pointer to a buffer containing the message to transmit.
 * @param msg_size 	Size of the message to transmit.
 * @param enc_msg 	Pointer to buffer to store the generated encrypted msg. 
 * Its size must be CRYPTOLIB_ENC_MSG_SIZE.
 * @return uint8_t 	Error code. See Cryptolib_Error_t.
 */
uint8_t Cryptolib_Encrypt(Cryptolib_t *crypto_h,
						uint8_t *msg, 
						size_t msg_size, 
						uint8_t *enc_msg)
{
	if (!crypto_h->_is_key_set) {
		return CRYPTOLIB_KEY_ERROR;
	}

	// TODO: Generate random IV.
	size_t enc_msg_size = 0;

	if (msg_size == 0 || msg_size > CRYPTOLIB_MAX_MSG_SIZE) {
		return CRYPTOLIB_MSG_SIZE_ERROR;
	}

	memset(crypto_h->_msg, 0, CRYPTOLIB_MAX_MSG_SIZE); // Automatic zero padding.
	memcpy(crypto_h->_msg, msg, msg_size);
	
	memset(enc_msg, 0, CRYPTOLIB_ENC_MSG_SIZE);

	cmox_cipher_retval_t retval_c;
	retval_c = cmox_cipher_encrypt(CRYPTOLIB_AES_ALGO,  				/* Use AES CBC algorithm */
								crypto_h->_msg, CRYPTOLIB_MAX_MSG_SIZE, /* Plaintext to encrypt */
								crypto_h->_aes_key, CRYPTOLIB_KEY_SIZE,	/* AES key to use */
								crypto_h->_aes_iv, CRYPTOLIB_KEY_SIZE,  /* Initialization vector */
								enc_msg, &enc_msg_size); 				/* Data buffer to receive generated ciphertext */

	if (retval_c != CMOX_CIPHER_SUCCESS) {
		return CRYPTOLIB_ENCRYPTION_ERROR;
	}
	if (enc_msg_size != CRYPTOLIB_MAX_MSG_SIZE) {
		return CRYPTOLIB_ENCRYPTION_ERROR;
	}

	cmox_mac_retval_t retval_m;
	uint8_t hmac_tag[CRYPTOLIB_TAG_SIZE] = {0};
	size_t hmac_tag_size = 0;

	// HMAC tag must be computed over the encrypted message.
	retval_m = cmox_mac_compute(CRYPTOLIB_MAC_ALGO, 					/* Use HMAC SHA256 algorithm */
							enc_msg, CRYPTOLIB_MAX_MSG_SIZE,  			/* Message to authenticate */
							crypto_h->_hmac_key, CRYPTOLIB_KEY_SIZE, 	/* HMAC Key to use */
							NULL, 0,                    				/* Custom data */
							hmac_tag,                   				/* Data buffer to receive generated authnetication tag */
							CRYPTOLIB_TAG_SIZE,    						/* Expected authentication tag size */
							&hmac_tag_size);            				/* Generated tag size */
	
	if (retval_m != CMOX_MAC_SUCCESS) {
		return CRYPTOLIB_AUTH_ERROR;
	}
	if (hmac_tag_size != CRYPTOLIB_TAG_SIZE) {
		return CRYPTOLIB_AUTH_ERROR;
	}

	memmove(enc_msg + CRYPTOLIB_IV_SIZE + CRYPTOLIB_TAG_SIZE, enc_msg, CRYPTOLIB_MAX_MSG_SIZE);
	memcpy(enc_msg, crypto_h->_aes_iv, CRYPTOLIB_IV_SIZE);
	memcpy(enc_msg + CRYPTOLIB_IV_SIZE, hmac_tag, CRYPTOLIB_TAG_SIZE);

	printf("Cryptolib_Encrypt() debug:\n");
	printf("HMAC tag generated:\n");
	for (int i = 0; i < CRYPTOLIB_TAG_SIZE; i++) {
		printf("%02X", hmac_tag[i]);
		if (i == CRYPTOLIB_TAG_SIZE - 1) {
			printf("\n");
			break;
		}
		printf(", ");
	}

	return CRYPTOLIB_NO_ERROR;
}

/**
 * @brief 
 * 
 * @param crypto_h 
 * @param enc_msg 
 * @param msg 
 * @return uint8_t 
 */
uint8_t Cryptolib_Decrypt(Cryptolib_t *crypto_h, uint8_t *enc_msg, uint8_t *msg)
{
	if (!crypto_h->_is_key_set) {
		return CRYPTOLIB_KEY_ERROR;
	}

	printf("Cryptolib_Decrypt() debug:\n");
	printf("Encrypted msg:\n");
	for (int i = 0; i < CRYPTOLIB_ENC_MSG_SIZE; i++) {
		printf("%02X", enc_msg[i]);
		if (i == CRYPTOLIB_ENC_MSG_SIZE - 1) {
			printf("\n");
			break;
		}
		printf(", ");
	}

	uint8_t hmac_tag[CRYPTOLIB_TAG_SIZE] = {0};
	uint8_t ciphertext[CRYPTOLIB_MAX_MSG_SIZE] = {0};
	memcpy(hmac_tag, enc_msg + CRYPTOLIB_IV_SIZE, CRYPTOLIB_TAG_SIZE);
	memcpy(ciphertext, enc_msg + CRYPTOLIB_IV_SIZE + CRYPTOLIB_TAG_SIZE, CRYPTOLIB_MAX_MSG_SIZE);

	printf("HMAC tag extracted:\n");
	for (int i = 0; i < CRYPTOLIB_TAG_SIZE; i++) {
		printf("%02X", hmac_tag[i]);
		if (i == CRYPTOLIB_TAG_SIZE - 1) {
			printf("\n");
			break;
		}
		printf(", ");
	}

	printf("Ciphertext extracted:\n");
	for (int i = 0; i < CRYPTOLIB_MAX_MSG_SIZE; i++) {
		printf("%02X", ciphertext[i]);
		if (i == CRYPTOLIB_MAX_MSG_SIZE - 1) {
			printf("\n");
			break;
		}
		printf(", ");
	}

	cmox_mac_retval_t retval_m;

	// TEST: Recalculate tag to ensure tag match.
	size_t hmac_tag_size = 0;
	uint8_t hmac_tag_recalc[CRYPTOLIB_TAG_SIZE] = {0};
	retval_m = cmox_mac_compute(CRYPTOLIB_MAC_ALGO, 					/* Use HMAC SHA256 algorithm */
							ciphertext, CRYPTOLIB_MAX_MSG_SIZE,     	/* Message to authenticate */
							crypto_h->_hmac_key, CRYPTOLIB_KEY_SIZE, 	/* HMAC Key to use */
							NULL, 0,                    				/* Custom data */
							hmac_tag_recalc,                   			/* Data buffer to receive generated authnetication tag */
							CRYPTOLIB_TAG_SIZE,    						/* Expected authentication tag size */
							&hmac_tag_size);            				/* Generated tag size */
	
	if (retval_m != CMOX_MAC_SUCCESS) {
		printf("CRYPTOLIB_AUTH_ERROR\n");
	}
	if (hmac_tag_size != CRYPTOLIB_TAG_SIZE) {
		printf("CRYPTOLIB_AUTH_ERROR\n");
	}

	printf("Recalculated tag:\n");
	for (int i = 0; i < CRYPTOLIB_TAG_SIZE; i++) {
		printf("%02X", hmac_tag_recalc[i]);
		if (i == CRYPTOLIB_TAG_SIZE - 1) {
			printf("\n");
			break;
		}
		printf(", ");
	}

	retval_m = cmox_mac_compute(CRYPTOLIB_MAC_ALGO, 					/* Use HMAC SHA256 algorithm */
							ciphertext, CRYPTOLIB_MAX_MSG_SIZE,     	/* Message to authenticate */
							crypto_h->_hmac_key, CRYPTOLIB_KEY_SIZE, 	/* HMAC Key to use */
							NULL, 0,                    				/* Custom data */
							hmac_tag_recalc,                   			/* Data buffer to receive generated authnetication tag */
							CRYPTOLIB_TAG_SIZE,    						/* Expected authentication tag size */
							&hmac_tag_size);            				/* Generated tag size */
	
	if (retval_m != CMOX_MAC_SUCCESS) {
		printf("CRYPTOLIB_AUTH_ERROR\n");
	}
	if (hmac_tag_size != CRYPTOLIB_TAG_SIZE) {
		printf("CRYPTOLIB_AUTH_ERROR\n");
	}

	printf("RERecalculated tag:\n");
	for (int i = 0; i < CRYPTOLIB_TAG_SIZE; i++) {
		printf("%02X", hmac_tag_recalc[i]);
		if (i == CRYPTOLIB_TAG_SIZE - 1) {
			printf("\n");
			break;
		}
		printf(", ");
	}

	// END TEST.
	
	retval_m = cmox_mac_verify(CRYPTOLIB_MAC_ALGO,
							ciphertext, CRYPTOLIB_MAX_MSG_SIZE,		/* Message to verify */
							crypto_h->_hmac_key, CRYPTOLIB_KEY_SIZE,/* HMAC Key to use */
							NULL, 0,              					/* Custom data */
							hmac_tag,         						/* Authentication tag */
							CRYPTOLIB_TAG_SIZE);      				/* tag size */

	if (retval_m != CMOX_MAC_AUTH_SUCCESS) {
		return CRYPTOLIB_AUTH_ERROR;
	}

	uint8_t iv[CRYPTOLIB_IV_SIZE] = {0};
	memcpy(iv, enc_msg, CRYPTOLIB_IV_SIZE);

	memset(msg, 0, CRYPTOLIB_MAX_MSG_SIZE);
	size_t msg_size = 0;

	cmox_cipher_retval_t retval_c;
	retval_c = cmox_cipher_decrypt(CRYPTOLIB_AES_ALGO,					/* Use AES CBC algorithm */
								ciphertext, CRYPTOLIB_MAX_MSG_SIZE, 	/* Ciphertext to decrypt */
								crypto_h->_aes_key, CRYPTOLIB_KEY_SIZE,	/* AES key to use */
								iv, CRYPTOLIB_IV_SIZE,         			/* Initialization vector */
								msg, &msg_size);   				/* Data buffer to receive generated plaintext */
		
	if (retval_c != CMOX_CIPHER_SUCCESS) {
		return CRYPTOLIB_DECRYPTION_ERROR;
	}

	if (msg_size != CRYPTOLIB_MAX_MSG_SIZE) {
		return CRYPTOLIB_DECRYPTION_ERROR;
	}

	return CRYPTOLIB_NO_ERROR;
}

/**
 * @brief Stores a reference to the arrays containing the keys required for encryption.
 * 
 * @param crypto_h	Pointer to a Cryptolib_t struct containing the encryption configuration.
 * @param aes_key 	AES key.
 * @param hmac_key 	HMAC key.
 * @return uint8_t 	Error code. See Cryptolib_Error_t.
 */
uint8_t Cryptolib_SetKeys(Cryptolib_t *crypto_h, 
						Cryptolib_key_t aes_key, 
						Cryptolib_key_t hmac_key)
{
	crypto_h->_aes_key = aes_key;
	crypto_h->_hmac_key = hmac_key;

	crypto_h->_is_key_set = 1;

	return CRYPTOLIB_NO_ERROR;
}

#ifdef __cplusplus
}
#endif

#endif // CRYPTOLIB_H
