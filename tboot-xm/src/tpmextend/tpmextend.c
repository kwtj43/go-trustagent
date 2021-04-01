/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * tpmextend.c
 *
 *  Created on: 26-June-2018
 *      Author: Arvind Rawat
 */

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include "common.h"
#include "tpm.h"
#include "tpm2.h"

extern int errno;

#define BUFSIZE 4*1024
#define MAX_HASH_LEN 65

#define TPMDEVICE "/dev/tpm0"

//map of asci char to hex values
const uint8_t char_hashmap[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
		};

/**
 * convert hex string to binary string
 * hex_str: hex character string, hex_str_len: length of hex_character string,
 * byte_buffer: buffer to store byte array, byte_buffer_len: length of byte_buffer array
 * return:
 * 		on success: the length of resultant converted byte string
 * 		on failure: less than 0, -1 for hex_string is NULL, -2 for byte buffer is NULL,
 * 					-3 for byte buffer is not long enough to store converted binary string
 * 					-4 if hex string is on odd length
 * 					-5 if hex string contains invalid chars
 */
int hex2bin(char* hex_str, int hex_str_len, unsigned char* byte_buffer,
		int byte_buffer_len) {
	if (hex_str == NULL)
		return -1;
	if (byte_buffer == NULL)
		return -2;
	if (hex_str_len / 2 > byte_buffer_len - 1)
		return -3;
	if (hex_str_len % 2 != 0)
		return -4;
	int index;
	uint8_t msb_half_idx;
	uint8_t lsb_half_idx;

	bzero(byte_buffer, byte_buffer_len);
	for (index = 0; index / 2 < byte_buffer_len - 1 && index < hex_str_len;
			index += 2) {
		char msb_hex_char = hex_str[index];
		char lsb_hex_char = hex_str[index + 1];
		if ((msb_hex_char >= 48 && msb_hex_char <= 57)
				|| (msb_hex_char >= 65 && msb_hex_char <= 70)
				|| (msb_hex_char >= 97 && msb_hex_char <= 102)) {
			msb_half_idx = (uint8_t) msb_hex_char;
		} else
			return -5;
		if ((lsb_hex_char >= 48 && lsb_hex_char <= 57)
				|| (lsb_hex_char >= 65 && lsb_hex_char <= 70)
				|| (lsb_hex_char >= 97 && lsb_hex_char <= 102)) {
			lsb_half_idx = (uint8_t) lsb_hex_char;
			byte_buffer[index / 2] = (uint8_t) (char_hashmap[msb_half_idx] << 4)
					| char_hashmap[lsb_half_idx];
		} else
			return -5;
	}
	return (index / 2);
}

void PrintBytes(const char* szMsg, byte* pbData, int iSize)
{
    int i;
    int col = 80;
    fprintf(STDOUT, "%s", szMsg);
    for (i= 0; i<iSize; i++) {
        fprintf(STDOUT, "%02x", pbData[i]);
        if((i%col)==(col-1))
            fprintf(STDOUT, "\n");
        }
    fprintf(STDOUT, "\n");
}

int tpm_extend(int pcr, uint8_t *buff, int size) {

	tpm_digest_t in;
	tpm_pcr_value_t out= {{0,}};

	if(buff == NULL || size > BUFSIZE){	
		fprintf(STDOUT, "tpm: write error, buff null or size %d > %d\n", size, BUFSIZE);
		return -1;
	}

	if( size > TPM_DIGEST_SIZE){
        fprintf(STDOUT, "tpm: write error, size %d > %d\n", size, TPM_DIGEST_SIZE);
        return -1;
	}

	memcpy_s(in.digest, TPM_DIGEST_SIZE, buff, size);
	tpm_pcr_extend(pcr, &in, &out);
	
	fprintf(STDOUT, "tpm: write, size %d\n", size);
	return size;
}

int tpm_extend2(int pcr, uint8_t *buff, int size) {

	tpmi_alg_hash hash;
	if(size == 20)
		hash = TPM_ALG_SHA1;
	else
		hash = TPM_ALG_SHA256;

	tpmi_dh_pcr handle = pcr;

	tpmu_ha in;

	fprintf(STDOUT, "Device: Pcr %d extend\n", handle);
	fprintf(STDOUT, "Device: Hash %d extend\n", hash);
	fprintf(STDOUT, "Device: Size %d extend\n", size);

	if(buff == NULL || size > BUFSIZE){
		fprintf(STDOUT, "tpm: write error, buff null or size %d > %d\n", size, BUFSIZE);
		return -1;
	}

	if( size > SHA256_DIGEST_SIZE){
        fprintf(STDOUT, "tpm: write error, size %d > %d\n", size, SHA256_DIGEST_SIZE);
        return -1;
	}

	memcpy_s(in.sha256, SHA256_DIGEST_SIZE, buff, size);
	tpm_pcr_extend2(handle, hash, size, in.sha256);
	
	fprintf(STDOUT, "tpm: write, size %d\n", size);
	return size;
}

int main(int argc, char** argv) {

    int     size = 0;
    int     ret = -1;
    int     pcrno = -1;
    int     hash_size = 0;
    double  version = 0;
    uint8_t digest[MAX_HASH_LEN];
    char    filesystem_hash[MAX_HASH_LEN] = {0};

    if(argc != 4) {
        printf("Usage: tpmextend <PCR number> <filesystem hash> <TPM version>\n");
        return -1;
    }

	fprintf(STDOUT, "TPM extension\n\n");
	
    pcrno = strtol(argv[1], (char **)NULL, 10);
    if (pcrno < 0 || pcrno > 22) {
      	printf("Invalid PCR no. found.\nCurrently supported PCR nos. are 0 to 22\n");
       	return -1;
    }
	
	size = snprintf(filesystem_hash, MAX_HASH_LEN, "%s", argv[2]);
	if(size == 40) {
		hash_size = 20;
	}
	else if(size == 64) {
		hash_size = 32;
	}
	else {
		printf("Invalid digest size found.\nCurrently supported digest sizes are 40 and 64\n");
		return -1;
	}

	version = atof(argv[3]);
	if (version != 1.2 && version != 2.0) {
		printf("Invalid TPM version found.\nCurrently supported TPM versions are 1.2 and 2.0\n");
       	return -1;
	}

	fprintf(STDOUT, "use tpm\n");
	tpmfd = open(TPMDEVICE, O_RDWR);

    if(tpmfd < 0) {
        fprintf(STDOUT, "Can't open %s\n", TPMDEVICE);
		// print which type of error have in a code
        fprintf(STDOUT, "Error Number % d\n", errno); 
         
        // print program detail "Success or failure"
        perror("Program");
        return -1;
    }

	hex2bin(filesystem_hash, size, digest, MAX_HASH_LEN);
	PrintBytes("extend pcr: ", digest, hash_size);
	
	if (version == 1.2) {
		fprintf(STDOUT, "TPM1.2: Extend PCR\n");
		ret = tpm_extend(pcrno, digest, hash_size);
	}
	else {
		fprintf(STDOUT, "TPM2.0: Extend PCR\n");
		ret = tpm_extend2(pcrno, digest, hash_size);
	}
    close(tpmfd);

	if(ret < 0){
        fprintf(STDOUT, "submitTPMExtendReq failed\n");
        return -1;
    }

    fprintf(STDOUT, "\n\nTPM test done\n");
    return 0;
}
