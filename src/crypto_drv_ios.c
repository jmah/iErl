//
//  crypto_drv_ios.c
//  Couchbase Mobile
//
//  Created by Jens Alfke on 9/13/11 (based on original Erlang crypto_drv.c)
//  Copyright 2011 Couchbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// The implementation of the Erlang crypto driver uses iOS/Mac OS APIs instead of OpenSSL.
// It currently only implements the small number of functions needed by Couchbase Mobile:
// DRV_MD5, DRV_RAND_BYTES, DRV_RAND_UNIFORM.
// The spec for the Erlang APIs is at http://www.erlang.org/doc/man/crypto.html

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "erl_driver.h"

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CoreFoundation/CFByteOrder.h>
#include <Security/SecRandom.h>


#define get_int32(s) CFSwapInt32BigToHost(*(const int32_t*)(s))
#define put_int32(s,i) {*(int32_t*)(s) = CFSwapInt32HostToBig((i));}

static unsigned char* return_binary(char **rbuf, int rlen, int len);

static int generateUniformRandom(int from_len, const void* from_ptr,
								 int to_len, const void* to_ptr,
								 void* result_ptr);


#pragma mark - DRIVER INTERFACE

int crypto_init();
void crypto_finish();
ErlDrvData crypto_start(ErlDrvPort port, char *command);
void crypto_stop(ErlDrvData drv_data);
int crypto_control(ErlDrvData drv_data, unsigned int command, char *buf,
                   int len, char **rbuf, int rlen);

ErlDrvEntry crypto_driver_entry = {
    crypto_init,
    crypto_start,
    crypto_stop,
    NULL,                       /* output */
    NULL,                       /* ready_input */
    NULL,                       /* ready_output */
    "crypto_drv",
    crypto_finish,
    NULL,                       /* handle */
    crypto_control,
    NULL,                       /* timeout */
    NULL,                       /* outputv */

    NULL,                       /* ready_async */
    NULL,                       /* flush */
    NULL,                       /* call */
    NULL,                       /* event */
    ERL_DRV_EXTENDED_MARKER,
    ERL_DRV_EXTENDED_MAJOR_VERSION,
    ERL_DRV_EXTENDED_MINOR_VERSION,
#ifdef OPENSSL_THREADS
    ERL_DRV_FLAG_USE_PORT_LOCKING,
#else
    0,
#endif
    NULL,                       /* handle2 */
    NULL                        /* process_exit */
};


/* Keep the following definitions in alignment with the FUNC_LIST
 * in crypto.erl.
 */

#define DRV_INFO                0
#define DRV_MD5                 1
#define DRV_MD5_INIT            2
#define DRV_MD5_UPDATE          3
#define DRV_MD5_FINAL           4
#define DRV_SHA                 5
#define DRV_SHA_INIT            6
#define DRV_SHA_UPDATE          7
#define DRV_SHA_FINAL           8
#define DRV_MD5_MAC             9
#define DRV_MD5_MAC_96          10
#define DRV_SHA_MAC             11
#define DRV_SHA_MAC_96          12
#define DRV_CBC_DES_ENCRYPT     13
#define DRV_CBC_DES_DECRYPT     14
#define DRV_EDE3_CBC_DES_ENCRYPT 15
#define DRV_EDE3_CBC_DES_DECRYPT 16
#define DRV_AES_CFB_128_ENCRYPT 17
#define DRV_AES_CFB_128_DECRYPT 18
#define DRV_RAND_BYTES          19
#define DRV_RAND_UNIFORM        20
#define DRV_MOD_EXP             21
#define DRV_DSS_VERIFY          22
#define DRV_RSA_VERIFY_SHA      23
/* #define DRV_RSA_VERIFY_MD5      35 */
#define DRV_CBC_AES128_ENCRYPT  24
#define DRV_CBC_AES128_DECRYPT  25
#define DRV_XOR                 26
#define DRV_RC4_ENCRYPT         27 /* no decrypt needed; symmetric */
#define DRV_RC4_SETKEY          28
#define DRV_RC4_ENCRYPT_WITH_STATE 29
#define DRV_CBC_RC2_40_ENCRYPT     30
#define DRV_CBC_RC2_40_DECRYPT     31
#define DRV_CBC_AES256_ENCRYPT  32
#define DRV_CBC_AES256_DECRYPT  33
#define DRV_INFO_LIB            34
/* #define DRV_RSA_VERIFY_SHA      23 */
#define DRV_RSA_VERIFY_MD5      35
#define DRV_RSA_SIGN_SHA        36
#define DRV_RSA_SIGN_MD5        37
#define DRV_DSS_SIGN            38
#define DRV_RSA_PUBLIC_ENCRYPT  39
#define DRV_RSA_PRIVATE_DECRYPT 40
#define DRV_RSA_PRIVATE_ENCRYPT 41
#define DRV_RSA_PUBLIC_DECRYPT  42
#define DRV_DH_GENERATE_PARAMS  43
#define DRV_DH_CHECK            44
#define DRV_DH_GENERATE_KEY     45
#define DRV_DH_COMPUTE_KEY      46
#define DRV_MD4                 47
#define DRV_MD4_INIT            48
#define DRV_MD4_UPDATE          49
#define DRV_MD4_FINAL           50

#define SSL_VERSION_0_9_8 0
#if SSL_VERSION_0_9_8
#define DRV_SHA256              51
#define DRV_SHA256_INIT         52
#define DRV_SHA256_UPDATE       53
#define DRV_SHA256_FINAL        54
#define DRV_SHA512              55
#define DRV_SHA512_INIT         56
#define DRV_SHA512_UPDATE       57
#define DRV_SHA512_FINAL        58
#endif

#define DRV_BF_CFB64_ENCRYPT     59
#define DRV_BF_CFB64_DECRYPT     60

/* #define DRV_CBC_IDEA_ENCRYPT    34 */
/* #define DRV_CBC_IDEA_DECRYPT    35 */

/* Not DRV_DH_GENERATE_PARAMS DRV_DH_CHECK
 * Calc RSA_VERIFY_*  and RSA_SIGN once */
#define NUM_CRYPTO_FUNCS        46


/* List of implemented commands. Returned by DRV_INFO. */
static const uint8_t kImplementedFuncs[] = {
	DRV_MD5,
	DRV_SHA,
	DRV_SHA_MAC,
	DRV_RAND_BYTES,
	DRV_RAND_UNIFORM
};


#pragma mark - DRIVER INTERFACE

int crypto_init(void)
{
    return 0;
}

void crypto_finish(void)
{
}

ErlDrvData crypto_start(ErlDrvPort port, char *command)
{
    set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);
    return 0; /* not used */
}

void crypto_stop(ErlDrvData drv_data)
{
}

/* Main entry point for crypto functions. Spec is at http://www.erlang.org/doc/man/crypto.html */
int crypto_control(ErlDrvData drv_data, unsigned int command,
				   char *buf, int len,
				   char **rbuf, int rlen)
{
	unsigned char* bin;
    switch(command) {
		case DRV_INFO: {
			bin = return_binary(rbuf,rlen,sizeof(kImplementedFuncs));
			if (bin==NULL) return -1;
			memcpy(bin, kImplementedFuncs, sizeof(kImplementedFuncs));
			return sizeof(kImplementedFuncs);
		}
		case DRV_MD5: {
			bin = return_binary(rbuf,rlen,CC_MD5_DIGEST_LENGTH);
			if (bin==NULL) return -1;
			CC_MD5(buf, len, bin);
			return CC_MD5_DIGEST_LENGTH;
		}
		case DRV_SHA: {
			bin = return_binary(rbuf,rlen,CC_SHA1_DIGEST_LENGTH);
			if (bin==NULL) return -1;
			CC_SHA1(buf, len, bin);
			return CC_SHA1_DIGEST_LENGTH;
		}
		case DRV_SHA_MAC: {
			/* buf = klen:32/integer,key:klen/binary,dbuf:remainder/binary */
			if (len < 4)
				return -1;
			int klen = get_int32(buf);
			if (klen < 0 || klen > len - 4)
				return -1;
			const char* key = buf + 4;
			int dlen = len - klen - 4;
			const char* dbuf = key + klen;
			bin = return_binary(rbuf,rlen,CC_SHA1_DIGEST_LENGTH);
			if (bin==NULL) return -1;

			CCHmac(kCCHmacAlgSHA1, key, klen, dbuf, dlen, bin);
			return CC_SHA1_DIGEST_LENGTH;
		}
		case DRV_RAND_BYTES: {
			/* buf = <<rlen:32/integer,topmask:8/integer,bottommask:8/integer>> */
			if (len != 6)
				return -1;
			int dlen = get_int32(buf);
			bin = return_binary(rbuf,rlen,dlen);
			if (bin==NULL) return -1;
			if (SecRandomCopyBytes(NULL, dlen, bin) != 0)
				return -1;
			int or_mask = ((unsigned char*)buf)[4];
			bin[dlen-1] |= or_mask; /* topmask */
			or_mask = ((unsigned char*)buf)[5];
			bin[0] |= or_mask; /* bottommask */
			return dlen;
		}
		case DRV_RAND_UNIFORM: {
			/* buf = <<from_len:32/integer,bn_from:from_len/binary,   *
			 *         to_len:32/integer,bn_to:to_len/binary>>        */
			if (len < 8)
				return -1;
			int from_len = get_int32(buf);
			if (from_len < 0 || len < (8 + from_len))
				return -1;
			int to_len = get_int32(buf + 4 + from_len);
			if (to_len < 0 || len != (8 + from_len + to_len))
				return -1;

			int result_len;
			char result[8];
			result_len = generateUniformRandom(from_len, buf + 4,
											   to_len, buf + 4 + from_len + 4,
											   &result);
			if (result_len < 0)
				return -1;

			bin = return_binary(rbuf,rlen,4+result_len);
			put_int32(bin, result_len);
			memcpy(bin+4, result, result_len);
			return 4+result_len;
		}
		// NOTE: If you implement more cases, you must add them to kImplementedFuncs[].
		default: {
			fprintf(stderr, "ERROR: crypto_drv_ios.c: unsupported crypto_control command %u\n",
					command);
			return -1;
		}
    }
}


#pragma mark - HELPER FUNCTIONS:


static unsigned char* return_binary(char **rbuf, int rlen, int len)
{
    if (len <= rlen) {
		return (unsigned char *) *rbuf;
    }
    else {
		ErlDrvBinary* bin;
		*rbuf = (char*) (bin = driver_alloc_binary(len));
		return (bin==NULL) ? NULL : (unsigned char *) bin->orig_bytes;
    }
}


/* Returns a random number n such that from <= n < to.  On failure returns 'to'. */
static uint64_t randomNumberInRange(uint64_t from, uint64_t to) {
	if (to <= from)
		return to;
	uint64_t range = to - from;

	int shift = 64;
	for (uint64_t shiftedRange = range; shiftedRange != 0; shiftedRange >>= 1)
		--shift;

	uint64_t n;
	do {
		if (SecRandomCopyBytes(NULL, sizeof(n), (uint8_t*)&n) != 0)
			return to; // error
		n >>= shift;
	} while (n >= range);
	return from + n;
}


/* Fake implementation of bignum rand_uniform function. Only handles numbers up to 8 bytes long. */
static int generateUniformRandom(int from_len, const void* from_ptr,
								 int to_len, const void* to_ptr,
								 void* result_ptr)
{
	// Convert the from and to numbers into native long ints:
	if (from_len > 8 || to_len > 8)
		return -1;
	uint64_t from = 0;
	memcpy((char*)&from + 8 - from_len, from_ptr, from_len);
	from = CFSwapInt64BigToHost(from);
	uint64_t to = 0;
	memcpy((char*)&to + 8 - to_len, to_ptr, to_len);
	to = CFSwapInt64BigToHost(to);

	// Generate the random number.
	uint64_t result = randomNumberInRange(from, to);
	if (result >= to)
		return -1;

	*(uint64_t*)result_ptr = CFSwapInt64HostToBig(result);
	return sizeof(result);
}
