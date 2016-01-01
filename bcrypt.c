/*
 * Copyright (C) 2016 Niko Rosvall <niko@byteptr.com>
 * Originally written by Ricardo Garcia under CC0 Public Domain Dedication.
 *
 * This file is part of Steel.
 *
 * Steel is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Steel is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Steel.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "bcrypt.h"
#include "crypt_blowfish/ow-crypt.h"

#define RANDBYTES (16)

static int
try_close(int fd)
{
    int ret;

    for (;;)
    {
	errno = 0;
	ret = close(fd);
		
	if (ret == -1 && errno == EINTR)
	    continue;
		
	break;
    }
	
    return ret;
}

static int
try_read(int fd, char *out, size_t count)
{
    size_t total;
    ssize_t partial;

    total = 0;
	
    while (total < count)
    {
	for (;;)
	{
	    errno = 0;
	    partial = read(fd, out + total, count - total);
			
	    if (partial == -1 && errno == EINTR)
		continue;
			
	    break;
	}

	if (partial < 1)
	    return -1;

	total += partial;
    }

    return 0;
}

/*
 * This is a best effort implementation. Nothing prevents a compiler from
 * optimizing this function and making it vulnerable to timing attacks, but
 * this method is commonly used in crypto libraries like NaCl.
 *
 * Return value is zero if both strings are equal and nonzero otherwise.
 */
static int
timing_safe_strcmp(const char *str1, const char *str2)
{
    const unsigned char *u1;
    const unsigned char *u2;
    int ret;
    int i;

    int len1 = strlen(str1);
    int len2 = strlen(str2);

    if (len1 != len2)
	return 1;

    u1 = (const unsigned char *)str1;
    u2 = (const unsigned char *)str2;

    ret = 0;

    for (i = 0; i < len1; ++i)
	ret |= (u1[i] ^ u2[i]);

    return ret;
}

/* This function expects a work factor between 4 and 31 and a char array to
 * store the resulting generated salt. The char array should typically have
 * BCRYPT_HASHSIZE bytes at least. If the provided work factor is not in the
 * previous range, it will default to 12.
 *
 * The return value is zero if the salt could be correctly generated and
 * nonzero otherwise.
 */
int
bcrypt_gensalt(int factor, char salt[BCRYPT_HASHSIZE])
{
    int fd;
    char input[RANDBYTES];
    int workf;
    char *aux;

    fd = open("/dev/urandom", O_RDONLY);

    if (fd == -1)
	return 1;

    if (try_read(fd, input, RANDBYTES) != 0)
    {
	if (try_close(fd) != 0)
	    return 4;
		
	return 2;
    }

    if (try_close(fd) != 0)
	return 3;

    /*Generate salt.*/
    workf = (factor < 4 || factor > 31)?12:factor;
	
    aux = crypt_gensalt_rn("$2a$", workf, input, RANDBYTES,
			   salt, BCRYPT_HASHSIZE);
	
    return (aux == NULL)?5:0;
}


/* This function expects a password to be hashed, a salt to hash the password
 * with and a char array to leave the result. Both the salt and the hash
 * parameters should have room for BCRYPT_HASHSIZE characters at least.
 *
 * It can also be used to verify a hashed password. In that case, provide the
 * expected hash in the salt parameter and verify the output hash is the same
 * as the input hash. However, to avoid timing attacks, it's better to use
 * bcrypt_checkpw when verifying a password.
 *
 * The return value is zero if the password could be hashed and nonzero
 * otherwise.
 */
int
bcrypt_hashpw(const char *passwd, const char salt[BCRYPT_HASHSIZE],
	      char hash[BCRYPT_HASHSIZE])
{
    char *aux;
    aux = crypt_rn(passwd, salt, hash, BCRYPT_HASHSIZE);
	
    return (aux == NULL)?1:0;
}

/* This function expects a password and a hash to verify the password against.
 * The internal implementation is tuned to avoid timing attacks.
 *
 * The return value will be -1 in case of errors, zero if the provided password
 * matches the given hash and greater than zero if no errors are found and the
 * passwords don't match.
 */
int
bcrypt_checkpw(const char *passwd, const char hash[BCRYPT_HASHSIZE])
{
    int ret;
    char outhash[BCRYPT_HASHSIZE];

    ret = bcrypt_hashpw(passwd, hash, outhash);
	
    if (ret != 0)
	return -1;

    return timing_safe_strcmp(hash, outhash);
}
