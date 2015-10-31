/*
 * Copyright (C) 2015 Niko Rosvall <niko@byteptr.com>
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

#ifndef BCRYPT_H_
#define BCRYPT_H_

#define BCRYPT_HASHSIZE	(64)

int bcrypt_gensalt(int workfactor, char salt[BCRYPT_HASHSIZE]);
int bcrypt_hashpw(const char *passwd, const char salt[BCRYPT_HASHSIZE],
		  char hash[BCRYPT_HASHSIZE]);
    
int bcrypt_checkpw(const char *passwd, const char hash[BCRYPT_HASHSIZE]);


#endif
