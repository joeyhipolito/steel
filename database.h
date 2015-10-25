/*
 * Copyright (C) 2015 Niko Rosvall <niko@byteptr.com>
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

#ifndef __DATABASE_H
#define __DATABASE_H

#include "entries.h"

bool db_init(const char *path);
bool db_open(const char *path, const char *passphrase);
void db_close(const char *passphrase);
bool db_file_exists(const char *path);
char *read_path_from_lockfile();
void db_remove_lockfile();
int db_get_next_id();
bool db_add_entry(Entry_t *entry);
bool db_update_entry(int id, Entry_t *entry);
Entry_t *db_get_all_entries();
Entry_t *db_get_entry_by_id(int id);
bool db_delete_entry_by_id(int id, bool *success);
char *db_last_modified(const char *path);
bool db_shred(const char *path);

#endif
