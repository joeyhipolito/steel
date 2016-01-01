/*
 * Copyright (C) 2016 Niko Rosvall <niko@byteptr.com>
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

#ifndef __STATUS_H
#define __STATUS_H

int status_count_file_lines(FILE *fp);
char *status_read_file_line(FILE *fp);
FILE *status_get_file_ptr(char *mode);
void status_set_tracking(const char *path);
int status_del_tracking(const char *path);
char *status_get_file_path();

#endif
