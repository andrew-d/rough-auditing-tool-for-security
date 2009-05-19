/* 
 * Copyright (c) 2001-2002 Secure Software, Inc
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifndef PYTHON_TOKENS_H
#define PYTHON_TOKENS_H

/*
 * Tokens that are specific to the Python language
 */

#define TOKEN_NEWLINE             (TOKEN_PY_START +  0)
#define TOKEN_AND                 (TOKEN_PY_START +  1)
#define TOKEN_ASSERT              (TOKEN_PY_START +  2)
#define TOKEN_CLASS               (TOKEN_PY_START +  3)
#define TOKEN_DEF                 (TOKEN_PY_START +  4)
#define TOKEN_DEL                 (TOKEN_PY_START +  5)
#define TOKEN_ELIF                (TOKEN_PY_START +  6)
#define TOKEN_EXCEPT              (TOKEN_PY_START +  7)
#define TOKEN_EXEC                (TOKEN_PY_START +  8)
#define TOKEN_FINALLY             (TOKEN_PY_START +  9)
#define TOKEN_FROM                (TOKEN_PY_START + 10)
#define TOKEN_GLOBAL              (TOKEN_PY_START + 11)
#define TOKEN_IMPORT              (TOKEN_PY_START + 12)
#define TOKEN_IN                  (TOKEN_PY_START + 13)
#define TOKEN_IS                  (TOKEN_PY_START + 14)
#define TOKEN_LAMBDA              (TOKEN_PY_START + 15)
#define TOKEN_NOT                 (TOKEN_PY_START + 16)
#define TOKEN_OR                  (TOKEN_PY_START + 17)
#define TOKEN_PASS                (TOKEN_PY_START + 18)
#define TOKEN_PRINT               (TOKEN_PY_START + 19)
#define TOKEN_RAISE               (TOKEN_PY_START + 20)
#define TOKEN_TRY                 (TOKEN_PY_START + 21)

#define TOKEN_SSTRING_LITERAL     TOKEN_STRING_CONST 
#define TOKEN_LSTRING_LITERAL     TOKEN_STRING_CONST 

#define TOKEN_EXP_ASSIGN          (TOKEN_PY_START + 25)
#define TOKEN_EXP_OP              (TOKEN_PY_START + 26)

#endif
