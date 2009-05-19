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

#ifndef C_TOKENS_H
#define C_TOKENS_H

/*
 * Tokens that are specific to the C language
 */

#define TOKEN_AUTO            (TOKEN_C_START +  0)
#define TOKEN_CASE            (TOKEN_C_START +  1)
#define TOKEN_CHAR            (TOKEN_C_START +  2)
#define TOKEN_CONST           (TOKEN_C_START +  3)
#define TOKEN_DEFAULT         (TOKEN_C_START +  4)
#define TOKEN_DO              (TOKEN_C_START +  5)
#define TOKEN_DOUBLE          (TOKEN_C_START +  6)
#define TOKEN_ENUM            (TOKEN_C_START +  7)
#define TOKEN_EXTERN          (TOKEN_C_START +  8)
#define TOKEN_FLOAT           (TOKEN_C_START +  9)
#define TOKEN_GOTO            (TOKEN_C_START + 10)
#define TOKEN_INT             (TOKEN_C_START + 11)
#define TOKEN_LONG            (TOKEN_C_START + 12)
#define TOKEN_REGISTER        (TOKEN_C_START + 13)
#define TOKEN_SHORT           (TOKEN_C_START + 14)
#define TOKEN_SIGNED          (TOKEN_C_START + 15)
#define TOKEN_SIZEOF          (TOKEN_C_START + 16)
#define TOKEN_STATIC          (TOKEN_C_START + 17)
#define TOKEN_STRUCT          (TOKEN_C_START + 18)
#define TOKEN_SWITCH          (TOKEN_C_START + 19)
#define TOKEN_TYPEDEF         (TOKEN_C_START + 20)
#define TOKEN_UNION           (TOKEN_C_START + 21)
#define TOKEN_UNSIGNED        (TOKEN_C_START + 22)
#define TOKEN_VOID            (TOKEN_C_START + 23)
#define TOKEN_VOLATILE        (TOKEN_C_START + 24)
#define TOKEN_CIN	      (TOKEN_C_START + 25)


#define TOKEN_DEC_OP          (TOKEN_C_START + 27)
#define TOKEN_INC_OP          (TOKEN_C_START + 28)
#define TOKEN_PTR_OP          (TOKEN_C_START + 29)
#define TOKEN_AND_OP          (TOKEN_C_START + 30)
#define TOKEN_OR_OP           (TOKEN_C_START + 31)
#endif
