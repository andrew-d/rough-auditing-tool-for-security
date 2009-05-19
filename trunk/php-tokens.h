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

#ifndef PHP_TOKENS_H
#define PHP_TOKENS_H

/*
 * Tokens that are specific to the C language
 */

#define TOKEN_PHP_IN_SCRIPT 	(TOKEN_PHP_START + 0)
#define TOKEN_FUNCTION	(TOKEN_PHP_START + 1)
#define TOKEN_ELSEIF		(TOKEN_PHP_START + 2)
#define TOKEN_ENDWHILE	(TOKEN_PHP_START + 3)
#define TOKEN_ENDFOR		(TOKEN_PHP_START + 4)
#define TOKEN_FOREACH		(TOKEN_PHP_START + 5)
#define TOKEN_ENDFOREACH	(TOKEN_PHP_START + 6)
#define TOKEN_DECLARE		(TOKEN_PHP_START + 7)
#define TOKEN_ENDDECLARE	(TOKEN_PHP_START + 8)
#define TOKEN_AS		(TOKEN_PHP_START + 9)
#define TOKEN_ENDSWITCH	(TOKEN_PHP_START + 10)
#define TOKEN_EXTENDS		(TOKEN_PHP_START + 11)
#define	TOKEN_VAR		(TOKEN_PHP_START + 12)
#define TOKEN_DOUBLE_ARROW	(TOKEN_PHP_START + 13)
#define TOKEN_T_EQUAL		(TOKEN_PHP_START + 14)
#define TOKEN_T_NOTEQUAL	(TOKEN_PHP_START + 15)
#define TOKEN_XOR_OP		(TOKEN_PHP_START + 16)


#endif

