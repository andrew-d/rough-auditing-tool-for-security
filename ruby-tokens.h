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

#ifndef RUBY_TOKENS_H
#define RUBY_TOKENS_H


/*
 * Tokens that are specific to the Ruby language
 */

//#define	TOKEN_ALIAS		(TOKEN_RUBY_START + 	0	)
//#define	TOKEN_BEGIN		(TOKEN_RUBY_START + 	1	)
//#define	TOKEN_BEGIN		(TOKEN_RUBY_START + 	2	)
//#define	TOKEN_DEFINED	(TOKEN_RUBY_START + 	3	)
//#define	TOKEN_ELSIF		(TOKEN_RUBY_START + 	4	)
//#define	TOKEN_ENSURE	(TOKEN_RUBY_START + 	5	)
//#define	TOKEN_FALSE		(TOKEN_RUBY_START + 	6	)
//#define	TOKEN_MODULE	(TOKEN_RUBY_START + 	7	)
//#define	TOKEN_NEXT		(TOKEN_RUBY_START + 	8	)
//#define	TOKEN_NIL		(TOKEN_RUBY_START + 	9	)
//#define	TOKEN_REDO		(TOKEN_RUBY_START + 	10	)
//#define	TOKEN_RESCUE	(TOKEN_RUBY_START + 	11	)
//#define	TOKEN_RETRY		(TOKEN_RUBY_START + 	12	)
//#define	TOKEN_SELF		(TOKEN_RUBY_START + 	13	)
//#define	TOKEN_SUPER		(TOKEN_RUBY_START + 	14	)
//#define	TOKEN_THEN		(TOKEN_RUBY_START + 	15	)
//#define	TOKEN_TRUE		(TOKEN_RUBY_START + 	16	)
//#define	TOKEN_UNDEF		(TOKEN_RUBY_START + 	17	)
//#define	TOKEN_UNLESS	(TOKEN_RUBY_START + 	18	)
//#define	TOKEN_UNTIL		(TOKEN_RUBY_START + 	19	)
//#define	TOKEN_WHEN		(TOKEN_RUBY_START + 	20	)
//#define	TOKEN_YIELD		(TOKEN_RUBY_START + 	21	)
static const int	TOKEN_ALIAS		= (TOKEN_RUBY_START + 	0	);
static const int	TOKEN_BEGIN		= (TOKEN_RUBY_START + 	1	);
static const int	TOKEN_DEFINED	= (TOKEN_RUBY_START + 	3	);
static const int	TOKEN_ELSIF		= (TOKEN_RUBY_START + 	4	);
static const int	TOKEN_ENSURE	= (TOKEN_RUBY_START + 	5	);
static const int	TOKEN_FALSE		= (TOKEN_RUBY_START + 	6	);
static const int	TOKEN_MODULE	= (TOKEN_RUBY_START + 	7	);
static const int	TOKEN_NEXT		= (TOKEN_RUBY_START + 	8	);
static const int	TOKEN_NIL		= (TOKEN_RUBY_START + 	9	);
static const int	TOKEN_REDO		= (TOKEN_RUBY_START + 	10	);
static const int	TOKEN_RESCUE	= (TOKEN_RUBY_START + 	11	);
static const int	TOKEN_RETRY		= (TOKEN_RUBY_START + 	12	);
static const int	TOKEN_SELF		= (TOKEN_RUBY_START + 	13	);
static const int	TOKEN_SUPER		= (TOKEN_RUBY_START + 	14	);
static const int	TOKEN_THEN		= (TOKEN_RUBY_START + 	15	);
static const int	TOKEN_TRUE		= (TOKEN_RUBY_START + 	16	);
static const int	TOKEN_UNDEF		= (TOKEN_RUBY_START + 	17	);
static const int	TOKEN_UNLESS	= (TOKEN_RUBY_START + 	18	);
static const int	TOKEN_UNTIL		= (TOKEN_RUBY_START + 	19	);
static const int	TOKEN_WHEN		= (TOKEN_RUBY_START + 	20	);
static const int	TOKEN_YIELD		= (TOKEN_RUBY_START + 	21	);
static const int	TOKEN_INSTANCE_VARIABLE		= (TOKEN_RUBY_START + 	22	);
static const int	TOKEN_CLASS_VARIABLE		= (TOKEN_RUBY_START + 	23	);
static const int	TOKEN_GLOBAL_VARIABLE		= (TOKEN_RUBY_START + 	24	);



//static const int	TOKEN_RUBY_IN_SCRIPT 	(TOKEN_RUBY_START + 0)
//static const int	TOKEN_NEW				(TOKEN_RUBY_START + 1)
//static const int	TOKEN_ELSEIF		(TOKEN_RUBY_START + 2)
//static const int	TOKEN_ENDWHILE	(TOKEN_RUBY_START + 3)
//static const int	TOKEN_ENDFOR		(TOKEN_RUBY_START + 4)
//static const int	TOKEN_FOREACH		(TOKEN_RUBY_START + 5)
//static const int	TOKEN_ENDFOREACH	(TOKEN_RUBY_START + 6)
//static const int	TOKEN_DECLARE		(TOKEN_RUBY_START + 7)
//static const int	TOKEN_ENDDECLARE	(TOKEN_RUBY_START + 8)
//static const int	TOKEN_AS		(TOKEN_RUBY_START + 9)
//static const int	TOKEN_ENDSWITCH	(TOKEN_RUBY_START + 10)
//static const int	TOKEN_EXTENDS		(TOKEN_RUBY_START + 11)
//#define	TOKEN_VAR		(TOKEN_RUBY_START + 12)
//static const int	TOKEN_DOUBLE_ARROW	(TOKEN_RUBY_START + 13)
//static const int	TOKEN_T_EQUAL		(TOKEN_RUBY_START + 14)
//static const int	TOKEN_T_NOTEQUAL	(TOKEN_RUBY_START + 15)
//static const int	TOKEN_XOR_OP		(TOKEN_RUBY_START + 16)


#endif

