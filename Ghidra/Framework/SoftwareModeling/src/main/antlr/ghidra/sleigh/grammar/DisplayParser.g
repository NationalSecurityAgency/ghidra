parser grammar DisplayParser;

options {
	superClass = AbstractSleighParser;
}

/**
 * This is the parser used in the display portion. It's root rule is display, which will swap in
 * the corresponding DisplayLexer. Instead of overriding the lexer rules for operators and other
 * special symbols, the parser simply recognizes them and just uses them for their characters.
 */

// See the README.txt regarding some restrictions on this rule.
display
	:	{ lexer.pushMode(DISPLAY); } COLON pieces RES_IS { lexer.popMode(); } -> ^(OP_DISPLAY pieces)
	;

pieces
	:	printpiece*
	;

printpiece
	:	identifier
	|	whitespace
	|	concatenate
	|	qstring
	|	special
	;

whitespace
	:	lc=WS -> ^(OP_WHITESPACE[$lc, "WS"] WS)
	;

// Adjacent print pieces are already catenated, but two adjacent identifiers must be separated by
// something in the source. I suppose an empty string "" would also do, but this is clearer.
concatenate
	:	lc=CARET -> ^(OP_CONCATENATE[$lc])
	;

qstring
	:	lc=QSTRING -> ^(OP_QSTRING[$lc, "QSTRING"] QSTRING)
	;

special
	:	lc=DISPCHAR			-> ^(OP_STRING[$lc, "DISPCHAR"] DISPCHAR)
	|	lc=LINECOMMENT		-> ^(OP_STRING[$lc, "LINECOMMENT"] LINECOMMENT) // really, just the #
	|	lc=LBRACE			-> ^(OP_STRING[$lc, "LBRACE"] LBRACE)
	|	lc=RBRACE			-> ^(OP_STRING[$lc, "RBRACE"] RBRACE)
	|	lc=LBRACKET			-> ^(OP_STRING[$lc, "LBRACKET"] LBRACKET)
	|	lc=RBRACKET			-> ^(OP_STRING[$lc, "RBRACKET"] RBRACKET)
	|	lc=LPAREN			-> ^(OP_STRING[$lc, "LPAREN"] LPAREN)
	|	lc=RPAREN			-> ^(OP_STRING[$lc, "RPAREN"] RPAREN)
	|	lc=ELLIPSIS			-> ^(OP_STRING[$lc, "ELLIPSIS"] ELLIPSIS)
	|	lc=EQUAL			-> ^(OP_STRING[$lc, "EQUAL"] EQUAL)
	|	lc=NOTEQUAL			-> ^(OP_STRING[$lc, "NOTEQUAL"] NOTEQUAL)
	|	lc=LESS				-> ^(OP_STRING[$lc, "LESS"] LESS)
	|	lc=GREAT			-> ^(OP_STRING[$lc, "GREAT"] GREAT)
	|	lc=LESSEQUAL		-> ^(OP_STRING[$lc, "LESSEQUAL"] LESSEQUAL)
	|	lc=GREATEQUAL		-> ^(OP_STRING[$lc, "GREATEQUAL"] GREATEQUAL)
	|	lc=ASSIGN			-> ^(OP_STRING[$lc, "ASSIGN"] ASSIGN)
	|	lc=COLON			-> ^(OP_STRING[$lc, "COLON"] COLON)
	|	lc=COMMA			-> ^(OP_STRING[$lc, "COMMA"] COMMA)
	|	lc=ASTERISK			-> ^(OP_STRING[$lc, "ASTERISK"] ASTERISK)
	|	lc=BOOL_OR			-> ^(OP_STRING[$lc, "BOOL_OR"] BOOL_OR)
	|	lc=BOOL_XOR			-> ^(OP_STRING[$lc, "BOOL_XOR"] BOOL_XOR)
	|	lc=BOOL_AND			-> ^(OP_STRING[$lc, "BOOL_AND"] BOOL_AND)
	|	lc=PIPE				-> ^(OP_STRING[$lc, "PIPE"] PIPE)
	|	lc=AMPERSAND		-> ^(OP_STRING[$lc, "AMPERSAND"] AMPERSAND)
	|	lc=LEFT				-> ^(OP_STRING[$lc, "LEFT"] LEFT)
	|	lc=RIGHT			-> ^(OP_STRING[$lc, "RIGHT"] RIGHT)
	|	lc=PLUS				-> ^(OP_STRING[$lc, "PLUS"] PLUS)
	|	lc=MINUS			-> ^(OP_STRING[$lc, "MINUS"] MINUS)
	|	lc=SLASH			-> ^(OP_STRING[$lc, "SLASH"] SLASH)
	|	lc=PERCENT			-> ^(OP_STRING[$lc, "PERCENT"] PERCENT)
	|	lc=EXCLAIM			-> ^(OP_STRING[$lc, "EXCLAIM"] EXCLAIM)
	|	lc=TILDE			-> ^(OP_STRING[$lc, "TILDE"] TILDE)
	|	lc=SEMI				-> ^(OP_STRING[$lc, "SEMI"] SEMI)
	|	lc=SPEC_OR			-> ^(OP_STRING[$lc, "SPEC_OR"] SPEC_OR)
	|	lc=SPEC_AND			-> ^(OP_STRING[$lc, "SPEC_AND"] SPEC_AND)
	|	lc=SPEC_XOR			-> ^(OP_STRING[$lc, "SPEC_XOR"] SPEC_XOR)
	|	lc=DEC_INT			-> ^(OP_STRING[$lc, "DEC_INT"] DEC_INT)
	|	lc=HEX_INT			-> ^(OP_STRING[$lc, "HEX_INT"] HEX_INT)
	|	lc=BIN_INT			-> ^(OP_STRING[$lc, "BIN_INT"] BIN_INT)
	;
