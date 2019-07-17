parser grammar SemanticParser;

options {
	superClass = AbstractSleighParser;
}

/**
 * This is the parser used in the semantics portion. It's root rule is semanticbody, which will
 * swap in the corresponding SemanticLexer.
 */

// See the README.txt regarding some restrictions on this rule.
semanticbody
	:	LBRACE { lexer.pushMode(SEMANTIC); } semantic RBRACE { lexer.popMode(); } -> semantic
	;

semantic
	:	code_block -> ^(OP_SEMANTIC code_block)
	;

code_block
	:	statements
	|	-> ^(OP_NOP)
	;

// with this change, export can ONLY be followed by a section label,
// and it MUST occur only in the first, default, unnamed section

statements
	:	statement+
	;

label
	:	lc=LESS identifier GREAT -> ^(OP_LABEL[$lc] identifier)
	;

section_def
	:	lc=LEFT identifier RIGHT -> ^(OP_SECTION_LABEL[$lc] identifier)
	;

statement
	@init {
		boolean empty = false;
	}
	:	(	assignment
		|	declaration
		|	funcall
		|	build_stmt
		|	crossbuild_stmt
		|	goto_stmt
		|	cond_stmt
		|	call_stmt
		|	export
		|	return_stmt
		|	{
				empty = true;
			}
		) lc=SEMI! {
			if(empty)
				bail("Empty statement at " + ((SleighToken) $lc).getLocation());
		}
	|	label
	|	section_def
	|	outererror
	;

outererror
	:	(lc=EQUAL
	|	lc=NOTEQUAL
	|	lc=FEQUAL
	|	lc=FNOTEQUAL
	|	lc=LESSEQUAL
	|	lc=GREATEQUAL
	|	lc=SLESS
	|	lc=SGREAT
	|	lc=SLESSEQUAL
	|	lc=SGREATEQUAL
	|	lc=FLESS
	|	lc=FGREAT
	|	lc=FLESSEQUAL
	|	lc=FGREATEQUAL
	|	lc=ASSIGN
	|	lc=COLON
	|	lc=COMMA
	|	lc=RBRACKET
	|	lc=BOOL_OR
	|	lc=BOOL_XOR
	|	lc=BOOL_AND
	|	lc=PIPE
	|	lc=CARET
	|	lc=AMPERSAND
	|	lc=SRIGHT
	|	lc=PLUS
	|	lc=MINUS
	|	lc=FPLUS
	|	lc=FMINUS
	|	lc=SLASH
	|	lc=PERCENT
	|	lc=SDIV
	|	lc=SREM
	|	lc=FMULT
	|	lc=FDIV
	|	lc=TILDE
	|	lc=LPAREN
	|	lc=RPAREN) {
			UnwantedTokenException ute = new UnwantedTokenException(0, input);
			ute.token = lc;
			reportError(ute);
	}
	;

assignment
	:	lb=KEY_LOCAL lvalue lc=ASSIGN expr -> ^(OP_LOCAL[$lb] OP_ASSIGN[$lc] lvalue expr)
	|	lvalue lc=ASSIGN expr -> ^(OP_ASSIGN[$lc] lvalue expr)
	;

declaration
	:	lb=KEY_LOCAL identifier lc=COLON constant -> ^(OP_LOCAL[$lb] identifier constant)
	|	lb=KEY_LOCAL identifier -> ^(OP_LOCAL[$lb] identifier)
	;

lvalue
	:	sembitrange
	|	identifier lc=COLON constant -> ^(OP_DECLARATIVE_SIZE[$lc] identifier constant)
	|	identifier
	|	sizedstar^ expr
	;

sembitrange
	:	identifier lc=LBRACKET a=constant COMMA b=constant RBRACKET -> ^(OP_BITRANGE[$lc] identifier $a $b)
	;

sizedstar
	:	lc=ASTERISK LBRACKET identifier RBRACKET COLON constant -> ^(OP_DEREFERENCE[$lc] identifier constant)
	|	lc=ASTERISK LBRACKET identifier RBRACKET                -> ^(OP_DEREFERENCE[$lc] identifier)
	|	lc=ASTERISK                              COLON constant -> ^(OP_DEREFERENCE[$lc] constant)
	|	lc=ASTERISK                                             -> ^(OP_DEREFERENCE[$lc])
	;

funcall
	:	expr_apply
	;

build_stmt
	:	lc=KEY_BUILD identifier -> ^(OP_BUILD[$lc] identifier)
	;

crossbuild_stmt
	:	lc=KEY_CROSSBUILD varnode COMMA identifier-> ^(OP_CROSSBUILD[$lc] varnode identifier)
	;

goto_stmt
	:	lc=KEY_GOTO jumpdest -> ^(OP_GOTO[$lc] jumpdest)
	;

jumpdest
	:	identifier -> ^(OP_JUMPDEST_SYMBOL identifier)
	|	LBRACKET expr RBRACKET -> ^(OP_JUMPDEST_DYNAMIC expr)
	|	integer -> ^(OP_JUMPDEST_ABSOLUTE integer)
	|	constant LBRACKET identifier RBRACKET -> ^(OP_JUMPDEST_RELATIVE constant identifier)
	|	label -> ^(OP_JUMPDEST_LABEL label)
	;

cond_stmt
	:	lc=RES_IF expr goto_stmt -> ^(OP_IF[$lc] expr goto_stmt)
	;

call_stmt
	:	lc=KEY_CALL jumpdest -> ^(OP_CALL[$lc] jumpdest)
	;

return_stmt
	:	lc=KEY_RETURN LBRACKET expr RBRACKET -> ^(OP_RETURN[$lc] expr)
	;

sizedexport
	:	sizedstar^ identifier
	;

export
	:	lc=KEY_EXPORT sizedexport -> ^(OP_EXPORT[$lc] sizedexport)
	|	lc=KEY_EXPORT varnode -> ^(OP_EXPORT[$lc] varnode)
	;

expr
	:	expr_boolor
	;

expr_boolor
	:	expr_booland ( expr_boolor_op^ expr_booland )*
	;

expr_boolor_op
	:	lc=BOOL_OR -> ^(OP_BOOL_OR[$lc])
	;

expr_booland
	:	expr_or ( booland_op^ expr_or )*
	;

booland_op
	:	lc=BOOL_AND -> ^(OP_BOOL_AND[$lc])
	|	lc=BOOL_XOR -> ^(OP_BOOL_XOR[$lc])
	;

expr_or
	:	expr_xor ( expr_or_op^ expr_xor )*
	;

expr_or_op
	:	lc=PIPE -> ^(OP_OR[$lc])
	;

expr_xor
	:	expr_and ( expr_xor_op^ expr_and )*
	;

expr_xor_op
	:	lc=CARET -> ^(OP_XOR[$lc])
	;

expr_and
	:	expr_eq ( expr_and_op^ expr_eq )*
	;

expr_and_op
	:	lc=AMPERSAND -> ^(OP_AND[$lc])
	;

expr_eq
	:	expr_comp ( eq_op^ expr_comp )*
	;

eq_op
	:	lc=EQUAL -> ^(OP_EQUAL[$lc])
	|	lc=NOTEQUAL -> ^(OP_NOTEQUAL[$lc])
	|	lc=FEQUAL -> ^(OP_FEQUAL[$lc])
	|	lc=FNOTEQUAL -> ^(OP_FNOTEQUAL[$lc])
	;

expr_comp
	:	expr_shift ( compare_op^ expr_shift )*
	;

compare_op
	:	lc=LESS -> ^(OP_LESS[$lc])
	|	lc=GREATEQUAL -> ^(OP_GREATEQUAL[$lc])
	|	lc=LESSEQUAL -> ^(OP_LESSEQUAL[$lc])
	|	lc=GREAT -> ^(OP_GREAT[$lc])
	|	lc=SLESS -> ^(OP_SLESS[$lc])
	|	lc=SGREATEQUAL -> ^(OP_SGREATEQUAL[$lc])
	|	lc=SLESSEQUAL -> ^(OP_SLESSEQUAL[$lc])
	|	lc=SGREAT -> ^(OP_SGREAT[$lc])
	|	lc=FLESS -> ^(OP_FLESS[$lc])
	|	lc=FGREATEQUAL -> ^(OP_FGREATEQUAL[$lc])
	|	lc=FLESSEQUAL -> ^(OP_FLESSEQUAL[$lc])
	|	lc=FGREAT -> ^(OP_FGREAT[$lc])
	;

expr_shift
	:	expr_add ( shift_op^ expr_add )*
	;

shift_op
	:	lc=LEFT -> ^(OP_LEFT[$lc])
	|	lc=RIGHT -> ^(OP_RIGHT[$lc])
	|	lc=SRIGHT -> ^(OP_SRIGHT[$lc])
	;

expr_add
	:	expr_mult ( add_op^ expr_mult )*
	;

add_op
	:	lc=PLUS -> ^(OP_ADD[$lc])
	|	lc=MINUS -> ^(OP_SUB[$lc])
	|	lc=FPLUS -> ^(OP_FADD[$lc])
	|	lc=FMINUS -> ^(OP_FSUB[$lc])
	;

expr_mult
	:	expr_unary ( mult_op^ expr_unary )*
	;

mult_op
	:	lc=ASTERISK -> ^(OP_MULT[$lc])
	|	lc=SLASH -> ^(OP_DIV[$lc])
	|	lc=PERCENT -> ^(OP_REM[$lc])
	|	lc=SDIV -> ^(OP_SDIV[$lc])
	|	lc=SREM -> ^(OP_SREM[$lc])
	|	lc=FMULT -> ^(OP_FMULT[$lc])
	|	lc=FDIV -> ^(OP_FDIV[$lc])
	;

expr_unary
	:	unary_op^ ? expr_func
	;

unary_op
	:	lc=EXCLAIM -> ^(OP_NOT[$lc])
	|	lc=TILDE -> ^(OP_INVERT[$lc])
	|	lc=MINUS -> ^(OP_NEGATE[$lc])
	|	lc=FMINUS -> ^(OP_FNEGATE[$lc])
	|	sizedstar
	;

expr_func
	:	expr_apply
	|	expr_term
	;

expr_apply
	:	identifier expr_operands -> ^(OP_APPLY identifier expr_operands?)
	;

expr_operands
	:	LPAREN! (expr (COMMA! expr)* )? RPAREN!
	;

expr_term
	:	varnode
	|	sembitrange
	|	lc=LPAREN expr RPAREN -> ^(OP_PARENTHESIZED[$lc, "(...)"] expr)
	;

varnode
	:	integer
	|	identifier
	|	integer lc=COLON constant -> ^(OP_TRUNCATION_SIZE[$lc] integer constant)
	|	identifier lc=COLON constant -> ^(OP_BITRANGE2[$lc] identifier constant)
	|	lc=AMPERSAND fp=COLON constant varnode -> ^(OP_ADDRESS_OF[$lc] ^(OP_SIZING_SIZE[$fp] constant) varnode)
	|	lc=AMPERSAND varnode -> ^(OP_ADDRESS_OF[$lc] varnode)
	;

constant
	:	integer
	;

integer
	:	lc=HEX_INT -> ^(OP_HEX_CONSTANT[$lc, "HEX_INT"] HEX_INT)
	|	lc=DEC_INT -> ^(OP_DEC_CONSTANT[$lc, "DEC_INT"] DEC_INT)
	|	lc=BIN_INT -> ^(OP_BIN_CONSTANT[$lc, "BIN_INT"] BIN_INT)
	;
