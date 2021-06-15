parser grammar SleighParser;

options	{
	output = AST;
	ASTLabelType = CommonTree;
	tokenVocab = SleighLexer;
	superClass = AbstractSleighParser;
}

import DisplayParser, SemanticParser;

@members {
	@Override
	public void setLexer(SleighLexer lexer) {
		super.setLexer(lexer);
		gDisplayParser.setLexer(lexer);
		gSemanticParser.setLexer(lexer);
	}

	@Override
	public void setEnv(ParsingEnvironment env) {
		super.setEnv(env);
		gDisplayParser.setEnv(env);
		gSemanticParser.setEnv(env);
	}
}

/**
 * This is the root parser for a .slaspec file. Its root rule is spec.
 */

spec
	@after {
		if (env.getParsingErrors() > 0) {
			bail("Abort");
		}
	}
	:	{
			if (env.getLexingErrors() > 0) {
				bail("Abort");
			}
		}
		endiandef
		(	definition
		|	constructorlike
		)* EOF
	;

endiandef
	:	lc=KEY_DEFINE KEY_ENDIAN ASSIGN endian SEMI -> ^(OP_ENDIAN[$lc,"define endian"] endian)
	;

endian
	:	lc=KEY_BIG -> OP_BIG[$lc]
	|	lc=KEY_LITTLE -> OP_LITTLE[$lc]
	;

definition
	:	(aligndef
	|	tokendef
	|	contextdef
	|	spacedef
	|	varnodedef
	|	bitrangedef
	|	pcodeopdef
	|	valueattach
	|	nameattach
	|	varattach) SEMI!
	;

aligndef
	:	lc=KEY_DEFINE KEY_ALIGNMENT ASSIGN integer -> ^(OP_ALIGNMENT[$lc, "define alignment"] integer)
	;

tokendef
	:	lc=KEY_DEFINE KEY_TOKEN identifier LPAREN integer rp=RPAREN fielddefs[$rp] -> ^(OP_TOKEN[$lc, "define token"] identifier integer fielddefs)
	|   lc=KEY_DEFINE KEY_TOKEN identifier LPAREN integer RPAREN rp=KEY_ENDIAN ASSIGN endian fielddefs[$rp] -> ^(OP_TOKEN_ENDIAN[$lc, "define token"] identifier integer endian fielddefs)
	;

fielddefs[Token lc]
	:	fielddef* -> ^(OP_FIELDDEFS[lc, "field definitions"] fielddef*)
	;

fielddef
	:	strict_id lc=ASSIGN LPAREN s=integer COMMA e=integer rp=RPAREN fieldmods[$rp] -> ^(OP_FIELDDEF[$lc, "field definition"] strict_id $s $e fieldmods)
	;

fieldmods[Token it]
	:	fieldmod+ -> ^(OP_FIELD_MODS[it, "field modifiers"] fieldmod+)
	|	-> OP_NO_FIELD_MOD[it, "<no field mod>"]
	;

fieldmod
    :   lc=KEY_SIGNED -> OP_SIGNED[$lc]
    |   lc=KEY_HEX -> OP_HEX[$lc]
    |   lc=KEY_DEC -> OP_DEC[$lc]
    ;

contextfielddefs[Token lc]
	:	contextfielddef* -> ^(OP_FIELDDEFS[lc, "field definitions"] contextfielddef*)
	;

contextfielddef
	:	identifier lc=ASSIGN LPAREN s=integer COMMA e=integer rp=RPAREN contextfieldmods[$rp] -> ^(OP_FIELDDEF[$lc, "field definition"] identifier $s $e contextfieldmods)
	;

contextfieldmods[Token it]
    :   contextfieldmod+ -> ^(OP_FIELD_MODS[it, "context field modifiers"] contextfieldmod+)
    |   -> OP_NO_FIELD_MOD[it, "<no field mod>"]
    ;

contextfieldmod
    :   lc=KEY_SIGNED -> OP_SIGNED[$lc]
    |   lc=KEY_NOFLOW -> OP_NOFLOW[$lc]
    |   lc=KEY_HEX -> OP_HEX[$lc]
    |   lc=KEY_DEC -> OP_DEC[$lc]
    ;

contextdef
	:	lc=KEY_DEFINE rp=KEY_CONTEXT identifier contextfielddefs[$rp] -> ^(OP_CONTEXT[$lc, "define context"] identifier contextfielddefs)
	;

spacedef
	:	lc=KEY_DEFINE KEY_SPACE identifier spacemods[$lc] -> ^(OP_SPACE[$lc, "define space"] identifier spacemods)
	;

spacemods[Token lc]
	:	spacemod* -> ^(OP_SPACEMODS[$lc, "space modifier"] spacemod*)
	;

spacemod
	:	typemod
	|	sizemod
	|	wordsizemod
	|	lc=KEY_DEFAULT -> OP_DEFAULT[$lc]
	;

typemod
	:	lc=KEY_TYPE ASSIGN type -> ^(OP_TYPE[$lc] type)
	;

type
	:	identifier
	;

sizemod
	:	lc=KEY_SIZE ASSIGN integer -> ^(OP_SIZE[$lc] integer)
	;

wordsizemod
	:	lc=KEY_WORDSIZE ASSIGN integer -> ^(OP_WORDSIZE[$lc] integer)
	;

varnodedef
	:	lc=KEY_DEFINE identifier KEY_OFFSET ASSIGN offset=integer KEY_SIZE rb=ASSIGN size=integer identifierlist[$rb]
		-> ^(OP_VARNODE[$lc, "define varnode"] identifier $offset $size identifierlist)
	;

bitrangedef
	:	lc=KEY_DEFINE KEY_BITRANGE bitranges -> ^(OP_BITRANGES[$lc, "define bitrange"] bitranges)
	;

bitranges
	:	bitrange+
	;

bitrange
	:	a=identifier lc=ASSIGN b=identifier LBRACKET i=integer COMMA j=integer RBRACKET -> ^(OP_BITRANGE[$lc, "bitrange definition"] $a $b $i $j)
	;

pcodeopdef
	:	lc=KEY_DEFINE rb=KEY_PCODEOP identifierlist[$rb] -> ^(OP_PCODEOP[$lc, "define pcodeop"] identifierlist)
	;

valueattach
	:	lc=KEY_ATTACH rp=KEY_VALUES identifierlist[$rp] intblist[$rp] -> ^(OP_VALUES[$lc, "attach values"] identifierlist intblist)
	;

nameattach
	:	lc=KEY_ATTACH rp=KEY_NAMES a=identifierlist[$rp] b=stringoridentlist[$rp] -> ^(OP_NAMES[$lc, "attach names"] $a $b)
	;

varattach
	:	lc=KEY_ATTACH rp=KEY_VARIABLES a=identifierlist[$rp] b=identifierlist[$rp] -> ^(OP_VARIABLES[$lc, "attach variables"] $a $b)
	;

identifierlist[Token lc]
	:	LBRACKET id_or_wild+ RBRACKET -> ^(OP_IDENTIFIER_LIST[$lc, "identifier list"] id_or_wild+)
	|	id_or_wild -> ^(OP_IDENTIFIER_LIST[$lc, "identifier list"] id_or_wild)
	;

stringoridentlist[Token lc]
	:	LBRACKET stringorident+ RBRACKET -> ^(OP_STRING_OR_IDENT_LIST[$lc, "string or identifier list"] stringorident+)
	|	stringorident -> ^(OP_STRING_OR_IDENT_LIST[$lc, "string or identifier list"] stringorident)
	;

stringorident
	:	id_or_wild
	|	qstring
	;

intblist[Token lc]
	:	LBRACKET intbpart+ RBRACKET -> ^(OP_INTBLIST[$lc, "integer or wildcard list"] intbpart+)
	|	neginteger -> ^(OP_INTBLIST[$lc, "integer or wildcard list"] neginteger)
	;

intbpart
	:	neginteger
	|	lc=UNDERSCORE -> OP_WILDCARD[$lc]
	;

neginteger
	:	integer
	|	lc=MINUS integer -> ^(OP_NEGATE[$lc] integer)
	;

constructorlike
	:	macrodef
	|	withblock
	|	constructor
	;

macrodef
	:	lc=KEY_MACRO identifier lp=LPAREN arguments[$lp] RPAREN semanticbody -> ^(OP_MACRO[$lc, "macro"] identifier arguments semanticbody)
	;

arguments[Token lc]
	:	oplist -> ^(OP_ARGUMENTS[$lc, "arguments"] oplist)
	|	-> ^(OP_EMPTY_LIST[$lc, "no arguments"])
	;

oplist
	:	identifier (COMMA! identifier)*
	;

withblock
	:	lc=RES_WITH id_or_nil COLON bitpat_or_nil contextblock LBRACE constructorlikelist RBRACE
			-> ^(OP_WITH[$lc, "with"] id_or_nil bitpat_or_nil contextblock constructorlikelist)
	;

id_or_nil
	:	identifier
	|	-> ^(OP_NIL)
	;

bitpat_or_nil
	:	bitpattern
	|	-> ^(OP_NIL)
	;

def_or_conslike
	:	definition
	|	constructorlike
	;

constructorlikelist
	: def_or_conslike* -> ^(OP_CTLIST def_or_conslike* )
	;

constructor
	:	ctorstart bitpattern contextblock ctorsemantic -> ^(OP_CONSTRUCTOR ctorstart bitpattern contextblock ctorsemantic)
	;

ctorsemantic
	:	semanticbody -> ^(OP_PCODE semanticbody)
	|	lc=KEY_UNIMPL -> ^(OP_PCODE[$lc] OP_UNIMPL[$lc])
	;

bitpattern
	:	pequation -> ^(OP_BIT_PATTERN pequation)
	;

ctorstart
	:	identifier display -> ^(OP_SUBTABLE identifier display)
	|	display -> ^(OP_TABLE display)
	;

contextblock
	:	lc=LBRACKET ctxstmts RBRACKET -> ^(OP_CONTEXT_BLOCK[$lc, "[...]"] ctxstmts)
	|	-> ^(OP_NO_CONTEXT_BLOCK)
	;

ctxstmts
	:	ctxstmt*
	;

ctxstmt
	:	ctxassign SEMI!
	|	pfuncall SEMI!
	;

ctxassign
	:	ctxlval lc=ASSIGN pexpression -> ^(OP_ASSIGN[$lc] ctxlval pexpression)
	;

ctxlval
	:	identifier
	;

pfuncall
	:	pexpression_apply
	;

pequation
	:	pequation_or
	;

pequation_or
	:	pequation_seq ( pequation_or_op^ pequation_seq )*
	;

pequation_or_op
	:	lc=PIPE -> ^(OP_BOOL_OR[$lc])
	;

pequation_seq
	:	pequation_and ( pequation_seq_op^ pequation_and )*
	;

pequation_seq_op
	:	lc=SEMI -> ^(OP_SEQUENCE[$lc])
	;

pequation_and
	:	pequation_ellipsis ( pequation_and_op^ pequation_ellipsis )*
	;

pequation_and_op
	:	lc=AMPERSAND -> ^(OP_BOOL_AND[$lc])
	;

pequation_ellipsis
	:	lc=ELLIPSIS pequation_ellipsis_right -> ^(OP_ELLIPSIS[$lc] pequation_ellipsis_right)
	|	pequation_ellipsis_right
	;

pequation_ellipsis_right
	:	(pequation_atomic ELLIPSIS)=> pequation_atomic lc=ELLIPSIS -> ^(OP_ELLIPSIS_RIGHT[$lc] pequation_atomic)
	|	pequation_atomic
	;

pequation_atomic	
	:	constraint
	|	lc=LPAREN pequation RPAREN -> ^(OP_PARENTHESIZED[$lc,"(...)"] pequation)
	;

constraint
	:	identifier (constraint_op^ pexpression2)?
	;

constraint_op
	:	lc=ASSIGN -> ^(OP_EQUAL[$lc])
	|	lc=NOTEQUAL -> ^(OP_NOTEQUAL[$lc])
	|	lc=LESS -> ^(OP_LESS[$lc])
	|	lc=LESSEQUAL -> ^(OP_LESSEQUAL[$lc])
	|	lc=GREAT -> ^(OP_GREAT[$lc])
	|	lc=GREATEQUAL -> ^(OP_GREATEQUAL[$lc])
	;

pexpression
	:	pexpression_or
	;

pexpression_or
	:	pexpression_xor (pexpression_or_op^ pexpression_xor)*
	;

pexpression_or_op
	:	lc=PIPE -> ^(OP_OR[$lc])
	|	lc=SPEC_OR -> ^(OP_OR[$lc])
	;

pexpression_xor
	:	pexpression_and (pexpression_xor_op^ pexpression_and)*
	;

pexpression_xor_op
	:	lc=CARET -> ^(OP_XOR[$lc])
	|	lc=SPEC_XOR -> ^(OP_XOR[$lc])
	;

pexpression_and
	:	pexpression_shift (pexpression_and_op^ pexpression_shift)*
	;

pexpression_and_op
	:	lc=AMPERSAND -> ^(OP_AND[$lc])
	|	lc=SPEC_AND -> ^(OP_AND[$lc])
	;

pexpression_shift
	:	pexpression_add (pexpression_shift_op^ pexpression_add)*
	;

pexpression_shift_op
	:	lc=LEFT -> ^(OP_LEFT[$lc])
	|	lc=RIGHT -> ^(OP_RIGHT[$lc])
	;

pexpression_add
	:	pexpression_mult (pexpression_add_op^ pexpression_mult)*
	;

pexpression_add_op
	:	lc=PLUS -> ^(OP_ADD[$lc])
	|	lc=MINUS -> ^(OP_SUB[$lc])
	;

pexpression_mult
	:	pexpression_unary (pexpression_mult_op^ pexpression_unary)*
	;

pexpression_mult_op
	:	lc=ASTERISK -> ^(OP_MULT[$lc])
	|	lc=SLASH -> ^(OP_DIV[$lc])
	;

pexpression_unary
	:	pexpression_unary_op^ pexpression_term
	|	pexpression_func
	;

pexpression_unary_op
	:	lc=MINUS -> ^(OP_NEGATE[$lc])
	|	lc=TILDE -> ^(OP_INVERT[$lc])
	;

pexpression_func
	:	pexpression_apply
	|	pexpression_term
	;

pexpression_apply
	:	identifier pexpression_operands -> ^(OP_APPLY identifier pexpression_operands?)
	;

pexpression_operands
	:	LPAREN! (pexpression (COMMA! pexpression)* )? RPAREN!
	;

pexpression_term
	:	identifier
	|	integer
	|	lc=LPAREN pexpression RPAREN -> ^(OP_PARENTHESIZED[$lc, "(...)"] pexpression)
	;

pexpression2
	:	pexpression2_or
	;

pexpression2_or
	:	pexpression2_xor (pexpression2_or_op^ pexpression2_xor)*
	;

pexpression2_or_op
	:	lc=SPEC_OR -> ^(OP_OR[$lc])
	;

pexpression2_xor
	:	pexpression2_and (pexpression2_xor_op^ pexpression2_and)*
	;

pexpression2_xor_op
	:	lc=SPEC_XOR -> ^(OP_XOR[$lc])
	;

pexpression2_and
	:	pexpression2_shift (pexpression2_and_op^ pexpression2_shift)*
	;

pexpression2_and_op
	:	lc=SPEC_AND -> ^(OP_AND[$lc])
	;

pexpression2_shift
	:	pexpression2_add (pexpression2_shift_op^ pexpression2_add)*
	;

pexpression2_shift_op
	:	lc=LEFT -> ^(OP_LEFT[$lc])
	|	lc=RIGHT -> ^(OP_RIGHT[$lc])
	;

pexpression2_add
	:	pexpression2_mult (pexpression2_add_op^ pexpression2_mult)*
	;

pexpression2_add_op
	:	lc=PLUS -> ^(OP_ADD[$lc])
	|	lc=MINUS -> ^(OP_SUB[$lc])
	;

pexpression2_mult
	:	pexpression2_unary (pexpression2_mult_op^ pexpression2_unary)*
	;

pexpression2_mult_op
	:	lc=ASTERISK -> ^(OP_MULT[$lc])
	|	lc=SLASH -> ^(OP_DIV[$lc])
	;

pexpression2_unary
	:	pexpression2_unary_op^ pexpression2_term
	|	pexpression2_func
	;

pexpression2_unary_op
	:	lc=MINUS -> ^(OP_NEGATE[$lc])
	|	lc=TILDE -> ^(OP_INVERT[$lc])
	;

pexpression2_func
	:	pexpression2_apply
	|	pexpression2_term
	;

pexpression2_apply
	:	identifier pexpression2_operands -> ^(OP_APPLY identifier pexpression2_operands?)
	;

pexpression2_operands
	:	LPAREN! (pexpression2 (COMMA! pexpression2)* )? RPAREN!
	;

pexpression2_term
	:	identifier
	|	integer
	|	lc=LPAREN pexpression2 RPAREN -> ^(OP_PARENTHESIZED[$lc, "(...)"] pexpression2)
	;

qstring
	:	lc=QSTRING -> ^(OP_QSTRING[$lc, "QSTRING"] QSTRING)
	;

id_or_wild
	:	identifier
	|	wildcard
	;

wildcard
	:	lc=UNDERSCORE		-> OP_WILDCARD[$lc]
	;

identifier
	:	strict_id
	|	key_as_id
	;

key_as_id
	:	lc=KEY_ALIGNMENT	-> ^(OP_IDENTIFIER[$lc, "KEY_ALIGNMENT"] KEY_ALIGNMENT)
	|	lc=KEY_ATTACH		-> ^(OP_IDENTIFIER[$lc, "KEY_ATTACH"] KEY_ATTACH)
	|	lc=KEY_BIG			-> ^(OP_IDENTIFIER[$lc, "KEY_BIG"] KEY_BIG)
	|	lc=KEY_BITRANGE		-> ^(OP_IDENTIFIER[$lc, "KEY_BITRANGE"] KEY_BITRANGE)
	|	lc=KEY_BUILD		-> ^(OP_IDENTIFIER[$lc, "KEY_BUILD"] KEY_BUILD)
	|	lc=KEY_CALL			-> ^(OP_IDENTIFIER[$lc, "KEY_CALL"] KEY_CALL)	// appeared in printpiece
	|	lc=KEY_CONTEXT		-> ^(OP_IDENTIFIER[$lc, "KEY_CONTEXT"] KEY_CONTEXT)
	|	lc=KEY_CROSSBUILD	-> ^(OP_IDENTIFIER[$lc, "KEY_CROSSBUILD"] KEY_CROSSBUILD)
	|	lc=KEY_DEC			-> ^(OP_IDENTIFIER[$lc, "KEY_DEC"] KEY_DEC)	// appeared in printpiece
	|	lc=KEY_DEFAULT		-> ^(OP_IDENTIFIER[$lc, "KEY_DEFAULT"] KEY_DEFAULT)
	|	lc=KEY_DEFINE		-> ^(OP_IDENTIFIER[$lc, "KEY_DEFINE"] KEY_DEFINE)
	|	lc=KEY_ENDIAN		-> ^(OP_IDENTIFIER[$lc, "KEY_ENDIAN"] KEY_ENDIAN)
	|	lc=KEY_EXPORT		-> ^(OP_IDENTIFIER[$lc, "KEY_EXPORT"] KEY_EXPORT)
	|	lc=KEY_GOTO			-> ^(OP_IDENTIFIER[$lc, "KEY_GOTO"] KEY_GOTO)
	|	lc=KEY_HEX			-> ^(OP_IDENTIFIER[$lc, "KEY_HEX"] KEY_HEX)
	|	lc=KEY_LITTLE		-> ^(OP_IDENTIFIER[$lc, "KEY_LITTLE"] KEY_LITTLE)
	|	lc=KEY_LOCAL		-> ^(OP_IDENTIFIER[$lc, "KEY_LOCAL"] KEY_LOCAL)
	|	lc=KEY_MACRO		-> ^(OP_IDENTIFIER[$lc, "KEY_MACRO"] KEY_MACRO)
	|	lc=KEY_NAMES		-> ^(OP_IDENTIFIER[$lc, "KEY_NAMES"] KEY_NAMES)
	|	lc=KEY_NOFLOW		-> ^(OP_IDENTIFIER[$lc, "KEY_NOFLOW"] KEY_NOFLOW)
	|	lc=KEY_OFFSET		-> ^(OP_IDENTIFIER[$lc, "KEY_OFFSET"] KEY_OFFSET)
	|	lc=KEY_PCODEOP		-> ^(OP_IDENTIFIER[$lc, "KEY_PCODEOP"] KEY_PCODEOP)
	|	lc=KEY_RETURN		-> ^(OP_IDENTIFIER[$lc, "KEY_RETURN"] KEY_RETURN)
	|	lc=KEY_SIGNED		-> ^(OP_IDENTIFIER[$lc, "KEY_SIGNED"] KEY_SIGNED)
	|	lc=KEY_SIZE			-> ^(OP_IDENTIFIER[$lc, "KEY_SIZE"] KEY_SIZE)
	|	lc=KEY_SPACE		-> ^(OP_IDENTIFIER[$lc, "KEY_SPACE"] KEY_SPACE)
	|	lc=KEY_TOKEN		-> ^(OP_IDENTIFIER[$lc, "KEY_TOKEN"] KEY_TOKEN)
	|	lc=KEY_TYPE			-> ^(OP_IDENTIFIER[$lc, "KEY_TYPE"] KEY_TYPE)
	|	lc=KEY_UNIMPL		-> ^(OP_IDENTIFIER[$lc, "KEY_UNIMPL"] KEY_UNIMPL)
	|	lc=KEY_VALUES		-> ^(OP_IDENTIFIER[$lc, "KEY_VALUES"] KEY_VALUES)
	|	lc=KEY_VARIABLES	-> ^(OP_IDENTIFIER[$lc, "KEY_VARIABLES"] KEY_VARIABLES)
	|	lc=KEY_WORDSIZE		-> ^(OP_IDENTIFIER[$lc, "KEY_WORDSIZE"] KEY_WORDSIZE)
	;

strict_id
	:	lc=IDENTIFIER		-> ^(OP_IDENTIFIER[$lc, "IDENTIFIER"] IDENTIFIER)
	;

integer
	:	lc=HEX_INT -> ^(OP_HEX_CONSTANT[$lc, "HEX_INT"] HEX_INT)
	|	lc=DEC_INT -> ^(OP_DEC_CONSTANT[$lc, "DEC_INT"] DEC_INT)
	|	lc=BIN_INT -> ^(OP_BIN_CONSTANT[$lc, "BIN_INT"] BIN_INT)
	;
