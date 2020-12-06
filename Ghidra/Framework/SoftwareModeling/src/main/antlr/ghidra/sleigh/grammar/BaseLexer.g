lexer grammar BaseLexer;

options {
	superClass = AbstractSleighLexer;
	tokenVocab = SleighLexer;
}

tokens {
	OP_ADD;
	OP_ADDRESS_OF;
	OP_ALIGNMENT;
	OP_AND;
	OP_APPLY;
	OP_ARGUMENTS;
	OP_ASSIGN;
	OP_BIG;
	OP_BIN_CONSTANT;
	OP_BITRANGE;
	OP_BITRANGE2;
	OP_BITRANGES;
	OP_BIT_PATTERN;
	OP_BOOL_AND;
	OP_BOOL_OR;
	OP_BOOL_XOR;
	OP_BUILD;
	OP_CALL;
	OP_CONCATENATE;
	OP_CONSTRUCTOR;
	OP_CONTEXT;
	OP_CONTEXT_BLOCK;
	OP_CROSSBUILD;
	OP_CTLIST;
	OP_DEC;
	OP_DECLARATIVE_SIZE;
	OP_DEC_CONSTANT;
	OP_DEFAULT;
	OP_DEREFERENCE;
	OP_DISPLAY;
	OP_DIV;
	OP_ELLIPSIS;
	OP_ELLIPSIS_RIGHT;
	OP_EMPTY_LIST;
	OP_ENDIAN;
	OP_EQUAL;
	OP_EXPORT;
	OP_FADD;
	OP_FDIV;
	OP_FEQUAL;
	OP_FGREAT;
	OP_FGREATEQUAL;
	OP_FIELDDEF;
	OP_FIELDDEFS;
	OP_FIELD_MODS;
	OP_FLESS;
	OP_FLESSEQUAL;
	OP_FMULT;
	OP_FNEGATE;
	OP_FNOTEQUAL;
	OP_FSUB;
	OP_GOTO;
	OP_GREAT;
	OP_GREATEQUAL;
	OP_HEX;
	OP_HEX_CONSTANT;
	OP_IDENTIFIER;
	OP_IDENTIFIER_LIST;
	OP_IF;
	OP_INTBLIST;
	OP_INVERT;
	OP_JUMPDEST_ABSOLUTE;
	OP_JUMPDEST_DYNAMIC;
	OP_JUMPDEST_LABEL;
	OP_JUMPDEST_RELATIVE;
	OP_JUMPDEST_SYMBOL;
	OP_LABEL;
	OP_LEFT;
	OP_LESS;
	OP_LESSEQUAL;
	OP_LITTLE;
	OP_LOCAL;
	OP_MACRO;
	OP_MULT;
	OP_NAMES;
	OP_NEGATE;
	OP_NIL;
    OP_NOFLOW;
    OP_NOP;
    OP_NOT;
	OP_NOTEQUAL;
	OP_NOT_DEFAULT;
	OP_NO_CONTEXT_BLOCK;
	OP_NO_FIELD_MOD;
	OP_OR;
	OP_PARENTHESIZED;
	OP_PCODE;
	OP_PCODEOP;
	OP_QSTRING;
	OP_REM;
	OP_RETURN;
	OP_RIGHT;
	OP_SDIV;
	OP_SECTION_LABEL;
	OP_SEMANTIC;
	OP_SEQUENCE;
	OP_SGREAT;
	OP_SGREATEQUAL;
    OP_SIGNED;
    OP_SIZING_SIZE;
	OP_SIZE;
	OP_SLESS;
	OP_SLESSEQUAL;
	OP_SPACE;
	OP_SPACEMODS;
	OP_SREM;
	OP_SRIGHT;
	OP_STRING;
	OP_STRING_OR_IDENT_LIST;
	OP_SUB;
	OP_SUBTABLE;
	OP_TABLE;
	OP_TOKEN;
	OP_TOKEN_ENDIAN;
	OP_TRUNCATION_SIZE;
	OP_TYPE;
	OP_UNIMPL;
	OP_VALUES;
	OP_VARIABLES;
	OP_VARNODE;
	OP_WHITESPACE;
	OP_WILDCARD;
	OP_WITH;
	OP_WORDSIZE;
	OP_XOR;
}

/**
 * This lexer represents the rules that are common to all sleigh lexers. It is also the "default"
 * lexer used at the start of the .slaspec file being compiled. It specifies the tree tokens output
 * within the AST by the parsers as well as all the keywords used throughout the language. Note
 * that 'is' and 'if' are treated as reserved words in the display and semantics parsers,
 * respectively.
 */

// Preprocessor-generated directives
fragment
PP_ESCAPE
	:	'\b'
	;

PP_POSITION
	:	PP_ESCAPE ~('\n'|PP_ESCAPE)* PP_ESCAPE { setText(getText().substring(1, getText().length()-1)); preprocess(getText()); $channel = PREPROC; }
	;

// Reserved words and keywords
RES_WITH		:	'with';

KEY_ALIGNMENT	:	'alignment';
KEY_ATTACH		:	'attach';
KEY_BIG			:	'big';
KEY_BITRANGE	:	'bitrange';
KEY_BUILD		:	'build';
KEY_CALL		:	'call';
KEY_CONTEXT		:	'context';
KEY_CROSSBUILD	:	'crossbuild';
KEY_DEC			:	'dec';
KEY_DEFAULT		:	'default';
KEY_DEFINE		:	'define';
KEY_ENDIAN		:	'endian';
KEY_EXPORT		:	'export';
KEY_GOTO		:	'goto';
KEY_HEX			:	'hex';
KEY_LITTLE		:	'little';
KEY_LOCAL		:	'local';
KEY_MACRO		:	'macro';
KEY_NAMES		:	'names';
KEY_NOFLOW		:	'noflow';
KEY_OFFSET		:	'offset';
KEY_PCODEOP		:	'pcodeop';
KEY_RETURN		:	'return';
KEY_SIGNED		:	'signed';
KEY_SIZE		:	'size';
KEY_SPACE		:	'space';
KEY_TOKEN		:	'token';
KEY_TYPE		:	'type';
KEY_UNIMPL		:	'unimpl';
KEY_VALUES		:	'values';
KEY_VARIABLES	:	'variables';
KEY_WORDSIZE	:	'wordsize';


// Grouping, block, and sectioning symbols
LBRACE			:	'{';
RBRACE			:	'}';
LBRACKET		:	'[';
RBRACKET		:	']';
LPAREN			:	'(';
RPAREN			:	')';

// Miscellaneous
ELLIPSIS		:	'...';
UNDERSCORE		:	'_';
COLON			:	':';
COMMA			:	',';
EXCLAIM			:	'!';
TILDE			:	'~';
SEMI			:	';';

// ----------
// Operators:
// ----------

ASSIGN			:	'=';

// Comparisons
EQUAL			:	'==';
NOTEQUAL		:	'!=';
LESS			:	'<';
GREAT			:	'>';
LESSEQUAL		:	'<=';
GREATEQUAL		:	'>=';

// Boolean and bitwise logic operations
BOOL_OR			:	'||';
BOOL_XOR		:	'^^';
BOOL_AND		:	'&&';
PIPE			:	'|';
CARET			:	'^';
AMPERSAND		:	'&';

// Shifting operations
LEFT			:	'<<';
RIGHT			:	'>>';

// Arithmetic operations
PLUS			:	'+';
MINUS			:	'-';
ASTERISK		:	'*';
SLASH			:	'/';
PERCENT			:	'%';

// Explicitly named boolean operations
SPEC_OR			:	'$or';
SPEC_AND		:	'$and';
SPEC_XOR		:	'$xor';


// IDs, Literals

IDENTIFIER
	:	ALPHAUP (ALPHAUP | DIGIT)*
	;

fragment
ALPHA
	:	'A'..'Z'
	|	'a'..'z'
	;

fragment
ALPHAUP
	:	ALPHA
	|	'_'
	|	'.'
	;

fragment
DIGIT
	:	'0'..'9'
	;

QSTRING
    :   '"' (ESCAPE | ~('\\' | '"'))* '"' { setText(getText().substring(1, getText().length()-1)); }
    ;

fragment
ESCAPE
    :   '\\' ('b' | 't' | 'n' | 'f' | 'r' | '\"' | '\'' | '\\')
    |   UNICODE_ESCAPE
    |   OCTAL_ESCAPE
    ;

fragment
OCTAL_ESCAPE
    :   '\\' ('0'..'3') ('0'..'7') ('0'..'7')
    |   '\\' ('0'..'7') ('0'..'7')
    |   '\\' ('0'..'7')
    ;

fragment
UNICODE_ESCAPE
    :   '\\' 'u' HEXDIGIT HEXDIGIT HEXDIGIT HEXDIGIT
    ;

fragment
HEXDIGIT
    :   DIGIT
    |   'a'..'f'
    |   'A'..'F'
    ;

DEC_INT
	:	DIGIT+
	;

HEX_INT
	:	'0x' (HEXDIGIT)+
	;

BIN_INT
	:	'0b' (BINDIGIT)+
	;

fragment
BINDIGIT
	:	'0'..'1'
	;

// Ignored things, Errors

LINECOMMENT
	:	'#' ~('\n' | '\r')* EOL { $channel = COMMENT; }
	;

fragment
EOL
	:	('\r'? '\n')=> '\r'? '\n'
	|	'\r'
	;

CPPCOMMENT
	:	'//'
	{
		SleighToken st = new SleighToken(_type, getText());
		UnwantedTokenException ute = new UnwantedTokenException(0, input);
		ute.token = st;
		reportError(ute);
	}
	;

WS
	:	(' ' | '\t' | '\r' | '\n')+ { $channel = HIDDEN; }
	;

UNKNOWN
	:	.
	{
		SleighToken st = new SleighToken(_type, getText());
		UnwantedTokenException ute = new UnwantedTokenException(0, input);
		ute.token = st;
		reportError(ute);
	}
	;
