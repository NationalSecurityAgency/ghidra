grammar BooleanExpression;

tokens {
	OP_OR = '||';
	OP_XOR = '^^';
	OP_AND = '&&';
	OP_NOT = '!';
	OP_EQ = '==';
	OP_NEQ = '!=';

	KEY_DEFINED = 'defined';
}

@members {
	public ExpressionEnvironment env;

	public static void main(String[] args) {
		try {
			CharStream input = new ANTLRFileStream(args[0]);
			BooleanExpressionLexer lex = new BooleanExpressionLexer(input);
			CommonTokenStream tokens = new CommonTokenStream(lex);
			BooleanExpressionParser parser = new BooleanExpressionParser(tokens);
			boolean result = parser.expression();
			System.out.println(result);
		} catch(Throwable t) {
			t.printStackTrace();
		}
    }
}

expression returns [boolean b]
	: e=expr EOF { $b = $e.b; }
	;

expr returns [boolean b]
	:	e=expr_or { $b = $e.b; }
	;

expr_or returns [boolean b]
	:	lhs=expr_xor { $b = $lhs.b; } (OP_OR rhs=expr_xor { $b = $b || $rhs.b; })*
	;

expr_xor returns [boolean b]
	:	lhs=expr_and { $b = $lhs.b; } (OP_XOR rhs=expr_and { $b = $b ^ $rhs.b; })*
	;

expr_and returns [boolean b]
	:	lhs=expr_not { $b = $lhs.b; } (OP_AND rhs=expr_not { $b = $b && $rhs.b; })*
	;

expr_not returns [boolean b]
	:	OP_NOT e=expr_paren { $b = ! $e.b; }
	|	e=expr_paren        { $b = $e.b; }
	|	e=expr_eq           { $b = $e.b; }
	|	KEY_DEFINED '(' id=IDENTIFIER ')' { $b = env.lookup($id.text) != null; }
	;

expr_paren returns [boolean b]
	:	'(' e=expr ')' { $b = $e.b; }
	;

expr_eq returns [boolean b]
	:	lhs=expr_term OP_EQ rhs=expr_term  { $b = env.equals(lhs, rhs); }
	|	lhs=expr_term OP_NEQ rhs=expr_term { $b = !env.equals(lhs, rhs); }
	;

expr_term returns [String s]
	:	id=IDENTIFIER { $s = env.lookup($id.text);
						if ($s == null)
							env.reportError("Macro: "+ $id.text + " is undefined");
					  }
	|	qs=QSTRING    {$s = $qs.text.substring(1, $qs.text.length() - 1); }
	;

IDENTIFIER
    :   (ALPHA | '_' | DIGIT)+
    ;

QSTRING
    :   '"' (ESCAPE | ~('\\' | '"'))* '"'
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
    :   '0'..'9'
    |   'a'..'f'
    |   'A'..'F'
    ;

fragment
DIGIT
    :   '0'..'9'
    ;

fragment
ALPHA
    :   'A'..'Z'
    |   'a'..'z'
    ;

WS
    :   (' ' | '\t' | '\r' | '\n')+ { $channel = HIDDEN; }
    ;
