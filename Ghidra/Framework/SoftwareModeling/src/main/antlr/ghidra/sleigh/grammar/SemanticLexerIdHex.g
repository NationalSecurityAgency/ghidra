lexer grammar SemanticLexerIdHex;

options {
	superClass = AbstractSleighLexer;
	tokenVocab = SleighLexer;
}

import SemanticLexer;

@members {
	@Override
	public void setEnv(ParsingEnvironment env) {
		super.setEnv(env);
		gSemanticLexer.setEnv(env);
		// HACK to fix ANTLR?
		gBaseLexer = gSemanticLexer.gBaseLexer;
	}
}

IDENTIFIER
	:   ALPHAUP (ALPHAUP | DIGIT)*
	;

DEF_INT
	:   DIGIT (HEXDIGIT)*
	;

BIN_INT
	:   '********THIS_SHOULD_NEVER_MATCH********'
	;
