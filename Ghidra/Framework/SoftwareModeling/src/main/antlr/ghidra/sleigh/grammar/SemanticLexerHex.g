lexer grammar SemanticLexerHex;

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

DEF_INT
	:   HEXDIGIT+
	;

IDENTIFIER
	:   ALPHAUP (ALPHAUP | DIGIT)*
	;

BIN_INT
	:   '********THIS_SHOULD_NEVER_MATCH********'
	;
