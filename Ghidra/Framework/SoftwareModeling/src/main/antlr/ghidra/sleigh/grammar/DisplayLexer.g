lexer grammar DisplayLexer;

options {
	superClass = AbstractSleighLexer;
	tokenVocab = SleighLexer;
}

import BaseLexer;

@members {
	@Override
	public void setEnv(ParsingEnvironment env) {
		super.setEnv(env);
		gBaseLexer.setEnv(env);
	}
}

/**
 * This is the lexer used for the display portion of the sleigh grammar. It reserves the word 'is'
 * so that it can clearly tell where the display portion ends. It also adds three special symbols
 * that would not otherwise be recognized by the core lexer, so that language modelers can use them
 * in assembly print pieces. Furthermore, it moves whitespace into the default channel so that
 * language modelers can control whether or not whitespace is printed.
 */

// Characters without meaning except for the display portion
DISPCHAR
	:	'@' | '$' | '?'
	;

// Override this, and parse # as a print piece
LINECOMMENT
	:	'#'
	;

// Whitespace must be processed
WS
	:	(' ' | '\t' | '\r' | '\n')+
	;

// Reserved words
RES_IS			:	'is';
