lexer grammar SemanticLexer;

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
 * This is the lexer used for the semantic portion of the sleigh grammar. It reserves the word 'if'
 * so that, e.g., 'if(a == b) ...', does not appear to be a call to a function named 'if'. All of
 * the operators that start with letters are lexed here only. If they were in the core lexer, then
 * ANTLR would not be able to lex 'f=0' properly. It would anticipate the 'f==' token, but detect a
 * 'mismatch' when it finds a '0' instead of another '='. ANTLRs lexers do not backtrack, so it
 * will never even try IDENTIFIER as it should. Worse yet, switching the lexer into "filter" mode
 * causes it to mis-lex any id starting with a keyword, e.g., contextreg is lexed:
 * KEY_CONTEXT, ID:reg instead of ID:contextreg. Pity. Thus, we only enable these tokens when we
 * know we're parsing the semantic portion.
 */

// Floating-point comparisons
FEQUAL			:	'f==';
FNOTEQUAL		:	'f!=';
FLESS			:	'f<';
FGREAT			:	'f>';
FLESSEQUAL		:	'f<=';
FGREATEQUAL		:	'f>=';

// Floating-point operations
FPLUS			:	'f+';
FMINUS			:	'f-';
FMULT			:	'f*';
FDIV			:	'f/';

// Signed comparisons
SLESS			:	's<';
SGREAT			:	's>';
SLESSEQUAL		:	's<=';
SGREATEQUAL		:	's>=';

// Signed operations
SRIGHT			:	's>>';
SDIV			:	's/';
SREM			:	's%';

// Reserved words
RES_IF			:	'if';
