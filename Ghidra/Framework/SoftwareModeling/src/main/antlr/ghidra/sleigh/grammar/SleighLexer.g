lexer grammar SleighLexer;

options {
	superClass = AbstractSleighLexer;
}

import BaseLexer, DisplayLexer, SemanticLexer;

/**
 * See README.txt (near the bottom) for more information.
 *
 * This grammar exists solely to tease a combined token vocabulary from all of the lexers. The
 * resulting vocabulary is used by all of the other grammars (parsers and lexers) except for
 * BooleanExpression.
 *
 * The output of this grammar (except for the .tokens file) is discarded by build.gradle.
 */

// A dummy rule. It reuses a name to avoid adding an unnecessary name to the vocabulary.
UNKNOWN:	'*****************************************';
