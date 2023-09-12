/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.tokenizer;

import ghidra.app.plugin.querylanguage.tokenizer.api.ContinuedMatcher;
import ghidra.app.plugin.querylanguage.tokenizer.api.InitiatorMatcher;
import ghidra.app.plugin.querylanguage.tokenizer.api.StringStream;

public enum TokenType {
	COMMA(',', (a, b) -> false),
	COMMENT(';', '\n'),
	PICKLED_CANARY_COMMAND('`', (stream, index) -> index == 1 || stream.peekBehind() != '`'),
	INSTRUCTION_COMPONENT(
			(character) -> Character.isLetterOrDigit(character) || !"\n;,`".contains(Character.toString(character)),
			(stream, ignored) -> !"\n, ".contains(Character.toString(stream.peek()))
					&& !PICKLED_CANARY_COMMAND.matchCanStart(stream.peek())),
	WHITESPACE(Character::isWhitespace),
	METADATA((character) -> true, (a, b) -> false),;

	TokenType(final InitiatorMatcher initiatorMatcher, final ContinuedMatcher continuedMatcher) {
		this.initiatorMatcher = initiatorMatcher;
		this.continuedMatcher = continuedMatcher;
	}

	TokenType(final char initiator, final ContinuedMatcher continuedMatcher) {
		this.initiatorMatcher = (character) -> character == initiator;
		this.continuedMatcher = continuedMatcher;
	}

	TokenType(final char initiator, final char terminator) {
		this.initiatorMatcher = (character) -> character == initiator;
		this.continuedMatcher = (stream, ignored) -> stream.peek() != terminator;
	}

	TokenType(final InitiatorMatcher initiatorMatcher) {
		this.initiatorMatcher = initiatorMatcher;
		this.continuedMatcher = (stream, ignored) -> initiatorMatcher.op(stream.peek());
	}

	public boolean matchCanStart(final char character) {
		return initiatorMatcher.op(character);
	}

	public boolean matchShouldContinue(final StringStream stream, final int index) {
		return continuedMatcher.op(stream, index);
	}

	private final InitiatorMatcher initiatorMatcher;
	private final ContinuedMatcher continuedMatcher;
}
