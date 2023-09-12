/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.tokenizer.api;

public class StringStream {

	private final char[] characters;
	private final String originalString;
	private int position = 0;

	public StringStream(final String originalString) {
		this.originalString = originalString;
		this.characters = originalString.toCharArray();
	}

	private int clampOffset(final int offset) {
		return Math.min(position + offset, characters.length);
	}

	private void incrementLocation(final int by) {
		position = clampOffset(by);
	}

	private void incrementLocation() {
		incrementLocation(1);
	}

	public int position() {
		return position;
	}

	public boolean tokensRemain() {
		return position != characters.length - 1;
	}

	private char peekAround(final int offset) {
		// Makes no sense to add takeAround. "Uhhh I'd like to take negative five of
		// your characters." - no one, ever
		final var index = position + offset;
		assert (0 <= index && index < characters.length);
		return characters[index];
	}

	public char peek() {
		return characters[clampOffset(0)];
	}

	public char peekBehind(final int offset) {
		return peekAround(-offset);
	}

	public char peekBehind() {
		return peekBehind(1);
	}

	public String peekString(final int chars) {
		return originalString.substring(position, clampOffset(chars));
	}

	public char take() {
		final var out = peek();
		incrementLocation();
		return out;
	}

	public String takeString(final int chars) {
		final var out = peekString(chars);
		incrementLocation(chars);
		return out;
	}

	public String takeWhile(final ContinuedMatcher continuedMatcher) {
		final var stringBuilder = new StringBuilder();

		var i = 0;
		do {
			stringBuilder.append(take());
		} while (continuedMatcher.op(this, ++i) && tokensRemain());

		return stringBuilder.toString();
	}
}
