/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.tokenizer;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import ghidra.app.plugin.querylanguage.exceptions.ErrorSourceData;
import ghidra.app.plugin.querylanguage.exceptions.SyntaxErrorException;
import ghidra.app.plugin.querylanguage.tokenizer.api.StringStream;

public class Tokenizer {

	private final StringStream stream;
	private final LinkedList<Token> tokens;
	private final List<String> lines;

	public Tokenizer(final String toTokenize) {
		final var normalized = toTokenize.replaceAll("\r\n", "\n") + "\n";
		final var usesCarriageReturns = !normalized.equals(toTokenize);

		if (usesCarriageReturns) {
			System.out.println(
					"[LOG : PickledCanary] Carriage returns have been converted to" + " non-carriage returns.");
		}

		this.stream = new StringStream(normalized);
		this.tokens = new LinkedList<>();
		this.lines = normalized.lines().collect(Collectors.toList());
	}

	public LinkedList<Token> tokenize(final boolean shouldCheckForErrors) {
		assert (stream != null);
		assert (tokens != null);
		assert (tokens.isEmpty());

		final var tokenTypes = Arrays.stream(TokenType.values()).toList();
		final var lineNumber = new AtomicInteger(1);

		while (stream.tokensRemain()) {
			// TODO: sanity check
			// assert (0 < lineNumber.get() && lineNumber.get() < lines.size());

			final var nextCharacter = stream.peek();

			final var currentLine = new Line(lineNumber.get(), lines.get(lineNumber.get() - 1));

			// We should never, ever have more than one match. It may be desirable to check
			// if there are multiple matches, and throw errors should that occur. But, for
			// now, that doesn't seem to be worth it.

			final var type = tokenTypes.stream().filter(tokenType -> tokenType.matchCanStart(nextCharacter)).findFirst()
					.orElseThrow(() -> new SyntaxErrorException(
							"Invalid token. (Did you forget to \"close\" a previous expression?)",
							new ErrorSourceData(currentLine, Character.toString(nextCharacter))));

			final var token = new Token(type, stream.takeWhile(type::matchShouldContinue), currentLine);

			tokens.add(token);

			if (shouldCheckForErrors) {
				checkTokenForErrors(token, currentLine);
			}

			updateLineNumber(token, lineNumber);
		}

		return tokens;
	}

	private void updateLineNumber(final Token token, final AtomicInteger lineNumber) {
		if (token.type() != TokenType.WHITESPACE) {
			return;
		}

		for (final var character : token.data().toCharArray()) {
			if (character == '\n') {
				lineNumber.incrementAndGet();
			}
		}
	}

	private void checkTokenForErrors(final Token token, final Line line) {
		final var errorSourceData = new ErrorSourceData(line, token.data());

		if (token.type() == TokenType.PICKLED_CANARY_COMMAND) {
			if (!(token.data().startsWith("`") && token.data().endsWith("`"))) {
				throw new SyntaxErrorException("No start/end found to PickledCanaryCommand. Are your quotes balanced?",
						errorSourceData);
			}

			if (token.data().startsWith("``")) {
				throw new SyntaxErrorException("Read an empty PickledCanaryCommand. Did you forget to fill it in?",
						errorSourceData);
			}
		}
	}
}
