/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.exceptions;

public class SyntaxErrorException extends RuntimeException {

	public SyntaxErrorException(String message) {
		super(message);
	}

	public SyntaxErrorException(final String message, final ErrorSourceData errorSourceData) {

		final var ERROR_FORMATTING_STRING = "\nError: %s\nStarting on line: %d (%s)\nBegan on symbol(s): %s\n";

		final var lineNumber = errorSourceData.line().number();
		final var lineText = errorSourceData.line().text();
		final var erroringSymbol = errorSourceData.erroringSymbol();

		final var error = String.format(ERROR_FORMATTING_STRING, message, lineNumber, lineText, erroringSymbol);

		throw new SyntaxErrorException(error);
	}
}
