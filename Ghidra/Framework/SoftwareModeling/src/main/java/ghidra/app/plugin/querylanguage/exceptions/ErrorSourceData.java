/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.exceptions;

import java.util.Objects;

import ghidra.app.plugin.querylanguage.tokenizer.Line;

public final class ErrorSourceData {

	private final Line line;
	private final String erroringSymbol;

	public ErrorSourceData(Line line, String erroringSymbol) {
		this.line = line;
		this.erroringSymbol = erroringSymbol;
	}

	public Line line() {
		return line;
	}

	public String erroringSymbol() {
		return erroringSymbol;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null || obj.getClass() != this.getClass()) {
			return false;
		}
		var that = (ErrorSourceData) obj;
		return Objects.equals(this.line, that.line) && Objects.equals(this.erroringSymbol, that.erroringSymbol);
	}

	@Override
	public int hashCode() {
		return Objects.hash(line, erroringSymbol);
	}

	@Override
	public String toString() {
		return "ErrorSourceData[line=" + line + ", erroringSymbol=" + erroringSymbol + ']';
	}
}
