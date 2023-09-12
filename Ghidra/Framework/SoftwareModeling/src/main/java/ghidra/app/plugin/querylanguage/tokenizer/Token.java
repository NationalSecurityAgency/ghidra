/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.tokenizer;

import java.util.Objects;

public final class Token {

	private final TokenType type;
	private final String data;
	private final Line line;

	public Token(TokenType type, String data, Line line) {
		this.type = type;
		this.data = data;
		this.line = line;
	}

	public TokenType type() {
		return type;
	}

	public String data() {
		return data;
	}

	public Line line() {
		return line;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null || obj.getClass() != this.getClass()) {
			return false;
		}
		var that = (Token) obj;
		return Objects.equals(this.type, that.type) && Objects.equals(this.data, that.data)
				&& Objects.equals(this.line, that.line);
	}

	@Override
	public int hashCode() {
		return Objects.hash(type, data, line);
	}

	@Override
	public String toString() {
		return "Token[type=" + type + ", data=" + data + ", line=" + line + ']';
	}
}
