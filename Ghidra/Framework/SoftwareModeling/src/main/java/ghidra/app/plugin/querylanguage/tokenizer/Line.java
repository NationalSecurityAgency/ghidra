/* ###
 * IP: GHIDRA
 **/
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package ghidra.app.plugin.querylanguage.tokenizer;

import java.util.Objects;

public final class Line {

	private final int number;
	private final String text;

	public Line(int number, String text) {
		this.number = number;
		this.text = text;
	}

	public int number() {
		return number;
	}

	public String text() {
		return text;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null || obj.getClass() != this.getClass()) {
			return false;
		}
		var that = (Line) obj;
		return this.number == that.number && Objects.equals(this.text, that.text);
	}

	@Override
	public int hashCode() {
		return Objects.hash(number, text);
	}

	@Override
	public String toString() {
		return "Line[number=" + number + ", text=" + text + ']';
	}
}
