/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.html;

import java.awt.Color;
import java.util.Objects;

import ghidra.util.exception.AssertException;

public class TextLine implements ValidatableLine {

	private String text;
	private Color textColor;

	private ValidatableLine validationLine;

	public TextLine(String text) {
		this.text = Objects.requireNonNull(text);
	}

	@Override
	public ValidatableLine copy() {
		return new TextLine(text);
	}

	@Override
	public String getText() {
		return text;
	}

	@Override
	public boolean isDiffColored() {
		return textColor != null;
	}

	public Color getTextColor() {
		return textColor;
	}

	public void setTextColor(Color color) {
		this.textColor = color;
	}

	boolean matches(TextLine otherLine) {
		return text.equals(otherLine.text);
	}

	@Override
	public String toString() {
		return text + colorStrig();
	}

	private String colorStrig() {
		return textColor == null ? "" : " " + textColor.toString();
	}

	@Override
	public boolean isValidated() {
		return validationLine != null;
	}

	@Override
	public boolean matches(ValidatableLine otherLine) {
		if (!(otherLine instanceof TextLine)) {
			throw new AssertException(
				"TextLine can only be matched against other " + "TextLine implementations.");
		}
		TextLine textLine = (TextLine) otherLine;
		return text.equals(textLine.getText());
	}

	@Override
	public void updateColor(ValidatableLine otherLine, Color invalidColor) {
		if (invalidColor == null) {
			throw new NullPointerException("Color cannot be null");
		}

		if (otherLine == null) {
			setTextColor(invalidColor);
			return;
		}

		if (!(otherLine instanceof TextLine)) {
			throw new AssertException(
				"TextLine can only be matched against other " + "TextLine implementations.");
		}
		TextLine textLine = (TextLine) otherLine;

		if (!matches(textLine)) {
			setTextColor(invalidColor);
			textLine.setTextColor(invalidColor);
		}
	}

	@Override
	public void setValidationLine(ValidatableLine line) {
		if (validationLine == line) {
			return; // already set
		}

		this.validationLine = line;
		line.setValidationLine(this);
		updateColor(line, INVALID_COLOR);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((text == null) ? 0 : text.hashCode());
		result = prime * result + ((textColor == null) ? 0 : textColor.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		TextLine other = (TextLine) obj;
		if (text == null) {
			if (other.text != null) {
				return false;
			}
		}
		else if (!text.equals(other.text)) {
			return false;
		}
		if (textColor == null) {
			if (other.textColor != null) {
				return false;
			}
		}
		else if (!textColor.equals(other.textColor)) {
			return false;
		}
		return true;
	}

}
