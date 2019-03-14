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

import ghidra.util.exception.AssertException;

import java.awt.Color;

public class EmptyTextLine extends TextLine implements PlaceHolderLine {

	private int widthInCharacters;

	public EmptyTextLine(int widthInCharacters) {
		super(buildDisplayText(widthInCharacters));
		this.widthInCharacters = widthInCharacters;
	}

	private static String buildDisplayText(int numberOfCharacters) {
		StringBuffer buffy = new StringBuffer();
		for (int i = 0; i < numberOfCharacters; i++) {
			buffy.append(' ');
		}
		return buffy.toString();
	}

	@Override
	public boolean isValidated() {
		return true;
	}

	@Override
	public ValidatableLine copy() {
		return new EmptyTextLine(widthInCharacters);
	}

	@Override
	boolean matches(TextLine otherLine) {
		return false; // empty line never match
	}

	@Override
	public void updateColor(ValidatableLine otherValidatableLine, Color invalidColor) {
		if (invalidColor == null) {
			throw new NullPointerException("Color cannot be null");
		}

		if (otherValidatableLine == null || (otherValidatableLine instanceof EmptyTextLine)) {
			return;
		}

		if (!(otherValidatableLine instanceof TextLine)) {
			throw new AssertException("TextLine can only be matched against other "
				+ "TextLine implementations.");
		}
		TextLine otherLine = (TextLine) otherValidatableLine;

		// since we are the empty line, the other line is all a mismatch
		otherLine.setTextColor(invalidColor);
	}

	@Override
	public String toString() {
		return "<FixedWidthEmptyTextLine>";
	}
}
