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

import ghidra.util.exception.AssertException;

public class EmptyVariableTextLine extends VariableTextLine implements PlaceHolderLine {

	private int numberOfCharacters;

	public EmptyVariableTextLine(int numberOfCharacters) {
		// pass up empty text that represents space for the type and name
		super(buildDisplayText(numberOfCharacters >> 1), buildDisplayText(numberOfCharacters >> 1),
			null);
		this.numberOfCharacters = numberOfCharacters;
	}

	private static String buildDisplayText(int numberOfCharacters) {
		StringBuffer buffy = new StringBuffer("<TT>");
		for (int i = 0; i < numberOfCharacters; i++) {
			buffy.append(HTMLDataTypeRepresentation.HTML_SPACE);
		}
		buffy.append("</TT>");
		return buffy.toString();
	}

	@Override
	public ValidatableLine copy() {
		return new EmptyVariableTextLine(numberOfCharacters);
	}

	@Override
	public void updateColor(ValidatableLine otherValidatableLine, Color invalidColor) {
		if (invalidColor == null) {
			throw new NullPointerException("Color cannot be null");
		}

		if (otherValidatableLine == null ||
			(otherValidatableLine instanceof EmptyVariableTextLine)) {
			return;
		}
		if (!(otherValidatableLine instanceof VariableTextLine)) {
			throw new AssertException("VariableTextLine can only be matched against other " +
				"VariableTextLine implementations.");
		}
		VariableTextLine otherLine = (VariableTextLine) otherValidatableLine;

		// since we are the empty line, the other line is all a mismatch
		otherLine.setAllColors(invalidColor);
	}

	@Override
	public boolean matches(ValidatableLine otherValidatableLine) {
		return false;
	}

	@Override
	public boolean isValidated() {
		return true;
	}

	@Override
	boolean matchesName(String otherName) {
		return false;
	}

	@Override
	boolean matchesType(String otherType) {
		return false;
	}

	@Override
	public String toString() {
		return "<EmptyVariableTextLine>";
	}
}
