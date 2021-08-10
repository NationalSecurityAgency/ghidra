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

public class EmptyDataTypeLine extends DataTypeLine implements PlaceHolderLine {
	public EmptyDataTypeLine() {
		super("", "", "", null);
	}

	@Override
	public ValidatableLine copy() {
		return new EmptyDataTypeLine();
	}

	@Override
	public void updateColor(ValidatableLine otherValidatableLine, Color invalidColor) {
		if (invalidColor == null) {
			throw new NullPointerException("Color cannot be null");
		}

		if (otherValidatableLine == null || (otherValidatableLine instanceof EmptyDataTypeLine)) {
			return;
		}

		if (!(otherValidatableLine instanceof DataTypeLine)) {
			throw new AssertException("DataTypeLine can only be matched against other " +
				"DataTypeLine implementations.");
		}
		DataTypeLine otherLine = (DataTypeLine) otherValidatableLine;

		// since we are the empty line, the other line is all a mismatch
		otherLine.setAllColors(invalidColor);
	}

	boolean matches(DataTypeLine otherLine) {
		return false;
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
	boolean matchesComment(String otherComment) {
		return false;
	}

	@Override
	public boolean isValidated() {
		return true;
	}

	@Override
	public String toString() {
		return "<Empty Line>";
	}
}
