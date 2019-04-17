/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.viewer.field;

import ghidra.framework.options.CustomOption;
import ghidra.framework.options.SaveState;

public class ArrayElementWrappedOption implements CustomOption {
	private static final String SHOW_MULTI_ELEMENTS_PER_LINE = "showMultiArrayElementsPerLine";
	private static final String ELEMENTS_PER_LINE = "elementsPerLine";
	private static final boolean DEFAULT_SHOW_MULTI = true;
	private static final int DEFAULT_ELEMENTS_PER_LINE = 4;

	private boolean showMultipleArrayElementPerLine = DEFAULT_SHOW_MULTI;
	private int arrayElementsPerLine = DEFAULT_ELEMENTS_PER_LINE;

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ArrayElementWrappedOption)) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		ArrayElementWrappedOption otherOption = (ArrayElementWrappedOption) obj;
		return showMultipleArrayElementPerLine == otherOption.showMultipleArrayElementPerLine &&
			arrayElementsPerLine == otherOption.arrayElementsPerLine;
	}

	@Override
	public int hashCode() {
		int prime = 31;
		int result = 1;
		result = prime * result + (showMultipleArrayElementPerLine ? 1 : 0);
		result = prime * result + arrayElementsPerLine;
		return result;
	}

//==================================================================================================
// Persistence
//==================================================================================================
	@Override
	public void readState(SaveState saveState) {
		showMultipleArrayElementPerLine =
			saveState.getBoolean(SHOW_MULTI_ELEMENTS_PER_LINE, DEFAULT_SHOW_MULTI);
		arrayElementsPerLine = saveState.getInt(ELEMENTS_PER_LINE, DEFAULT_ELEMENTS_PER_LINE);
	}

	@Override
	public void writeState(SaveState saveState) {
		saveState.putBoolean(SHOW_MULTI_ELEMENTS_PER_LINE, showMultipleArrayElementPerLine);
		saveState.putInt(ELEMENTS_PER_LINE, arrayElementsPerLine);
	}

	public boolean showMultipleArrayElementPerLine() {
		return showMultipleArrayElementPerLine;
	}

	public void setShowMultipleArrayElementPerLine(boolean b) {
		this.showMultipleArrayElementPerLine = b;
	}

	public int getArrayElementsPerLine() {
		return arrayElementsPerLine;
	}

	public void setArrayElementsPerLine(int arrayElementsPerLine) {
		if (arrayElementsPerLine <= 0) {
			arrayElementsPerLine = 1;
		}
		this.arrayElementsPerLine = arrayElementsPerLine;
	}
}
