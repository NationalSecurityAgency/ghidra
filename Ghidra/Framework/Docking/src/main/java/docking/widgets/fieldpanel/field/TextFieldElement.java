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
package docking.widgets.fieldpanel.field;

public class TextFieldElement extends AbstractTextFieldElement {

	public TextFieldElement(AttributedString attributedString, int row, int column) {
		super(attributedString, row, column);
	}

	@Override
	public FieldElement substring(int start, int end) {
		AttributedString as = attributedString.substring(start, end);
		if (as == attributedString) {
			return this;
		}
		return new TextFieldElement(as, row, column + start);
	}

	@Override
	public FieldElement replaceAll(char[] targets, char replacement) {
		return new TextFieldElement(attributedString.replaceAll(targets, replacement), row, column);
	}
}
