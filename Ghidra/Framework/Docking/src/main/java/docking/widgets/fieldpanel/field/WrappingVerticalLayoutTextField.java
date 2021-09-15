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

import docking.widgets.fieldpanel.support.*;

/**
 * A text field meant to take a string of text and wrap as needed.
 */
public class WrappingVerticalLayoutTextField extends VerticalLayoutTextField {

	/**
	 * This constructor will create a text field from an single AttributedString.  The string will
	 * be word wrapped.
	 * 
	 * @param textElement the element to display
	 * @param startX  the x position to draw the string
	 * @param width   the max width allocated to this field
	 * @param maxLines the max number of lines to display
	 * @param hlFactory the highlight factory
	 */
	public WrappingVerticalLayoutTextField(FieldElement textElement, int startX, int width,
			int maxLines, HighlightFactory hlFactory) {
		super(FieldUtils.wrap(textElement, width), startX, width, maxLines, hlFactory, " ");
	}

	/**
	 * This constructor will create a text field from an single AttributedString.  The string will
	 * be word wrapped.
	 * 
	 * @param textElement is the element to display
	 * @param startX is the position to draw the string
	 * @param width is the max width allocated to this field
	 * @param maxLines is the max number of lines to display
	 * @param hlFactory is the highlight factory
	 * @param breakOnWhiteSpace is true if wrapping should break on word boundaries
	 */
	public WrappingVerticalLayoutTextField(FieldElement textElement, int startX, int width,
			int maxLines, HighlightFactory hlFactory, boolean breakOnWhiteSpace) {
		super(FieldUtils.wrap(textElement, width, breakOnWhiteSpace), startX, width, maxLines,
			hlFactory, " ");
	}

	@Override
	public RowColLocation dataToScreenLocation(int dataRow, int dataColumn) {
		// we represent one data row that may be split into multiple screen rows
		return textOffsetToScreenLocation(dataColumn);
	}
}
