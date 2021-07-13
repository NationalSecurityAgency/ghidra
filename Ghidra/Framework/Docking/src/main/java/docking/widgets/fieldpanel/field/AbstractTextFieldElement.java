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

import java.awt.Color;
import java.awt.Graphics;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.support.RowColLocation;

/**
 * An object that wraps a string and provides data that describes how to render
 * that string.
 * <p>
 * This class was created as a place to house attributes of rendering that
 * are not described by Java's Font object, like underlining.
 * 
 * 
 */

abstract public class AbstractTextFieldElement implements FieldElement {

	/** the attributed string displayed by this field element */
	protected AttributedString attributedString;
	/** the row within the field where this element begins */
	protected int row;
	/** the offset within the field's row where this element begins */
	protected int column;

	protected AbstractTextFieldElement(AttributedString attributedString, int row, int column) {
		this.attributedString = attributedString;
		this.row = row;
		this.column = column;
	}

	@Override
	public String getText() {
		return attributedString.getText();
	}

	@Override
	public char charAt(int index) {
		return attributedString.getText().charAt(index);
	}

	@Override
	public int length() {
		return getText().length();
	}

//==================================================================================================
// font metrics methods
//==================================================================================================

	@Override
	public int getStringWidth() {
		return attributedString.getStringWidth();
	}

	@Override
	public int getHeightAbove() {
		return attributedString.getHeightAbove();
	}

	@Override
	public int getHeightBelow() {
		return attributedString.getHeightBelow();
	}

	@Override
	public int getMaxCharactersForWidth(int width) {
		return attributedString.getCharPosition(width);
	}

	@Override
	public Color getColor(int charIndex) {
		return attributedString.getColor(charIndex);
	}

	@Override
	public FieldElement getFieldElement(int characterOffset) {
		return this;
	}

	@Override
	public FieldElement substring(int start) {
		return substring(start, attributedString.length());
	}

	@Override
	public String toString() {
		return attributedString.getText();
	}

//==================================================================================================
// location info
//==================================================================================================
	@Override
	public RowColLocation getDataLocationForCharacterIndex(int characterIndex) {
		if (characterIndex < 0 || characterIndex > attributedString.getText().length()) {
			throw new IllegalArgumentException("columnPosition is out of range: " + characterIndex +
				"; range is [0," + attributedString.getText().length() + "]");
		}
		return new RowColLocation(row, column + characterIndex);
	}

	@Override
	public int getCharacterIndexForDataLocation(int dataRow, int dataColumn) {
		if (dataRow == row && (dataColumn >= column) && (dataColumn <= column + length())) {
			return dataColumn - column;
		}

		return -1;
	}

//==================================================================================================
// paint methods
//==================================================================================================

	@Override
	public void paint(JComponent c, Graphics g, int x, int y) {
		attributedString.paint(c, g, x, y);
	}
}
