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
import java.util.List;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.support.RowColLocation;

/**
 * A FieldElement that is composed of other FieldElements.
 */
public class CompositeFieldElement implements FieldElement {

	private FieldElement[] fieldElements;
	private int heightAbove = -1;
	private int heightBelow = -1;
	private int textWidth = -1;
	private String fullText;

	public CompositeFieldElement(List<? extends FieldElement> stringList) {
		this(stringList.toArray(new FieldElement[stringList.size()]));
	}

	public CompositeFieldElement(FieldElement[] fieldElements) {
		this.fieldElements = fieldElements;
	}

	public CompositeFieldElement(FieldElement[] elements, int start, int length) {
		fieldElements = new FieldElement[length];
		System.arraycopy(elements, start, fieldElements, 0, length);
	}

	private IndexedOffset getIndexedOffsetForCharPosition(int charPosition) {
		int n = 0;
		for (int i = 0; i < fieldElements.length; i++) {
			int len = fieldElements[i].getText().length();
			if (charPosition < n + len) {
				return new IndexedOffset(i, charPosition - n);
			}
			n += len;
		}

		return new IndexedOffset(fieldElements.length - 1,
			fieldElements[fieldElements.length - 1].getText().length());
	}

	@Override
	public int getMaxCharactersForWidth(int width) {
		int remainingWidth = width;
		int totalCharacters = 0;
		for (FieldElement fieldElement : fieldElements) {
			int nextWidth = fieldElement.getStringWidth();
			if (nextWidth >= remainingWidth) {
				totalCharacters += fieldElement.getMaxCharactersForWidth(remainingWidth);
				break;
			}
			remainingWidth -= nextWidth;
			totalCharacters += fieldElement.length();
		}

		return totalCharacters;
	}

	@Override
	public Color getColor(int index) {
		IndexedOffset pos = getIndexedOffsetForCharPosition(index);
		return fieldElements[pos.index].getColor(pos.offset);
	}

	@Override
	public char charAt(int index) {
		IndexedOffset pos = getIndexedOffsetForCharPosition(index);
		return fieldElements[pos.index].charAt(pos.offset);
	}

	@Override
	public int getHeightAbove() {
		if (heightAbove < 0) {
			heightAbove = 0;
			for (FieldElement fieldElement : fieldElements) {
				heightAbove = Math.max(heightAbove, fieldElement.getHeightAbove());
			}
		}
		return heightAbove;
	}

	@Override
	public int getHeightBelow() {
		if (heightBelow < 0) {
			heightBelow = 0;
			for (FieldElement fieldElement : fieldElements) {
				heightBelow = Math.max(heightBelow, fieldElement.getHeightBelow());
			}
		}
		return heightBelow;
	}

//==================================================================================================
// FontMetrics methods
//==================================================================================================	

	@Override
	public int getStringWidth() {
		if (textWidth == -1) {
			textWidth = 0;
			for (FieldElement fieldElement : fieldElements) {
				textWidth += fieldElement.getStringWidth();
			}
		}
		return textWidth;
	}

	@Override
	public String getText() {
		if (fullText == null) {
			StringBuffer buffer = new StringBuffer();
			for (FieldElement fieldElement : fieldElements) {
				buffer.append(fieldElement.getText());
			}
			fullText = buffer.toString();
		}
		return fullText;
	}

//==================================================================================================
// Paint methods
//==================================================================================================	

	@Override
	public void paint(JComponent c, Graphics g, int x, int y) {
		int xPos = x;
		for (FieldElement fieldElement : fieldElements) {
			fieldElement.paint(c, g, xPos, y);
			xPos += fieldElement.getStringWidth();
		}
	}

	@Override
	public FieldElement replaceAll(char[] targets, char repacement) {
		FieldElement[] newStrings = new FieldElement[fieldElements.length];
		for (int i = 0; i < fieldElements.length; i++) {
			newStrings[i] = fieldElements[i].replaceAll(targets, repacement);
		}
		return new CompositeFieldElement(newStrings);
	}

	@Override
	public FieldElement substring(int start) {
		return substring(start, getText().length());
	}

	@Override
	public FieldElement substring(int start, int end) {
		IndexedOffset startPos = getIndexedOffsetForCharPosition(start);
		IndexedOffset endPos = getIndexedOffsetForCharPosition(end);

		// start and end are in the same attributed string
		if (startPos.index == endPos.index) {
			FieldElement asStart = fieldElements[startPos.index];
			return asStart.substring(startPos.offset, endPos.offset);
		}

		// 1) find the new start and end attributed strings
		FieldElement asStart = fieldElements[startPos.index];
		FieldElement newStart = asStart.substring(startPos.offset);
		FieldElement asEnd = fieldElements[endPos.index];
		FieldElement newEnd = asEnd.substring(0, endPos.offset);

		// 2) add the strings in between
		FieldElement[] newStrings = new FieldElement[(endPos.index - startPos.index) + 1];

		// copy into the second position until the second to last position, as the first and
		// last positions will be filled in later
		System.arraycopy(fieldElements, startPos.index + 1, newStrings, 1, newStrings.length - 1);

		// 3) add the new start and new end into the respective positions
		newStrings[0] = newStart;
		newStrings[newStrings.length - 1] = newEnd;
		return new CompositeFieldElement(newStrings);
	}

	private static class IndexedOffset {
		int index;
		int offset;

		IndexedOffset(int index, int offset) {
			this.index = index;
			this.offset = offset;
		}
	}

	@Override
	public FieldElement getFieldElement(int column) {
		IndexedOffset startPos = getIndexedOffsetForCharPosition(column);
		return fieldElements[startPos.index].getFieldElement(startPos.offset);
	}

	@Override
	public int length() {
		return getText().length();
	}

//==================================================================================================
// Location Info
//==================================================================================================	

	@Override
	public RowColLocation getDataLocationForCharacterIndex(int characterIndex) {
		IndexedOffset startPos = getIndexedOffsetForCharPosition(characterIndex);
		return fieldElements[startPos.index].getDataLocationForCharacterIndex(startPos.offset);
	}

	@Override
	public int getCharacterIndexForDataLocation(int dataRow, int dataColumn) {
		int columnCount = 0;
		for (int i = fieldElements.length - 1; i >= 0; i--) {
			columnCount += fieldElements[i].length();
			int column = fieldElements[i].getCharacterIndexForDataLocation(dataRow, dataColumn);
			if (column != -1) {
				return length() - columnCount + column;
			}
		}

		return -1;
	}
}
