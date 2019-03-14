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
package docking.widgets.fieldpanel.field;

import java.awt.*;
import java.util.List;

import javax.swing.JComponent;

/**
 * An AttributedString that is composed of other AttributedStrings.
 */
public class CompositeAttributedString extends AttributedString {

	private String fullText;
	private AttributedString[] attributedStrings;
	private int heightAbove = -1;
	private int heightBelow = -1;

	public CompositeAttributedString(List<AttributedString> stringList) {
		this(stringList.toArray(new AttributedString[stringList.size()]));
	}

	public CompositeAttributedString(AttributedString[] attributedStrings) {
		this.attributedStrings = attributedStrings;
	}

	private IndexedOffset getIndexedOffsetForCharPosition(int charPosition) {
		int n = 0;
		for (int i = 0; i < attributedStrings.length; i++) {
			int len = attributedStrings[i].getText().length();
			if (charPosition < n + len) {
				return new IndexedOffset(i, charPosition - n);
			}
			n += len;
		}

		return new IndexedOffset(attributedStrings.length - 1,
			attributedStrings[attributedStrings.length - 1].getText().length());
	}

	@Override
	public int getColumnPosition(int width) {
		int remainingWidth = width;
		int totalCharacters = 0;
		for (int i = 0; i < attributedStrings.length; i++) {
			int nextWidth = attributedStrings[i].getStringWidth();
			if (nextWidth >= remainingWidth) {
				totalCharacters += attributedStrings[i].getColumnPosition(remainingWidth);
				break;
			}
			remainingWidth -= nextWidth;
			totalCharacters += attributedStrings[i].length();
		}

		return totalCharacters;
	}

	@Override
	public Color getColor(int index) {
		IndexedOffset pos = getIndexedOffsetForCharPosition(index);
		return attributedStrings[pos.index].getColor(pos.offset);
	}

	@Override
	public FontMetrics getFontMetrics(int charIndex) {
		IndexedOffset pos = getIndexedOffsetForCharPosition(charIndex);
		return attributedStrings[pos.index].getFontMetrics(pos.offset);
	}

	@Override
	public int getHeightAbove() {
		if (heightAbove < 0) {
			heightAbove = 0;
			for (int i = 0; i < attributedStrings.length; i++) {
				heightAbove = Math.max(heightAbove, attributedStrings[i].getHeightAbove());
			}
		}
		return heightAbove;
	}

	@Override
	public int getHeightBelow() {
		if (heightBelow < 0) {
			heightBelow = 0;
			for (int i = 0; i < attributedStrings.length; i++) {
				heightBelow = Math.max(heightBelow, attributedStrings[i].getHeightBelow());
			}
		}
		return heightBelow;
	}

	// =============================================================================================
	// font metrics methods
	// =============================================================================================

	@Override
	public int getStringWidth() {
		if (textWidth == -1) {
			textWidth = 0;
			for (int i = 0; i < attributedStrings.length; i++) {
				textWidth += attributedStrings[i].getStringWidth();
			}
		}
		return textWidth;
	}

	@Override
	public String getText() {
		if (fullText == null) {
			StringBuffer buffer = new StringBuffer();
			for (int i = 0; i < attributedStrings.length; i++) {
				buffer.append(attributedStrings[i].getText());
			}
			fullText = buffer.toString();
		}
		return fullText;
	}

	// =============================================================================================
	// paint methods
	// =============================================================================================

	@Override
	public void paint(JComponent c, Graphics g, int x, int y) {
		int xPos = x;
		for (int i = 0; i < attributedStrings.length; i++) {
			attributedStrings[i].paint(c, g, xPos, y);
			xPos += attributedStrings[i].getStringWidth();
		}
	}

	@Override
	public AttributedString replaceAll(char[] targets, char repacement) {
		AttributedString[] newStrings = new AttributedString[attributedStrings.length];
		for (int i = 0; i < attributedStrings.length; i++) {
			newStrings[i] = attributedStrings[i].replaceAll(targets, repacement);
		}
		return new CompositeAttributedString(newStrings);
	}

	@Override
	public AttributedString substring(int start) {
		return substring(start, getText().length());
	}

	@Override
	public AttributedString substring(int start, int end) {
		IndexedOffset startPos = getIndexedOffsetForCharPosition(start);
		IndexedOffset endPos = getIndexedOffsetForCharPosition(end);

		// start and end are in the same attributed string
		if (startPos.index == endPos.index) {
			AttributedString asStart = attributedStrings[startPos.index];
			return asStart.substring(startPos.offset, endPos.offset);
		}

		// 1) find the new start and end attributed strings
		AttributedString asStart = attributedStrings[startPos.index];
		AttributedString newStart = asStart.substring(startPos.offset);
		AttributedString asEnd = attributedStrings[endPos.index];
		AttributedString newEnd = asEnd.substring(0, endPos.offset);

		// 2) add the strings in between
		AttributedString[] newStrings = new AttributedString[(endPos.index - startPos.index) + 1];

		// copy into the second position until the second to last position, as the first and
		// last positions will be filled in later
		System.arraycopy(attributedStrings, startPos.index + 1, newStrings, 1,
			newStrings.length - 1);

		// 3) add the new start and new end into the respective positions
		newStrings[0] = newStart;
		newStrings[newStrings.length - 1] = newEnd;
		return new CompositeAttributedString(newStrings);
	}

	private static class IndexedOffset {
		int index;
		int offset;

		IndexedOffset(int index, int offset) {
			this.index = index;
			this.offset = offset;
		}
	}

}
