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
package docking.widgets.fieldpanel.support;

import java.math.BigInteger;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;

public class FieldSelectionHelper {

	public static boolean isStringSelection(FieldSelection selection) {
		if (selection.getNumRanges() != 1) {
			return false;
		}
		FieldRange fieldRange = selection.getFieldRange(0);
		FieldLocation start = fieldRange.getStart();
		FieldLocation end = fieldRange.getEnd();
		return start.getIndex().equals(end.getIndex()) && start.fieldNum == end.fieldNum;

	}

	/** 
	 * Gets the selected text that pertains to an individual field.  Null is returned if the
	 * given selection spans more than one field.
	 */
	public static String getFieldSelectionText(FieldSelection selection, FieldPanel panel) {
		if (!isStringSelection(selection)) {
			return null;
		}
		return getTextForField(selection.getFieldRange(0), panel);
	}

	/** Returns the text within the given selection. */
	public static String getAllSelectedText(FieldSelection selection, FieldPanel panel) {
		StringBuffer buffy = new StringBuffer();
		int numRanges = selection.getNumRanges();
		for (int i = 0; i < numRanges; i++) {
			FieldRange fieldRange = selection.getFieldRange(i);
			buffy.append(getTextForRange(fieldRange, panel));
			if (i != numRanges - 1) {
				buffy.append(' ');
			}
		}

		// remove any whitespace on the ends, as it doesn't offer any value to text selections
		return buffy.toString().trim();
	}

	private static String getTextForField(FieldRange fieldRange, FieldPanel panel) {
		FieldLocation startLoc = fieldRange.getStart();
		BigInteger index = startLoc.getIndex();
		int fieldNum = startLoc.fieldNum;
		int startRow = startLoc.row;
		int startCol = startLoc.col;
		FieldLocation endLoc = fieldRange.getEnd();
		int endRow = endLoc.row;
		int endCol = endLoc.col;

		Layout layout = panel.getLayoutModel().getLayout(index);
		if (layout == null) {
			return null;
		}
		Field field = layout.getField(fieldNum);
		if (field == null) {
			return null;
		}
		String text = field.getText();
		if (text == null) {
			return null;
		}
		int startPos = field.screenLocationToTextOffset(startRow, startCol);
		int endPos = field.screenLocationToTextOffset(endRow, endCol);
		if (startPos < 0 || startPos >= text.length() || endPos < 0 || endPos > text.length()) {
			return null;
		}
		return text.substring(startPos, endPos);
	}

	private static String getTextForRange(FieldRange fieldRange, FieldPanel panel) {
		FieldLocation startLoc = fieldRange.getStart();
		FieldLocation endLoc = fieldRange.getEnd();
		BigInteger startIndex = startLoc.getIndex();
		int startFieldNumber = startLoc.fieldNum;
		BigInteger endIndex = endLoc.getIndex();

		StringBuffer buffy = new StringBuffer();
		for (BigInteger i = startIndex; i.compareTo(endIndex) <= 0; i = i.add(BigInteger.ONE)) {
			Layout layout = panel.getLayoutModel().getLayout(i);
			String text = null;
			if (i.equals(startIndex)) {
				if (i.equals(endIndex)) {
					// only one index, use the end values
					text =
						getTextForFieldsInLayout(layout, fieldRange, startFieldNumber,
							endLoc.getFieldNum());
				}
				else {
					text =
						getTextForFieldsInLayout(layout, fieldRange, startFieldNumber,
							layout.getNumFields());
				}
			}
			else if (!i.equals(endIndex)) {
				text = getTextForFieldsInLayout(layout, fieldRange, 0, layout.getNumFields());
			}
			else {
				text = getTextForFieldsInLayout(layout, fieldRange, 0, endLoc.getFieldNum());
			}
			buffy.append(text);

			if (!i.equals(endIndex)) {
				buffy.append(' '); // add space between lines
			}
		}
		return buffy.toString();
	}

	private static String getTextForFieldsInLayout(Layout layout, FieldRange fieldRange,
			int startFieldNumber, int endFieldNumber) {
		StringBuffer buffy = new StringBuffer();
		for (int i = startFieldNumber; i < endFieldNumber; i++) {
			Field field = layout.getField(i);
			buffy.append(field.getTextWithLineSeparators());
			if (i != endFieldNumber - 1) {
				buffy.append(' ');
			}
		}
		return buffy.toString();
	}
}
