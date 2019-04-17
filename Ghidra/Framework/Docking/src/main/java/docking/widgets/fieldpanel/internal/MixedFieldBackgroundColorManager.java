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
package docking.widgets.fieldpanel.internal;

import java.awt.Color;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.support.*;

public class MixedFieldBackgroundColorManager implements FieldBackgroundColorManager {

	private final Color selectionColor;
	private final FieldSelection selection;
	private final BigInteger index;
	private final int fieldNum;
	private final MixedLayoutBackgroundColorManager layoutSelection;
	private final Color backgroundColor;

	public MixedFieldBackgroundColorManager(BigInteger index, int fieldNum,
			MixedLayoutBackgroundColorManager layoutSelection, Color selectionColor,
			Color backgroundColor) {
		this.index = index;
		this.fieldNum = fieldNum;
		this.layoutSelection = layoutSelection;
		this.backgroundColor = backgroundColor;
		this.selection = layoutSelection.getSelection();
		this.selectionColor = selectionColor;
	}

	public List<Highlight> getSelectionHighlights(int row) {
		FieldLocation start = new FieldLocation(index, fieldNum, row, 0);
		FieldLocation end = new FieldLocation(index, fieldNum, row + 1, 0);
		FieldSelection intersect = selection.intersect(new FieldRange(start, end));
		List<Highlight> highlights = new ArrayList<Highlight>(intersect.getNumRanges());
		for (int i = 0; i < intersect.getNumRanges(); i++) {
			FieldRange range = intersect.getFieldRange(i);
			int min = range.getStart().col;
			int max = range.getEnd().row == row ? range.getEnd().col : Integer.MAX_VALUE;
			highlights.add(new Highlight(min, max, selectionColor));
		}
		return highlights;
	}

	public Color getBackgroundColor() {
		if (layoutSelection.getBackgroundColor() == backgroundColor) {
			return null;
		}
		return backgroundColor;
	}

	public Color getPaddingColor(int padIndex) {
		return layoutSelection.getPaddingColor(fieldNum + padIndex);
	}

}
