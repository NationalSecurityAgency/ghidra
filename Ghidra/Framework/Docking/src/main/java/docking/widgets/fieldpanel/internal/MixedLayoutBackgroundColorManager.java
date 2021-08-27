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
package docking.widgets.fieldpanel.internal;

import java.awt.Color;
import java.math.BigInteger;

import docking.widgets.fieldpanel.support.*;

public class MixedLayoutBackgroundColorManager implements LayoutBackgroundColorManager {

	private final Color backgroundColor;
	private final Color selectionColor;
	private final Color highlightColor;
	private final Color mixedColor;
	
	private final BigInteger index;
	private final FieldSelection selection;
	private final FieldSelection highlight;
	private final Color leftBorderColor;
	private final Color rightBorderColor;

	public MixedLayoutBackgroundColorManager(BigInteger index, FieldSelection selection, FieldSelection highlight,
			Color backgroundColor, Color selectionColor, Color highlightColor,
			Color mixedColor, Color leftBorderColor, Color rightBorderColor) {
	
		this.index = index;
		this.selection = selection;
		this.highlight = highlight;
		this.backgroundColor = backgroundColor;
		this.selectionColor = selectionColor;
		this.highlightColor = highlightColor;
		this.mixedColor = mixedColor;
		this.leftBorderColor = leftBorderColor;
		this.rightBorderColor = rightBorderColor;
	}

	public FieldBackgroundColorManager getFieldBackgroundColorManager(int fieldNum) {
		FieldLocation start = new FieldLocation(index, fieldNum, 0, 0);
		FieldLocation end = new FieldLocation(index, fieldNum+1, 0, 0);
		FieldRange range = new FieldRange(start, end);
		boolean isHighlighted = highlight.containsEntirely(range);
		if (selection.containsEntirely(range)) {
			Color color = isHighlighted ? mixedColor : selectionColor;
			return new FullySelectedFieldBackgroundColorManager(color);
		}
		if (selection.excludesEntirely(range)) {
			if (isHighlighted) {
				return new FullySelectedFieldBackgroundColorManager(highlightColor);
			}
			return EmptyFieldBackgroundColorManager.EMPTY_INSTANCE;
		}
		Color fieldBackgroundColor = isHighlighted ? highlightColor : backgroundColor;
		return new MixedFieldBackgroundColorManager(index, fieldNum, this, selectionColor, fieldBackgroundColor);
	}

	public Color getBackgroundColor() {
		return backgroundColor;
	}

	public Color getPaddingColor(int padIndex) {
		Color paddingColor = null;
		if (padIndex == 0) {
			paddingColor = leftBorderColor;
		}
		else if (padIndex == -1) {
			paddingColor = rightBorderColor;
		}
		else {
			paddingColor = getPaddingColorBetweenFields(padIndex);
		}

		// if paddingColor equals backgroundColor, return null to indicate we don't have to paint it.
		if (paddingColor == backgroundColor) {
			return null;
		}
		return paddingColor;
	}

	private Color getPaddingColorBetweenFields(int padIndex) {
		FieldLocation start = new FieldLocation(index, padIndex-1,Integer.MAX_VALUE,Integer.MAX_VALUE);
		FieldLocation end = new FieldLocation(index, padIndex, 0, 0);
		FieldRange range = new FieldRange(start, end);
		boolean gapSelected = selection.containsEntirely(range);
		boolean gapHighlighted = highlight.containsEntirely(range);
		if (gapSelected && gapHighlighted) {
			return mixedColor;
		}
		if (gapSelected) {
			return selectionColor;
		}
		if (gapHighlighted) {
			return highlightColor;
		}
		return backgroundColor;
	}

	public FieldSelection getSelection() {
		return selection;
	}

	public Color getBackgroundColor(FieldLocation location) {
		boolean isSelected = selection.contains(location);
		boolean isHighlighted = highlight.contains(location);
		if (isSelected && isHighlighted) {
			return mixedColor;
		}
		if (isSelected) {
			return selectionColor;
		}
		if (isHighlighted) {
			return highlightColor;
		}
		return backgroundColor;
	}
}
