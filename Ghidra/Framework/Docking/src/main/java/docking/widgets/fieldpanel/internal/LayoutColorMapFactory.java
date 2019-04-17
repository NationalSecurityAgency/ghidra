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

import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldSelection;

public class LayoutColorMapFactory {

	public static LayoutBackgroundColorManager getLayoutColorMap(BigInteger index,
			FieldSelection selection, FieldSelection highlight, Color backgroundColor,
			Color selectionColor, Color highlightColor, Color mixedColor) {

		FieldSelection selectionIntersect = selection.intersect(index);
		FieldSelection highlightIntersect = highlight.intersect(index);
		if (selectionIntersect.isEmpty() && highlightIntersect.isEmpty()) {
			return new EmptyLayoutBackgroundColorManager(backgroundColor);
		}

		boolean isTotallySelected =
			selectionIntersect.getNumRanges() == 1 &&
				selectionIntersect.getFieldRange(0).containsEntirely(index);

		boolean isTotallyHighlighted =
			highlightIntersect.getNumRanges() == 1 &&
				highlightIntersect.getFieldRange(0).containsEntirely(index);

		if (isTotallySelected && isTotallyHighlighted) {
			return new EmptyLayoutBackgroundColorManager(mixedColor);
		}

		if (isTotallySelected && highlightIntersect.isEmpty()) {
			return new EmptyLayoutBackgroundColorManager(selectionColor);
		}

		if (isTotallyHighlighted && selectionIntersect.isEmpty()) {
			return new EmptyLayoutBackgroundColorManager(highlightColor);
		}

		FieldLocation startOfLine = new FieldLocation(index, 0, 0, 0);
		FieldLocation endOfLine =
			new FieldLocation(index, Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE);

		boolean leftBorderSelected = selection.contains(startOfLine);

		boolean rightBorderSelected = selection.contains(endOfLine);

		boolean leftBorderHighlighted = highlight.contains(startOfLine);

		boolean rightBorderHighlighted = highlight.contains(endOfLine);

		Color leftBorderColor = backgroundColor;
		if (leftBorderSelected && leftBorderHighlighted) {
			leftBorderColor = mixedColor;
		}
		else if (leftBorderSelected) {
			leftBorderColor = selectionColor;
		}
		else if (leftBorderHighlighted) {
			leftBorderColor = highlightColor;
		}

		Color rightBorderColor = backgroundColor;
		if (leftBorderSelected && rightBorderHighlighted) {
			rightBorderColor = mixedColor;
		}
		else if (rightBorderSelected) {
			rightBorderColor = selectionColor;
		}
		else if (rightBorderHighlighted) {
			rightBorderColor = highlightColor;
		}

		return new MixedLayoutBackgroundColorManager(index, selectionIntersect, highlightIntersect,
			backgroundColor, selectionColor, highlightColor, mixedColor, leftBorderColor,
			rightBorderColor);
	}
}
