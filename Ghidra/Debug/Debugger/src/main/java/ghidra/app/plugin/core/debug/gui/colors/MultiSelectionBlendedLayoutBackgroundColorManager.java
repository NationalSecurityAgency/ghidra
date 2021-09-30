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
package ghidra.app.plugin.core.debug.gui.colors;

import java.awt.Color;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

import docking.widgets.fieldpanel.internal.*;
import docking.widgets.fieldpanel.support.*;
import ghidra.util.ColorUtils.ColorBlender;

public class MultiSelectionBlendedLayoutBackgroundColorManager
		implements LayoutBackgroundColorManager {

	public static class ColoredFieldSelection {
		FieldSelection selection;
		Color color;

		public ColoredFieldSelection(FieldSelection selection, Color color) {
			this.selection = Objects.requireNonNull(selection);
			this.color = Objects.requireNonNull(color);
		}

		public ColoredFieldSelection intersect(BigInteger index) {
			return new ColoredFieldSelection(selection.intersect(index), color);
		}

		public boolean isTotal(BigInteger index) {
			return selection.getNumRanges() == 1 &&
				selection.getFieldRange(0).containsEntirely(index);
		}

		public boolean isEmpty() {
			return selection.isEmpty();
		}

		public boolean contains(FieldLocation loc) {
			return selection.contains(loc);
		}

		public boolean containsEntirely(FieldRange range) {
			return selection.containsEntirely(range);
		}

		public boolean excludesEntirely(FieldRange range) {
			return selection.excludesEntirely(range);
		}
	}

	public static LayoutBackgroundColorManager getLayoutColorMap(BigInteger index,
			Collection<ColoredFieldSelection> selections, Color backgroundColor,
			boolean isBackgroundDefault) {
		List<ColoredFieldSelection> intersections =
			selections.stream().map(cfs -> cfs.intersect(index)).collect(Collectors.toList());

		List<ColoredFieldSelection> empties =
			intersections.stream().filter(cfs -> cfs.isEmpty()).collect(Collectors.toList());
		// Check for completely empty, i.e., use the background
		if (empties.size() == intersections.size()) {
			return new EmptyLayoutBackgroundColorManager(backgroundColor);
		}

		ColorBlender blender = new ColorBlender();
		if (!isBackgroundDefault) {
			blender.add(backgroundColor);
		}

		List<ColoredFieldSelection> totals =
			intersections.stream().filter(cfs -> cfs.isTotal(index)).collect(Collectors.toList());
		if (totals.size() + empties.size() == intersections.size()) {
			totals.forEach(cfs -> blender.add(cfs.color));
			return new EmptyLayoutBackgroundColorManager(blender.getColor(backgroundColor));
		}

		FieldLocation startOfLine = new FieldLocation(index, 0, 0, 0);
		FieldLocation endOfLine =
			new FieldLocation(index, Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE);
		for (ColoredFieldSelection cfs : intersections) {
			if (cfs.contains(startOfLine)) {
				blender.add(cfs.color);
			}
		}
		ColorBlender blenderR = new ColorBlender();
		if (!isBackgroundDefault) {
			blenderR.add(backgroundColor);
		}
		for (ColoredFieldSelection cfs : intersections) {
			if (cfs.contains(endOfLine)) {
				blenderR.add(cfs.color);
			}
		}

		return new MultiSelectionBlendedLayoutBackgroundColorManager(index, intersections,
			backgroundColor,
			blender.getColor(backgroundColor), blenderR.getColor(backgroundColor));
	}

	public static class MultiSelectionBlendedFieldBackgroundColorManager
			implements FieldBackgroundColorManager {

		private final BigInteger index;
		private final int fieldNum;
		private final MultiSelectionBlendedLayoutBackgroundColorManager layoutSelection;
		private final List<ColoredFieldSelection> selections;
		private final Color backgroundColor;

		public MultiSelectionBlendedFieldBackgroundColorManager(BigInteger index, int fieldNum,
				MultiSelectionBlendedLayoutBackgroundColorManager layoutSelection,
				List<ColoredFieldSelection> selections, Color backgroundColor) {
			this.index = index;
			this.fieldNum = fieldNum;
			this.layoutSelection = layoutSelection;
			this.selections = selections;
			this.backgroundColor = backgroundColor;
		}

		@Override
		public Color getBackgroundColor() {
			return layoutSelection.dontPaintBg(backgroundColor);
		}

		@Override
		public List<Highlight> getSelectionHighlights(int row) {
			FieldLocation start = new FieldLocation(index, fieldNum, row, 0);
			FieldLocation end = new FieldLocation(index, fieldNum, row + 1, 0);
			FieldRange range = new FieldRange(start, end);
			List<Highlight> highlights = new ArrayList<>();
			for (ColoredFieldSelection cfs : selections) {
				FieldSelection intersect = cfs.selection.intersect(range);
				for (int i = 0; i < intersect.getNumRanges(); i++) {
					FieldRange rng = intersect.getFieldRange(i);
					int min = rng.getStart().col;
					int max = rng.getEnd().row == row ? range.getEnd().col : Integer.MAX_VALUE;
					highlights.add(new Highlight(min, max, cfs.color));
				}
			}
			return highlights;
		}

		@Override
		public Color getPaddingColor(int padIndex) {
			return layoutSelection.getPaddingColor(padIndex);
		}
	}

	private final BigInteger index;
	private final List<ColoredFieldSelection> selections;
	private final Color backgroundColor;
	private final Color leftBorderColor;
	private final Color rightBorderColor;

	public MultiSelectionBlendedLayoutBackgroundColorManager(BigInteger index,
			List<ColoredFieldSelection> selections, Color backgroundColor, Color leftBorderColor,
			Color rightBorderColor) {
		this.index = index;
		this.selections = selections;
		this.backgroundColor = backgroundColor;
		this.leftBorderColor = leftBorderColor;
		this.rightBorderColor = rightBorderColor;
	}

	@Override
	public Color getBackgroundColor() {
		return backgroundColor;
	}

	protected Color dontPaintBg(Color color) {
		return color == backgroundColor ? null : color;
	}

	@Override
	public Color getPaddingColor(int padIndex) {
		if (padIndex == 0) {
			return dontPaintBg(leftBorderColor);
		}
		if (padIndex == -1) {
			return dontPaintBg(rightBorderColor);
		}
		return dontPaintBg(getPaddingColorBetweenFields(padIndex));
	}

	protected Color getPaddingColorBetweenFields(int padIndex) {
		FieldLocation start =
			new FieldLocation(index, padIndex - 1, Integer.MAX_VALUE, Integer.MAX_VALUE);
		FieldLocation end = new FieldLocation(index, padIndex, 0, 0);
		FieldRange range = new FieldRange(start, end);

		ColorBlender blender = new ColorBlender();
		for (ColoredFieldSelection cfs : selections) {
			if (cfs.containsEntirely(range)) {
				blender.add(cfs.color);
			}
		}
		return blender.getColor(backgroundColor);
	}

	protected boolean excludedByAll(FieldRange range) {
		for (ColoredFieldSelection cfs : selections) {
			if (!cfs.excludesEntirely(range)) {
				return false;
			}
		}
		return true;
	}

	protected Color computeSolidColor(FieldRange range) {
		ColorBlender blender = new ColorBlender();
		for (ColoredFieldSelection cfs : selections) {
			if (cfs.containsEntirely(range)) {
				blender.add(cfs.color);
				continue;
			}
			if (cfs.excludesEntirely(range)) {
				// good, but don't add color
				continue;
			}
			// Field is not a solid color
			return null;
		}
		return blender.getColor(backgroundColor);
	}

	@Override
	public FieldBackgroundColorManager getFieldBackgroundColorManager(int fieldNum) {
		FieldLocation start = new FieldLocation(index, fieldNum, 0, 0);
		FieldLocation end = new FieldLocation(index, fieldNum + 1, 0, 0);
		FieldRange range = new FieldRange(start, end);

		if (excludedByAll(range)) {
			return EmptyFieldBackgroundColorManager.EMPTY_INSTANCE;
		}

		Color solidColor = computeSolidColor(range);
		if (solidColor != null) {
			return new FullySelectedFieldBackgroundColorManager(solidColor);
		}

		// Could separate out solid colors, but at the expense of constructing a collection....
		// Leave fieldBackgroudColor the same as backgroundColor, and pass all selections in
		return new MultiSelectionBlendedFieldBackgroundColorManager(index, fieldNum, this,
			selections, backgroundColor);
	}

	@Override
	public Color getBackgroundColor(FieldLocation location) {
		ColorBlender blender = new ColorBlender();
		for (ColoredFieldSelection cfs : selections) {
			if (cfs.contains(location)) {
				blender.add(cfs.color);
			}
		}
		return blender.getColor(backgroundColor);
	}
}
