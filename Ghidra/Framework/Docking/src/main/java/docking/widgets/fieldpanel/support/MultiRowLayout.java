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
package docking.widgets.fieldpanel.support;

import java.awt.Graphics;
import java.awt.Rectangle;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.EmptyTextField;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.internal.*;

/**
 * Handles layouts with multiple rows.
 */
public class MultiRowLayout implements Layout {
	private RowLayout[] layouts;
	private int[] offsets;
	private int numFields;
	private int heightAbove;
	private int heightBelow;
	private int primaryOffset = -1;
	private int indexSize = 1;

	/**
	 * Constructs a new MultiRowLayout with a single layout row.
	 * @param layout the single layout to add to this MultiRowLayout.
	 * @param indexSize the index size.
	 */
	public MultiRowLayout(RowLayout layout, int indexSize) {
		this.indexSize = indexSize;
		numFields = layout.getNumFields();
		layouts = new RowLayout[1];
		layouts[0] = layout;
		heightAbove = layouts[0].getHeightAbove();
		heightBelow = layouts[0].getHeightBelow();
		buildOffsets();
	}

	public MultiRowLayout(RowLayout[] layouts, int indexSize) {
		this.indexSize = indexSize;
		this.layouts = layouts;
		int height = 0;

		for (RowLayout layout : layouts) {
			numFields += layout.getNumFields();
			height += layout.getHeight();
		}
		heightAbove = layouts[0].getHeightAbove();
		heightBelow = height - heightAbove;
		buildOffsets();
	}

	private void buildOffsets() {
		offsets = new int[layouts.length + 1];
		int soFar = 0;
		for (int i = 0; i < layouts.length; i++) {
			offsets[i] = soFar;
			soFar += layouts[i].getNumFields();
		}
		offsets[layouts.length] = soFar;
	}

	@Override
	public int getHeight() {
		return heightAbove + heightBelow;
	}

	@Override
	public int getCompressableWidth() {
		// 
		// Since this is a multi-row layout, we have to make sure that our compressible width
		// is the largest of all rows so that the longest row doesn't get clipped.
		//
		int max = 0;
		for (Layout layout : layouts) {
			max = Math.max(max, layout.getCompressableWidth());
		}
		return max;
	}

	@Override
	public int getNumFields() {
		return numFields;
	}

	@Override
	public Field getField(int index) {
		for (int i = 0; i < layouts.length; i++) {
			if (index < offsets[i + 1]) {
				return layouts[i].getField(index - offsets[i]);
			}
		}
		return null;
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context, Rectangle rect,
			LayoutBackgroundColorManager colorManager, FieldLocation cursorLocation) {

		int totalShift = 0;
		int offset = 0;
		LayoutBackgroundColorManagerAdapter shiftedColorManager =
			new LayoutBackgroundColorManagerAdapter(colorManager);

		for (int i = 0; i < layouts.length; i++) {
			g.translate(0, offset);
			totalShift += offset;
			rect.y -= offset;
			shiftedColorManager.setRange(offsets[i], offsets[i + 1], i == layouts.length - 1);
			FieldLocation shiftedCursorLocation = null;
			if (cursorLocation != null) {
				int shiftedFieldNum = cursorLocation.fieldNum - offsets[i];
				if (shiftedFieldNum >= 0 && shiftedFieldNum < offsets[i + 1]) {
					shiftedCursorLocation = new FieldLocation(cursorLocation);
					shiftedCursorLocation.fieldNum = shiftedFieldNum;
				}
			}
			layouts[i].paint(c, g, context, rect, shiftedColorManager, shiftedCursorLocation);
			offset = layouts[i].getHeight();
		}
		g.translate(0, -totalShift);
		rect.y += totalShift;
	}

	@Override
	public int setCursor(FieldLocation cursorLoc, int x, int y) {
		int offset = 0;
		for (int i = 0; i < layouts.length; i++) {
			if (layouts[i].contains(y - offset)) {
				int lastX = layouts[i].setCursor(cursorLoc, x, y - offset);
				cursorLoc.fieldNum += offsets[i];
				return lastX;
			}
			offset += layouts[i].getHeight();
		}
		return layouts[0].setCursor(cursorLoc, x, y);
	}

	@Override
	public int getFieldIndex(int x, int y) {
		int offset = 0;
		for (int i = 0; i < layouts.length; i++) {
			if (layouts[i].contains(y - offset)) {
				return layouts[i].getFieldIndex(x, y - offset) + offsets[i];
			}
			offset += layouts[i].getHeight();
		}
		return layouts[0].getFieldIndex(x, y);
	}

	@Override
	public Rectangle getCursorRect(int fieldNum, int row, int col) {
		int offset = 0;
		for (int i = 0; i < layouts.length; i++) {
			if (fieldNum < offsets[i + 1]) {
				Rectangle rect = layouts[i].getCursorRect(fieldNum - offsets[i], row, col);
				if (rect != null) {
					rect.y += offset;
				}
				return rect;
			}
			offset += layouts[i].getHeight();
		}
		return null;
	}

	@Override
	public boolean cursorUp(FieldLocation cursorLoc, int lastX) {
		int row = findRow(cursorLoc);
		cursorLoc.fieldNum -= offsets[row];
		boolean result = layouts[row].cursorUp(cursorLoc, lastX);
		cursorLoc.fieldNum += offsets[row];
		if (!result) {
			if (row == 0) {
				return false;
			}
			cursorLoc.fieldNum -= offsets[--row];
			result = layouts[row].enterLayout(cursorLoc, lastX, false);
			cursorLoc.fieldNum += offsets[row];
		}
		return result;
	}

	@Override
	public boolean cursorDown(FieldLocation cursorLoc, int lastX) {
		int row = findRow(cursorLoc);
		cursorLoc.fieldNum -= offsets[row];
		boolean result = layouts[row].cursorDown(cursorLoc, lastX);
		cursorLoc.fieldNum += offsets[row];

		if (!result) {
			if (row >= layouts.length - 1) {
				return false;
			}
			cursorLoc.fieldNum -= offsets[++row];
			result = layouts[row].enterLayout(cursorLoc, lastX, true);
			cursorLoc.fieldNum += offsets[row];
		}
		return result;
	}

	@Override
	public int cursorBeginning(FieldLocation cursorLoc) {
		int row = findRow(cursorLoc);
		cursorLoc.fieldNum -= offsets[row];
		int lastX = layouts[row].cursorBeginning(cursorLoc);
		cursorLoc.fieldNum += offsets[row];
		return lastX;
	}

	@Override
	public int cursorEnd(FieldLocation cursorLoc) {
		int row = findRow(cursorLoc);
		cursorLoc.fieldNum -= offsets[row];
		int lastX = layouts[row].cursorEnd(cursorLoc);
		cursorLoc.fieldNum += offsets[row];
		return lastX;
	}

	@Override
	public int cursorLeft(FieldLocation cursorLoc) {
		int row = findRow(cursorLoc);
		cursorLoc.fieldNum -= offsets[row];
		int returnVal = layouts[row].cursorLeft(cursorLoc);
		cursorLoc.fieldNum += offsets[row];
		if (returnVal < 0) {
			if (row == 0) {
				return -1;
			}
			cursorLoc.fieldNum -= offsets[--row];
			returnVal = layouts[row].cursorEnd(cursorLoc);
			cursorLoc.fieldNum += offsets[row];
		}
		return returnVal;
	}

	@Override
	public int cursorRight(FieldLocation cursorLoc) {
		int row = findRow(cursorLoc);
		cursorLoc.fieldNum -= offsets[row];
		int returnVal = layouts[row].cursorRight(cursorLoc);
		cursorLoc.fieldNum += offsets[row];
		if (returnVal < 0) {
			if (row >= layouts.length - 1) {
				return -1;
			}
			cursorLoc.fieldNum -= offsets[++row];
			returnVal = layouts[row].cursorBeginning(cursorLoc);
			cursorLoc.fieldNum += offsets[row];
		}
		return returnVal;
	}

	@Override
	public boolean enterLayout(FieldLocation cursorLoc, int lastX, boolean fromTop) {
		if (fromTop) {
			return layouts[0].enterLayout(cursorLoc, lastX, fromTop);
		}
		cursorLoc.fieldNum -= offsets[layouts.length - 1];
		boolean result = layouts[layouts.length - 1].enterLayout(cursorLoc, lastX, fromTop);
		cursorLoc.fieldNum += offsets[layouts.length - 1];
		return result;
	}

	@Override
	public int getScrollableUnitIncrement(int topOfScreen, int direction) {
		int searchPoint = topOfScreen;
		if (direction < 0) {
			searchPoint--;
		}

		int offset = 0;
		for (int i = 0; i < layouts.length - 1; i++) {
			if (layouts[i].contains(searchPoint - offset)) {
				return layouts[i].getScrollableUnitIncrement(topOfScreen - offset, direction);
			}
			offset += layouts[i].getHeight();
		}
		return layouts[layouts.length - 1].getScrollableUnitIncrement(topOfScreen - offset,
			direction);
	}

	@Override
	public boolean contains(int yPos) {
		if ((yPos >= 0) && (yPos < heightAbove + heightBelow)) {
			return true;
		}
		return false;
	}

	/**
	 * Returns the row containing the given FieldLocation.
	 */
	private int findRow(FieldLocation loc) {
		for (int i = 0; i < layouts.length; i++) {
			if (loc.fieldNum < offsets[i + 1]) {
				return i;
			}
		}
		return 0;
	}

	@Override
	public int getPrimaryOffset() {
		if (primaryOffset == -1) {
			findPrimaryOffset();
		}
		return primaryOffset;
	}

	private void findPrimaryOffset() {
		primaryOffset = 0;
		for (RowLayout layout : layouts) {
			if (layout.isPrimary()) {
				return;
			}
			primaryOffset += layout.getHeight();
		}
		primaryOffset = 0;
	}

	@Override
	public Rectangle getFieldBounds(int index) {
		int offset = 0;
		for (int i = 0; i < layouts.length; i++) {
			if (index < offsets[i + 1]) {
				Rectangle rect = layouts[i].getFieldBounds(index - offsets[i]);
				rect.y += offset;
				return rect;
			}
			offset += layouts[i].getHeight();
		}
		return null;

	}

	@Override
	public void insertSpaceAbove(int size) {
		layouts[0].insertSpaceAbove(size);
		heightAbove += size;
	}

	@Override
	public void insertSpaceBelow(int size) {
		layouts[layouts.length - 1].insertSpaceBelow(size);
		heightBelow += size;
	}

	@Override
	public String toString() {
		return Arrays.asList(layouts)
				.stream()
				.map(RowLayout::toString)
				.collect(Collectors.joining("\n"));
	}

	@Override
	public int getIndexSize() {
		return indexSize;
	}

	@Override
	public int getBeginRowFieldNum(int fieldIndex) {
		for (int i = 0; i < layouts.length; i++) {
			if (fieldIndex < offsets[i + 1]) {
				return offsets[i];
			}
		}
		return offsets[layouts.length - 1];
	}

	@Override
	public int getEndRowFieldNum(int fieldIndex) {
		for (int i = 0; i < layouts.length; i++) {
			if (fieldIndex < offsets[i + 1]) {
				return offsets[i + 1];
			}
		}
		return offsets[layouts.length];
	}

	public int getFirstRowID() {
		return layouts[0].getRowID();
	}

	/**
	 * Returns an object that contains all row heights for the row layouts in this class.
	 * @return an object that contains all row heights for the row layouts in this class.
	 */
	public RowHeights getRowHeights() {
		RowHeights rowHeights = new RowHeights();
		for (RowLayout layout : layouts) {
			rowHeights.addHeight(layout);
		}
		return rowHeights;
	}

	/**
	 * Aligns the heights in this MultiRowLayout to match those in the given row heights array.  
	 * This is used by the diff provider to align two sets of rows.  
	 * 
	 * @param sharedRowHeights the row heights
	 */
	public void align(RowHeights sharedRowHeights) {

		// Gather and map all layouts by their assigned row number.  This map *may not* be a 
		// complete range of rows from 0 to rowHeights.length;
		Map<Integer, List<RowLayout>> layoutsByRow = new HashMap<>();
		for (RowLayout layout : layouts) {
			int row = layout.getRowID();
			List<RowLayout> list = layoutsByRow.computeIfAbsent(row, k -> new ArrayList<>());
			list.add(layout);
		}

		// Walk the entire range of shared rows between each diff.  If a row height is 0, then 
		// neither side of the diff contains a RowLayout object for that row.
		List<RowLayout> updatedRows = alignRows(sharedRowHeights, layoutsByRow);
		layouts = new RowLayout[updatedRows.size()];
		int height = 0;
		for (int i = 0; i < layouts.length; i++) {
			layouts[i] = updatedRows.get(i);
			height += layouts[i].getHeight();
		}

		heightAbove = layouts[0].getHeightAbove();
		heightBelow = height - heightAbove;
		buildOffsets();
	}

	private List<RowLayout> alignRows(RowHeights sharedRowHeights,
			Map<Integer, List<RowLayout>> layoutsByRow) {

		List<RowLayout> updatedRows = new ArrayList<>();
		int totalRows = sharedRowHeights.getRowCount(); // total rows shared between all views
		for (int row = 0; row < totalRows; row++) {
			int rowHeight = sharedRowHeights.getHeight(row);
			if (rowHeight == 0) {
				continue; // no rows on either side
			}

			List<RowLayout> rowLayouts = layoutsByRow.get(row);
			if (rowLayouts == null) {
				// No lines for this row.  This side of the diff that has no rows fields for the 
				// given row.  Add empty rows to act as spacers for this side of the diff.
				updatedRows.add(new EmptyRowLayout(row, rowHeight));
				continue;
			}

			// At this point we have one or more lines to add for the current row.  Add each line
			// but the last line.  The last line will consume all remaining height that has not yet
			// been consumed.
			int totalLines = rowLayouts.size();
			int lastLine = totalLines - 1;
			int allButLastLine = lastLine - 1;
			int consumedHeight = 0; // track all height used by each row
			for (int line = 0; line <= allButLastLine; line++) {
				RowLayout layout = rowLayouts.get(line);
				updatedRows.add(layout);
				consumedHeight += layout.getHeight();
			}

			// Process the last line, adding any space to fill the remaining row height.  Having
			// remaining height means that the other side of the diff has more RowLayouts than this
			// side of the diff.
			RowLayout layout = rowLayouts.get(lastLine);
			consumedHeight += layout.getHeight();
			int leftOverHeight = rowHeight - consumedHeight;
			layout.insertSpaceBelow(leftOverHeight);
			updatedRows.add(layout);
		}

		return updatedRows;
	}

	private class EmptyRowLayout extends RowLayout {

		public EmptyRowLayout(int rowId, int height) {
			super(getEmptyFields(height), rowId);
		}

		private static Field[] getEmptyFields(int height) {
			return new Field[] { new EmptyTextField(height, 0, 0, 0) };
		}
	}

	/**
	 * A class to track all row heights for a given {@link MultiRowLayout}.   Multiple instances
	 * of this class can be merged to create a total collection of row heights for more than one
	 * {@link MultiRowLayout}, such as is done for the diff tool.  The merged row heights 
	 * represent the total number of rows possible as well as the maximum possible height for a 
	 * given row.
	 */
	public static class RowHeights {

		private Map<Integer, Integer> heightsByRow = new HashMap<>();
		private int largestRow;

		void addHeight(RowLayout layout) {
			int row = layout.getRowID();
			int rowHeight = layout.getHeight();
			int totalHeight = heightsByRow.computeIfAbsent(row, k -> 0);
			heightsByRow.put(row, totalHeight + rowHeight);
			largestRow = Math.max(row, largestRow);
		}

		int getHeight(int row) {
			return heightsByRow.computeIfAbsent(row, k -> 0);
		}

		int getRowCount() {
			return largestRow + 1; // +1 for index vs count
		}

		public void merge(RowHeights other) {

			int myRowCount = getRowCount();
			int otherRowCount = other.getRowCount();
			int rowCount = Math.max(myRowCount, otherRowCount);

			for (int row = 0; row < rowCount; row++) {
				int myRowHeight = heightsByRow.computeIfAbsent(row, k -> 0);
				int otherRowHeight = other.getHeight(row);
				int largestRowHeight = Math.max(myRowHeight, otherRowHeight);
				heightsByRow.put(row, largestRowHeight);
				largestRow = Math.max(row, largestRow);
			}
		}
	}
}
