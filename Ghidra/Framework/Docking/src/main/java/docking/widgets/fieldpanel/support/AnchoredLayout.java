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

import java.awt.Graphics;
import java.awt.Rectangle;
import java.math.BigInteger;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.internal.LayoutBackgroundColorManager;
import docking.widgets.fieldpanel.internal.PaintContext;

public class AnchoredLayout implements Layout {

	private int yPos;
	private final Layout layout;
	private final BigInteger index;

	public AnchoredLayout(Layout layout, BigInteger index, int yPos) {
		this.layout = layout;
		this.index = index;
		this.yPos = yPos;
	}

	public int getYPos() {
		return yPos;
	}

	@Override
	public void paint(JComponent c, Graphics g, PaintContext context, Rectangle rect,
			LayoutBackgroundColorManager layoutSelectionMap, FieldLocation cursorLocation) {

		g.translate(0, yPos);
		rect.y -= yPos;
		try {
			layout.paint(c, g, context, rect, layoutSelectionMap, cursorLocation);
		}
		finally {
			g.translate(0, -yPos);
			rect.y += yPos;
		}
	}

	public void setYPos(int yPos) {
		this.yPos = yPos;
	}

	public BigInteger getIndex() {
		return index;
	}

	@Override
	public int getHeight() {
		return layout.getHeight();
	}

	@Override
	public int getCompressableWidth() {
		return layout.getCompressableWidth();
	}

	@Override
	public int getScrollableUnitIncrement(int y, int direction) {
		return layout.getScrollableUnitIncrement(y, direction);
	}

	public int getEndY() {
		return yPos + layout.getHeight();
	}

	@Override
	public String toString() {
		return index.toString() + " (ypos = " + yPos + ")";
	}

	@Override
	public boolean contains(int y) {
		if ((y >= yPos) && (y < yPos + layout.getHeight())) {
			return true;
		}
		return false;
	}

	@Override
	public int cursorBeginning(FieldLocation cursorLoc) {
		return layout.cursorBeginning(cursorLoc);
	}

	@Override
	public boolean cursorDown(FieldLocation cursorLoc, int lastX) {
		return layout.cursorDown(cursorLoc, lastX);
	}

	@Override
	public int cursorEnd(FieldLocation cursorLoc) {
		return layout.cursorEnd(cursorLoc);
	}

	@Override
	public int cursorLeft(FieldLocation cursorLoc) {
		return layout.cursorLeft(cursorLoc);
	}

	@Override
	public int cursorRight(FieldLocation cursorLoc) {
		return layout.cursorRight(cursorLoc);
	}

	@Override
	public boolean cursorUp(FieldLocation cursorLoc, int lastX) {
		return layout.cursorUp(cursorLoc, lastX);
	}

	@Override
	public boolean enterLayout(FieldLocation cursorLoc, int lastX, boolean fromTop) {
		cursorLoc.setIndex(index);
		return layout.enterLayout(cursorLoc, lastX, fromTop);
	}

	@Override
	public int getBeginRowFieldNum(int field1) {
		return layout.getBeginRowFieldNum(field1);
	}

	@Override
	public Rectangle getCursorRect(int fieldNum, int row, int col) {
		Rectangle rect = layout.getCursorRect(fieldNum, row, col);
		if (rect == null) {
			rect = new Rectangle(4, 4);
		}
		rect.y += yPos;
		return rect;
	}

	@Override
	public int getEndRowFieldNum(int field2) {
		return layout.getEndRowFieldNum(field2);
	}

	@Override
	public Field getField(int fieldIndex) {
		try {
			return layout.getField(fieldIndex);
		}
		catch (RuntimeException e) {
			if ((fieldIndex < 0) || (fieldIndex >= layout.getNumFields())) {
				return null;
			}
			throw e;
		}
	}

	@Override
	public Rectangle getFieldBounds(int fieldIndex) {
		Rectangle r = layout.getFieldBounds(fieldIndex);
		r.y += yPos;
		return r;
	}

	@Override
	public int getIndexSize() {
		return layout.getIndexSize();
	}

	@Override
	public int getNumFields() {
		return layout.getNumFields();
	}

	@Override
	public int getPrimaryOffset() {
		return layout.getPrimaryOffset();
	}

	@Override
	public void insertSpaceAbove(int size) {
		layout.insertSpaceAbove(size);
	}

	@Override
	public void insertSpaceBelow(int size) {
		layout.insertSpaceBelow(size);
	}

	@Override
	public int setCursor(FieldLocation cursorLoc, int x, int y) {
		cursorLoc.setIndex(index);
		return layout.setCursor(cursorLoc, x, y - yPos);
	}
}
