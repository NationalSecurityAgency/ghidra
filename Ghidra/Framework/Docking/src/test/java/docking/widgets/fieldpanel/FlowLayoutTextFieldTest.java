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
package docking.widgets.fieldpanel;

import static org.junit.Assert.*;

import java.awt.*;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import generic.test.AbstractGenericTest;

public class FlowLayoutTextFieldTest extends AbstractGenericTest {

	private static final String CLIPPED_STRING = "Supercalifragilisticexpialidocious ";

	private FlowLayoutTextField textField;

	public FlowLayoutTextFieldTest() {
		super();
	}

	@SuppressWarnings("deprecation") // we mean to use getFontMetrics
	@Before
	public void setUp() throws Exception {

		HighlightFactory factory = (field, text, cursorTextOffset) -> {
			return new Highlight[] { new Highlight(4, 4, Color.YELLOW) };
		};

		Font font = new Font("Times New Roman", 0, 14);
		Toolkit tk = Toolkit.getDefaultToolkit();
		FontMetrics fm = tk.getFontMetrics(font);
		FieldElement[] elements = new FieldElement[4];
		elements[0] = new TextFieldElement(new AttributedString("Hello ", Color.BLUE, fm), 0, 0);
		elements[1] = new TextFieldElement(
			new AttributedString("World ", Color.RED, fm, true, Color.BLUE), 1, 0);
		elements[2] =
			new TextFieldElement(new AttributedString(CLIPPED_STRING, Color.GREEN, fm), 2, 0);
		elements[3] = new TextFieldElement(new AttributedString("Wow! ", Color.GRAY, fm), 3, 0);

		textField = new FlowLayoutTextField(elements, 100, 100, 3, factory);
	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getWidth()'
	 */
	@Test
	public void testGetWidth() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getHeight()'
	 */
	@Test
	public void testGetHeight() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getStartX()'
	 */
	@Test
	public void testGetStartX() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getNumRows()'
	 */
	@Test
	public void testGetNumRows() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getNumCols(int)'
	 */
	@Test
	public void testGetNumCols() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getRow(int)'
	 */
	@Test
	public void testGetRow() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getCol(int, int)'
	 */
	@Test
	public void testGetCol() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getY(int)'
	 */
	@Test
	public void testGetY() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getX(int, int)'
	 */
	@Test
	public void testGetX() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.isValid(int, int)'
	 */
	@Test
	public void testIsValid() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.paint(Graphics, PaintContext, boolean)'
	 */
	@Test
	public void testPaint() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.paintCursor(Graphics, PaintContext, boolean, int, int)'
	 */
	@Test
	public void testPaintCursor() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getCursorBounds(int, int)'
	 */
	@Test
	public void testGetCursorBounds() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.contains(int, int)'
	 */
	@Test
	public void testContains() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getScrollableUnitIncrement(int, int, int)'
	 */
	@Test
	public void testGetScrollableUnitIncrement() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.isPrimary()'
	 */
	@Test
	public void testIsPrimary() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.setPrimary(boolean)'
	 */
	@Test
	public void testSetPrimary() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getStringLocation(int, int)'
	 */
	@Test
	public void testScreenToDataLocation() {
		assertEquals(new RowColLocation(0, 0), textField.screenToDataLocation(0, 0));
		assertEquals(new RowColLocation(0, 2), textField.screenToDataLocation(0, 2));
		assertEquals(new RowColLocation(0, 5), textField.screenToDataLocation(0, 5));

		assertEquals(new RowColLocation(1, 0), textField.screenToDataLocation(0, 6));
		assertEquals(new RowColLocation(1, 4), textField.screenToDataLocation(0, 10));
		assertEquals(new RowColLocation(1, 5), textField.screenToDataLocation(0, 11));
		assertEquals(new RowColLocation(1, 6), textField.screenToDataLocation(0, 13));
		assertEquals(new RowColLocation(1, 6), textField.screenToDataLocation(0, 75));

		assertEquals(new RowColLocation(2, 0), textField.screenToDataLocation(1, 0));
		assertEquals(new RowColLocation(2, 6), textField.screenToDataLocation(1, 6));
		assertEquals(new RowColLocation(2, 16), textField.screenToDataLocation(1, 16));
		assertEquals(new RowColLocation(2, 17), textField.screenToDataLocation(1, 17));
		assertEquals(new RowColLocation(2, 35), textField.screenToDataLocation(1, 75));

		assertEquals(new RowColLocation(3, 0), textField.screenToDataLocation(2, 0));
		assertEquals(new RowColLocation(3, 4), textField.screenToDataLocation(2, 4));
		assertEquals(new RowColLocation(3, 5), textField.screenToDataLocation(2, 75));
		assertEquals(new RowColLocation(3, 0), textField.screenToDataLocation(3, 0));
		assertEquals(new RowColLocation(3, 5), textField.screenToDataLocation(50, 75));
	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getWrappedLocation(int, int)'
	 */
	@Test
	public void testDataToScreenLocation() {
		assertEquals(new RowColLocation(0, 0), textField.dataToScreenLocation(0, 0));
		assertEquals(new RowColLocation(0, 2), textField.dataToScreenLocation(0, 2));
		assertEquals(new RowColLocation(0, 5), textField.dataToScreenLocation(0, 5));
		assertEquals(new RowColLocation(0, 6), textField.dataToScreenLocation(0, 6));

		assertEquals(new RowColLocation(0, 6), textField.dataToScreenLocation(1, 0));
		assertEquals(new RowColLocation(0, 10), textField.dataToScreenLocation(1, 4));
		assertEquals(new RowColLocation(0, 11), textField.dataToScreenLocation(1, 5));

		assertEquals(new RowColLocation(1, 0), textField.dataToScreenLocation(2, 0));
		assertEquals(new RowColLocation(1, 4), textField.dataToScreenLocation(2, 4));
		assertEquals(new RowColLocation(1, 15), textField.dataToScreenLocation(2, 15));

		assertEquals(new RowColLocation(2, 0), textField.dataToScreenLocation(3, 0));
		assertEquals(new RowColLocation(2, 4), textField.dataToScreenLocation(3, 4));

		assertEquals(new RowColLocation(0, 0), textField.dataToScreenLocation(0, 12));
		assertEquals(new RowColLocation(0, 0), textField.dataToScreenLocation(0, 75));
	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getRowColumn(int)'
	 */
	@Test
	public void testGetRowColumn() {
		assertEquals(new RowColLocation(0, 0), textField.textOffsetToScreenLocation(0));
		assertEquals(new RowColLocation(0, 5), textField.textOffsetToScreenLocation(5));
		assertEquals(new RowColLocation(0, 6), textField.textOffsetToScreenLocation(6));
		assertEquals(new RowColLocation(0, 10), textField.textOffsetToScreenLocation(10));
		assertEquals(new RowColLocation(1, 0), textField.textOffsetToScreenLocation(12));
		assertEquals(new RowColLocation(1, 1), textField.textOffsetToScreenLocation(13));
		assertEquals(new RowColLocation(1, 2), textField.textOffsetToScreenLocation(14));
		assertEquals(new RowColLocation(1, 3), textField.textOffsetToScreenLocation(15));

		assertEquals(new RowColLocation(1, 18), textField.textOffsetToScreenLocation(30));

		assertEquals(new RowColLocation(2, 5), textField.textOffsetToScreenLocation(1000));

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getSubfields()'
	 */
	@Test
	public void testGetSubfields() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getHeightAbove()'
	 */
	@Test
	public void testGetHeightAbove() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getHeightBelow()'
	 */
	@Test
	public void testGetHeightBelow() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.rowHeightChanged(int, int)'
	 */
	@Test
	public void testRowHeightChanged() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getText()'
	 */
	@Test
	public void testGetText() {

	}

	/*
	 * Test method for 'ghidra.util.bean.field.WrappingTextField.getTextOffset(int, int)'
	 */
	@Test
	public void testGetTextOffset() {

	}

}
