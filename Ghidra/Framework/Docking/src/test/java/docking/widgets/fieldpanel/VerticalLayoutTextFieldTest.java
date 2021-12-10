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
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import generic.test.AbstractGenericTest;

public class VerticalLayoutTextFieldTest extends AbstractGenericTest {

	private static final String CLIPPED_STRING = "Supercalifragilisticexpialidocious";

	private VerticalLayoutTextField field;

	@SuppressWarnings("deprecation") // we mean to use getFontMetrics
	@Before
	public void setUp() throws Exception {

		HighlightFactory factory = (f, text, cursorTextOffset) -> {
			return new Highlight[] { new Highlight(4, 4, Color.YELLOW) };
		};

		Font font = new Font("Times New Roman", 0, 14);
		Toolkit tk = Toolkit.getDefaultToolkit();
		FontMetrics fm = tk.getFontMetrics(font);

		List<FieldElement> elements = new ArrayList<>();

		elements.add(new TextFieldElement(new AttributedString("Hello", Color.BLUE, fm), 0, 0));
		elements.add(new TextFieldElement(
			new AttributedString("World", Color.RED, fm, true, Color.BLUE), 1, 0));
		elements.add(
			new TextFieldElement(new AttributedString(CLIPPED_STRING, Color.GREEN, fm), 2, 0));
		elements.add(new TextFieldElement(new AttributedString("Wow!", Color.GRAY, fm), 3, 0));

		field = new VerticalLayoutTextField(elements, 100, 100, 5, factory);
	}

	@Test
	public void testScreenToDataLocation() {
		assertEquals(new RowColLocation(0, 0), field.screenToDataLocation(0, 0));
		assertEquals(new RowColLocation(0, 2), field.screenToDataLocation(0, 2));
		assertEquals(new RowColLocation(0, 5), field.screenToDataLocation(0, 5));
		assertEquals(new RowColLocation(0, 5), field.screenToDataLocation(0, 6));
		assertEquals(new RowColLocation(0, 5), field.screenToDataLocation(0, 75));

		assertEquals(new RowColLocation(1, 0), field.screenToDataLocation(1, 0));
		assertEquals(new RowColLocation(1, 5), field.screenToDataLocation(1, 6));
		assertEquals(new RowColLocation(1, 5), field.screenToDataLocation(1, 16));

		assertEquals(new RowColLocation(2, 0), field.screenToDataLocation(2, 0));
		assertEquals(new RowColLocation(2, 4), field.screenToDataLocation(2, 4));
		assertEquals(new RowColLocation(2, 34), field.screenToDataLocation(2, 75));

		assertEquals(new RowColLocation(3, 0), field.screenToDataLocation(3, 0));
		assertEquals(new RowColLocation(3, 4), field.screenToDataLocation(50, 75));
	}

	@Test
	public void testDataToScreenLocation() {
		assertEquals(new RowColLocation(0, 0), field.dataToScreenLocation(0, 0));
		assertEquals(new RowColLocation(0, 2), field.dataToScreenLocation(0, 2));
		assertEquals(new RowColLocation(0, 5), field.dataToScreenLocation(0, 5));

		assertEquals(new RowColLocation(1, 0), field.dataToScreenLocation(1, 0));
		assertEquals(new RowColLocation(1, 4), field.dataToScreenLocation(1, 4));
		assertEquals(new RowColLocation(1, 5), field.dataToScreenLocation(1, 5));

		assertEquals(new RowColLocation(2, 0), field.dataToScreenLocation(2, 0));
		assertEquals(new RowColLocation(2, 4), field.dataToScreenLocation(2, 4));
		assertEquals(new RowColLocation(2, 12), field.dataToScreenLocation(2, 12));
		assertEquals(new DefaultRowColLocation(2, 12), field.dataToScreenLocation(2, 15));

		assertEquals(new RowColLocation(3, 0), field.dataToScreenLocation(3, 0));
		assertEquals(new RowColLocation(3, 4), field.dataToScreenLocation(3, 4));
	}

	@Test
	public void testTextOffsetToScreenLocation() {
		assertEquals(new RowColLocation(0, 0), field.textOffsetToScreenLocation(0));
		assertEquals(new RowColLocation(0, 5), field.textOffsetToScreenLocation(5));

		assertEquals(new RowColLocation(1, 0), field.textOffsetToScreenLocation(6));
		assertEquals(new RowColLocation(1, 4), field.textOffsetToScreenLocation(10));
		assertEquals(new RowColLocation(1, 5), field.textOffsetToScreenLocation(11));

		assertEquals(new RowColLocation(2, 0), field.textOffsetToScreenLocation(12));

		assertEquals(new RowColLocation(1, 4), field.textOffsetToScreenLocation(10));

		assertEquals(new DefaultRowColLocation(3, 4), field.textOffsetToScreenLocation(1000));
	}

	@Test
	public void testGetY_And_GetRow() {

		int y = field.getY(0);
		int row = field.getRow(y);
		assertEquals("Wrong row for y value: " + y, 0, row);

		y = field.getY(1);
		row = field.getRow(y);
		assertEquals("Wrong row for y value: " + y, 1, row);

		y = field.getY(2);
		row = field.getRow(y);
		assertEquals("Wrong row for y value: " + y, 2, row);

		y = field.getY(3);
		row = field.getRow(y);
		assertEquals("Wrong row for y value: " + y, 3, row);

		// try values past the end
		int yForRowTooBig = field.getY(10);
		assertEquals(y, yForRowTooBig);
		int rowForYTooBig = field.getRow(1000);
		assertEquals(3, rowForYTooBig);

		// try values before the beginning
		int yForRowTooSmall = field.getY(-1);
		int expectedY = -field.getHeightAbove();
		assertEquals(expectedY, yForRowTooSmall);
		int rowForYTooSmall = field.getRow(-1000);
		assertEquals(0, rowForYTooSmall);
	}
}
