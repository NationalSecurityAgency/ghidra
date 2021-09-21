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
package docking.widgets.fieldpanel.field;

import static org.junit.Assert.*;

import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.support.*;
import generic.test.AbstractGenericTest;

public class CompositeVerticalLayoutTextFieldTest extends AbstractGenericTest {

	private static final String LONG_STRING = "Supercalifragilisticexpialidocious";
	private FontMetrics fontMetrics;

	private CompositeVerticalLayoutTextField field;
	private List<String> rows;

	// some default field values
	int startX = 100; // arbitrary
	int width = 100; // used to trigger horizontal clipping
	int maxLines = 5; // used to trigger vertical clipping

	private HighlightFactory hlFactory = (hlField, text, cursorTextOffset) -> {
		return new Highlight[] {};
	};

	@Before
	public void setUp() throws Exception {

		Font font = new Font("Times New Roman", 0, 14);
		fontMetrics = getFontMetrics(font);

		field = createField(maxLines, List.of(
			"Hello",
			"World",
			LONG_STRING,
			"Wow!"));
	}

	private CompositeVerticalLayoutTextField createField(int lineLimit, List<String> lines) {

		rows = lines;

		List<FieldElement> elements = new ArrayList<>();
		int row = 0;
		for (String line : lines) {
			elements.add(createRow(row++, line, Color.BLUE));
		}

		List<TextField> fields = new ArrayList<>();
		for (FieldElement element : elements) {
			fields.add(new ClippingTextField(startX, width, element, hlFactory));
		}

		return new CompositeVerticalLayoutTextField(fields, startX, width, lineLimit, hlFactory);
	}

	private CompositeVerticalLayoutTextField createBasicWrappingField(List<String> lines) {

		rows = lines;

		List<FieldElement> elements = new ArrayList<>();
		int row = 0;
		for (String line : lines) {
			elements.add(createRow(row++, line, Color.BLUE));
		}

		List<TextField> fields = new ArrayList<>();
		for (FieldElement element : elements) {
			fields.add(new WrappingVerticalLayoutTextField(element, startX, width, maxLines,
				hlFactory));
		}

		return new CompositeVerticalLayoutTextField(fields, startX, width, maxLines, hlFactory);
	}

	private CompositeVerticalLayoutTextField createMixedWrappingField(List<String> lines) {

		rows = lines;

		int row = 0;
		List<TextField> fields = new ArrayList<>();
		fields.add(wrappedField(row++, lines.get(0)));
		fields.add(clippedField(row++, lines.get(1)));
		fields.add(wrappedField(row++, lines.get(2)));

		return new CompositeVerticalLayoutTextField(fields, startX, width, maxLines, hlFactory);
	}

	private CompositeVerticalLayoutTextField createMixedWrappingField(TextField... fields) {
		return new CompositeVerticalLayoutTextField(Arrays.asList(fields), startX, width, maxLines,
			hlFactory);
	}

	private TextField wrappedField(int row, String text) {
		FieldElement element = createRow(row, text, Color.BLUE);
		return new WrappingVerticalLayoutTextField(element, startX, width, maxLines, hlFactory);
	}

	private TextField clippedField(int row, String text) {
		FieldElement element = createRow(row, text, Color.BLUE);
		return new ClippingTextField(startX, width, element, hlFactory);
	}

	private FieldElement createRow(int row, String text, Color color) {
		return new TextFieldElement(new AttributedString(text, color, fontMetrics), row, 0);
	}

	@Test
	public void testScreenToDataLocation() {

		assertRowCol(0, 0, field.screenToDataLocation(0, 0));
		assertRowCol(0, 2, field.screenToDataLocation(0, 2));
		assertRowCol(0, 5, field.screenToDataLocation(0, 5));
		assertRowCol(0, 5, field.screenToDataLocation(0, 6)); // past end
		assertRowCol(0, 5, field.screenToDataLocation(0, 75));

		assertRowCol(1, 0, field.screenToDataLocation(1, 0));
		assertRowCol(1, 5, field.screenToDataLocation(1, 6));
		assertRowCol(1, 5, field.screenToDataLocation(1, 16));

		assertRowCol(2, 0, field.screenToDataLocation(2, 0));
		assertRowCol(2, 4, field.screenToDataLocation(2, 4));
		assertRowCol(2, 34, field.screenToDataLocation(2, 75));

		assertRowCol(3, 0, field.screenToDataLocation(3, 0));
		assertRowCol(3, 4, field.screenToDataLocation(50, 75));
	}

	@Test
	public void testDataToScreenLocation() {
		assertRowCol(0, 0, field.dataToScreenLocation(0, 0));
		assertRowCol(0, 2, field.dataToScreenLocation(0, 2));
		assertRowCol(0, 5, field.dataToScreenLocation(0, 5));

		assertRowCol(1, 0, field.dataToScreenLocation(1, 0));
		assertRowCol(1, 4, field.dataToScreenLocation(1, 4));
		assertRowCol(1, 5, field.dataToScreenLocation(1, 5));

		assertRowCol(2, 0, field.dataToScreenLocation(2, 0));
		assertRowCol(2, 4, field.dataToScreenLocation(2, 4));
		assertRowCol(2, 12, field.dataToScreenLocation(2, 12));
		assertRowCol(2, 12, field.dataToScreenLocation(2, 15));

		assertRowCol(3, 0, field.dataToScreenLocation(3, 0));
		assertRowCol(3, 4, field.dataToScreenLocation(3, 4));
	}

	@Test
	public void testTextOffsetToScreenLocation() {

		//
		// Each row of text has text.lenghth() + 1 possible positions: before and after each
		// character.  For example, in the text "hi", these are the possible cursor positions:
		//
		// 		|hi
		// 		h|i
		// 		hi|
		//

		// each line may have a line separator
		int separator = field.getRowSeparator().length();

		// dumpFieldOffsets();

		// the end is after the last character
		String row1 = rows.get(0);
		int row1End = row1.length();
		assertRowCol(0, 0, field.textOffsetToScreenLocation(0));
		assertRowCol(0, row1End - 1, field.textOffsetToScreenLocation(row1End - 1));
		assertRowCol(0, row1End, field.textOffsetToScreenLocation(row1End));

		int row2Start = row1End + separator;
		String row2 = rows.get(1);
		int row2End = row2Start + row2.length();
		int relativeEnd = row2End - row2Start;
		assertRowCol(1, 0, field.textOffsetToScreenLocation(row2Start));
		assertRowCol(1, relativeEnd - 1, field.textOffsetToScreenLocation(row2End - 1));
		assertRowCol(1, relativeEnd, field.textOffsetToScreenLocation(row2End));

		String row3 = rows.get(2);
		int row3Start = row2End + separator;
		assertRowCol(2, 0, field.textOffsetToScreenLocation(row3Start));

		int row3End = row3Start + row3.length();
		int row4Start = row3End + 1;
		assertRowCol(3, 0, field.textOffsetToScreenLocation(row4Start));

		// far past the end will put the cursor at the end
		String row4 = rows.get(3);
		assertRowCol(3, row4.length(), field.textOffsetToScreenLocation(1000));
	}

	@Test
	public void testScreenLocationToTextOffset() {

		// each line may have a line separator
		int separator = field.getRowSeparator().length();

		String row1 = rows.get(0);
		int row1End = row1.length();
		assertEquals(0, field.screenLocationToTextOffset(0, 0));
		assertEquals(row1End - 1, field.screenLocationToTextOffset(0, row1End - 1));
		assertEquals(row1End, field.screenLocationToTextOffset(0, row1End));

		int row2Start = row1End + separator;
		String row2 = rows.get(1);
		int row2End = row2Start + row2.length();
		int relativeEnd = row2End - row2Start;
		assertEquals(row2Start, field.screenLocationToTextOffset(1, 0));
		assertEquals(row2End - 1, field.screenLocationToTextOffset(1, relativeEnd - 1));
		assertEquals(row2End, field.screenLocationToTextOffset(1, relativeEnd));

		String row3 = rows.get(2);
		int row3Start = row2End + separator;
		assertEquals(row3Start, field.screenLocationToTextOffset(2, 0));

		int row3End = row3Start + row3.length();
		int row4Start = row3End + 1;
		assertEquals(row4Start, field.screenLocationToTextOffset(3, 0));
		assertRowCol(3, 0, field.textOffsetToScreenLocation(row4Start));

		// far past the end will put the cursor at the end
		String row4 = rows.get(3);
		int row4End = row4Start + row4.length();
		assertEquals(row4End, field.screenLocationToTextOffset(3, 1000));
	}

	@Test
	public void testGetFieldElement() {

		String row1 = rows.get(0);
		assertEquals(row1, field.getFieldElement(0, 0).toString());
		assertEquals(row1, field.getFieldElement(0, 1).toString());
		assertEquals(row1, field.getFieldElement(0, row1.length()).toString());
		assertEquals(row1, field.getFieldElement(0, row1.length() + 1).toString());
		assertEquals(row1, field.getFieldElement(0, 100).toString());

		String row2 = rows.get(1);
		assertEquals(row2, field.getFieldElement(1, 0).toString());
		assertEquals(row2, field.getFieldElement(1, 1).toString());
		assertEquals(row2, field.getFieldElement(1, row2.length()).toString());
		assertEquals(row2, field.getFieldElement(1, row2.length() + 1).toString());
		assertEquals(row2, field.getFieldElement(1, 100).toString());

		String row3 = rows.get(2);
		assertEquals(row3, field.getFieldElement(2, 0).toString());
		assertEquals(row3, field.getFieldElement(2, 1).toString());
		assertEquals(row3, field.getFieldElement(2, row3.length()).toString());
		assertEquals(row3, field.getFieldElement(2, row3.length() + 1).toString());
		assertEquals(row3, field.getFieldElement(2, 100).toString());

		String row4 = rows.get(3);
		assertEquals(row4, field.getFieldElement(3, 0).toString());
		assertEquals(row4, field.getFieldElement(3, 1).toString());
		assertEquals(row4, field.getFieldElement(3, row4.length()).toString());
		assertEquals(row4, field.getFieldElement(3, row4.length() + 1).toString());
		assertEquals(row4, field.getFieldElement(3, 100).toString());
	}

	@Test
	public void testGetNumColumns() {

		int separator = field.getRowSeparator().length();

		String row1 = rows.get(0);
		int row1Columns = row1.length() + separator;
		assertEquals(row1Columns, field.getNumCols(0));

		String row2 = rows.get(1);
		int row2Columns = row2.length() + separator;
		assertEquals(row2Columns, field.getNumCols(1));

		// note: the number of columns is the clipped text length, which is 12, plus 1 extra
		//       column to allow for placing the cursor after the text
		int clippedLength = 13; // not sure how to get this from the field
		assertEquals(clippedLength, field.getNumCols(2));

		String row4 = rows.get(3);
		int row4Columns = row4.length() + separator;
		assertEquals(row4Columns, field.getNumCols(3));
	}

	@Test
	public void testClippingWithTooManyRows() {

		int lineLimit = 2;
		field = createField(lineLimit, List.of(
			"Hello",
			"Wolrd",
			LONG_STRING,
			"Wow!"));

		assertEquals(2, field.getNumRows());
		assertEquals(4, field.getNumDataRows());

		assertRowCol(0, 0, field.dataToScreenLocation(0, 0));
		assertRowCol(0, 2, field.dataToScreenLocation(0, 2));
		assertRowCol(0, 5, field.dataToScreenLocation(0, 5));

		assertRowCol(1, 0, field.dataToScreenLocation(1, 0));
		assertRowCol(1, 4, field.dataToScreenLocation(1, 4));
		assertRowCol(1, 5, field.dataToScreenLocation(1, 5));

		// try accessing clipped rows
		assertRowCol(1, 5, field.dataToScreenLocation(2, 0));
		assertRowCol(1, 5, field.dataToScreenLocation(2, 5));
		assertRowCol(1, 5, field.dataToScreenLocation(20, 50));
	}

	@Test
	public void testIsClipped_NoClipping() {
		field = createField(maxLines, List.of("Hello", "Wolrd"));
		assertFalse(field.isClipped());
	}

	@Test
	public void testIsClipped_HorizontalClipping() {
		field = createField(maxLines, List.of(LONG_STRING));
		assertTrue(field.isClipped());
	}

	@Test
	public void testIsClipped_VerticalClipping() {
		int lineLimit = 2;
		field = createField(lineLimit, List.of(
			"Hello",
			"Wolrd",
			"Wow!"));
		assertTrue(field.isClipped());
	}

	@Test
	public void testIsClipped_HorizontalAndVerticalClipping() {
		int lineLimit = 2;
		field = createField(lineLimit, List.of(
			"Hello",
			"Wolrd",
			LONG_STRING,
			"Wow!"));
		assertTrue(field.isClipped());
	}

	@Test
	public void getGetAllRows() {

		String row1 = rows.get(0);
		List<TextField> allRows = field.getAllRowsUpTo(0);
		assertEquals(1, allRows.size());
		assertEquals(row1, allRows.get(0).toString());

		String row2 = rows.get(1);
		allRows = field.getAllRowsUpTo(1);
		assertEquals(2, allRows.size());
		assertEquals(row1, allRows.get(0).toString());
		assertEquals(row2, allRows.get(1).toString());

		String row3 = rows.get(2);
		allRows = field.getAllRowsUpTo(2);
		assertEquals(3, allRows.size());
		assertEquals(row1, allRows.get(0).toString());
		assertEquals(row2, allRows.get(1).toString());
		assertEquals(row3, allRows.get(2).toString());

		String row4 = rows.get(3);
		allRows = field.getAllRowsUpTo(3);
		assertEquals(4, allRows.size());
		assertEquals(row1, allRows.get(0).toString());
		assertEquals(row2, allRows.get(1).toString());
		assertEquals(row3, allRows.get(2).toString());
		assertEquals(row4, allRows.get(3).toString());

		allRows = field.getAllRowsUpTo(10);
		assertEquals(4, allRows.size());

		allRows = field.getAllRowsUpTo(-1);
		assertEquals(0, allRows.size());
	}

	@Test
	public void testGetText() {
		assertEquals("Hello World Supercalifragilisticexpialidocious Wow! ", field.getText());
	}

	@Test
	public void testGetTextWithLineSeparators() {
		assertEquals("Hello\nWorld\nSupercalifragilisticexpialidocious\nWow!",
			field.getTextWithLineSeparators());
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

	@Test
	public void testGetX_And_GetCol() {

		String row1 = rows.get(0);
		int x = field.getX(0, 0);
		int column = field.getCol(0, x);
		assertEquals(0, column);

		x = field.getX(0, row1.length());
		column = field.getCol(0, x);
		assertEquals(row1.length(), column);

		String row2 = rows.get(1);
		x = field.getX(1, 0);
		column = field.getCol(1, x);
		assertEquals(0, column);

		x = field.getX(1, row2.length());
		column = field.getCol(1, x);
		assertEquals(row2.length(), column);

		String row3 = rows.get(2);
		x = field.getX(2, 0);
		column = field.getCol(2, x);
		assertEquals(0, column);

		x = field.getX(2, row3.length());
		column = field.getCol(2, x);
		int clippedLength = 12; // not sure how to get this from the field
		assertEquals(clippedLength, column);

		x = field.getX(2, row3.length() + 1);
		column = field.getCol(2, x);
		assertEquals(clippedLength, column);
	}

	@Test
	public void testLayoutWithWrapping_OneWrappedRow() {

		//
		// Test the composite field when one of the internal fields will wrap into multiple rows
		// when too long.
		//

		field =
			createBasicWrappingField(List.of("This is a line with multiple words for wrapping"));

		assertEquals(4, field.getNumRows());

		assertEquals("This is a line", field.getFieldElement(0, 0).getText());
		assertEquals("with multiple", field.getFieldElement(1, 0).getText());
		assertEquals("words for", field.getFieldElement(2, 0).getText());
		assertEquals("wrapping", field.getFieldElement(3, 0).getText());

		// note: the final 'data' row becomes 4 'screen' rows
		assertEquals(15, field.getNumCols(0));
		assertEquals(14, field.getNumCols(1));
		assertEquals(10, field.getNumCols(2));
		assertEquals(9, field.getNumCols(3));
	}

	@Test
	public void testLayoutWrapping_TwoWrappedRow() {

		field = createBasicWrappingField(List.of("This is line one", "This is line two"));

		assertEquals(4, field.getNumRows());

		assertEquals("This is line", field.getFieldElement(0, 0).getText());
		assertEquals("one", field.getFieldElement(1, 0).getText());
		assertEquals("This is line", field.getFieldElement(2, 0).getText());
		assertEquals("two", field.getFieldElement(3, 0).getText());

		// note: the final 'data' row becomes 4 'screen' rows
		assertEquals(13, field.getNumCols(0));
		assertEquals(4, field.getNumCols(1));
		assertEquals(13, field.getNumCols(2));
		assertEquals(4, field.getNumCols(3));
	}

	@Test
	public void testLayoutWrapping_MixedRows() {

		//
		// Test that we can mix wrapping and non-wrapping rows
		//

		field = createMixedWrappingField(
			List.of("This is line one", "This line does not wrap", "This is line two"));

		assertEquals(5, field.getNumRows());

		assertEquals("This is line", field.getFieldElement(0, 0).getText());
		assertEquals("one", field.getFieldElement(1, 0).getText());
		assertEquals("This line does not wrap", field.getFieldElement(2, 0).getText());
		assertEquals("This is line", field.getFieldElement(3, 0).getText());
		assertEquals("two", field.getFieldElement(4, 0).getText());

		// note: the final 'data' row becomes 5 'screen' rows
		assertEquals(13, field.getNumCols(0));
		assertEquals(4, field.getNumCols(1));
		assertEquals(14, field.getNumCols(2));
		assertEquals(13, field.getNumCols(3));
		assertEquals(4, field.getNumCols(4));
	}

	@Test
	public void testLayoutWrapping_MixedRows_TrailingWrappingRow() {

		String row1 = "1: clipped row: This will be clipped horizonally";
		String row2 = "2: clipped row: This will be clipped horizonally";
		String row3 = "3: wrapped row: This field will wrap";
		TextField field1 = clippedField(0, row1);
		TextField field2 = clippedField(1, row2);
		TextField field3 = wrappedField(2, row3);

		field = createMixedWrappingField(field1, field2, field3);

		assertEquals(5, field.getNumRows());

		assertEquals(row1, field.getFieldElement(0, 0).getText());
		assertEquals(row2, field.getFieldElement(1, 0).getText());
		assertEquals("3: wrapped", field.getFieldElement(2, 0).getText());
		assertEquals("row: This field", field.getFieldElement(3, 0).getText());
		assertEquals("will wrap", field.getFieldElement(4, 0).getText());

		// not sure how to get this from the field
		int clippedLength = 14;
		assertEquals(clippedLength, field.getNumCols(0));
		assertEquals(clippedLength, field.getNumCols(1));

		// note: the final 'data' row becomes 3 'screen' rows
		assertEquals(11, field.getNumCols(2));
		assertEquals(16, field.getNumCols(3));
		assertEquals(10, field.getNumCols(4));
	}

	private void assertRowCol(int expectedRow, int expectedColumn, RowColLocation actualLocation) {
		assertEquals("Wrong row", expectedRow, actualLocation.row());
		assertEquals("Wrong column", expectedColumn, actualLocation.col());
	}
}
