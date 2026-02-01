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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.accessibility.*;
import javax.swing.JLabel;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.internal.EmptyBigLayoutModel;
import docking.widgets.fieldpanel.support.*;

public class AccessibleFieldPanelDelegateTest {
	private static final int FIELD_WIDTH = 100;
	private static final int FIELD_HEIGHT = 100;

	private AccessibleFieldPanelDelegate delegate;
	private static FontMetrics fontMetrics =
		new JLabel("Dummy").getFontMetrics(new Font("Monospaced", Font.PLAIN, 12));
	private List<AnchoredLayout> layouts;
	private FieldPanel panel = new FieldPanel(new EmptyBigLayoutModel());
	private TestAccessibleContext testContext = new TestAccessibleContext();
	private int fieldLineHeight = fontMetrics.getHeight() + 1;

	@Before
	public void setup() {
		layouts = List.of(buildAnchoredLayout(0, 0, 3), buildAnchoredLayout(1, FIELD_HEIGHT, 13));
		delegate = new AccessibleFieldPanelDelegate(layouts, testContext, panel);
		delegate.setFieldDescriptionProvider(new TestFieldDescriptionProvider());
		delegate.setCaret(new FieldLocation(BigInteger.ZERO, 0, 0, 0), EventTrigger.API_CALL);

	}

	@Test
	public void testGetChildrenCount() {
		layouts = List.of(buildAnchoredLayout(0, 0, 3), buildAnchoredLayout(1, FIELD_HEIGHT, 5));
		delegate.setLayouts(layouts);

		assertEquals(8, delegate.getFieldCount());
	}

	@Test
	public void testGetAccessibleChildFromOrdinal() {
		assertEquals("Field 0, 0", getId(delegate.getAccessibleField(0)));
		assertEquals("Field 0, 1", getId(delegate.getAccessibleField(1)));
		assertEquals("Field 0, 2", getId(delegate.getAccessibleField(2)));
		assertEquals("Field 1, 0", getId(delegate.getAccessibleField(3)));
		assertEquals("Field 1, 1", getId(delegate.getAccessibleField(4)));
		assertEquals("Field 1, 11", getId(delegate.getAccessibleField(14)));
		assertEquals(null, delegate.getAccessibleField(16));

		assertEquals(null, delegate.getAccessibleField(-1));
	}

	private String getId(AccessibleField field) {
		String text = field.getText();
		int indexOf = text.indexOf(":");
		return text.substring(0, indexOf);
	}

	@Test
	public void testGetAccessibleChildFromFieldLocation() {
		assertEquals("Field 0, 0", getId(delegate.getAccessibleField(fieldLoc(0, 0))));
		assertEquals("Field 0, 1", getId(delegate.getAccessibleField(fieldLoc(0, 1))));
		assertEquals("Field 0, 2", getId(delegate.getAccessibleField(fieldLoc(0, 2))));
		assertEquals("Field 1, 0", getId(delegate.getAccessibleField(fieldLoc(1, 0))));
		assertEquals("Field 1, 1", getId(delegate.getAccessibleField(fieldLoc(1, 1))));
		assertEquals("Field 1, 2", getId(delegate.getAccessibleField(fieldLoc(1, 2))));
		assertEquals("Field 1, 12", getId(delegate.getAccessibleField(fieldLoc(1, 12))));
		assertEquals(null, delegate.getAccessibleField(fieldLoc(15, 0)));
		assertEquals(null, delegate.getAccessibleField(fieldLoc(-1, 0)));
	}

	@Test
	public void testGetAccessibleChildCache() {
		AccessibleField accessibleField1 = delegate.getAccessibleField(0);
		assertEquals("Field 0, 0", getId(accessibleField1));

		AccessibleField accessibleField2 = delegate.getAccessibleField(0);
		assertEquals("Field 0, 0", getId(accessibleField1));

		assertTrue(accessibleField1 == accessibleField2);
	}

	@Test
	public void testGetAccessbileAt() {
		AccessibleField accessibleField =
			(AccessibleField) delegate.getAccessibleAt(new Point(0, 0));
		assertEquals("Field 0, 0", getId(accessibleField));

		accessibleField = (AccessibleField) delegate.getAccessibleAt(new Point(210, 0));
		assertEquals("Field 0, 2", getId(accessibleField));

		accessibleField = (AccessibleField) delegate.getAccessibleAt(new Point(220, 112));
		assertEquals("Field 1, 2", getId(accessibleField));

	}

	@Test
	public void testGetFieldDescription() {
		assertEquals("Description for field: 0, 0", delegate.getFieldDescription());
		delegate.setCaret(new FieldLocation(BigInteger.ONE, 2, 0, 0), EventTrigger.API_CALL);
		assertEquals("Description for field: 1, 2", delegate.getFieldDescription());
	}

	@Test
	public void testGetCaretPosition() {
		assertEquals(0, delegate.getCaretPosition());
		delegate.setCaret(new FieldLocation(BigInteger.ONE, 2, 0, 3), EventTrigger.API_CALL);
		assertEquals(3, delegate.getCaretPosition());
	}

	@Test
	public void testGetCharCount() {
		// the first field is "Field 0, 0: line 1\nField 0, 0: line 2", so length is 37
		assertEquals(37, delegate.getCharCount());
		delegate.setCaret(fieldLoc(1, 11), EventTrigger.API_CALL);
		// the active field is now "Field 1, 10: line 1 Field 1,10: line 2", so length is 39
		assertEquals(39, delegate.getCharCount());
	}

	@Test
	public void testGetCharBounds() {
		int row = 0;
		int fieldNum = 0;
		delegate.setCaret(fieldLoc(row, fieldNum), EventTrigger.API_CALL);

		assertEquals(rect(0, 0, 7, fieldLineHeight), delegate.getCharacterBounds(0));
		assertEquals(rect(7, 0, 7, fieldLineHeight), delegate.getCharacterBounds(1));
		assertEquals(rect(14, 0, 7, fieldLineHeight), delegate.getCharacterBounds(2));

		row = 0;
		fieldNum = 1;
		delegate.setCaret(fieldLoc(row, fieldNum), EventTrigger.API_CALL);
		int startX = FIELD_WIDTH * fieldNum;
		int startY = FIELD_HEIGHT * row;

		assertEquals(rect(startX, startY, 7, fieldLineHeight), delegate.getCharacterBounds(0));
		assertEquals(rect(startX + 7, startY, 7, fieldLineHeight), delegate.getCharacterBounds(1));
		assertEquals(rect(startX + 14, startY, 7, fieldLineHeight), delegate.getCharacterBounds(2));

		row = 1;
		fieldNum = 3;
		delegate.setCaret(fieldLoc(row, fieldNum), EventTrigger.API_CALL);
		startX = FIELD_WIDTH * fieldNum;
		startY = FIELD_HEIGHT * row;

		assertEquals(rect(startX, startY, 7, fieldLineHeight), delegate.getCharacterBounds(0));
		assertEquals(rect(startX + 7, startY, 7, fieldLineHeight), delegate.getCharacterBounds(1));
		assertEquals(rect(startX + 14, startY, 7, fieldLineHeight), delegate.getCharacterBounds(2));

	}

	@Test
	public void testGetIndexAtPoint_1stRow1stFieldActive() {
		int row = 0;
		int fieldNum = 0;
		delegate.setCaret(fieldLoc(row, fieldNum), EventTrigger.API_CALL);
		// char size is 8 x 16
		// second line starts at char 19
		// the field starts at 0,0 and contains:
		//
		// Field 0,0: line 1
		// Field 0,0: line 2

		assertEquals(0, delegate.getIndexAtPoint(new Point(0, 0)));
		assertEquals(0, delegate.getIndexAtPoint(new Point(3, 3)));
		assertEquals(1, delegate.getIndexAtPoint(new Point(8, 3)));
		assertEquals(11, delegate.getIndexAtPoint(new Point(80, 0)));
		assertEquals(0, delegate.getIndexAtPoint(new Point(0, fieldLineHeight - 1)));
		assertEquals(19, delegate.getIndexAtPoint(new Point(0, fieldLineHeight)));
		assertEquals(19, delegate.getIndexAtPoint(new Point(0, fieldLineHeight + 1)));

	}

	@Test
	public void testGetIndexAtPoint_2ndRow3rdFieldActive() {
		int row = 1;
		int fieldNum = 2;
		delegate.setCaret(fieldLoc(row, fieldNum), EventTrigger.API_CALL);
		// char size is 8 x 16
		// second line starts at char 19
		// field upper left corner is at point 200,100
		// the field starts at 0,0 and contains:
		//
		// Field 0,0: line 1
		// Field 0,0: line 2

		assertEquals(0, delegate.getIndexAtPoint(new Point(200, 100)));
		assertEquals(0, delegate.getIndexAtPoint(new Point(203, 103)));
		assertEquals(1, delegate.getIndexAtPoint(new Point(208, 103)));
		assertEquals(11, delegate.getIndexAtPoint(new Point(280, 100)));
		assertEquals(0, delegate.getIndexAtPoint(new Point(200, 100 + fieldLineHeight - 1)));
		assertEquals(19, delegate.getIndexAtPoint(new Point(200, 100 + fieldLineHeight)));
		assertEquals(19, delegate.getIndexAtPoint(new Point(200, 100 + fieldLineHeight + 1)));

		assertEquals(-1, delegate.getIndexAtPoint(new Point(0, 0)));
	}

	@Test
	public void testGetAtIndex() {
		delegate.setCaret(fieldLoc(0, 0), EventTrigger.API_CALL);

		assertEquals("F", delegate.getAtIndex(AccessibleText.CHARACTER, 0));
		assertEquals("i", delegate.getAtIndex(AccessibleText.CHARACTER, 1));
		assertEquals("e", delegate.getAtIndex(AccessibleText.CHARACTER, 2));
		assertEquals("1", delegate.getAtIndex(AccessibleText.CHARACTER, 17));
		assertEquals("2", delegate.getAtIndex(AccessibleText.CHARACTER, 36));

	}

	@Test
	public void testGetAfterIndex() {
		delegate.setCaret(fieldLoc(0, 0), EventTrigger.API_CALL);

		assertEquals("i", delegate.getAfterIndex(AccessibleText.CHARACTER, 0));
		assertEquals("e", delegate.getAfterIndex(AccessibleText.CHARACTER, 1));
		assertEquals("l", delegate.getAfterIndex(AccessibleText.CHARACTER, 2));
		assertEquals("1", delegate.getAfterIndex(AccessibleText.CHARACTER, 16));
		assertEquals("2", delegate.getAfterIndex(AccessibleText.CHARACTER, 35));

	}

	@Test
	public void testGetBeforeIndex() {
		delegate.setCaret(fieldLoc(0, 0), EventTrigger.API_CALL);

		assertEquals(null, delegate.getBeforeIndex(AccessibleText.CHARACTER, 0));
		assertEquals("F", delegate.getBeforeIndex(AccessibleText.CHARACTER, 1));
		assertEquals("i", delegate.getBeforeIndex(AccessibleText.CHARACTER, 2));
		assertEquals("1", delegate.getBeforeIndex(AccessibleText.CHARACTER, 18));
		assertEquals("2", delegate.getBeforeIndex(AccessibleText.CHARACTER, 37));

	}

	@Test
	public void testGetSelectionStartEndAndText_noSelection() {
		delegate.setCaret(fieldLoc(0, 0), EventTrigger.API_CALL);
		delegate.setSelection(null, EventTrigger.API_CALL);

		assertEquals(0, delegate.getSelectionStart());
		assertEquals(0, delegate.getSelectionEnd());
		assertEquals(null, delegate.getSelectedText());
	}

	@Test
	public void testGetSelectionStartEndAndText_withSelection() {
		delegate.setCaret(fieldLoc(0, 0), EventTrigger.API_CALL);
		FieldSelection fieldSelection = new FieldSelection();
		fieldSelection.addRange(0, 1);
		delegate.setSelection(fieldSelection, EventTrigger.API_CALL);

		assertEquals(0, delegate.getSelectionStart());
		assertEquals(delegate.getCharCount(), delegate.getSelectionEnd());
		assertEquals("Field 0, 0: Line 1 Field 0, 0: Line 2", delegate.getSelectedText());
	}

	private FieldLocation fieldLoc(int index, int fieldNum) {
		return new FieldLocation(BigInteger.valueOf(index), fieldNum, 0, 0);
	}

	private Rectangle rect(int x, int y, int w, int h) {
		return new Rectangle(x, y, w, h);
	}

	private AnchoredLayout buildAnchoredLayout(int index, int yPos, int numFields) {
		return new AnchoredLayout(buildLayout(index, numFields), BigInteger.valueOf(index), yPos);
	}

	private Layout buildLayout(int index, int numFields) {
		return new DummyLayout(index, numFields);
	}

	private class DummyLayout extends RowLayout {

		public DummyLayout(int index, int numFields) {
			super(createFields(index, numFields), 0);
		}

		private static Field[] createFields(int index, int numFields) {
			Field[] fields = new Field[numFields];
			for (int i = 0; i < numFields; i++) {
				fields[i] = new DummyField(index, i);
			}
			return fields;
		}

	}

	private static class DummyField extends VerticalLayoutTextField {

		public DummyField(int index, int fieldNum) {
			super(createSubFields(index, fieldNum), fieldNum * FIELD_WIDTH, FIELD_WIDTH, 2, null);
		}

		private static List<FieldElement> createSubFields(int index, int fieldNum) {
			List<FieldElement> list = new ArrayList<>();

			String text = "Field " + index + ", " + fieldNum + ": Line 1";
			AttributedString as = new AttributedString(text, Color.BLACK, fontMetrics);
			list.add(new TextFieldElement(as, 0, 0));

			text = "Field " + index + ", " + fieldNum + ": Line 2";
			as = new AttributedString(text, Color.BLACK, fontMetrics);
			list.add(new TextFieldElement(as, 1, 0));

			return list;
		}

	}

	private class TestFieldDescriptionProvider implements FieldDescriptionProvider {

		@Override
		public String getDescription(FieldLocation loc, Field field) {
			return "Description for field: " + loc.getIndex() + ", " + loc.getFieldNum();
		}

	}

	private class TestAccessibleContext extends AccessibleContext {

		@Override
		public AccessibleRole getAccessibleRole() {
			return AccessibleRole.TEXT;
		}

		@Override
		public AccessibleStateSet getAccessibleStateSet() {
			return null;
		}

		@Override
		public int getAccessibleIndexInParent() {
			return 0;
		}

		@Override
		public int getAccessibleChildrenCount() {
			return 0;
		}

		@Override
		public Accessible getAccessibleChild(int i) {
			return null;
		}

		@Override
		public Locale getLocale() throws IllegalComponentStateException {
			return null;
		}

	}

}
