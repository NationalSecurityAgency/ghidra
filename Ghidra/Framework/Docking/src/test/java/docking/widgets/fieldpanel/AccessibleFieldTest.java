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

import javax.accessibility.*;
import javax.swing.JLabel;
import javax.swing.JPanel;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.field.*;
import generic.test.AbstractGenericTest;

public class AccessibleFieldTest extends AbstractGenericTest {
	private static final int PARENT_X = 1000;
	private static final int PARENT_Y = 1000;
	private static final int FIELD_X = 100;
	private static final int FIELD_Y = 100;
	private static final int FIELD_WIDTH = 75;

	private JPanel parent = new JPanel() {
		public Point getLocationOnScreen() {
			return new Point(PARENT_X, PARENT_Y);
		}
	};
	private TestField testField;
	private AccessibleField accessibleField;
	private Rectangle boundsInParent;
	private int fieldHeight;

	@Before
	public void setUp() {
		testField = new TestField(FIELD_X, FIELD_WIDTH, "line1", "line2");
		fieldHeight = testField.getHeight();
		boundsInParent = new Rectangle(FIELD_X, FIELD_Y, FIELD_WIDTH, fieldHeight);
		accessibleField = new AccessibleField(testField, parent, 0, boundsInParent);
	}

	@Test
	public void testGetName() {
		assertEquals("Field", accessibleField.getAccessibleName());
	}

	@Test
	public void testGetAccessibleContext() {
		assertEquals(accessibleField, accessibleField.getAccessibleContext());
	}

	@Test
	public void testGetAccessibleText() {
		assertEquals(accessibleField, accessibleField.getAccessibleText());
	}

	@Test
	public void testGetAccessibleComponent() {
		assertEquals(accessibleField, accessibleField.getAccessibleComponent());
	}

	@Test
	public void testGetAccessibleRole() {
		assertEquals(AccessibleRole.TEXT, accessibleField.getAccessibleRole());
	}

	@Test
	public void testAccessibleIndexInParent() {
		assertEquals(0, accessibleField.getAccessibleIndexInParent());
		accessibleField = new AccessibleField(testField, parent, 5, boundsInParent);
		assertEquals(5, accessibleField.getAccessibleIndexInParent());
	}

	@Test
	public void testGetAccessibleStateSet() {
		AccessibleStateSet set = accessibleField.getAccessibleStateSet();
		assertTrue(set.contains(AccessibleState.MULTI_LINE));
		assertTrue(set.contains(AccessibleState.TRANSIENT));
	}

	@Test
	public void testGetLocale() {
		assertEquals(parent.getLocale(), accessibleField.getLocale());
	}

	@Test
	public void testGetAccessibleChildCount() {
		assertEquals(0, accessibleField.getAccessibleChildrenCount());
	}

	@Test
	public void testGetAccessibleChild() {
		assertNull(accessibleField.getAccessibleChild(0));
	}

	@Test
	public void testGetBounds() {
		assertEquals(new Rectangle(FIELD_X, FIELD_Y, FIELD_WIDTH, fieldHeight),
			accessibleField.getBounds());
	}

	@Test
	public void testGetIndexAtPoint() {
		assertEquals(0, accessibleField.getIndexAtPoint(new Point(0, 0)));
		assertEquals(3,
			accessibleField.getIndexAtPoint(new Point(3 * testField.getCharWidth(), 0)));
		assertEquals(6, accessibleField.getIndexAtPoint(new Point(0, testField.getLineHeight())));
	}

	@Test
	public void testGetCharacterBounds() {
		// text = "line1 line2"
		int charWidth = testField.getCharWidth();
		int lineHeight = testField.getLineHeight();

		assertEquals(new Rectangle(0, 0, charWidth, lineHeight),
			accessibleField.getCharacterBounds(0));

		assertEquals(new Rectangle(4 * charWidth, 0, charWidth, lineHeight),
			accessibleField.getCharacterBounds(4));

		// this is the imaginary space char that separates the lines
		assertEquals(new Rectangle(5 * charWidth, 0, 0, lineHeight),
			accessibleField.getCharacterBounds(5));

		assertEquals(new Rectangle(0, lineHeight, charWidth, lineHeight),
			accessibleField.getCharacterBounds(6));

		// this is the last char on the 2nd line
		assertEquals(new Rectangle(4 * charWidth, lineHeight, charWidth, lineHeight),
			accessibleField.getCharacterBounds(10));

		// this is just past the last char on the 2nd line
		assertEquals(new Rectangle(0, 0, 0, 0), accessibleField.getCharacterBounds(11));

		assertEquals(new Rectangle(0, 0, 0, 0), accessibleField.getCharacterBounds(12));
		assertEquals(new Rectangle(0, 0, 0, 0), accessibleField.getCharacterBounds(-1));

	}

	@Test
	public void testGetCharCount() {
		// text = "line1 line2"
		assertEquals(testField.getText().length(), accessibleField.getCharCount());
	}

	@Test
	public void testGetAtIndex_char() {
		// text = "line1 line2"
		assertEquals("l", accessibleField.getAtIndex(AccessibleText.CHARACTER, 0));
		assertEquals("i", accessibleField.getAtIndex(AccessibleText.CHARACTER, 1));
		assertEquals("n", accessibleField.getAtIndex(AccessibleText.CHARACTER, 2));
		assertEquals("e", accessibleField.getAtIndex(AccessibleText.CHARACTER, 3));
		assertEquals("1", accessibleField.getAtIndex(AccessibleText.CHARACTER, 4));
		assertEquals(" ", accessibleField.getAtIndex(AccessibleText.CHARACTER, 5));
		assertEquals("l", accessibleField.getAtIndex(AccessibleText.CHARACTER, 6));
		assertEquals("i", accessibleField.getAtIndex(AccessibleText.CHARACTER, 7));
		assertEquals("n", accessibleField.getAtIndex(AccessibleText.CHARACTER, 8));
		assertEquals("e", accessibleField.getAtIndex(AccessibleText.CHARACTER, 9));
		assertEquals("2", accessibleField.getAtIndex(AccessibleText.CHARACTER, 10));

		assertEquals(null, accessibleField.getAtIndex(AccessibleText.CHARACTER, 11));
	}

	@Test
	public void testGetBeforeIndex_char() {
		// text = "line1 line2"
		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 0));
		assertEquals("l", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 1));
		assertEquals("i", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 2));
		assertEquals("n", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 3));
		assertEquals("e", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 4));
		assertEquals("1", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 5));
		assertEquals(" ", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 6));
		assertEquals("l", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 7));
		assertEquals("i", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 8));
		assertEquals("n", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 9));
		assertEquals("e", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 10));
		assertEquals("2", accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 11));
		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.CHARACTER, 12));
	}

	@Test
	public void testGetAfterIndex_char() {
		// text = "line1 line2"
		assertEquals("i", accessibleField.getAfterIndex(AccessibleText.CHARACTER, 0));
		assertEquals("n", accessibleField.getAfterIndex(AccessibleText.CHARACTER, 1));
		assertEquals("e", accessibleField.getAfterIndex(AccessibleText.CHARACTER, 2));
		assertEquals("1", accessibleField.getAfterIndex(AccessibleText.CHARACTER, 3));
		assertEquals(" ", accessibleField.getAfterIndex(AccessibleText.CHARACTER, 4));
		assertEquals("l", accessibleField.getAfterIndex(AccessibleText.CHARACTER, 5));
		assertEquals("i", accessibleField.getAfterIndex(AccessibleText.CHARACTER, 6));
		assertEquals("n", accessibleField.getAfterIndex(AccessibleText.CHARACTER, 7));
		assertEquals("e", accessibleField.getAfterIndex(AccessibleText.CHARACTER, 8));
		assertEquals("2", accessibleField.getAfterIndex(AccessibleText.CHARACTER, 9));

		assertEquals(null, accessibleField.getAtIndex(AccessibleText.CHARACTER, 11));
	}

	@Test
	public void testGetAtIndex_word() {
		// text = "line1 line2"
		assertEquals("line1", accessibleField.getAtIndex(AccessibleText.WORD, 0));
		assertEquals("line1", accessibleField.getAtIndex(AccessibleText.WORD, 1));
		assertEquals("line1", accessibleField.getAtIndex(AccessibleText.WORD, 2));
		assertEquals("line1", accessibleField.getAtIndex(AccessibleText.WORD, 3));
		assertEquals("line1", accessibleField.getAtIndex(AccessibleText.WORD, 4));
		assertEquals(" ", accessibleField.getAtIndex(AccessibleText.WORD, 5));
		assertEquals("line2", accessibleField.getAtIndex(AccessibleText.WORD, 6));
		assertEquals("line2", accessibleField.getAtIndex(AccessibleText.WORD, 7));
		assertEquals("line2", accessibleField.getAtIndex(AccessibleText.WORD, 8));
		assertEquals("line2", accessibleField.getAtIndex(AccessibleText.WORD, 9));
		assertEquals("line2", accessibleField.getAtIndex(AccessibleText.WORD, 10));

		assertEquals(null, accessibleField.getAtIndex(AccessibleText.WORD, 11));
	}

	@Test
	public void testGetBeforeIndex_word() {
		// text = "line1 line2"
		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.WORD, 0));
		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.WORD, 1));
		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.WORD, 2));
		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.WORD, 3));
		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.WORD, 4));
		assertEquals("line1", accessibleField.getBeforeIndex(AccessibleText.WORD, 5));
		assertEquals(" ", accessibleField.getBeforeIndex(AccessibleText.WORD, 6));
		assertEquals(" ", accessibleField.getBeforeIndex(AccessibleText.WORD, 7));
		assertEquals(" ", accessibleField.getBeforeIndex(AccessibleText.WORD, 8));
		assertEquals(" ", accessibleField.getBeforeIndex(AccessibleText.WORD, 9));
		assertEquals(" ", accessibleField.getBeforeIndex(AccessibleText.WORD, 10));
		assertEquals("line2", accessibleField.getBeforeIndex(AccessibleText.WORD, 11));
		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.WORD, 12));
	}

	@Test
	public void testGetAfterIndex_word() {
		// text = "line1 line2"
		assertEquals(" ", accessibleField.getAfterIndex(AccessibleText.WORD, 0));
		assertEquals(" ", accessibleField.getAfterIndex(AccessibleText.WORD, 1));
		assertEquals(" ", accessibleField.getAfterIndex(AccessibleText.WORD, 2));
		assertEquals(" ", accessibleField.getAfterIndex(AccessibleText.WORD, 3));
		assertEquals(" ", accessibleField.getAfterIndex(AccessibleText.WORD, 4));
		assertEquals("line2", accessibleField.getAfterIndex(AccessibleText.WORD, 5));
		assertEquals(null, accessibleField.getAfterIndex(AccessibleText.WORD, 6));
		assertEquals(null, accessibleField.getAfterIndex(AccessibleText.WORD, 7));
		assertEquals(null, accessibleField.getAfterIndex(AccessibleText.WORD, 8));
		assertEquals(null, accessibleField.getAfterIndex(AccessibleText.WORD, 9));
		assertEquals(null, accessibleField.getAfterIndex(AccessibleText.WORD, 10));
		assertEquals(null, accessibleField.getAfterIndex(AccessibleText.WORD, 11));
	}

	@Test
	public void testGetAtIndex_sentence() {
		testField = new TestField(FIELD_X, FIELD_WIDTH, "This line. Why?", "Why not? Wow");
		accessibleField = new AccessibleField(testField, parent, 0, boundsInParent);
		assertEquals("This line. ", accessibleField.getAtIndex(AccessibleText.SENTENCE, 0));
		assertEquals("This line. ", accessibleField.getAtIndex(AccessibleText.SENTENCE, 4));
		assertEquals("This line. ", accessibleField.getAtIndex(AccessibleText.SENTENCE, 10));

		assertEquals("Why? ", accessibleField.getAtIndex(AccessibleText.SENTENCE, 11));
		assertEquals("Why? ", accessibleField.getAtIndex(AccessibleText.SENTENCE, 15));

		assertEquals("Why not? ", accessibleField.getAtIndex(AccessibleText.SENTENCE, 16));
		assertEquals("Why not? ", accessibleField.getAtIndex(AccessibleText.SENTENCE, 19));
		assertEquals("Why not? ", accessibleField.getAtIndex(AccessibleText.SENTENCE, 23));

		assertEquals(null, accessibleField.getAtIndex(AccessibleText.SENTENCE, 500));
	}

	@Test
	public void testGetBeforeIndex_sentence() {
		testField = new TestField(FIELD_X, FIELD_WIDTH, "This line. Why?", "Why not? Wow");
		accessibleField = new AccessibleField(testField, parent, 0, boundsInParent);

		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.SENTENCE, 0));
		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.SENTENCE, 4));
		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.SENTENCE, 10));

		assertEquals("This line. ", accessibleField.getBeforeIndex(AccessibleText.SENTENCE, 11));
		assertEquals("This line. ", accessibleField.getBeforeIndex(AccessibleText.SENTENCE, 15));

		assertEquals("Why? ", accessibleField.getBeforeIndex(AccessibleText.SENTENCE, 16));
		assertEquals("Why? ", accessibleField.getBeforeIndex(AccessibleText.SENTENCE, 19));
		assertEquals("Why? ", accessibleField.getBeforeIndex(AccessibleText.SENTENCE, 23));

		assertEquals(null, accessibleField.getBeforeIndex(AccessibleText.SENTENCE, 500));
	}

	@Test
	public void testAfterIndex_sentence() {
		testField = new TestField(FIELD_X, FIELD_WIDTH, "This line. Why?", "Why not? Wow");
		accessibleField = new AccessibleField(testField, parent, 0, boundsInParent);

		assertEquals("Why? ", accessibleField.getAfterIndex(AccessibleText.SENTENCE, 0));
		assertEquals("Why? ", accessibleField.getAfterIndex(AccessibleText.SENTENCE, 4));
		assertEquals("Why? ", accessibleField.getAfterIndex(AccessibleText.SENTENCE, 10));

		assertEquals("Why not? ", accessibleField.getAfterIndex(AccessibleText.SENTENCE, 11));
		assertEquals("Why not? ", accessibleField.getAfterIndex(AccessibleText.SENTENCE, 15));

		assertEquals(null, accessibleField.getAfterIndex(AccessibleText.SENTENCE, 500));
	}

	@Test
	public void testCaretPos() {
		assertEquals(0, accessibleField.getCaretPosition());
		accessibleField.setCaretPos(5);
		assertEquals(5, accessibleField.getCaretPosition());
	}

	@Test
	public void testSelection() {
		// text = "line1 line2"
		assertEquals(0, accessibleField.getSelectionStart());
		assertEquals(0, accessibleField.getSelectionEnd());
		assertEquals(null, accessibleField.getSelectedText());

		accessibleField.setSelected(true);
		assertEquals(0, accessibleField.getSelectionStart());
		assertEquals(11, accessibleField.getSelectionEnd());
		assertEquals("line1 line2", accessibleField.getSelectedText());
	}

	@Test
	public void testContainsPoint() {
		assertTrue(accessibleField.contains(new Point(0, 0)));
		int width = testField.getWidth();
		int height = testField.getHeight();
		assertTrue(accessibleField.contains(new Point(width - 1, height - 1)));
		assertFalse(accessibleField.contains(new Point(width, height - 1)));
		assertFalse(accessibleField.contains(new Point(width - 1, height)));
		assertFalse(accessibleField.contains(new Point(-1, 0)));
		assertFalse(accessibleField.contains(new Point(0, -1)));
	}

	@Test
	public void testGetLocation() {
		Point expectedLocationOnScreen = new Point(FIELD_X, FIELD_Y);
		assertEquals(expectedLocationOnScreen, accessibleField.getLocation());
	}

	@Test
	public void testGetLocationOnScreen() {
		Rectangle boundsRelativeToParent = accessibleField.getBounds();
		Point expectedLocationOnScreen =
			new Point(PARENT_X + boundsRelativeToParent.x, PARENT_Y + boundsRelativeToParent.y);
		assertEquals(expectedLocationOnScreen, accessibleField.getLocationOnScreen());
	}

	@Test
	public void testGetSize() {
		assertEquals(new Dimension(FIELD_WIDTH, fieldHeight), accessibleField.getSize());
	}

	@Test
	public void testGetTextOffset() {
		assertEquals(0, accessibleField.getTextOffset(0, 0));
		assertEquals(1, accessibleField.getTextOffset(0, 1));
		assertEquals(5, accessibleField.getTextOffset(0, 5));
		assertEquals(6, accessibleField.getTextOffset(1, 0));
		assertEquals(5, accessibleField.getTextOffset(0, 10));
		assertEquals(11, accessibleField.getTextOffset(1, 10));
	}

	private static class TestField extends VerticalLayoutTextField {
		private static FontMetrics metrics = createFontMetrics();

		private static FontMetrics createFontMetrics() {
			Font f = new Font("Monospaced", Font.PLAIN, 12);
			JLabel label = new JLabel("Hey");
			return label.getFontMetrics(f);
		}

		public TestField(int startX, int width, String... lines) {
			super(createElements(lines), startX, width, lines.length, null);
		}

		public int getLineHeight() {
			return metrics.getHeight() + 1; // our lines are always 1 more than the font
		}

		public int getCharWidth() {
			return metrics.charWidth('a'); // monospace so all chars same width
		}

		private static List<FieldElement> createElements(String[] lines) {
			List<FieldElement> fieldElements = new ArrayList<>();
			int row = 0;
			for (String line : lines) {
				AttributedString as = new AttributedString(line, Color.black, metrics);
				fieldElements.add(new TextFieldElement(as, row++, 0));
			}
			return fieldElements;
		}
	}

}
