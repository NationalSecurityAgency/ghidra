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

import static org.junit.Assert.assertEquals;

import java.awt.*;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.field.*;
import generic.test.AbstractGenericTest;

public class AttributedStringTest extends AbstractGenericTest {
	FontMetrics fm;

	public AttributedStringTest() {
		super();
	}

	@SuppressWarnings("deprecation") // we mean to use getFontMetrics
	@Before
	public void setUp() {
		Font font = new Font("Times New Roman", 0, 14);
		Toolkit tk = Toolkit.getDefaultToolkit();
		fm = tk.getFontMetrics(font);

	}

	@Test
	public void testSubstring() {
		FieldElement[] strings =
			new FieldElement[] {
				new TextFieldElement(new AttributedString("This is string", Color.BLACK, fm), 0, 0), // 14 chars
				new TextFieldElement(new AttributedString("to test", Color.RED, fm), 0, 0), //  7 chars
				new TextFieldElement(new AttributedString("the substring of ", Color.BLACK, fm), 0,
					0), // 17 chars
				new TextFieldElement(new AttributedString(" ....   ", Color.BLACK, fm), 0, 0), //  8 chars
				new TextFieldElement(
					new AttributedString("the CompositeAttributedString", Color.BLUE, fm), 0, 0), // 29 chars
				new TextFieldElement(new AttributedString("class.", Color.BLACK, fm), 0, 0) };
		FieldElement compositeString = new CompositeFieldElement(strings);

		FieldElement substring = compositeString.substring(0);
		assertEquals(compositeString.getText(), substring.getText());

		substring = compositeString.substring(0, compositeString.getText().length());
		assertEquals(compositeString.getText(), substring.getText());

		// start and end inside same attributed string inside of composite
		substring = compositeString.substring(25, 34);
		assertEquals("substring", substring.getText());

		// start and end span 2 lines
		substring = compositeString.substring(17, 24);
		assertEquals("testthe", substring.getText());

		// more than 2 lines
		substring = compositeString.substring(8, 43);
		assertEquals("stringto testthe substring of  ....", substring.getText());

		// exactly one line
		substring = compositeString.substring(46, 75);
		assertEquals("the CompositeAttributedString", substring.getText());

		substring = compositeString.substring(compositeString.getText().length());
		assertEquals("", substring.getText());

		// runtime ArrayIndexOutOfBoundsException 7/11/06
		strings = new FieldElement[] {
			new TextFieldElement(
				new AttributedString("This is an annotated comment: ", Color.BLUE, fm), 0, 0),
			new TextFieldElement(new AttributedString("RegSetValueExW", Color.BLUE, fm), 0, 0),
			new TextFieldElement(new AttributedString(
				" This is an annotated comment with symbol name: ", Color.RED, fm), 0, 0),
			new TextFieldElement(new AttributedString("No symbol: RegSetValueExW", Color.RED, fm),
				0, 0),
			new TextFieldElement(new AttributedString("  Bad annotation: ", Color.BLUE, fm), 0, 0),
			new TextFieldElement(
				new AttributedString("Invalid Annotation: {@cowhide smile}:", Color.RED, fm), 0, 0),
			new TextFieldElement(new AttributedString(" ", Color.BLUE, fm), 0, 0),
			new TextFieldElement(new AttributedString("{@cowhide smile}", Color.BLUE, fm), 0, 0),
			new TextFieldElement(new AttributedString("Invalid Annotation: {@sym}", Color.BLUE, fm),
				0, 0) };
		FieldElement compositeString2 = new CompositeFieldElement(strings);

		// the first call was valid
		compositeString2.substring(0, 50);

		// the second call was not - 50, 198
		compositeString2.substring(50, 198);
	}
}
