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
package ghidra.app.plugin.core.function.editor;

import static org.junit.Assert.assertEquals;

import java.awt.Color;

import javax.swing.text.*;

import org.junit.*;

import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class FunctionSignatureTextFieldTest extends AbstractGhidraHeadedIntegrationTest {

	private FunctionSignatureTextField field;
	private StyledDocument doc;
	private Color functionNameColor = FunctionSignatureTextField.FUNCTION_NAME_COLOR;
	private Color defaultColor = FunctionSignatureTextField.DEFAULT_COLOR;
	private Color paramNameColor = FunctionSignatureTextField.PARAMETER_NAME_COLOR;

	public FunctionSignatureTextFieldTest() {
		super();
	}

    @Before
    public void setUp() throws Exception {
		
		field = new FunctionSignatureTextField();
		doc = field.getStyledDocument();
	}

@Test
    public void testSimpleFunciton() {
		setText("void fool()");

		verifyChar(0, 'v', defaultColor);
		verifyChar(5, 'f', functionNameColor);
		verifyChar(5, 'f', functionNameColor);
		verifyChar(9, '(', defaultColor);
		verifyChar(10, ')', defaultColor);
	}

@Test
    public void testOneParam() {
		setText("void fool(int a)");

		verifyChar(0, 'v', defaultColor);
		verifyChar(5, 'f', functionNameColor);
		verifyChar(5, 'f', functionNameColor);
		verifyChar(9, '(', defaultColor);
		verifyChar(10, 'i', defaultColor);
		verifyChar(14, 'a', paramNameColor);
		verifyChar(15, ')', defaultColor);
	}

@Test
    public void testTwoParams() {
		setText("void fool(int a, char b)");

		verifyChar(0, 'v', defaultColor);
		verifyChar(5, 'f', functionNameColor);
		verifyChar(5, 'f', functionNameColor);
		verifyChar(9, '(', defaultColor);
		verifyChar(10, 'i', defaultColor);
		verifyChar(14, 'a', paramNameColor);
		verifyChar(15, ',', defaultColor);
		verifyChar(17, 'c', defaultColor);
		verifyChar(22, 'b', paramNameColor);
		verifyChar(23, ')', defaultColor);
	}

@Test
    public void testVarArgs() {
		setText("void fool(...)");

		verifyChar(0, 'v', defaultColor);
		verifyChar(5, 'f', functionNameColor);
		verifyChar(5, 'f', functionNameColor);
		verifyChar(9, '(', defaultColor);
		verifyChar(10, '.', defaultColor);
		verifyChar(11, '.', defaultColor);
		verifyChar(12, '.', defaultColor);
		verifyChar(13, ')', defaultColor);

	}

@Test
    public void testBadlyFormedFunction() {
		setText("abc(");
		// since it didn't parse, no attributes were set
		verifyChar(0, 'a', defaultColor);
		verifyChar(3, '(', defaultColor);
	}

@Test
    public void testBadFunctionAfterGoodLeavesColorsAlone() {
		setText("int abc()");
		replaceText(")", "int");
		assertEquals("int abc(int", field.getText());
		verifyChar(4, 'a', functionNameColor);
		verifyChar(8, 'i', defaultColor);
	}

	private void verifyChar(int charPosition, char expectedChar, Color expectedColor) {
		try {
			assertEquals(expectedChar, doc.getText(charPosition, 1).charAt(0));
		}
		catch (BadLocationException e) {
			Assert.fail("bad position");
		}
		assertEquals(expectedColor, getColor(charPosition));
	}

	private Color getColor(int charPosition) {
		Element element = doc.getCharacterElement(charPosition);
		AttributeSet attributes = element.getAttributes();
		return (Color) attributes.getAttribute(StyleConstants.Foreground);
	}

	private void setText(final String s) {
		runSwing(new Runnable() {
			@Override
			public void run() {
				field.setText(s);
			}
		});
		waitForPostedSwingRunnables();
	}

	private void replaceText(final String textToReplace, final String newText) {
		runSwing(new Runnable() {
			@Override
			public void run() {
				int start = field.getText().indexOf(textToReplace);
				field.setCaretPosition(start);
				field.moveCaretPosition(start + textToReplace.length());
				field.replaceSelection(newText);
			}
		});
		waitForPostedSwingRunnables();
	}
}
