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
package docking.widgets.table.constrainteditor;

import static org.junit.Assert.*;

import java.awt.Component;
import java.math.BigInteger;

import javax.swing.JTextField;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.table.constraint.*;
import docking.widgets.textfield.IntegerTextField;

public class UnsignedLongValueConstraintEditorTest extends AbstractDockingTest {

	private SingleValueColumnConstraint<BigInteger> constraint;
	private UnsignedLongConstraintEditor editor;
	private IntegerTextField textField;

	@Before
	public void setup() {
		constraint = new TestUnsignedValueConstraint(BigInteger.ZERO);
		editor = (UnsignedLongConstraintEditor) constraint.getEditor(null);

		forceBuildOfGuiComponents();
		textField = (IntegerTextField) getInstanceField("field", editor);

		assertNotNull("Unable to locate JTextField editor component of spinner", textField);
	}

	private Component forceBuildOfGuiComponents() {
		return runSwing(() -> editor.getInlineComponent());
	}

	@Test
	public void testSetValue() {
		setEditorValue("128");

		assertEquals("0x128", textField.getText());
		assertEquals(BigInteger.valueOf(0x128), textField.getValue());
	}

	@Test
	public void testSetBigValue() {
		setEditorValue("fffffffffffffffe");

		assertEquals(new BigInteger("fffffffffffffffe", 16), textField.getValue());
	}

	@Test
	public void testGetValue() {
		setEditorValue("923");
		assertEquals("923", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testGetBigValue() {
		setEditorValue("fffffffffffffffa");
		assertEquals("fffffffffffffffa", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testReset() {
		setTextValue(23);
		editor.reset();
		assertEquals("0x0", textField.getText());
	}

	@Test
	public void testValidity() {
		setText((JTextField) textField.getComponent(), "");
		assertTrue(!editor.hasValidValue());

		setText((JTextField) textField.getComponent(), "0");
		assertTrue(editor.hasValidValue());
		assertEquals("", editor.getErrorMessage());

	}

	@Test
	public void testDetailComponent() {
		assertNull(editor.getDetailComponent());
	}

	private void setTextValue(int value) {
		runSwing(() -> textField.setValue(value));
		waitForSwing();
	}

	private void setEditorValue(String constraintValue) {
		runSwing(() -> editor.setValue(constraint.parseConstraintValue(constraintValue, null)));
		waitForSwing();
	}

	private ColumnConstraint<BigInteger> getEditorValue() {
		return runSwing(() -> editor.getValue());
	}

	class TestUnsignedValueConstraint extends SingleValueColumnConstraint<BigInteger> {

		protected TestUnsignedValueConstraint(BigInteger constraintValue) {
			super("Test", constraintValue, new UnsignedLongConstraintEditorProvider(), "group");
		}

		@Override
		public boolean accepts(BigInteger value, TableFilterContext context) {
			return false;
		}

		@Override
		public SingleValueColumnConstraint<BigInteger> copy(BigInteger newValue) {
			return new TestUnsignedValueConstraint(newValue);
		}

	}
}
