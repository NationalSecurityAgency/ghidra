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

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.InRangeColumnConstraint;
import docking.widgets.textfield.IntegerTextField;

public class UnsignedLongRangeConstraintEditorTest extends AbstractDockingTest {

	private TestUnsignedLongRangeConstraint constraint;
	private UnsignedLongRangeConstraintEditor editor;
	private IntegerTextField lowerField;
	private IntegerTextField upperField;

	@Before
	public void setup() {
		constraint = new TestUnsignedLongRangeConstraint(BigInteger.ZERO, BigInteger.ZERO);
		editor = (UnsignedLongRangeConstraintEditor) constraint.getEditor(null);
		forceBuildOfGuiComponents();
		lowerField = editor.getLowerField();
		upperField = editor.getUpperField();
	}

	private Component forceBuildOfGuiComponents() {
		return runSwing(() -> editor.getInlineComponent());
	}

	@Test
	public void testSetValue() {
		setEditorValue("[5,25]");

		assertEquals("0x5", lowerField.getText());
		assertEquals("0x25", upperField.getText());
	}

	@Test
	public void testSetBigValue() {
		setEditorValue("[4, fffffffffffffffa]");
		assertEquals("0x4", lowerField.getText());
		assertEquals("0xfffffffffffffffa", upperField.getText());
		assertTrue(editor.hasValidValue());  // make sure that the big number is not treated as negative
	}

	@Test
	public void testGetValue() {
		setLowerValue(0x10);
		setUpperValue(0x20);

		assertEquals("[10,20]", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testReset() {
		setLowerValue(10);
		setUpperValue(20);

		runSwing(() -> editor.reset());
		waitForSwing();

		assertEquals("0x0", lowerField.getText());
		assertEquals("0xffffffffffffffff", upperField.getText());
	}

	@Test
	public void testMinValueGreaterThanMaxValue() {
		setLowerValue(20);
		setUpperValue(10);

		waitForSwing();

		assertTrue(!editor.hasValidValue());
		assertEquals("Upper bound must be greater or equal to lower bound!",
			editor.getErrorMessage());
	}

	@Test
	public void testDetailComponent() {
		assertNull(editor.getDetailComponent());
	}

	private void setLowerValue(int value) {
		runSwing(() -> lowerField.setValue(value));
		waitForSwing();
	}

	private void setUpperValue(int value) {
		runSwing(() -> upperField.setValue(value));
		waitForSwing();
	}

	private void setEditorValue(String constraintValue) {
		runSwing(() -> editor.setValue(constraint.parseConstraintValue(constraintValue, null)));
		waitForSwing();
	}

	private ColumnConstraint<BigInteger> getEditorValue() {
		return runSwing(() -> editor.getValue());
	}

	class TestUnsignedLongRangeConstraint extends InRangeColumnConstraint<BigInteger> {

		public TestUnsignedLongRangeConstraint(BigInteger minValue, BigInteger maxValue) {
			super(minValue, maxValue, new UnsignedLongRangeEditorProvider());
		}
	}
}
