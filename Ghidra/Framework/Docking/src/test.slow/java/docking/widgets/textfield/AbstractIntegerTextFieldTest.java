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
package docking.widgets.textfield;

import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicIntegerArray;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.junit.After;
import org.junit.Before;

import docking.test.AbstractDockingTest;
import docking.widgets.textfield.integer.AbstractIntegerTextField;
import docking.widgets.textfield.integer.IntegerFormat;

public abstract class AbstractIntegerTextFieldTest<T extends AbstractIntegerTextField>
		extends AbstractDockingTest {
	private JFrame frame;
	protected T field;
	protected JTextField textField;

	@Before
	public void setUp() throws Exception {
		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		field = createField();
		field.setShowNumberMode(true);
		textField = (JTextField) field.getComponent();
		frame = new JFrame("Test");
		frame.getContentPane().add(field.getComponent());
		frame.pack();
		frame.setVisible(true);
	}

	abstract protected T createField();

	@After
	public void tearDown() throws Exception {
		runSwing(() -> frame.dispose());
	}

	protected void setFormat(IntegerFormat format) {
		runSwing(() -> field.setFormat(format));
	}

	protected IntegerFormat getFormat() {
		return runSwing(() -> field.getFormat());
	}

	protected void setValue(long value) {
		runSwing(() -> field.setValue(value));
	}

	protected long getValue() {
		return runSwing(() -> field.getLongValue());
	}

	protected int getIntValue() {
		return runSwing(() -> field.getIntValue());
	}

	protected BigInteger getBigIntegerValue() {
		return runSwing(() -> field.getValue());
	}

	protected String getText() {
		return runSwing(() -> field.getText());
	}

	protected BigInteger getMinValue() {
		return runSwing(() -> field.getMinValue());
	}

	protected BigInteger getMaxValue() {
		return runSwing(() -> field.getMaxValue());
	}

	protected void setText(String text) {
		runSwing(() -> field.setText(text));
	}

	protected void typeText(String text) {
		triggerText(textField, text);
	}

	protected void setUsePrefix(boolean b) {
		runSwing(() -> field.setUseNumberPrefix(b));
	}

	class TestChangeListener implements ChangeListener {
		volatile int count;
		protected AtomicIntegerArray values = new AtomicIntegerArray(10);

		@Override
		public void stateChanged(ChangeEvent e) {
			values.set(count++, field.getIntValue());
		}

	}
}
