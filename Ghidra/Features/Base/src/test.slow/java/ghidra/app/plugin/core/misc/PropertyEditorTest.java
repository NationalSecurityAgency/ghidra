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
package ghidra.app.plugin.core.misc;

import static org.junit.Assert.*;

import java.awt.Component;
import java.awt.Container;

import javax.swing.*;

import org.junit.After;
import org.junit.Test;

import docking.DockingWindowManager;
import docking.options.editor.OptionsDialog;
import docking.options.editor.StringWithChoicesEditor;
import docking.widgets.tree.GTree;
import ghidra.framework.options.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class PropertyEditorTest extends AbstractGhidraHeadedIntegrationTest {

	private OptionsDialog dialog;

	@After
	public void tearDown() throws Exception {
		if (dialog != null) {
			close(dialog);
		}
		waitForSwing();
	}

	private OptionsDialog showEditor(Options options) {
		OptionsDialog dialogComponent =
			new OptionsDialog("Test Properties", "Properties", new Options[] { options }, null);
		runSwing(() -> DockingWindowManager.showDialog(dialogComponent), false);

		OptionsDialog editorDialog = waitForDialogComponent(OptionsDialog.class);
		waitForSwing();
		waitForOptionsTree(dialogComponent);
		return editorDialog;
	}

	private void waitForOptionsTree(OptionsDialog optionsDialog) {
		Object optionsPanel = getInstanceField("panel", optionsDialog);
		GTree tree = (GTree) getInstanceField("gTree", optionsPanel);
		waitForTree(tree);
	}

	private Component findPairedComponent(final String labelText) {
		JComponent component = dialog.getComponent();
		return runSwing(() -> doFindPairedComponent(component, labelText));
	}

	private Component doFindPairedComponent(Container container, String labelText) {
		Component[] c = container.getComponents();
		for (int i = 0; i < c.length; i++) {
			if (c[i] instanceof JLabel) {
				if (((JLabel) c[i]).getText().equals(labelText)) {
					return c[i + 1];
				}
			}
			if (c[i] instanceof Container) {
				Component comp = doFindPairedComponent((Container) c[i], labelText);
				if (comp != null) {
					return comp;
				}
			}
		}
		return null;

	}

	private void selectTextField(final JTextField field) {
		runSwing(() -> field.selectAll(), true);
	}

	@Test
	public void testInt() throws Exception {

		Options options = new ToolOptions("Test");
		options.registerOption("TestInt", Integer.MAX_VALUE, null, "Int");

		dialog = showEditor(options);

		Component editor = findPairedComponent("TestInt");
		assertNotNull("Could not find editor component", editor);
		assertEquals(PropertyText.class, editor.getClass());
		final PropertyText textField = (PropertyText) editor;
		assertEquals(Integer.toString(Integer.MAX_VALUE), textField.getText());

		selectTextField(textField);

		triggerText(textField, Integer.toString(Integer.MIN_VALUE));

		pressButtonByText(dialog, "OK");

		assertEquals(Integer.MIN_VALUE, options.getInt("TestInt", 0));
	}

	@Test
	public void testLong() throws Exception {

		Options options = new ToolOptions("Test");
		options.registerOption("TestLong", Long.MAX_VALUE, null, "Long");

		dialog = showEditor(options);

		Component editor = findPairedComponent("TestLong");
		assertNotNull("Could not find editor component", editor);
		assertEquals(PropertyText.class, editor.getClass());
		final PropertyText textField = (PropertyText) editor;
		assertEquals(Long.toString(Long.MAX_VALUE), textField.getText());

		selectTextField(textField);

		triggerText(textField, Long.toString(Long.MIN_VALUE));

		pressButtonByText(dialog, "OK");

		assertEquals(Long.MIN_VALUE, options.getLong("TestLong", 0));
	}

	@Test
	public void testFloat() throws Exception {

		Options options = new ToolOptions("Test");
		options.registerOption("TestFloat", Float.MAX_VALUE, null, "Float");

		dialog = showEditor(options);

		Component editor = findPairedComponent("TestFloat");
		assertNotNull("Could not find editor component", editor);
		assertEquals(PropertyText.class, editor.getClass());
		final PropertyText textField = (PropertyText) editor;

		assertEquals(Float.toString(Float.MAX_VALUE), textField.getText());

		selectTextField(textField);

		triggerText(textField, Float.toString(Float.MIN_VALUE));

		pressButtonByText(dialog, "OK");

		assertEquals(Float.toString(Float.MIN_VALUE),
			Float.toString(options.getFloat("TestFloat", 0)));
	}

	@Test
	public void testDouble() throws Exception {

		Options options = new ToolOptions("Test");
		options.registerOption("TestDouble", Double.MAX_VALUE, null, "Double");

		dialog = showEditor(options);

		Component editor = findPairedComponent("TestDouble");
		assertNotNull("Could not find editor component", editor);
		assertEquals(PropertyText.class, editor.getClass());
		final PropertyText textField = (PropertyText) editor;
		assertEquals(Double.toString(Double.MAX_VALUE), textField.getText());

		selectTextField(textField);

		triggerText(textField, Double.toString(Double.MIN_VALUE));

		pressButtonByText(dialog, "OK");

		assertEquals(Double.toString(Double.MIN_VALUE),
			Double.toString(options.getDouble("TestDouble", 0)));
	}

	@Test
	public void testString() throws Exception {

		Options options = new ToolOptions("Test");
		options.registerOption("TestString", "xyz", null, "String");

		dialog = showEditor(options);

		Component editor = findPairedComponent("TestString");
		assertNotNull("Could not find editor component", editor);
		assertEquals(PropertyText.class, editor.getClass());
		final PropertyText textField = (PropertyText) editor;
		assertEquals("xyz", textField.getText());

		selectTextField(textField);

		triggerText(textField, "abc");

		pressButtonByText(dialog, "OK");

		assertEquals("abc", options.getString("TestString", (String) null));
	}

	@Test
	public void testStringWithChoices() throws Exception {

		Options options = new ToolOptions("Test");
		String[] choices = new String[] { "abc", "def", "ghi", "jkl" };
		options.registerOption("TestStringWithChoices", OptionType.STRING_TYPE, choices[0], null,
			"String Choices", () -> new StringWithChoicesEditor(choices));

		dialog = showEditor(options);

		Component editor = findPairedComponent("TestStringWithChoices");
		assertNotNull("Could not find editor component", editor);
		assertEquals(PropertySelector.class, editor.getClass());
		final PropertySelector textSelector = (PropertySelector) editor;
		assertEquals("abc", textSelector.getSelectedItem());

		runSwing(() -> textSelector.setSelectedItem("ghi"), true);
		waitForSwing();

		pressButtonByText(dialog, "OK");

		assertEquals("ghi", options.getString("TestStringWithChoices", (String) null));
	}

}
