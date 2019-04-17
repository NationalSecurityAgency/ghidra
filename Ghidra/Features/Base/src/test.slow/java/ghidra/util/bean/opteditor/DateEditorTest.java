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
package ghidra.util.bean.opteditor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.awt.Component;
import java.awt.Container;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.junit.*;

import com.toedter.calendar.JCalendar;

import docking.action.DockingActionIf;
import docking.options.editor.*;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class DateEditorTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String TEST_CATEGORY_NAME = "Test Editor";
	private static final String TEST_DATE_OPTION_NAME = "Time Option Name";
	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private CodeBrowserPlugin plugin;

	@Before
	public void setUp() throws Exception {

		program = buildProgram();

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		plugin = env.getPlugin(CodeBrowserPlugin.class);
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x1001000), 0x2000);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testEditor() throws Exception {

		Date initialDate = new Date(System.currentTimeMillis());
		DateEditor dateEditor = addDateProperty(initialDate);

		showProgramOptions();

		OptionsDialog optionsDialog = waitForDialogComponent(OptionsDialog.class);
		ScrollableOptionsEditor optionsEditor = selectionDateOptionCategory(optionsDialog);
		Component c = findPairedComponent(optionsEditor, TEST_DATE_OPTION_NAME);
		assertNotNull(c);

		JTextField optionTextField = findComponent((Container) c, JTextField.class);
		assertNotNull(optionTextField);
		String testDateString = dateEditor.format(initialDate);
		assertEquals(testDateString, getText(optionTextField));

		JDialog dateDialog = lauchDateEditorDialog(c);
		JCalendar calendar = findComponent(dateDialog, JCalendar.class);
		assertNotNull("Could not find JCalendar", calendar);

		Calendar cal = calendar.getCalendar();
		int hours = runSwing(() -> cal.get(Calendar.HOUR_OF_DAY));
		int minutes = runSwing(() -> cal.get(Calendar.MINUTE));
		int seconds = runSwing(() -> cal.get(Calendar.SECOND));

		JTextField hoursField = getTextField(dateDialog, "Hours");
		JTextField minutesField = getTextField(dateDialog, "Minutes");
		JTextField secondsField = getTextField(dateDialog, "Seconds");

		assertEquals(hours, Integer.parseInt(getText(hoursField)));
		assertEquals(minutes, Integer.parseInt(getText(minutesField)));
		assertEquals(seconds, Integer.parseInt(getText(secondsField)));

		JCalendar cd = calendar;
		Date currentDate = runSwing(() -> cd.getCalendar().getTime());
		assertDateLabelValue(dateDialog, currentDate);

		// change the time
		setText(hoursField, "01");
		setText(minutesField, "21");
		setText(secondsField, "59");

		Calendar c2 = (Calendar) cal.clone();
		runSwing(() -> {
			c2.set(Calendar.HOUR_OF_DAY, 1);
			c2.set(Calendar.MINUTE, 21);
			c2.set(Calendar.SECOND, 59);

			cd.setCalendar(c2);
		});

		Date newDate = runSwing(() -> c2.getTime());

		pressOk(dateDialog);

		// make sure the text field was updated
		testDateString = dateEditor.format(newDate);
		assertEquals(testDateString, getText(optionTextField));

		pressApply(optionsDialog);

		// make sure the property changed
		Options plist = program.getOptions(TEST_CATEGORY_NAME);
		Date actualDate = plist.getDate(TEST_DATE_OPTION_NAME, (Date) null);
		assertEquals(newDate, actualDate);

		closeAllWindowsAndFrames();
	}

	private void assertDateLabelValue(Container c, Date date) {

		JLabel dateLabel = (JLabel) findComponentByName(c, "DateString");
		assertNotNull(dateLabel);
		SimpleDateFormat formatter = new SimpleDateFormat("MMM dd, yyyy  ");
		assertEquals(formatter.format(date), runSwing(() -> dateLabel.getText()));
	}

	private JTextField getTextField(Container c, String name) {
		JTextField tf = (JTextField) findComponentByName(c, name);
		assertNotNull(tf);
		return tf;
	}

	private ScrollableOptionsEditor selectionDateOptionCategory(OptionsDialog optionsDialog)
			throws Exception {

		OptionsPanel optionsPanel = (OptionsPanel) getInstanceField("panel", optionsDialog);
		Container pane = optionsDialog.getComponent();
		GTree tree = findComponent(pane, GTree.class);

		waitForTree(tree);

		GTreeNode testNode = getGTreeNode(tree.getRootNode(), TEST_CATEGORY_NAME);
		selectNode(testNode);
		ScrollableOptionsEditor p =
			(ScrollableOptionsEditor) getEditorPanel(optionsPanel, testNode);
		assertNotNull(p);
		return p;
	}

	private void pressApply(OptionsDialog optionsDialog) {
		JButton applyButton = findButtonByText(optionsDialog.getComponent(), "Apply");
		pressButton(applyButton);
		waitForSwing();
	}

	private void pressOk(JDialog dateDialog) {

		JButton okButton = findButtonByText(dateDialog.getContentPane(), "OK");
		assertNotNull(okButton);
		pressButton(okButton);
		waitForSwing();
	}

	private JDialog lauchDateEditorDialog(Component c) {
		JButton button = findButtonByIcon((Container) c, ButtonPanelFactory.BROWSE_ICON);
		assertNotNull(button);
		pressButton(button, false);
		waitForSwing();

		JDialog dateDialog = waitForJDialog("Edit Date");
		assertNotNull(dateDialog);
		return dateDialog;
	}

	private void showProgramOptions() {
		List<DockingActionIf> list = tool.getAllActions();
		for (int i = 0; i < list.size(); i++) {

			DockingActionIf action = list.get(i);
			if (action.getName().equals("Program Options")) {
				performAction(action, plugin.getProvider(), false);
				break;
			}
		}
		waitForSwing();
	}

	private Object getEditorPanel(OptionsPanel optionsPanel, Object testNode) {
		Map<?, ?> map = (Map<?, ?>) getInstanceField("editorMap", optionsPanel);
		return map.get(testNode);
	}

	private void selectNode(GTreeNode node) throws Exception {
		TreePath path = node.getTreePath();
		GTree tree = node.getTree();
		tree.setSelectionPath(path);
		waitForTree(tree);
	}

	private GTreeNode getGTreeNode(GTreeNode parent, String nodeName) throws Exception {

		for (int i = 0; i < parent.getChildCount(); i++) {
			GTreeNode node = parent.getChild(i);
			if (node.getName().equals(nodeName)) {
				return node;
			}
			GTreeNode foundNode = getGTreeNode(node, nodeName);
			if (foundNode != null) {
				return foundNode;
			}
		}

		return null;
	}

	private DateEditor addDateProperty(Date date) {
		Options list = program.getOptions(TEST_CATEGORY_NAME);
		list.registerOption(TEST_DATE_OPTION_NAME, new Date(0), null, "Test for the DateEditor");

		int transactionID = program.startTransaction("My Test");
		try {
			list.setDate(TEST_DATE_OPTION_NAME, date);
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		return (DateEditor) runSwing(() -> list.getPropertyEditor(TEST_DATE_OPTION_NAME));
	}

	private Component findPairedComponent(Container container, String labelText) {
		Component[] c = container.getComponents();
		for (int i = 0; i < c.length; i++) {
			if (c[i] instanceof JLabel) {
				if (((JLabel) c[i]).getText().equals(labelText)) {
					return c[i + 1];
				}
			}
			if (c[i] instanceof Container) {
				Component comp = findPairedComponent((Container) c[i], labelText);
				if (comp != null) {
					return comp;
				}
			}
		}
		return null;

	}

}
