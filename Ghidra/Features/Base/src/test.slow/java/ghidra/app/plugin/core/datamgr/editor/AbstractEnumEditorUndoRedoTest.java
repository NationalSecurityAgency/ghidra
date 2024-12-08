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
package ghidra.app.plugin.core.datamgr.editor;

import static org.junit.Assert.*;

import java.awt.*;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.test.*;

/**
 * {@link AbstractEnumEditorUndoRedoTest} contains tests which should be applied to the various 
 * {@link DataTypeManager} implementations which are responsible for setting {@code dtm} during
 * the setUp phase.
 */
public abstract class AbstractEnumEditorUndoRedoTest extends AbstractGhidraHeadedIntegrationTest {

	protected Program program;
	protected DataTypeManagerPlugin plugin;
	protected PluginTool tool;
	protected TestEnv env;

	protected DataTypeManager dtm; // must be set by test implementation during setUp

	@Before
	public void setUp() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);
		builder.addCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));
		program = builder.getProgram();

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		plugin = getPlugin(tool, DataTypeManagerPlugin.class);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testUndoRedo() throws Exception {

		Enum enumDt = editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		// delete a row
		table.setRowSelectionInterval(0, 0);
		runSwing(() -> {
			DockingActionIf action = getDeleteAction();
			action.actionPerformed(new DefaultActionContext());
		});
		applyChanges(true);
		assertNull(enumDt.getName(0));

		// undo
		undo(true);
		assertEquals("Red", model.getValueAt(0, EnumTableModel.NAME_COL));

		//redo
		redo(true);
		assertEquals("Pink", model.getValueAt(0, EnumTableModel.NAME_COL));
	}

	@Test
	public void testUndoRemoval() throws Exception {

		editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		assertFalse(model.hasChanges());

		undo(true); // will remove enum from DTM

		DataType dt = dtm.getDataType("/Category1/Colors");
		assertNull(dt);

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Close Enum Editor?", d.getTitle());

		JButton button = findButtonByText(d.getComponent(), "Continue Edit");
		assertNotNull(button);
		runSwing(() -> button.getActionListeners()[0].actionPerformed(null));
		waitForSwing();

		assertTrue(panel.needsSave());

		DockingActionIf applyAction = getApplyAction();
		assertTrue(applyAction.isEnabled());

		applyChanges(true);

		dt = dtm.getDataType("/Category1/Colors");
		assertNotNull(dt);
	}

	@Test
	public void testChangesBeforeUndoYes() throws Exception {

		editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		int origRowCount = model.getRowCount();
		runSwing(() -> {
			DockingActionIf action = getAddAction();
			action.actionPerformed(new DefaultActionContext());
			action.actionPerformed(new DefaultActionContext());
		});
		waitForSwing();
		applyChanges(true);
		// make more changes
		runSwing(() -> {
			DockingActionIf action = getAddAction();
			action.actionPerformed(new DefaultActionContext());
			action.actionPerformed(new DefaultActionContext());
		});
		waitForSwing();
		undo(false);
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		// yes to reload the enum data type
		JButton button = findButtonByText(d.getComponent(), "Yes");
		assertNotNull(button);
		runSwing(() -> button.getActionListeners()[0].actionPerformed(null));
		waitForSwing();
		assertEquals(origRowCount, model.getRowCount());
	}

	@Test
	public void testChangesBeforeUndoNo() throws Exception {

		editSampleEnum();

		EnumEditorPanel panel = findEditorPanel(tool.getToolFrame());
		JTable table = panel.getTable();
		EnumTableModel model = (EnumTableModel) table.getModel();

		runSwing(() -> {
			int lastRow = model.getRowCount() - 1;
			if (lastRow >= 0) {
				table.addRowSelectionInterval(lastRow, lastRow);
			}
			DockingActionIf action = getAddAction();
			action.actionPerformed(new DefaultActionContext());
			action.actionPerformed(new DefaultActionContext());
		});
		waitForSwing();
		applyChanges(true);
		// make more changes
		runSwing(() -> {
			int lastRow = model.getRowCount() - 1;
			if (lastRow >= 0) {
				table.addRowSelectionInterval(lastRow, lastRow);
			}
			DockingActionIf action = getAddAction();
			action.actionPerformed(new DefaultActionContext());
			action.actionPerformed(new DefaultActionContext());
		});
		waitForSwing();
		int rowCount = model.getRowCount();
		undo(false);
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		// not to not reload the enum data type
		JButton button = findButtonByText(d.getComponent(), "No");
		assertNotNull(button);
		runSwing(() -> button.getActionListeners()[0].actionPerformed(null));
		waitForSwing();
		assertEquals(rowCount, model.getRowCount());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private EnumEditorPanel findEditorPanel(Window w) {
		Window[] windows = w.getOwnedWindows();
		for (Window window : windows) {
			if (window.isVisible() && JDialog.class.isAssignableFrom(window.getClass())) {
				Container c =
					findContainer(((JDialog) window).getContentPane(), EnumEditorPanel.class);
				if (c != null) {
					return (EnumEditorPanel) c;
				}
			}
		}
		return null;
	}

	private Container findContainer(Container parent, Class<?> theClass) {
		Component[] c = parent.getComponents();
		for (Component element : c) {
			if (theClass.isAssignableFrom(element.getClass())) {
				return (Container) element;
			}
			if (element instanceof Container) {
				Container container = findContainer((Container) element, theClass);
				if (container != null) {
					return container;
				}
			}
		}
		return null;
	}

	private void applyChanges(boolean doWait) throws Exception {

		DockingActionIf applyAction = getApplyAction();
		assertTrue(applyAction.isEnabled());
		Runnable r = () -> applyAction.actionPerformed(new DefaultActionContext());
		if (doWait) {
			runSwing(r);
			dtm.flushEvents();
		}
		else {
			runSwingLater(r);
		}
		waitForSwing();

	}

	private DockingActionIf getAddAction() {
		return getAction(plugin, "Add Enum Value");
	}

	private DockingActionIf getApplyAction() {
		return getAction(plugin, "Apply Enum Changes");
	}

	private DockingActionIf getDeleteAction() {
		return getAction(plugin, "Delete Enum Value");
	}

	private Enum editSampleEnum() {

		AtomicReference<Enum> enumRef = new AtomicReference<>();

		dtm.withTransaction("Create Test Enum", () -> {

			Category cat = dtm.createCategory(new CategoryPath(CategoryPath.ROOT, "Category1"));

			Enum enumm = new EnumDataType("Colors", 1);
			enumm.add("Red", 0);
			enumm.add("Green", 0x10);
			enumm.add("Blue", 0x20);
			enumm.add("Purple", 5);
			enumm.add("Turquoise", 0x22);
			enumm.add("Pink", 2);
			enumm.setDescription("This is a set of Colors");

			Enum enumDt = (Enum) cat.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
			enumRef.set(enumDt);

			dtm.flushEvents();
			waitForSwing();

			runSwingLater(() -> plugin.edit(enumDt));
		});

		waitForSwing();
		return enumRef.get();

	}

	private void undo(boolean doWait) throws Exception {
		Runnable r = () -> {
			try {
				undo();
				dtm.flushEvents();
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		};
		if (doWait) {
			runSwing(r);
		}
		else {
			runSwingLater(r);
		}
		waitForSwing();
	}

	private void redo(boolean doWait) throws Exception {
		Runnable r = () -> {
			try {
				redo();
				dtm.flushEvents();
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		};
		if (doWait) {
			runSwing(r);
		}
		else {
			runSwingLater(r);
		}
		waitForSwing();
	}

	abstract void undo() throws IOException;

	abstract void redo() throws IOException;
}
