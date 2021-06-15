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
package ghidra.app.tablechooser;

import static org.junit.Assert.*;

import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;

import org.junit.*;

import docking.*;
import docking.action.*;
import docking.actions.KeyEntryDialog;
import docking.actions.ToolActions;
import docking.tool.util.DockingToolConstants;
import docking.widgets.table.TableSortState;
import ghidra.app.nav.Navigatable;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.DummyPluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import resources.Icons;
import util.CollectionUtils;

public class TableChooserDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String OK_BUTTON_TEXT = "Do Work";
	private static final TestExecutorDecision DEFAULT_DECISION = r -> true;

	private DummyPluginTool tool;
	private SpyTableChooserExecutor executor;
	private TableChooserDialog dialog;
	private TestAction testAction;

	/** Interface for tests to signal what is expected of the executor */
	private TestExecutorDecision testDecision = DEFAULT_DECISION;

	@Before
	public void setUp() throws Exception {
		executor = new SpyTableChooserExecutor();
		createDialog(executor);
	}

	@After
	public void tearDown() {
		runSwing(() -> {
			tool.close();
		});
	}

	private void createDialog(SpyTableChooserExecutor dialogExecutor) throws Exception {
		executor = dialogExecutor;

		tool = new DummyPluginTool();
		tool.setVisible(true);

		List<Address> addresses = new ArrayList<>();
		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true);
		builder.createMemory(".text", "0x0", 0x110);
		Function f = createFunction(builder, 0x00);
		addresses.add(f.getEntryPoint());
		f = createFunction(builder, 0x10);
		addresses.add(f.getEntryPoint());
		f = createFunction(builder, 0x20);
		addresses.add(f.getEntryPoint());
		f = createFunction(builder, 0x30);
		addresses.add(f.getEntryPoint());
		f = createFunction(builder, 0x40);
		addresses.add(f.getEntryPoint());
		f = createFunction(builder, 0x50);
		addresses.add(f.getEntryPoint());

		Program program = builder.getProgram();
		Navigatable navigatable = null;
		dialog = new TableChooserDialog(tool, executor, program, "Dialog Title", navigatable);

		testAction = new TestAction();
		dialog.addAction(testAction);

		dialog.addCustomColumn(new OffsetTestColumn());
		dialog.addCustomColumn(new SpaceTestColumn());

		dialog.show();
		waitForDialogComponent(TableChooserDialog.class);
		loadData(addresses);
	}

	private Function createFunction(ProgramBuilder builder, long addr) throws Exception {
		ProgramDB p = builder.getProgram();
		FunctionManager fm = p.getFunctionManager();
		Function f = fm.getFunctionAt(builder.addr(addr));
		if (f != null) {
			return f;
		}

		String a = Long.toHexString(addr);
		return builder.createEmptyFunction("Function_" + a, "0x" + a, 5, DataType.DEFAULT);
	}

	private void reCreateDialog(SpyTableChooserExecutor dialogExecutor) throws Exception {
		runSwing(() -> dialog.close());
		createDialog(dialogExecutor);
	}

	private void loadData(List<Address> addresses) {
		for (Address a : addresses) {
			dialog.add(new TestStubRowObject(a));
		}

		waitForDialog();
	}

	@Test
	public void testClosedListener() {

		AtomicBoolean called = new AtomicBoolean();
		dialog.setClosedListener(() -> called.set(true));

		runSwing(() -> dialog.close());

		assertTrue("Dialog 'closed' listener not called", called.get());
	}

	@Test
	public void testNullExecutor() throws Exception {
		reCreateDialog(null);  // null executor

		assertNull("OK button should not be showing",
			findComponentByName(dialog.getComponent(), "OK"));
	}

	@Test
	public void testButtonCallbabck() {

		int rowCount = getRowCount();
		TestStubRowObject rowObject = selectRow(0);

		pressExecuteButton();
		waitForDialog();

		assertNotInDialog(rowObject);
		assertRowCount(rowCount - 1);
	}

	@Test
	public void testCallbackWithoutRemoval() {

		int rowCount = getRowCount();
		TestStubRowObject rowObject = selectRow(0);

		testDecision = r -> false; // don't remove

		pressExecuteButton();
		waitForDialog();

		assertInDialog(rowObject);
		assertOnlyExecutedOnce(rowObject);
		assertRowCount(rowCount);
	}

	@Test
	public void testCalllbackRemovesItems_OtherItemSelected() {
		/*
		 	Select multiple items.
		 	Have the first callback remove one of the remaining *unselected* items.
		 	The removed item should not itself get a callback.
		 */

		int rowCount = getRowCount();
		List<TestStubRowObject> selected = selectRows(0, 2);
		List<TestStubRowObject> toRemove = new ArrayList<>(toRowObjects(1, 3));

		List<TestStubRowObject> removedButNotExecuted = new ArrayList<>();
		testDecision = r -> {

			// remove the non-selected items
			for (TestStubRowObject other : toRemove) {
				removedButNotExecuted.add(other);
				dialog.remove(other);
			}
			toRemove.clear(); // only do this one time

			return true; // remove 'r'
		};

		pressExecuteButton();
		waitForDialog();
		assertEquals("Did not remove all items", 2, removedButNotExecuted.size());

		assertNotInDialog(selected);
		assertNotInDialog(removedButNotExecuted);
		assertRowCount(rowCount - (selected.size() + removedButNotExecuted.size()));
		assertNotExecuted(removedButNotExecuted);
	}

	@Test
	public void testCalllbackRemovesItems_OtherItemNotSelected() {

		/*
		 	Select multiple items.
		 	Have the first callback remove one of the remaining *selected* items.
		 	The removed item should not itself get a callback.
		 */

		int rowCount = getRowCount();
		List<TestStubRowObject> selected = selectRows(0, 1, 3);
		List<TestStubRowObject> toProcess = new ArrayList<>(selected);

		List<TestStubRowObject> removedButNotExecuted = new ArrayList<>();
		testDecision = r -> {
			toProcess.remove(r);

			// if not empty, remove one of the remaining items
			if (!toProcess.isEmpty()) {
				TestStubRowObject other = toProcess.remove(0);
				removedButNotExecuted.add(other);
				dialog.remove(other);
			}
			return true; // remove 'r'
		};

		pressExecuteButton();
		waitForDialog();
		assertTrue(toProcess.isEmpty());

		assertNotInDialog(selected);
		assertRowCount(rowCount - selected.size());
		assertNotExecuted(removedButNotExecuted);
	}

	@Test
	public void testItemsRepeatedlyRequestedToBeProcessed() {

		/*
		 	The execution step of the dialog can be slow, depending upon what work the user is
		 	doing in the callback.  Due to this, the UI allows the user to select the same item
		 	while it is schedule to be processed.   This test ensures that an item processed and
		 	removed in one scheduled request will not be processed again later.
		 */

		List<TestStubRowObject> selected1 = selectRows(0, 1, 2);

		CountDownLatch startLatch = new CountDownLatch(1);
		CountDownLatch continueLatch = new CountDownLatch(1);
		testDecision = r -> {

			//
			// Signal that we have started and wait to continue
			//
			startLatch.countDown();
			waitFor(continueLatch);

			return true; // remove 'r'
		};

		pressExecuteButton();
		waitFor(startLatch);

		List<TestStubRowObject> selected2 = selectRows(1);
		pressExecuteButton();      // schedule the second request
		continueLatch.countDown(); // release the first scheduled request

		waitForDialog();

		assertNotInDialog(selected1);
		assertNotInDialog(selected2);
		assertOnlyExecutedOnce(selected2);
	}

	@Test
	public void testActionToolBarButtonIconUpdate() {

		Icon icon = testAction.getToolBarData().getIcon();
		JButton button = getToolBarButton(icon);
		assertNotNull("Could not find button for icon: " + icon, button);

		Icon newIcon = Icons.LEFT_ICON;
		runSwing(() -> testAction.setToolBarData(new ToolBarData(newIcon)));
		button = getToolBarButton(newIcon);
		assertNotNull("Could not find button for icon: " + icon, button);
	}

	@Test
	public void testActionKeyBinding() {
		KeyStroke ks = testAction.getKeyBinding();
		triggerKey(dialog.getComponent(), ks);
		assertTrue(testAction.wasInvoked());
	}

	@Test
	public void testActionKeyBinding_ChangeKeyBinding_FromOptions() {
		KeyStroke newKs = KeyStroke.getKeyStroke('A', 0, false);
		setOptionsKeyStroke(testAction, newKs);
		triggerKey(dialog.getComponent(), newKs);
		assertTrue(testAction.wasInvoked());
	}

	@Test
	public void testActionKeyBinding_ChangeKeyBinding_FromKeyBindingDialog() {
		KeyStroke newKs = KeyStroke.getKeyStroke('A', 0, false);
		setKeyBindingViaF4Dialog(testAction, newKs);
		triggerKey(dialog.getComponent(), newKs);
		assertTrue("Action was not invoked from the new key binding: " + newKs,
			testAction.wasInvoked());
	}

	@Test
	public void testSetKeyBindingUpdatesToolBarButtonTooltip() {

		JButton button = getToolBarButton(testAction);
		String toolTip = button.getToolTipText();
		assertTrue(toolTip.contains("(Z)"));

		KeyStroke newKs = KeyStroke.getKeyStroke('A', 0, false);
		setOptionsKeyStroke(testAction, newKs);

		String newToolTip = button.getToolTipText();
		assertTrue(newToolTip.contains("(A)"));
	}

	@Test
	public void testSetSortColumn() throws Exception {
		assertSortedColumn(0);
		dialog.setSortColumn(1);
		assertSortedColumn(1);
	}

	@Test
	public void testSetSortState() throws Exception {
		assertSortedColumn(0);
		dialog.setSortState(TableSortState.createDefaultSortState(2, false));
		assertSortedColumn(2);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testSetSortState_Invalid() throws Exception {
		assertSortedColumn(0);
		dialog.setSortState(TableSortState.createDefaultSortState(100));
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertSortedColumn(int expectedColumn) {
		waitForCondition(() -> expectedColumn == getSortColumn(),
			"Incorrect sorted column; expected " + expectedColumn + ", found " + getSortColumn());
	}

	private int getSortColumn() {
		TableChooserTableModel model = getModel();
		return runSwing(() -> model.getPrimarySortColumnIndex());
	}

	private void setKeyBindingViaF4Dialog(DockingAction action, KeyStroke ks) {

		// simulate the user mousing over the toolbar button
		assertNotNull("Provider action not installed in toolbar", action);
		DockingWindowManager.setMouseOverAction(action);

		performLaunchKeyStrokeDialogAction();
		KeyEntryDialog keyDialog = waitForDialogComponent(KeyEntryDialog.class);

		runSwing(() -> keyDialog.setKeyStroke(ks));

		pressButtonByText(keyDialog, "OK");

		assertFalse("Invalid key stroke: " + ks, runSwing(() -> keyDialog.isVisible()));
	}

	private void performLaunchKeyStrokeDialogAction() {
		ToolActions toolActions = (ToolActions) ((AbstractDockingTool) tool).getToolActions();
		Action action = toolActions.getAction(KeyStroke.getKeyStroke("F4"));
		assertNotNull(action);
		runSwing(() -> action.actionPerformed(new ActionEvent(this, 0, "")), false);
	}

	private void setOptionsKeyStroke(DockingAction action, KeyStroke newKs) {

		ToolOptions keyOptions = tool.getOptions(DockingToolConstants.KEY_BINDINGS);

		String name = action.getName() + " (" + action.getOwner() + ")";
		runSwing(() -> keyOptions.setKeyStroke(name, newKs));
		waitForSwing();

		KeyStroke actual = action.getKeyBinding();
		assertEquals("Key binding was not updated after changing options", newKs, actual);
	}

	private JButton getToolBarButton(TestAction action) {
		return getToolBarButton(action.getToolBarData().getIcon());
	}

	private JButton getToolBarButton(Icon icon) {
		JButton button = findButtonByIcon(dialog.getComponent(), icon);
		return button;
	}

	private void assertRowCount(int expected) {
		int actual = getRowCount();
		assertEquals("Table model row count is not as expected", expected, actual);
	}

	private void assertInDialog(TestStubRowObject... rowObject) {
		assertInDialog(Arrays.asList(rowObject));
	}

	private void assertInDialog(List<TestStubRowObject> rowObjects) {
		TableChooserTableModel model = getModel();
		for (TestStubRowObject rowObject : rowObjects) {
			int index = runSwing(() -> model.getRowIndex(rowObject));
			assertTrue("Row object is not in the dialog", index >= 0);
		}
	}

	private void assertNotInDialog(TestStubRowObject... rowObjects) {
		assertNotInDialog(Arrays.asList(rowObjects));
	}

	private void assertNotInDialog(List<TestStubRowObject> rowObjects) {
		TableChooserTableModel model = getModel();
		for (TestStubRowObject rowObject : rowObjects) {
			int index = runSwing(() -> model.getRowIndex(rowObject));
			assertFalse("Row object is still in the dialog", index >= 0);
		}
	}

	private void assertNotExecuted(List<TestStubRowObject> removedButNotExecuted) {
		for (TestStubRowObject rowObject : removedButNotExecuted) {
			assertFalse("Row object was unexpectedly processed by the Executor",
				executor.wasExecuted(rowObject));
		}
	}

	private void assertOnlyExecutedOnce(TestStubRowObject... rowObjects) {
		assertOnlyExecutedOnce(Arrays.asList(rowObjects));
	}

	private void assertOnlyExecutedOnce(List<TestStubRowObject> rowObjects) {
		for (TestStubRowObject rowObject : rowObjects) {
			assertEquals("Row object was unexpectedly processed by the Executor", 1,
				executor.getExecutedCount(rowObject));
		}
	}

	private List<TestStubRowObject> toRowObjects(int... rows) {

		List<TestStubRowObject> results = new ArrayList<>();
		for (int row : rows) {
			AddressableRowObject r = runSwing(() -> getModel().getRowObject(row));
			results.add((TestStubRowObject) r);
		}
		return results;
	}

	private void waitForDialog() {
		waitForCondition(() -> !dialog.isBusy());
		waitForSwing();
	}

	private void pressExecuteButton() {
		pressButtonByName(dialog.getComponent(), "OK");
	}

	private int getRowCount() {
		return runSwing(() -> dialog.getRowCount());
	}

	private TestStubRowObject selectRow(int row) {
		List<TestStubRowObject> selected = selectRows(row);
		return selected.get(0);
	}

	private List<TestStubRowObject> selectRows(int... row) {
		runSwing(() -> dialog.clearSelection());
		runSwing(() -> dialog.selectRows(row));
		List<AddressableRowObject> selected = runSwing(() -> dialog.getSelectedRowObjects());
		return CollectionUtils.asList(selected, TestStubRowObject.class);
	}

	private TableChooserTableModel getModel() {
		return (TableChooserTableModel) getInstanceField("model", dialog);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private interface TestExecutorDecision {
		public boolean decide(AddressableRowObject rowObject);
	}

	private class SpyTableChooserExecutor implements TableChooserExecutor {

		private Map<AddressableRowObject, AtomicInteger> callbacks = new HashMap<>();

		@Override
		public String getButtonName() {
			return OK_BUTTON_TEXT;
		}

		int getExecutedCount(TestStubRowObject rowObject) {
			AtomicInteger counter = callbacks.get(rowObject);
			if (counter == null) {
				return 0;
			}
			return counter.get();
		}

		@Override
		public boolean execute(AddressableRowObject rowObject) {

			callbacks.merge(rowObject, new AtomicInteger(1), (k, v) -> {
				v.incrementAndGet();
				return v;
			});

			boolean result = testDecision.decide(rowObject);
			return result;
		}

		boolean wasExecuted(AddressableRowObject rowObject) {
			return callbacks.containsKey(rowObject);
		}
	}

	private static class TestStubRowObject implements AddressableRowObject {

		private Address addr;

		TestStubRowObject(Address a) {
			this.addr = a;
		}

		@Override
		public Address getAddress() {
			return addr;
		}

		@Override
		public String toString() {
			return getAddress().toString();
		}
	}

	private static class OffsetTestColumn extends AbstractColumnDisplay<String> {

		@Override
		public String getColumnValue(AddressableRowObject rowObject) {
			return Long.toString(rowObject.getAddress().getOffset());
		}

		@Override
		public String getColumnName() {
			return "Offset";
		}

		@Override
		public int compare(AddressableRowObject o1, AddressableRowObject o2) {
			return o1.getAddress().compareTo(o2.getAddress());
		}
	}

	private static class SpaceTestColumn extends AbstractColumnDisplay<String> {

		@Override
		public String getColumnValue(AddressableRowObject rowObject) {
			return rowObject.getAddress().getAddressSpace().toString();
		}

		@Override
		public String getColumnName() {
			return "Space";
		}

		@Override
		public int compare(AddressableRowObject o1, AddressableRowObject o2) {
			return o1.getAddress().compareTo(o2.getAddress());
		}
	}

	private class TestAction extends DockingAction {

		private int invoked;

		TestAction() {
			super("Test Action", "Test Owner");

			KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_Z, 0, false);
			setKeyBindingData(new KeyBindingData(ks));
			setToolBarData(new ToolBarData(Icons.ERROR_ICON));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			invoked++;
		}

		boolean wasInvoked() {
			if (invoked > 1) {
				fail("Action invoked more than once");
			}
			return invoked == 1;
		}
	}
}
