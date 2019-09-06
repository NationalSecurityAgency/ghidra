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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.nav.Navigatable;
import ghidra.framework.plugintool.DummyPluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.TestAddress;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import util.CollectionUtils;

public class TableChooserDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String OK_BUTTON_TEXT = "Do Work";
	private static final TestExecutorDecision DEFAULT_DECISION = r -> true;

	private DummyPluginTool tool;
	private TableChooserDialog dialog;
	private SpyTableChooserExecutor executor;

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
			//dialog.close();
		});
	}

	private void createDialog(SpyTableChooserExecutor dialogExecutor) throws Exception {
		executor = dialogExecutor;

		tool = new DummyPluginTool();
		tool.setVisible(true);
		Program program = new ToyProgramBuilder("Test", true).getProgram();
		Navigatable navigatable = null;
		dialog = new TableChooserDialog(tool, executor, program, "Title", navigatable);
		dialog.show();
		loadData();
	}

	private void reCreateDialog(SpyTableChooserExecutor dialogExecutor) throws Exception {
		runSwing(() -> dialog.close());
		createDialog(dialogExecutor);
	}

	private void loadData() {
		for (int i = 0; i < 7; i++) {
			dialog.add(new TestStubRowObject());
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

//==================================================================================================
// Private Methods
//==================================================================================================

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

		private static int counter;
		private long addr;

		TestStubRowObject() {
			addr = ++counter;
		}

		@Override
		public Address getAddress() {
			return new TestAddress(addr);
		}

		@Override
		public String toString() {
			return getAddress().toString();
		}
	}
}
