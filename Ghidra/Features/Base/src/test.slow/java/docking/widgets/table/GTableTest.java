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
package docking.widgets.table;

import static org.junit.Assert.*;

import java.awt.BorderLayout;

import javax.swing.*;

import org.junit.*;

import docking.widgets.table.model.TestDataModel;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.table.GhidraTable;

public class GTableTest extends AbstractGhidraHeadedIntegrationTest {
	private TestDataModel model;
	private GhidraTable table;
	private JFrame frame;
	private long testKeyTimeout = 100;

	@Before
	public void setUp() throws Exception {
		model = new TestDataModel();
		table = new GhidraTable(model);
		table.setAutoLookupTimeout(testKeyTimeout);

		frame = new JFrame("Ghidra Table Test");
		frame.getContentPane().setLayout(new BorderLayout());
		frame.getContentPane().add(new JScrollPane(table));
		frame.pack();
		frame.setVisible(true);
	}

	@After
	public void tearDown() throws Exception {
		frame.dispose();
	}

	@Test
	public void testAutoLookup() throws Exception {

		table.setAutoLookupColumn(4);

		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals(11, table.getSelectedRow());
		triggerText(table, "c");
		assertEquals(12, table.getSelectedRow());
		timeout();
		triggerText(table, "ad");
		assertEquals(24, table.getSelectedRow());
		timeout();
		triggerText(table, "av");
		assertEquals(70, table.getSelectedRow());
		timeout();
		triggerText(table, "x");
		assertEquals(1920, table.getSelectedRow());
		timeout();
		triggerText(table, "a");
		assertEquals(11, table.getSelectedRow());

		// test the case where no match is found
		table.setAutoLookupTimeout(1000); // longer timeout needed for multiple keys
		triggerText(table, "zed");
		assertEquals(11, table.getSelectedRow()); // no change
	}

	@Test
	public void testAutoLookup_SortDescending() throws Exception {

		int column = 4;
		sortDescending(column);

		table.setAutoLookupColumn(column);

		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals(1846, table.getSelectedRow());

		triggerText(table, "c");
		assertEquals(1902, table.getSelectedRow());

		timeout();
		triggerText(table, "ad");
		assertEquals(1885, table.getSelectedRow());

		timeout();
		triggerText(table, "av");
		assertEquals(1848, table.getSelectedRow());

		timeout();
		triggerText(table, "x");
		assertEquals(0, table.getSelectedRow());

		timeout();
		triggerText(table, "a");
		assertEquals(1846, table.getSelectedRow());

		// test the case where no match is found
		table.setAutoLookupTimeout(1000); // longer timeout needed for multiple keys
		triggerText(table, "zed");
		assertEquals(1846, table.getSelectedRow()); // no change
	}

	@Test
	public void testAutoLookup_WhenColumnIsNotSorted() throws Exception {

		int column = 4;
		removeSortColumn(column);

		table.setAutoLookupColumn(column);

		setSelectedRow(table, 0);

		// note: the order checked here is the same as the sorted order, since we did not move
		//       any rows after disabling the sort
		triggerText(table, "a");
		assertEquals(11, table.getSelectedRow());
		triggerText(table, "c");
		assertEquals(12, table.getSelectedRow());
		timeout();
		triggerText(table, "ad");
		assertEquals(24, table.getSelectedRow());
		timeout();
		triggerText(table, "av");
		assertEquals(70, table.getSelectedRow());
		timeout();
		triggerText(table, "x");
		assertEquals(1920, table.getSelectedRow());
		timeout();
		triggerText(table, "a");
		assertEquals(11, table.getSelectedRow());

		// test the case where no match is found
		table.setAutoLookupTimeout(1000); // longer timeout needed for multiple keys
		triggerText(table, "zed");
		assertEquals(11, table.getSelectedRow()); // no change
	}

	@Test
	public void testSetActionsEnabled() throws Exception {

		table.setAutoLookupColumn(4);
		assertFalse(table.areActionsEnabled());
		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals("Auto-lookup failed to change the table row", 11, table.getSelectedRow());

		// this will disable 'auto lookup'
		table.setActionsEnabled(true);
		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals("Auto-lookup should be disabled when actions are enabled", 0,
			table.getSelectedRow());

		table.setActionsEnabled(false);
		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals("Auto-lookup failed to change the table row", 11, table.getSelectedRow());

		table.setActionsEnabled(true);
		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals("Auto-lookup should be disabled when actions are enabled", 0,
			table.getSelectedRow());

		table.setAutoLookupColumn(4);
		setSelectedRow(table, 0);

		triggerText(table, "a");
		assertEquals("Auto-lookup failed to change the table row", 11, table.getSelectedRow());
	}

	private void removeSortColumn(int column) {
		waitForSwing();
		runSwing(() -> TableUtils.columnAlternativelySelected(table, column));
		waitForSwing();
	}

	private void sortDescending(int column) {

		TableSortState descendingSortState = TableSortState.createDefaultSortState(column, false);
		runSwing(() -> model.setTableSortState(descendingSortState));
		waitForSwing();
	}

	private void timeout() {
		sleep(testKeyTimeout * 2);
	}

	private void setSelectedRow(final GhidraTable table, final int i) throws Exception {
		SwingUtilities.invokeAndWait(() -> table.setRowSelectionInterval(i, i));
		waitForPostedSwingRunnables();
	}

}
