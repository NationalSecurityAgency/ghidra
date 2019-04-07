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

import static org.junit.Assert.assertEquals;

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

	@Before
	public void setUp() throws Exception {
		model = new TestDataModel();
		table = new GhidraTable(model);
		table.setAutoLookupColumn(4);

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
	}

	private void timeout() throws InterruptedException {
		Thread.sleep(GTable.KEY_TIMEOUT * 2);
	}

	private void setSelectedRow(final GhidraTable table, final int i) throws Exception {
		SwingUtilities.invokeAndWait(() -> table.setRowSelectionInterval(i, i));
		waitForPostedSwingRunnables();
	}

}
