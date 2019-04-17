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
import static org.junit.Assert.fail;

import java.awt.BorderLayout;

import javax.swing.JFrame;
import javax.swing.JScrollPane;

import org.junit.*;

import docking.widgets.table.model.DirData;
import docking.widgets.table.model.TestGDynamicColumnTableModel;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.table.GhidraTable;

public class GTableDynamicColumnModelTest extends AbstractGhidraHeadedIntegrationTest {

	private TestGDynamicColumnTableModel model;
	private GhidraTable table;
	private JFrame frame;

	@Before
	public void setUp() throws Exception {

		model = new TestGDynamicColumnTableModel();
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
	public void testRemoveColumn() throws Exception {

		// Grab a column in the middle to remove
		int count = model.getColumnCount();
		DynamicTableColumn<DirData, ?, ?> column = model.getColumn(2);

		runSwing(() -> {
			model.removeTableColumn(column);
		});

		assertEquals(count - 1, model.getColumnCount());
		assertColumnMissing(column);
	}

	@Test
	public void testAddColumn() throws Exception {

		// Grab a column in the middle to remove
		int count = model.getColumnCount();
		DynamicTableColumn<DirData, ?, ?> column = model.getColumn(2);

		int index = 2; // in the middle
		runSwing(() -> {
			model.addTableColumn(column, index, true);
		});

		assertEquals(count + 1, model.getColumnCount());
		assertColumnPresent(column);
	}

	private void assertColumnPresent(DynamicTableColumn<DirData, ?, ?> column) {
		int count = model.getColumnCount();
		for (int i = 0; i < count; i++) {
			DynamicTableColumn<DirData, ?, ?> existingColumn = model.getColumn(i);
			if (column.equals(existingColumn)) {
				return;
			}
		}
		fail("Column not found in model - " + column.getColumnName());
	}

	private void assertColumnMissing(DynamicTableColumn<DirData, ?, ?> column) {
		int count = model.getColumnCount();
		for (int i = 0; i < count; i++) {
			DynamicTableColumn<DirData, ?, ?> existingColumn = model.getColumn(i);
			Assert.assertNotEquals(column, existingColumn);
		}
	}

}
