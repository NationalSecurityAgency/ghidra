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
import java.util.List;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.table.TableColumn;

import org.junit.*;

import docking.widgets.table.model.*;
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

		int count = model.getColumnCount();
		DynamicTableColumn<DirData, ?, ?> column = new DirDataSizeColumn();

		int index = 2; // in the middle
		runSwing(() -> {
			model.addTableColumn(column, index, true);
		});

		assertEquals(count + 1, model.getColumnCount());
		assertColumnPresent(column);
	}

	@Test
	public void testTableColumnDescriptor_ShortcutColumnCreation() throws Exception {

		frame.dispose();

		model = new TestGDynamicColumnTableModel() {
			@Override
			protected TableColumnDescriptor<DirData> createTableColumnDescriptor() {
				TableColumnDescriptor<DirData> descriptor = new TableColumnDescriptor<>();
				descriptor.addVisibleColumn("Name", String.class, data -> data.getName());
				descriptor.addVisibleColumn("Size", Integer.class, data -> data.getSize());
				descriptor.addHiddenColumn("Date", String.class, data -> data.getTime());
				return descriptor;
			}
		};
		table = new GhidraTable(model);

		frame = new JFrame("Ghidra Table Test");
		frame.getContentPane().setLayout(new BorderLayout());
		frame.getContentPane().add(new JScrollPane(table));
		frame.pack();
		frame.setVisible(true);

		// Note: when building the column model, all columns are visible by default, including those
		// created as hidden columns.  A swing process will run to update the hidden columns.  Thus,
		// we need to flush the swing processes to get that update to happen.
		waitForSwing();

		assertEquals(3, model.getColumnCount());

		GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();
		assertEquals(2, columnModel.getColumnCount());

		assertColumns("Name", "Size");

		showHiddenColumn("Date");
		assertColumns("Name", "Size", "Date");
	}

	private void showHiddenColumn(String name) {
		TableColumn tableColumn = getHiddenTableColumn(name);
		GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();
		runSwing(() -> columnModel.setVisible(tableColumn, true));
	}

	private TableColumn getHiddenTableColumn(String name) {
		GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();
		TableColumn tableColumn = runSwing(() -> {
			List<TableColumn> allColumns = columnModel.getAllColumns();
			for (TableColumn column : allColumns) {
				Object headerValue = column.getHeaderValue();
				if (headerValue.equals(name)) {
					return column;
				}
			}
			return null;
		});
		assertNotNull(tableColumn);

		boolean isVisible = runSwing(() -> {
			int index = tableColumn.getModelIndex();
			return columnModel.isVisible(index);
		});
		assertFalse(isVisible);
		return tableColumn;
	}

	private DynamicTableColumn<DirData, ?, ?> getColumn(String name) {
		int count = model.getColumnCount();
		for (int i = 0; i < count; i++) {

			DynamicTableColumn<DirData, ?, ?> column = model.getColumn(i);
			String columnName = column.getColumnName();
			if (columnName.equals(name)) {
				return column;
			}
		}
		return null;
	}

	private void assertColumns(String... expectedNames) {
		for (String expectedName : expectedNames) {
			DynamicTableColumn<DirData, ?, ?> column = getColumn(expectedName);
			assertNotNull("Column not found in model - " + expectedName, column);
		}
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
