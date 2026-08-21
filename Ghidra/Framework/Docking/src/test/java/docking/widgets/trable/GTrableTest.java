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
package docking.widgets.trable;

import static org.junit.Assert.*;

import java.util.*;

import javax.swing.JFrame;
import javax.swing.JScrollPane;

import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGuiTest;
import ghidra.util.datastruct.Range;

public class GTrableTest extends AbstractGuiTest {

	private GTrableRowModel<TestDataRow> rowModel;
	private TestColumnModel columnModel;
	private GTrable<TestDataRow> gTrable;
	private JFrame frame;

	@Before
	public void setUp() {
		rowModel = createRowModel();
		columnModel = new TestColumnModel();
		gTrable = new GTrable<TestDataRow>(rowModel, columnModel);
		gTrable.setPreferredVisibleRowCount(3, 3);
		JScrollPane scroll = new JScrollPane(gTrable);
		frame = new JFrame("Test");
		frame.getContentPane().add(scroll);
		frame.pack();
		frame.setVisible(true);
	}

	@Test
	public void testInitialState() {

		//@formatter:off
		assertAllRows(
			"a",
			"b",
			"c"
		);
		assertVisibleRows(
			"a",
			"b",
			"c"
		);
		//@formatter:on

		Range visibleRows = gTrable.getVisibleRows();
		assertEquals(0, visibleRows.min);
		assertEquals(2, visibleRows.max);

		assertTrue(rowModel.getRow(0).isExpandable());
		assertFalse(rowModel.getRow(1).isExpandable());
		assertTrue(rowModel.getRow(2).isExpandable());
	}

	@Test
	public void testExpandRow() {
		selectRow(1);
		//@formatter:off
		assertVisibleRows(
			"a",
			"b",
			"c"
		);
		//@formatter:on

		assertTrue(rowModel.getRow(0).isExpandable());
		expandRow(0);

		//@formatter:off
		assertVisibleRows(
			"a",
			"	a.1",
			"	a.2"
		);
		assertAllRows(
			"a",
			"	a.1",
			"	a.2",
			"	a.3",
			"b",
			"c"
		);
		//@formatter:on

		assertEquals(4, gTrable.getSelectedRow());
	}

	@Test
	public void testCollapseRow() {
		expandRow(0);
		selectRow(5);

		//@formatter:off
		assertVisibleRows(
			"a",
			"	a.1",
			"	a.2"
		);
		assertAllRows(
			"a",
			"	a.1",
			"	a.2",
			"	a.3",
			"b",
			"c"
		);
		//@formatter:on

		assertTrue(rowModel.isExpanded(0));

		collapseRow(0);

		//@formatter:off
		assertVisibleRows(
			"a",
			"b",
			"c"
		);
		assertAllRows(
			"a",
			"b",
			"c"
		);
		//@formatter:on
		assertEquals(2, gTrable.getSelectedRow());
	}

	@Test
	public void testExpandAllRow() {

		//@formatter:off
		assertVisibleRows(
			"a",
			"b",
			"c"
		);
		//@formatter:on

		expandAll();

		//@formatter:off
		assertVisibleRows(
			"a",
			"	a.1",
			"	a.2"
		);
		assertAllRows(
			"a",
			"	a.1",
			"	a.2",
			"		a.2.A",
			"		a.2.B",
			"		a.2.C",
			"	a.3",
			"b",
			"c",
			"	c.1",
			"	c.2"
		);
		//@formatter:on
	}

	@Test
	public void testScrollToSelectedRow() {
		expandAll();
		selectRow(5);

		//@formatter:off
		assertVisibleRows(
			"a",
			"	a.1",
			"	a.2"
		);
		//@formatter:on

		scrollToSelectedRow();

		//@formatter:off
		assertVisibleRows(
			"		a.2.A",
			"		a.2.B",
			"		a.2.C"
		);
		//@formatter:on

	}

	private void scrollToSelectedRow() {
		runSwing(() -> {
			gTrable.scrollToSelectedRow();
		});
		waitForSwing();
	}

	private void expandRow(int row) {
		runSwing(() -> {
			gTrable.expandRow(row);
		});
		waitForSwing();
	}

	private void collapseRow(int row) {
		runSwing(() -> {
			gTrable.collapseRow(row);
		});
		waitForSwing();
	}

	private void expandAll() {
		runSwing(() -> {
			gTrable.expandAll();
		});
		waitForSwing();
	}

	private void selectRow(int row) {
		runSwing(() -> {
			gTrable.setSelectedRow(row);
		});
	}

	private void assertAllRows(String... expectedRows) {
		List<String> actualRows = getRowsAsText(0, rowModel.getRowCount() - 1);
		assertEquals(expectedRows.length, actualRows.size());
		List<String> expectedList = Arrays.asList(expectedRows);
		assertListEqualOrdered(expectedList, actualRows);
	}

	private void assertVisibleRows(String... expectedRows) {
		Range visibleRows = gTrable.getVisibleRows();
		List<String> actualRows = getRowsAsText(visibleRows.min, visibleRows.max);
		assertEquals(expectedRows.length, actualRows.size());
		List<String> expectedList = Arrays.asList(expectedRows);
		assertListEqualOrdered(expectedList, actualRows);
	}

	private List<String> getRowsAsText(int startRow, int endRow) {
		List<String> list = new ArrayList<>();
		for (int i = startRow; i <= endRow; i++) {
			TestDataRow row = rowModel.getRow(i);
			int indent = row.getIndentLevel();
			String name = row.getName();
			String indentation = StringUtils.repeat("\t", indent);
			list.add(indentation + name);
		}
		return list;
	}

	private GTrableRowModel<TestDataRow> createRowModel() {
		TestDataRow a2A = new TestDataRow("a.2.A", 2, null);
		TestDataRow a2B = new TestDataRow("a.2.B", 2, null);
		TestDataRow a2C = new TestDataRow("a.2.C", 2, null);

		TestDataRow a1 = new TestDataRow("a.1", 1, null);
		TestDataRow a2 = new TestDataRow("a.2", 1, List.of(a2A, a2B, a2C));
		TestDataRow a3 = new TestDataRow("a.3", 1, null);

		TestDataRow c1 = new TestDataRow("c.1", 1, null);
		TestDataRow c2 = new TestDataRow("c.2", 1, null);

		TestDataRow a = new TestDataRow("a", 0, List.of(a1, a2, a3));
		TestDataRow b = new TestDataRow("b", 0, null);
		TestDataRow c = new TestDataRow("c", 0, List.of(c1, c2));

		return new DefaultGTrableRowModel<>(List.of(a, b, c));
	}

	class TestDataRow extends GTrableRow<TestDataRow> {

		private List<TestDataRow> children;
		private String name;

		protected TestDataRow(String name, int indentLevel, List<TestDataRow> children) {
			super(indentLevel);
			this.name = name;
			this.children = children;
		}

		public String getName() {
			return name;
		}

		@Override
		public boolean isExpandable() {
			return children != null;
		}

		@Override
		protected List<TestDataRow> getChildRows() {
			return children;
		}

	}

	private class NameColumn extends GTrableColumn<TestDataRow, String> {
		@Override
		public String getValue(TestDataRow row) {
			return row.getName();
		}

		@Override
		protected int getPreferredWidth() {
			return 150;
		}

	}

	class TestColumnModel extends GTrableColumnModel<TestDataRow> {

		@Override
		protected void populateColumns(List<GTrableColumn<TestDataRow, ?>> columnList) {
			columnList.add(new NameColumn());
		}

	}
}
