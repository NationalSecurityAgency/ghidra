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

import static org.junit.Assume.assumeFalse;

import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.table.TableColumn;

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.Range;

import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.util.SystemUtilities;
import ghidra.util.table.GhidraTable;

public class DemoRangeCellRendererTest {
	@Before
	public void checkNotBatch() {
		assumeFalse(SystemUtilities.isInTestingBatchMode());
	}

	protected static class MyRow {
		private final String name;
		private Range<Integer> lifespan;

		public MyRow(String name, Range<Integer> lifespan) {
			this.name = name;
			this.lifespan = lifespan;
		}

		public String getName() {
			return name;
		}

		public Range<Integer> getLifespan() {
			return lifespan;
		}

		public void setLifespan(Range<Integer> lifespan) {
			this.lifespan = lifespan;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	protected enum MyColumns implements EnumeratedTableColumn<MyColumns, MyRow> {
		NAME("Name", String.class, MyRow::getName),
		LIFESPAN("Lifespan", Range.class, MyRow::getLifespan);

		private String header;
		private Class<?> cls;
		private Function<MyRow, ?> getter;

		private <T> MyColumns(String header, Class<T> cls, Function<MyRow, T> getter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(MyRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isSortable() {
			return this != LIFESPAN;
		}
	}

	@Test
	public void testDemoRangeCellRenderer() throws Throwable {
		JFrame window = new JFrame();
		window.setLayout(new BorderLayout());

		DefaultEnumeratedColumnTableModel<MyColumns, MyRow> model =
			new DefaultEnumeratedColumnTableModel<>("People", MyColumns.class);
		GhidraTable table = new GhidraTable(model);
		GTableFilterPanel<MyRow> filterPanel = new GTableFilterPanel<>(table, model);

		TableColumn column = table.getColumnModel().getColumn(MyColumns.LIFESPAN.ordinal());
		RangeTableCellRenderer<Integer> rangeRenderer = new RangeTableCellRenderer<>();
		RangeCursorTableHeaderRenderer<Integer> headerRenderer =
			new RangeCursorTableHeaderRenderer<>();
		column.setCellRenderer(rangeRenderer);
		column.setHeaderRenderer(headerRenderer);

		rangeRenderer.setFullRange(Range.closed(1800, 2000));
		headerRenderer.setFullRange(Range.closed(1800, 2000));
		headerRenderer.setCursorPosition(1940);

		model.add(new MyRow("Albert", Range.closed(1879, 1955)));
		model.add(new MyRow("Bob", Range.atLeast(1956)));
		model.add(new MyRow("Elvis", Range.closed(1935, 1977)));

		headerRenderer.addSeekListener(table, MyColumns.LIFESPAN.ordinal(), pos -> {
			System.out.println("pos: " + pos);
			headerRenderer.setCursorPosition(pos.intValue());
			table.getTableHeader().repaint();
		});

		window.add(new JScrollPane(table));
		window.add(filterPanel, BorderLayout.SOUTH);

		window.setBounds(0, 0, 1000, 200);
		CompletableFuture<Void> windowClosed = new CompletableFuture<>();
		WindowListener listener = new WindowAdapter() {
			@Override
			public void windowClosed(WindowEvent e) {
				windowClosed.complete(null);
			}
		};
		window.addWindowListener(listener);
		window.setVisible(true);
		windowClosed.get();
	}
}
