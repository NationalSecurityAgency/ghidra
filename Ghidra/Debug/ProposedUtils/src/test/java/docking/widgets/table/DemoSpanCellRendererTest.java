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
import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.table.TableColumn;

import org.junit.*;

import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener;
import generic.Span;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.SystemUtilities;
import ghidra.util.table.GhidraTable;

public class DemoSpanCellRendererTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;

	@Before
	public void setupDemo() throws IOException {
		assumeFalse(SystemUtilities.isInTestingBatchMode());
		env = new TestEnv();
	}

	@After
	public void tearDownDemo() {
		if (env != null) {
			env.dispose();
		}
	}

	protected static class MyRow {
		private final String name;
		private IntSpan lifespan;

		public MyRow(String name, IntSpan lifespan) {
			this.name = name;
			this.lifespan = lifespan;
		}

		public String getName() {
			return name;
		}

		public IntSpan getLifespan() {
			return lifespan;
		}

		public void setLifespan(IntSpan lifespan) {
			this.lifespan = lifespan;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	protected enum MyColumns implements EnumeratedTableColumn<MyColumns, MyRow> {
		NAME("Name", String.class, MyRow::getName),
		LIFESPAN("IntSpan", IntSpan.class, MyRow::getLifespan);

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

	sealed interface IntSpan extends Span<Integer, IntSpan> {
		Domain DOMAIN = Domain.INSTANCE;
		Empty EMPTY = Empty.INSTANCE;
		Impl ALL = new Impl(Integer.MIN_VALUE, Integer.MAX_VALUE);

		static enum Domain implements Span.Domain<Integer, IntSpan> {
			INSTANCE;

			@Override
			public IntSpan newSpan(Integer min, Integer max) {
				return new Impl(min, max);
			}

			@Override
			public IntSpan empty() {
				return EMPTY;
			}

			@Override
			public IntSpan all() {
				return ALL;
			}

			@Override
			public int compare(Integer n1, Integer n2) {
				return Integer.compare(n1, n2);
			}

			@Override
			public Integer min() {
				return Integer.MIN_VALUE;
			}

			@Override
			public Integer max() {
				return Integer.MAX_VALUE;
			}

			@Override
			public Integer inc(Integer n) {
				return n + 1;
			}

			@Override
			public Integer dec(Integer n) {
				return n - 1;
			}
		}

		final class Empty implements IntSpan, Span.Empty<Integer, IntSpan> {
			static final IntSpan.Empty INSTANCE = new IntSpan.Empty();

			private Empty() {
			}

			@Override
			public String toString() {
				return doToString();
			}

			@Override
			public IntSpan.Domain domain() {
				return DOMAIN;
			}
		}

		record Impl(Integer min, Integer max) implements IntSpan {
			@Override
			public String toString() {
				return doToString();
			}

			@Override
			public IntSpan.Domain domain() {
				return DOMAIN;
			}
		}

		static IntSpan span(int min, int max) {
			return DOMAIN.closed(min, max);
		}

		static IntSpan atLeast(int min) {
			return DOMAIN.closed(min, DOMAIN.max());
		}
	}

	@Test
	public void testDemoRangeCellRenderer() throws Throwable {
		JFrame window = new JFrame();
		window.setLayout(new BorderLayout());

		DefaultEnumeratedColumnTableModel<MyColumns, MyRow> model =
			new DefaultEnumeratedColumnTableModel<>(env.getTool(), "People", MyColumns.class);
		GhidraTable table = new GhidraTable(model);
		GTableFilterPanel<MyRow> filterPanel = new GTableFilterPanel<>(table, model);

		TableColumn column = table.getColumnModel().getColumn(MyColumns.LIFESPAN.ordinal());
		SpanTableCellRenderer<Integer> rangeRenderer = new SpanTableCellRenderer<>();
		RangeCursorTableHeaderRenderer<Integer> headerRenderer =
			new RangeCursorTableHeaderRenderer<>(0);
		column.setCellRenderer(rangeRenderer);
		column.setHeaderRenderer(headerRenderer);

		rangeRenderer.setFullRange(IntSpan.span(1800, 2000));
		headerRenderer.setFullRange(IntSpan.span(1800, 2000));
		headerRenderer.setCursorPosition(1940);

		model.add(new MyRow("Albert", IntSpan.span(1879, 1955)));
		model.add(new MyRow("Bob", IntSpan.atLeast(1956)));
		model.add(new MyRow("Elvis", IntSpan.span(1935, 1977)));

		SeekListener seekListener = pos -> {
			System.out.println("pos: " + pos);
			headerRenderer.setCursorPosition(pos.intValue());
			table.getTableHeader().repaint();
		};
		headerRenderer.addSeekListener(seekListener);

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
