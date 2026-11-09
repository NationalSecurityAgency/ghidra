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
package ghidra.symz3.gui;

import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.List;
import java.util.function.Function;

import javax.swing.*;

import docking.widgets.table.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.symz3.SymZ3RecordsExecution.RecInstruction;
import ghidra.program.model.address.Address;
import ghidra.util.formatter.InstructionHtmlFormatter;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.column.GColumnRenderer;

public class Z3SummaryInstructionLogPanel extends JPanel {
	private static final MonospaceCellRenderer MONO_RENDERER = new MonospaceCellRenderer();
	private static final HtmlCellRenderer HTML_RENDERER = new HtmlCellRenderer();

	protected enum InstructionLogTableColumns
		implements EnumeratedTableColumn<InstructionLogTableColumns, RecInstruction> {
		INDEX("Index", Integer.class, RecInstruction::index) {
			@Override
			public int getMaxWidth() {
				return 30;
			}

			@Override
			public int getMinWidth() {
				return 30;
			}
		},
		THREAD("Thread", String.class, RecInstruction::getThreadName) {
			@Override
			public int getMaxWidth() {
				return 30;
			}

			@Override
			public int getMinWidth() {
				return 30;
			}
		},
		ADDRESS("Address", Address.class, RecInstruction::getAddress) {
			@Override
			public GColumnRenderer<?> getRenderer() {
				return MONO_RENDERER;
			}

			@Override
			public int getPreferredWidth() {
				return 20;
			}
		},
		CODE("Instruction", String.class, InstructionLogTableColumns::getInstructionHtml) {
			@Override
			public GColumnRenderer<?> getRenderer() {
				return HTML_RENDERER;
			}

			@Override
			public int getPreferredWidth() {
				return 40;
			}
		};

		private final static InstructionHtmlFormatter FORMATTER = new InstructionHtmlFormatter();

		private final String header;
		private final Class<?> cls;
		private final Function<RecInstruction, ?> getter;

		<T> InstructionLogTableColumns(String header, Class<T> cls,
				Function<RecInstruction, T> getter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
		}

		static String getInstructionHtml(RecInstruction op) {
			return FORMATTER.formatInstruction(op.instruction());
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(RecInstruction row) {
			return getter.apply(row);
		}
	}

	protected static class InstructionLogTableModel extends
			DefaultEnumeratedColumnProgramTableModel<InstructionLogTableColumns, RecInstruction> {
		public InstructionLogTableModel(PluginTool tool) {
			super(tool, "Summary-InstructionLog", InstructionLogTableColumns.class,
				InstructionLogTableColumns.ADDRESS);
		}

		@Override
		public List<InstructionLogTableColumns> defaultSortOrder() {
			return List.of(InstructionLogTableColumns.INDEX);
		}
	}

	private final Z3SummaryProvider provider;

	protected final InstructionLogTableModel model;
	protected final GTable table;
	protected final GhidraTableFilterPanel<RecInstruction> filterPanel;

	public Z3SummaryInstructionLogPanel(Z3SummaryProvider provider) {
		super(new BorderLayout());
		this.provider = provider;

		model = new InstructionLogTableModel(provider.getTool());
		table = new GTable(model);
		add(new JScrollPane(table));

		filterPanel = new GhidraTableFilterPanel<>(table, model);
		add(filterPanel, BorderLayout.SOUTH);

		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() != 2) {
					return;
				}
				e.consume();
				fireSelectedAddress();
			}
		});
		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() != KeyEvent.VK_ENTER) {
					return;
				}
				e.consume();
				fireSelectedAddress();
			}
		});
	}

	private void fireSelectedAddress() {
		RecInstruction sel = filterPanel.getSelectedItem();
		if (sel == null) {
			return;
		}
		provider.fireAddress(sel.getAddress());
	}

	public void setLog(List<RecInstruction> log) {
		model.clear();
		model.addAll(log);
	}
}
