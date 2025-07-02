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
import java.util.List;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.stream.Stream;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import docking.widgets.table.GTable;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.symz3.SymZ3RecordsExecution.RecInstruction;
import ghidra.symz3.gui.Z3SummaryInstructionLogPanel.InstructionHtmlFormatter;
import ghidra.util.table.GhidraTableFilterPanel;

public class Z3SummaryInformationPanel extends JPanel {

	enum InfoKind {
		VALUATION("val"), PRECONDITION("pre");

		final String display;

		private InfoKind(String display) {
			this.display = display;
		}

		@Override
		public String toString() {
			return display;
		}
	}

	record InformationRow(InfoKind kind, String variable, String value) {

	}

	protected enum InformationTableColumns
		implements EnumeratedTableColumn<InformationTableColumns, InformationRow> {
		KIND("Kind", InfoKind.class, InformationRow::kind, true),
		VARIABLE("Variable", String.class, InformationRow::variable, true),
		VALUE("Value", String.class, InformationRow::value, true);

		private final String header;
		private final Class<?> cls;
		private final Function<InformationRow, ?> getter;
		private final boolean visible;

		<T> InformationTableColumns(String header, Class<T> cls,
				Function<InformationRow, T> getter, boolean visible) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.visible = visible;
		}

		static String getInstructionHtml(RecInstruction op) {
			InstructionHtmlFormatter formatter = new InstructionHtmlFormatter();
			return formatter.formatInstruction(op.instruction());
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(InformationRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isVisible() {
			return visible;
		}
	}

	protected static class InformationTableModel extends
			DefaultEnumeratedColumnTableModel<InformationTableColumns, InformationRow> {
		public InformationTableModel(PluginTool tool) {
			super(tool, "Summary-Information", InformationTableColumns.class);
		}

		@Override
		public List<InformationTableColumns> defaultSortOrder() {
			return List.of(InformationTableColumns.KIND, InformationTableColumns.VARIABLE);
		}
	}

	protected final InformationTableModel model;
	protected final GTable table;
	protected final GhidraTableFilterPanel<InformationRow> filterPanel;

	public Z3SummaryInformationPanel(Z3SummaryProvider provider) {
		super(new BorderLayout());

		model = new InformationTableModel(provider.getTool());
		table = new GTable(model);
		add(new JScrollPane(table));

		filterPanel = new GhidraTableFilterPanel<>(table, model);
		add(filterPanel, BorderLayout.SOUTH);

		TableColumnModel columnModel = table.getColumnModel();
		TableColumn kindCol = columnModel.getColumn(InformationTableColumns.KIND.ordinal());
		kindCol.setMaxWidth(40);
		kindCol.setMinWidth(40);
		TableColumn varCol = columnModel.getColumn(InformationTableColumns.VARIABLE.ordinal());
		varCol.setCellRenderer(new MonospaceCellRenderer());
		varCol.setPreferredWidth(20);
		TableColumn valCol = columnModel.getColumn(InformationTableColumns.VALUE.ordinal());
		valCol.setCellRenderer(new MonospaceCellRenderer());
		valCol.setPreferredWidth(60);
	}

	public void setInformation(Stream<Entry<String, String>> valuations,
			Stream<String> preconditions) {
		model.clear();
		Stream<InformationRow> fromValuations =
			valuations.map(v -> new InformationRow(InfoKind.VALUATION, v.getKey(), v.getValue()));
		Stream<InformationRow> fromPreconditions =
			preconditions.map(v -> new InformationRow(InfoKind.PRECONDITION, "", v));
		model.addAll(Stream.concat(fromValuations, fromPreconditions).toList());
	}
}
