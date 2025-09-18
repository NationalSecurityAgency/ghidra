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
import java.awt.Color;
import java.awt.event.*;
import java.util.List;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.widgets.table.DefaultEnumeratedColumnProgramTableModel;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import docking.widgets.table.GTable;
import generic.theme.GColor;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.symz3.SymZ3RecordsExecution.RecInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.util.HTMLUtilities;
import ghidra.util.WebColors;
import ghidra.util.table.GhidraTableFilterPanel;

public class Z3SummaryInstructionLogPanel extends JPanel {
	private static final Color COLOR_FOREGROUND_ADDRESS = new GColor("color.fg.listing.address");
	private static final Color COLOR_FOREGROUND_REGISTER = new GColor("color.fg.listing.register");
	private static final Color COLOR_FOREGROUND_SCALAR = new GColor("color.fg.listing.constant");
	private static final Color COLOR_FOREGROUND_MNEMONIC = new GColor("color.fg.listing.mnemonic");
	private static final Color COLOR_FOREGROUND_SEPARATOR =
		new GColor("color.fg.listing.separator");
	private static final Color COLOR_FOREGROUND_BADREF = new GColor("color.fg.listing.ref.bad");
	private static final Color COLOR_FOREGROUND_VARIABLE =
		new GColor("color.fg.listing.function.variable");

	protected static String htmlColor(Color color, String display) {
		return String.format("<font color=\"%s\">%s</font>", WebColors.toString(color, false),
			HTMLUtilities.escapeHTML(display));
	}

	protected enum InstructionLogTableColumns
		implements EnumeratedTableColumn<InstructionLogTableColumns, RecInstruction> {
		INDEX("Index", Integer.class, RecInstruction::index, true),
		THREAD("Thread", String.class, RecInstruction::getThreadName, true),
		ADDRESS("Address", Address.class, RecInstruction::getAddress, true),
		CODE("Instruction", String.class, InstructionLogTableColumns::getInstructionHtml, true),;

		private final String header;
		private final Class<?> cls;
		private final Function<RecInstruction, ?> getter;
		private final boolean visible;

		<T> InstructionLogTableColumns(String header, Class<T> cls,
				Function<RecInstruction, T> getter, boolean visible) {
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
		public Object getValueOf(RecInstruction row) {
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

	static class InstructionHtmlAppender {
		private final StringBuffer html = new StringBuffer("<html>");

		public void appendMnemonic(String mnemonic) {
			html.append(htmlColor(COLOR_FOREGROUND_MNEMONIC, mnemonic));
		}

		public void appendSeparator(String separator) {
			html.append(htmlColor(COLOR_FOREGROUND_SEPARATOR, separator));
		}

		public void appendSeparator(Character separator) {
			html.append(htmlColor(COLOR_FOREGROUND_SEPARATOR, Character.toString(separator)));
		}

		public void appendBadRef(String error) {
			html.append(htmlColor(COLOR_FOREGROUND_BADREF, error));
		}

		public void appendRegister(String regname) {
			html.append(htmlColor(COLOR_FOREGROUND_REGISTER, regname));
		}

		public void appendScalar(String scalar) {
			html.append(htmlColor(COLOR_FOREGROUND_SCALAR, scalar));
		}

		public void appendAddress(String address) {
			html.append(htmlColor(COLOR_FOREGROUND_ADDRESS, address));
		}

		public void appendVariableRef(String variable) {
			html.append(htmlColor(COLOR_FOREGROUND_VARIABLE, variable));
		}

		public String finish() {
			html.append("</html>");
			return html.toString();
		}
	}

	static class InstructionHtmlFormatter {
		private final static boolean SPACE_AFTER_SEP = true;

		String formatInstruction(Instruction instruction) {
			InstructionHtmlAppender appender = new InstructionHtmlAppender();
			appender.appendMnemonic(instruction.getMnemonicString());
			appender.appendSeparator(" ");

			int numOperands = instruction.getNumOperands();
			if (numOperands == 0) {
				return appender.finish();
			}

			formatSeparator(instruction, 0, appender);

			for (int opIndex = 0; opIndex < numOperands; opIndex++) {
				List<Object> operandRepresentationList =
					instruction.getDefaultOperandRepresentationList(opIndex);
				formatOperand(instruction, operandRepresentationList, opIndex, appender);
			}

			return appender.finish();
		}

		void formatSeparator(Instruction instruction, int separatorIndex,
				InstructionHtmlAppender appender) {
			String separator = instruction.getSeparator(separatorIndex);
			if (separator == null) {
				return;
			}
			if (SPACE_AFTER_SEP) {
				separator += " ";
			}
			appender.appendSeparator(separator);
		}

		void formatOperand(Instruction instruction, List<Object> opRepList, int opIndex,
				InstructionHtmlAppender appender) {
			if (opRepList == null) {
				appender.appendBadRef(opRepList == null ? "<UNSUPPORTED>" : opRepList.toString());
				return;
			}
			for (int subOpIndex = 0; subOpIndex < opRepList.size(); subOpIndex++) {
				formatSubOperand(instruction, opRepList.get(subOpIndex), opIndex, subOpIndex,
					appender);
			}
			formatSeparator(instruction, opIndex + 1, appender);
		}

		void formatSubOperand(Instruction instruction, Object opRep, int opIndex, int subOpIndex,
				InstructionHtmlAppender appender) {
			switch (opRep) {
				case VariableOffset vo -> formatSubOperand(instruction, vo.getObjects(), opIndex,
					subOpIndex, appender);
				case List<?> l -> formatSubOperand(instruction, l, opIndex, subOpIndex, appender);
				case String s -> formatSeparator(instruction, s, opIndex, subOpIndex, appender);
				case Register r -> formatRegister(instruction, r, opIndex, subOpIndex, appender);
				case Scalar s -> formatScalar(instruction, s, opIndex, subOpIndex, appender);
				case Address a -> formatAddress(instruction, a, opIndex, subOpIndex, appender);
				case Character c -> formatSeparator(instruction, c, opIndex, subOpIndex, appender);
				case Equate e -> formatEquate(instruction, e, opIndex, subOpIndex, appender);
				case LabelString l -> formatLabelString(instruction, l, opIndex, subOpIndex,
					appender);
				default -> formatSeparator(instruction, opRep.toString(), opIndex, subOpIndex,
					appender);
			}
		}

		void formatSeparator(Instruction instruction, String opRep, int opIndex, int subOpIndex,
				InstructionHtmlAppender appender) {
			appender.appendSeparator(opRep);
		}

		void formatSeparator(Instruction instruction, Character opRep, int opIndex, int subOpIndex,
				InstructionHtmlAppender appender) {
			appender.appendSeparator(opRep);
		}

		void formatRegister(Instruction instruction, Register opRep, int opIndex, int subOpIndex,
				InstructionHtmlAppender appender) {
			appender.appendRegister(opRep.toString());
		}

		void formatScalar(Instruction instruction, Scalar opRep, int opIndex, int subOpIndex,
				InstructionHtmlAppender appender) {
			appender.appendScalar(opRep.toString());
		}

		void formatAddress(Instruction instruction, Address opRep, int opIndex, int subOpIndex,
				InstructionHtmlAppender appender) {
			appender.appendAddress(opRep.toString());
		}

		void formatEquate(Instruction instruction, Equate opRep, int opIndex, int subOpIndex,
				InstructionHtmlAppender appender) {
			appender.appendScalar(opRep.toString());
		}

		void formatLabelString(Instruction instruction, LabelString l, int opIndex, int subOpIndex,
				InstructionHtmlAppender appender) {
			switch (l.getLabelType()) {
				case VARIABLE -> appender.appendVariableRef(l.toString());
				default -> appender.appendSeparator(l.toString());
			}
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

		TableColumnModel columnModel = table.getColumnModel();
		TableColumn indexCol = columnModel.getColumn(InstructionLogTableColumns.INDEX.ordinal());
		indexCol.setMaxWidth(30);
		indexCol.setMinWidth(30);
		TableColumn threadCol = columnModel.getColumn(InstructionLogTableColumns.THREAD.ordinal());
		threadCol.setMaxWidth(30);
		threadCol.setMinWidth(30);
		TableColumn addrCol = columnModel.getColumn(InstructionLogTableColumns.ADDRESS.ordinal());
		addrCol.setCellRenderer(new MonospaceCellRenderer());
		addrCol.setPreferredWidth(20);
		TableColumn codeCol = columnModel.getColumn(InstructionLogTableColumns.CODE.ordinal());
		codeCol.setCellRenderer(new HtmlCellRenderer());
		codeCol.setPreferredWidth(40);

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
