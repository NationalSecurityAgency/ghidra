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
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.app.util.pcode.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.symz3.SymZ3RecordsExecution.RecOp;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.HTMLUtilities;
import ghidra.util.WebColors;
import ghidra.util.table.GhidraTableFilterPanel;

public class Z3SummaryPcodeLogPanel extends JPanel {
	private static final Color COLOR_FOREGROUND_ADDRESS = new GColor("color.fg.listing.address");
	private static final Color COLOR_FOREGROUND_REGISTER = new GColor("color.fg.listing.register");
	private static final Color COLOR_FOREGROUND_SCALAR = new GColor("color.fg.listing.constant");
	private static final Color COLOR_FOREGROUND_LOCAL = new GColor("color.fg.listing.label.local");
	private static final Color COLOR_FOREGROUND_MNEMONIC = new GColor("color.fg.listing.mnemonic");
	private static final Color COLOR_FOREGROUND_UNIMPL =
		new GColor("color.fg.listing.mnemonic.unimplemented");
	private static final Color COLOR_FOREGROUND_SEPARATOR =
		new GColor("color.fg.listing.separator");
	private static final Color COLOR_FOREGROUND_LINE_LABEL =
		new GColor("color.fg.listing.pcode.label");
	private static final Color COLOR_FOREGROUND_SPACE =
		new GColor("color.fg.listing.pcode.address.space");
	private static final Color COLOR_FOREGROUND_RAW = new GColor("color.fg.listing.pcode.varnode");
	private static final Color COLOR_FOREGROUND_USEROP =
		new GColor("color.fg.listing.pcode.userop");

	protected static String htmlColor(Color color, String display) {
		return String.format("<font color=\"%s\">%s</font>", WebColors.toString(color, false),
			HTMLUtilities.escapeHTML(display));
	}

	protected enum PcodeLogTableColumns
		implements EnumeratedTableColumn<PcodeLogTableColumns, RecOp> {
		INDEX("Index", Integer.class, RecOp::index, true),
		THREAD("Thread", String.class, RecOp::getThreadName, true),
		ADDRESS("Address", Address.class, RecOp::getAddress, false),
		CODE("P-code", String.class, PcodeLogTableColumns::getPcodeHtml, true),
		;

		private final String header;
		private final Class<?> cls;
		private final Function<RecOp, ?> getter;
		private final boolean visible;

		<T> PcodeLogTableColumns(String header, Class<T> cls, Function<RecOp, T> getter,
				boolean visible) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.visible = visible;
		}

		static String getPcodeHtml(RecOp op) {
			PcodeHtmlFormatter formatter = new PcodeHtmlFormatter(op.thread());
			return formatter.formatOp(op.op());
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(RecOp row) {
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

	protected static class PcodeLogTableModel
			extends DefaultEnumeratedColumnProgramTableModel<PcodeLogTableColumns, RecOp> {
		public PcodeLogTableModel(PluginTool tool) {
			super(tool, "Summary-PcodeLog", PcodeLogTableColumns.class,
				PcodeLogTableColumns.ADDRESS);
		}

		@Override
		public List<PcodeLogTableColumns> defaultSortOrder() {
			return List.of(PcodeLogTableColumns.INDEX);
		}
	}

	static class PcodeHtmlAppender extends AbstractAppender<String> {
		private final PcodeFrame frame;
		private final StringBuffer html = new StringBuffer("<html>");

		public PcodeHtmlAppender(Language language, PcodeFrame frame) {
			super(language, false);
			this.frame = frame;
		}

		@Override
		public void appendAddressWordOffcut(long wordOffset, long offcut) {
			html.append(
				htmlColor(COLOR_FOREGROUND_ADDRESS, stringifyWordOffcut(wordOffset, offcut)));
		}

		@Override
		public void appendCharacter(char c) {
			if (c == '=') {
				html.append("&nbsp;");
				html.append(htmlColor(COLOR_FOREGROUND_SEPARATOR, "="));
				html.append("&nbsp;");
			}
			else if (c == ' ') {
				html.append("&nbsp;");
			}
			else {
				html.append(htmlColor(COLOR_FOREGROUND_SEPARATOR, Character.toString(c)));
			}
		}

		@Override
		public void appendIndent() {
			// stub
		}

		@Override
		public void appendLabel(String label) {
			html.append(htmlColor(COLOR_FOREGROUND_LOCAL, label));
		}

		@Override
		public void appendLineLabel(long label) {
			throw new AssertionError();
		}

		@Override
		public void appendLineLabelRef(long label) {
			html.append(htmlColor(COLOR_FOREGROUND_LINE_LABEL, stringifyLineLabel(label)));
		}

		@Override
		public void appendMnemonic(int opcode) {
			Color style = opcode == PcodeOp.UNIMPLEMENTED ? COLOR_FOREGROUND_UNIMPL
					: COLOR_FOREGROUND_MNEMONIC;
			html.append(htmlColor(style, stringifyOpMnemonic(opcode)));
		}

		@Override
		public void appendRawVarnode(AddressSpace space, long offset, long size) {
			html.append(
				htmlColor(COLOR_FOREGROUND_RAW, stringifyRawVarnode(space, offset, size)));
		}

		@Override
		public void appendRegister(Register register) {
			html.append(htmlColor(COLOR_FOREGROUND_REGISTER, stringifyRegister(register)));
		}

		@Override
		public void appendScalar(long value) {
			html.append(htmlColor(COLOR_FOREGROUND_SCALAR, stringifyScalarValue(value)));
		}

		@Override
		public void appendSpace(AddressSpace space) {
			html.append(htmlColor(COLOR_FOREGROUND_SPACE, stringifySpace(space)));
		}

		@Override
		public void appendUnique(long offset) {
			html.append(htmlColor(COLOR_FOREGROUND_LOCAL, stringifyUnique(offset)));
		}

		@Override
		public void appendUserop(int id) {
			html.append(htmlColor(COLOR_FOREGROUND_USEROP, stringifyUserop(language, id)));
		}

		@Override
		protected String stringifyUseropUnchecked(Language lang, int id) {
			String name = super.stringifyUseropUnchecked(lang, id);
			if (name != null) {
				return name;
			}
			return frame.getUseropName(id);
		}

		@Override
		public String finish() {
			html.append("</html>");
			return html.toString();
		}
	}

	static class PcodeHtmlFormatter extends AbstractPcodeFormatter<String, PcodeHtmlAppender> {
		private final Language language;
		private final PcodeFrame frame;

		public PcodeHtmlFormatter(PcodeThread<?> thread) {
			this.language = thread.getLanguage();
			PcodeProgram nop = thread.getMachine().compileSleigh("nothing", "");
			this.frame = thread.getExecutor().begin(nop);
		}

		String getHtml() {
			return formatOps(language, frame.getCode());
		}

		@Override
		protected PcodeHtmlAppender createAppender(Language lang, boolean indent) {
			return new PcodeHtmlAppender(lang, frame);
		}

		String formatOp(PcodeOp op) {
			OpTpl tpl = PcodeFormatter.getPcodeOpTemplateLog(language.getAddressFactory(), op);
			PcodeHtmlAppender appender = createAppender(language, false);
			formatOpTemplate(appender, tpl);
			return appender.finish();
		}
	}

	private final Z3SummaryProvider provider;

	protected final PcodeLogTableModel model;
	protected final GTable table;
	protected final GhidraTableFilterPanel<RecOp> filterPanel;

	public Z3SummaryPcodeLogPanel(Z3SummaryProvider provider) {
		super(new BorderLayout());
		this.provider = provider;

		model = new PcodeLogTableModel(provider.getTool());
		table = new GTable(model);
		add(new JScrollPane(table));

		filterPanel = new GhidraTableFilterPanel<>(table, model);
		add(filterPanel, BorderLayout.SOUTH);

		TableColumnModel columnModel = table.getColumnModel();
		TableColumn indexCol = columnModel.getColumn(PcodeLogTableColumns.INDEX.ordinal());
		indexCol.setMaxWidth(30);
		indexCol.setMinWidth(30);
		TableColumn threadCol = columnModel.getColumn(PcodeLogTableColumns.THREAD.ordinal());
		threadCol.setMaxWidth(30);
		threadCol.setMinWidth(30);
		TableColumn addrCol = columnModel.getColumn(PcodeLogTableColumns.ADDRESS.ordinal());
		addrCol.setCellRenderer(new MonospaceCellRenderer());
		addrCol.setPreferredWidth(20);
		TableColumn codeCol = columnModel.getColumn(PcodeLogTableColumns.CODE.ordinal());
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
		RecOp sel = filterPanel.getSelectedItem();
		if (sel == null) {
			return;
		}
		provider.fireAddress(sel.getAddress());
	}

	public void setLog(List<RecOp> log) {
		model.clear();
		model.addAll(log);
	}
}
