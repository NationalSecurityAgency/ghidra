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
package ghidra.app.plugin.core.assembler;

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.*;

import db.Transaction;
import docking.DialogComponentProvider;
import docking.widgets.table.*;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Tables;
import generic.theme.Gui;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.assembler.sleigh.grammars.AssemblySentential.WhiteSpaceParseToken;
import ghidra.app.plugin.assembler.sleigh.parse.*;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.assembler.sleigh.symbol.*;
import ghidra.app.plugin.assembler.sleigh.tree.*;
import ghidra.app.plugin.core.assembler.completion.*;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.ListingColors;
import ghidra.app.util.viewer.field.ListingColors.LabelColors;
import ghidra.app.util.viewer.field.ListingColors.MnemonicColors;
import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractAssemblePatchDialog<T extends Program>
		extends DialogComponentProvider {

	protected static final Color COLOR_ERROR = Colors.ERROR;
	protected static final Color COLOR_CONSTANT = ListingColors.CONSTANT;
	protected static final Color COLOR_LABEL = LabelColors.PRIMARY;
	protected static final Color COLOR_VARNODE = ListingColors.REGISTER;
	protected static final Color COLOR_MNEMONIC = MnemonicColors.NORMAL;
	protected static final Color COLOR_SEPARATOR = ListingColors.SEPARATOR;

	protected static final AttributeSet ATTRS_ERROR = makeAttributes(COLOR_ERROR, true);
	protected static final AttributeSet ATTRS_CONSTANT = makeAttributes(COLOR_CONSTANT, false);
	protected static final AttributeSet ATTRS_LABEL = makeAttributes(COLOR_LABEL, false);
	protected static final AttributeSet ATTRS_VARNODE = makeAttributes(COLOR_VARNODE, false);
	protected static final AttributeSet ATTRS_MNEMONIC = makeAttributes(COLOR_MNEMONIC, false);
	protected static final AttributeSet ATTRS_SEPARATOR = makeAttributes(COLOR_SEPARATOR, false);

	static AttributeSet makeAttributes(Color color, boolean underline) {
		MutableAttributeSet attributes = new SimpleAttributeSet();
		StyleConstants.setForeground(attributes, color);
		StyleConstants.setUnderline(attributes, underline);
		return attributes;
	}

	record AssemblyRow(Address address, String assembly, AssemblyPatternBlock context, byte[] bytes,
			Throwable error) {}

	class AsmTableModel extends GDynamicColumnTableModel<AssemblyRow, Void> {
		final List<AssemblyRow> modelData = new ArrayList<>();

		public AsmTableModel(ServiceProvider serviceProvider) {
			super(serviceProvider);
		}

		@Override
		public String getName() {
			return "Assembly";
		}

		@Override
		public List<AssemblyRow> getModelData() {
			return modelData;
		}

		@Override
		protected TableColumnDescriptor<AssemblyRow> createTableColumnDescriptor() {
			return new TableColumnDescriptor<>() {
				{
					addHiddenColumn(new AsmContextColumn());
					addVisibleColumn(new AsmAddressColumn(), 1, true);
					addHiddenColumn(new AsmBytesColumn());
					addVisibleColumn(new AsmAssemblyColumn());
					addHiddenColumn(new AsmErrorColumn());
				}
			};
		}

		@Override
		public Void getDataSource() {
			return null;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return false;
		}

		public List<String> getLines() {
			return modelData.stream().map(AssemblyRow::assembly).toList();
		}
	}

	static class MonospacedRenderer extends AbstractGColumnRenderer<Object> {
		static final MonospacedRenderer INSTANCE = new MonospacedRenderer();

		@SuppressWarnings("unchecked")
		static <T> GColumnRenderer<T> instance() {
			return (GColumnRenderer<T>) INSTANCE;
		}

		@Override
		public String getFilterString(Object t, Settings settings) {
			return t == null ? null : t.toString();
		}

		@Override
		protected Font getDefaultFont() {
			return fixedWidthFont;
		}
	}

	static abstract class AbstractAsmColumn<T>
			extends AbstractDynamicTableColumn<AssemblyRow, T, Void> {
		@Override
		public GColumnRenderer<T> getColumnRenderer() {
			return MonospacedRenderer.instance();
		}
	}

	static class AsmAddressColumn extends AbstractAsmColumn<Address> {
		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(AssemblyRow row, Settings settings, Void data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return row.address;
		}
	}

	static class AsmBytesColumn extends AbstractAsmColumn<String> {
		@Override
		public String getColumnName() {
			return "Bytes";
		}

		@Override
		public String getValue(AssemblyRow row, Settings settings, Void data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return row.bytes == null ? "" : NumericUtilities.convertBytesToString(row.bytes, " ");
		}
	}

	static class AsmContextColumn extends AbstractAsmColumn<String> {
		@Override
		public String getColumnName() {
			return "Context";
		}

		@Override
		public String getValue(AssemblyRow row, Settings settings, Void data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return row.context == null ? "" : row.context.toString();
		}
	}

	static class AssemblyLineRenderer extends AbstractGColumnRenderer<AssemblyRow> {
		static final AssemblyLineRenderer INSTANCE = new AssemblyLineRenderer();
		private static final Color COLOR_ERROR = Tables.ERROR_UNSELECTED;
		private static final Color COLOR_ERROR_SEL = Tables.ERROR_SELECTED;

		@Override
		public String getFilterString(AssemblyRow t, Settings settings) {
			return t == null ? null : t.assembly;
		}

		@Override
		protected String getText(Object value) {
			if (!(value instanceof AssemblyRow row)) {
				return Objects.toString(value);
			}
			return row.assembly;
		}

		@Override
		protected Font getDefaultFont() {
			return fixedWidthFont;
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			Component ret = super.getTableCellRendererComponent(data);
			if (!(data.getValue() instanceof AssemblyRow row)) {
				return ret;
			}
			if (row.error != null) {
				ret.setForeground(data.isSelected() ? COLOR_ERROR_SEL : COLOR_ERROR);
			}
			return ret;
		}
	}

	static class AsmErrorColumn extends AbstractAsmColumn<String> {
		@Override
		public String getColumnName() {
			return "Error";
		}

		@Override
		public String getValue(AssemblyRow row, Settings settings, Void data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return row.error == null ? "" : row.error.toString();
		}
	}

	static class AsmAssemblyColumn
			extends AbstractDynamicTableColumn<AssemblyRow, AssemblyRow, Void> {
		@Override
		public String getColumnName() {
			return "Assembly";
		}

		@Override
		public AssemblyRow getValue(AssemblyRow row, Settings settings, Void data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return row;
		}

		@Override
		public GColumnRenderer<AssemblyRow> getColumnRenderer() {
			return AssemblyLineRenderer.INSTANCE;
		}
	}

	protected final Navigatable navigatable;
	protected final T program;
	protected final Assembler assembler;
	protected final Address entry;
	protected final RegisterValue initialContext;

	protected final StyledDocument document;
	protected final JTextPane text;
	protected final AsmTableModel tableModel;
	protected final GTable table;

	private final AsyncDebouncer<Void> update = new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 500);

	protected AbstractAssemblePatchDialog(PluginTool tool, Navigatable navigatable, T program,
			Address entry, RegisterValue initialContext) {
		super("Assemble", true, true, true, true);
		this.navigatable = navigatable;
		this.program = program;
		Language language = getLanguage();
		AssemblerPlugin.CACHE.get(language).get(null);
		AssemblerPlugin.warnLanguage(language);
		this.assembler = getAssembler();
		this.entry = entry;
		this.initialContext = initialContext;

		update.addListener(_ -> reassemble());

		JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

		document = new DefaultStyledDocument();
		text = new JTextPane(document) {
			{
				Gui.registerFont(this, FieldFactory.BASE_LISTING_FONT_ID);
			}
		};
		document.addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				update.contact(null);
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				update.contact(null);
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				// Don't want to re-update on just attribute changes.
			}
		});
		JScrollPane spText = new JScrollPane(text);
		spText.setPreferredSize(new Dimension(600, 600));
		split.setTopComponent(spText);
		AssemblyAutocompletionModel autoModel = new AssemblyAutocompletionModel() {
			@Override
			protected void collectSuggestionsFromAccepted(Set<AssemblyCompletion> result,
					String text) {
				Collection<AssemblyParseResult> parses = assembler.parseLine(text);
				for (AssemblyParseResult parse : parses) {
					if (!parse.isError()) {
						result.add(new SuggestionAssemblyCompletion("",
							"<html><b>%s</b></html>".formatted(HTMLUtilities.escapeHTML(text))));
						return;
					}
				}
			}
		};
		autoModel.setAssembler(assembler);
		autoModel.setAddress(entry);
		autoModel.setExisting(program.getListing().getInstructionAt(entry));
		AssemblyAutocompleter auto = new AssemblyAutocompleter(autoModel) {
			@Override
			protected String getPrefix(JTextComponent field) {
				String fullPrefix = super.getPrefix(field);
				int whereLine = fullPrefix.lastIndexOf('\n');
				if (whereLine == -1) {
					return fullPrefix;
				}
				return fullPrefix.substring(whereLine + 1);
			}

			@Override
			protected void createControlButtons(Box controls) {
				// Remove the exhaust button
			}

			@Override
			protected Point getCompletionWindowPosition() {
				Point caretPos = getCaretPositionOnScreen(text);
				Point panePos = text.getLocationOnScreen();
				return new Point(panePos.x, caretPos.y);
			}
		};
		auto.attachTo(text);

		this.tableModel = new AsmTableModel(tool);
		this.table = new GTable(tableModel);
		split.setBottomComponent(new JScrollPane(table));
		split.setDividerLocation(0.5);
		split.setResizeWeight(0.5);

		addWorkPanel(split);
		addOKButton();
		addCancelButton();
	}

	protected Language getLanguage() {
		return program.getLanguage();
	}

	protected Assembler getAssembler() {
		return Assemblers.getAssembler(program);
	}

	class Highlighter {
		boolean seenWS;
		int offset;

		Highlighter() {
			document.setCharacterAttributes(0, document.getLength() + 1, SimpleAttributeSet.EMPTY,
				true);
		}

		void highlightToken(AssemblyParseToken token) {
			AttributeSet attrs = switch (token) {
				case AssemblyParseSymbolToken _ -> ATTRS_LABEL;
				case WhiteSpaceParseToken _ -> {
					seenWS = true;
					yield ATTRS_SEPARATOR;
				}
				default -> switch (token.getSym()) {
					case AssemblyNumericTerminal _ -> ATTRS_CONSTANT;
					case AssemblyStringMapTerminal _ -> ATTRS_VARNODE;
					case AssemblyStringTerminal st -> switch (st.getDefiningSymbol()) {
						case null -> seenWS ? ATTRS_SEPARATOR : ATTRS_MNEMONIC;
						default -> ATTRS_VARNODE;
					};
					default -> ATTRS_SEPARATOR;
				};
			};
			int length = token.getString().length();
			if (length != 0) {
				document.setCharacterAttributes(offset, length, attrs, true);
			}
			offset += length;
		}

		void highlightBranch(AssemblyParseBranch branch) {
			for (AssemblyParseTreeNode node : branch.getSubstitutions()) {
				switch (node) {
					case AssemblyParseBranch sub -> highlightBranch(sub);
					case AssemblyParseToken tok -> highlightToken(tok);
					default -> {
					}
				}
			}
		}

		void highlightAccept(AssemblyParseAcceptResult accept) {
			highlightBranch(accept.getTree());
		}

		void highlightError(String line, AssemblyParseErrorResult error) {
			int length = error.getBuffer().length();
			int off = offset + line.length() - length;
			document.setCharacterAttributes(off, length, ATTRS_ERROR, true);
		}

		void highlight(String line) {
			try {
				Collection<AssemblyParseResult> allResults = assembler.parseLine(line);
				if (allResults.isEmpty()) {
					return;
				}
				AssemblyParseResult correct =
					allResults.stream().filter(r -> !r.isError()).findFirst().orElse(null);
				if (correct instanceof AssemblyParseAcceptResult accept) {
					highlightAccept(accept);
					return;
				}
				AssemblyParseErrorResult error = allResults.stream()
						.filter(r -> r instanceof AssemblyParseErrorResult)
						.map(r -> (AssemblyParseErrorResult) r)
						// Favor the parse that got farthest
						.sorted(Comparator.comparing(r -> r.getBuffer().length()))
						.findFirst()
						.orElse(null);
				if (error != null) {
					highlightError(line, error);
					return;
				}
			}
			catch (Throwable t) {
				Msg.error(this, t.getMessage());
				// Let the actual assembly step handle user display
			}
		}

		void newLine() {
			seenWS = false;
			offset += 1;
		}
	}

	void reassemble() {
		tableModel.modelData.clear();

		AssemblyBuffer buf = new AssemblyBuffer(assembler, entry, initialContext);
		Highlighter highlighter = new Highlighter();
		for (String line : text.getText().lines().toList()) {
			if (line.isBlank()) {
				continue;
			}
			Address address = buf.getNext();
			AssemblyPatternBlock ctx = buf.getNextCtx();
			Swing.runLater(() -> highlighter.highlight(line));
			try {
				byte[] bytes = buf.assemble(line);
				tableModel.modelData.add(new AssemblyRow(address, line, ctx, bytes, null));
			}
			catch (Throwable t) {
				tableModel.modelData.add(new AssemblyRow(address, line, ctx, null, t));
				break;
			}
			Swing.runLater(() -> highlighter.newLine());
		}
		Swing.runLater(() -> tableModel.fireTableDataChanged());
	}

	protected abstract AbstractPatchAssemblyCommand<T> newPatchCommand(List<String> lines);

	@Override
	protected void okCallback() {
		AbstractPatchAssemblyCommand<T> patchCmd = newPatchCommand(tableModel.getLines());
		executeProgressTask(new Task("Assemble", true, true, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				try (Transaction _ = program.openTransaction(patchCmd.getName())) {
					if (patchCmd.applyTo(program, monitor)) {
						Swing.runLater(() -> close());
					}
					else {
						setStatusText(patchCmd.getStatusMsg(), MessageType.ERROR);
					}
				}
				catch (Exception e) {
					setStatusText(e.getMessage(), MessageType.ERROR);
				}
				AddressSetView set = patchCmd.getSet();
				if (set != null) {
					Swing.runLater(() -> navigatable.setSelection(new ProgramSelection(set)));
				}
				Address next = patchCmd.getNext();
				if (next != null) {
					Swing.runLater(() -> navigatable.goTo(new ProgramLocation(program, next)));
				}
			}
		}, 500);
	}
}
