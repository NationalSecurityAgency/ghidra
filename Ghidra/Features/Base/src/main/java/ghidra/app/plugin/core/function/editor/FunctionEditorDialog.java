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
package ghidra.app.plugin.core.function.editor;

import java.awt.*;
import java.awt.event.*;
import java.util.Arrays;
import java.util.EventObject;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.event.*;
import javax.swing.plaf.TableUI;
import javax.swing.table.TableCellEditor;

import org.apache.commons.lang3.StringUtils;

import docking.*;
import docking.widgets.OptionDialog;
import docking.widgets.button.GButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GLabel;
import docking.widgets.table.*;
import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Colors;
import generic.util.WindowUtilities;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.viewer.field.ListingColors.FunctionColors;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.util.*;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import resources.Icons;

public class FunctionEditorDialog extends DialogComponentProvider implements ModelChangeListener {

	private static final String COMMIT_FULL_SIGNATURE_WARNING =
		"All signature details will be commited (see Commit checkbox above)";
	private static final String SIGNATURE_LOSS_WARNING =
		"Return/Parameter changes will not be applied (see Commit checkbox above)";

	private FunctionEditorModel model;
	private DocumentListener nameFieldDocumentListener;
	private GTable parameterTable;

	private JTextField nameField;
	private JCheckBox varArgsCheckBox;
	private DataTypeManagerService service;
	private JCheckBox inLineCheckBox;
	private JCheckBox noReturnCheckBox;
	private JComboBox<String> callFixupComboBox;
	private JComboBox<String> callingConventionComboBox;
	private JButton addButton;
	private JButton removeButton;
	private JButton upButton;
	private JButton downButton;
	private ParameterTableModel paramTableModel;
	private ListSelectionListener selectionListener;
	private JCheckBox storageCheckBox;
	private JScrollPane scroll;
	private JPanel previewPanel;
	private JCheckBox commitFullParamDetailsCheckBox; // optional: may be null

	private FunctionSignatureTextField signatureTextField;
	private UndoRedoKeeper signatureFieldUndoRedoKeeper;

	private MyGlassPane glassPane;
	private JPanel centerPanel;

	/**
	 * Construct Function Editor dialog for a specified Function and associated DataType service.
	 * @param service DataType service
	 * @param function Function to be modified
	 */
	public FunctionEditorDialog(DataTypeManagerService service, Function function) {
		this(new FunctionEditorModel(service, function), true);
	}

	/**
	 * Construct Function Editor dialog using a specified model
	 * @param model function detail model
	 * @param hasOptionalSignatureCommit if true an optional control will be included which 
	 * controls commit of parameter/return details, including Varargs and use of custom storage.
	 */
	public FunctionEditorDialog(FunctionEditorModel model, boolean hasOptionalSignatureCommit) {
		super(createTitle(model.getFunction()));
		this.service = model.getDataTypeManagerService();
		setRememberLocation(true);
		setRememberSize(true);
		setHelpLocation(new HelpLocation("FunctionPlugin", "Edit_Function"));
		this.model = model;
		model.setModelChangeListener(this);
		addWorkPanel(buildMainPanel(hasOptionalSignatureCommit));
		addOKButton();
		addCancelButton();
		glassPane = new MyGlassPane();
		dataChanged();
	}

	private static String createTitle(Function function) {
		StringBuilder strBuilder = new StringBuilder();
		if (function.isExternal()) {
			strBuilder.append("Edit External Function");
			ExternalLocation extLoc = function.getExternalLocation();
			Address addr = extLoc.getAddress();
			if (addr != null) {
				strBuilder.append(" at ");
				strBuilder.append(addr.toString());
			}
		}
		else {
			Function thunkedFunction = function.getThunkedFunction(false);
			if (thunkedFunction != null) {
				strBuilder.append("Edit Thunk Function at ");
				strBuilder.append(function.getEntryPoint().toString());
			}
			else {
				strBuilder.append("Edit Function at ");
				strBuilder.append(function.getEntryPoint().toString());
			}
		}
		return strBuilder.toString();
	}

	@Override
	protected void dialogShown() {

		// put user focus in the signature field, ready to take keyboard input
		signatureTextField.requestFocus();
		Swing.runLater(() -> {
			int start = model.getFunctionNameStartPosition();
			int end = model.getNameString().length();
			signatureTextField.setCaretPosition(end);
			signatureTextField.setSelectionStart(start);
			signatureTextField.setSelectionEnd(start + end);

			// reset any edits that happened before the user interacted with the field
			signatureFieldUndoRedoKeeper.clear();
		});
	}

	@Override
	protected void okCallback() {
		if (model.isInParsingMode()) {
			try {
				model.parseSignatureFieldText();
			}
			catch (Exception e) {
				handleParseException(e);
				signatureTextField.requestFocus();
				return;
			}
		}

		boolean fullCommit = true;
		if (commitFullParamDetailsCheckBox != null &&
			!commitFullParamDetailsCheckBox.isSelected()) {
			fullCommit = false;
		}
		if (model.apply(fullCommit)) {
			close();
		}
	}

	@Override
	public void close() {
		model.dispose();
		super.close();
	}

	private JComponent buildMainPanel(boolean hasOptionalSignatureCommit) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildPreview(), BorderLayout.NORTH);
		panel.add(buildCenterPanel(hasOptionalSignatureCommit), BorderLayout.CENTER);
		return panel;
	}

	private JComponent buildCenterPanel(boolean hasOptionalSignatureCommit) {
		centerPanel = new JPanel(new BorderLayout());
		centerPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0));
		centerPanel.add(buildAttributePanel(), BorderLayout.NORTH);
		centerPanel.add(buildTable(), BorderLayout.CENTER);
		centerPanel.add(buildBottomPanel(hasOptionalSignatureCommit), BorderLayout.SOUTH);
		return centerPanel;
	}

	private Component buildBottomPanel(boolean hasOptionalSignatureCommit) {
		JPanel panel = new JPanel(new BorderLayout());

		Border b = BorderFactory.createEmptyBorder(0, 0, 0, 0);

		JComponent callFixupField = createCallFixupComboPanel();
		callFixupField.setBorder(BorderFactory.createTitledBorder(b, "Call Fixup:"));
		panel.add(callFixupField, BorderLayout.WEST);

		Function thunkedFunction = model.getFunction().getThunkedFunction(false);
		if (thunkedFunction != null) {
			JPanel thunkedPanel = createThunkedFunctionTextPanel(thunkedFunction);
			thunkedPanel.setBorder(BorderFactory.createTitledBorder(b, "Thunked Function:"));
			panel.add(thunkedPanel, BorderLayout.CENTER); // provide as much space as possible
		}
		else {
			panel.add(new JPanel(), BorderLayout.CENTER);
		}

		if (hasOptionalSignatureCommit) {
			commitFullParamDetailsCheckBox = new JCheckBox("Commit all return/parameter details");
			commitFullParamDetailsCheckBox.addActionListener(e -> {
				if (!model.isValid()) {
					return;
				}
				if (!commitFullParamDetailsCheckBox.isSelected()) {
					if (model.hasSignificantParameterChanges()) {
						setStatusText(SIGNATURE_LOSS_WARNING, MessageType.WARNING);
					}
					else {
						clearStatusText();
					}
				}
				else {
					setStatusText(COMMIT_FULL_SIGNATURE_WARNING, MessageType.WARNING);
					setOkEnabled(true);
				}
			});
			panel.add(commitFullParamDetailsCheckBox, BorderLayout.SOUTH);
		}

		return panel;
	}

	private JPanel createThunkedFunctionTextPanel(Function thunkedFunction) {
		JPanel thunkedPanel = new JPanel(new BorderLayout());
		JTextField thunkedText = new JTextField(thunkedFunction.getName(true));
		thunkedText.setEditable(false);
		DockingUtils.setTransparent(thunkedText);
		CompoundBorder border =
			BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Colors.BORDER),
				BorderFactory.createEmptyBorder(0, 5, 0, 5));
		thunkedText.setBorder(border);
		thunkedText.setForeground(FunctionColors.THUNK);
		thunkedPanel.add(thunkedText);
		return thunkedPanel;
	}

	private JComponent buildPreview() {
		previewPanel = new JPanel(new BorderLayout());
		JPanel verticalScrollPanel = new VerticalScrollablePanel();
		verticalScrollPanel.add(createSignatureTextPanel());
		scroll = new JScrollPane(verticalScrollPanel);
		scroll.setBorder(null);
		scroll.setOpaque(true);
		previewPanel.add(scroll, BorderLayout.CENTER);
		previewPanel.setBorder(BorderFactory.createLoweredBevelBorder());
		scroll.getViewport().addMouseListener(new MouseAdapter() {

			@Override
			public void mouseClicked(MouseEvent e) {
				signatureTextField.setCaretPosition(signatureTextField.getText().length());
				signatureTextField.requestFocus();
			}
		});
		return previewPanel;
	}

	private JComponent createSignatureTextPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		signatureTextField = new FunctionSignatureTextField();

		signatureFieldUndoRedoKeeper = DockingUtils.installUndoRedo(signatureTextField);

		panel.add(signatureTextField);

		signatureTextField.setEscapeListener(e -> {

			if (!model.hasSignatureTextChanges()) {
				// no changes; user wish to close the dialog
				cancelCallback();
				return;
			}

			// editor has changes, see if they wish to cancel editing
			if (!promptToAbortChanges()) {
				return; // keep editing
			}

			// abort changes confirmed
			model.resetSignatureTextField();
		});

		signatureTextField.setActionListener(e -> {
			try {
				if (model.isInParsingMode()) {
					model.parseSignatureFieldText();
					return;
				}
			}
			catch (Exception ex) {
				handleParseException(ex);
				return;
			}

			if (model.isValid()) {
				okCallback();
			}
			else {
				Toolkit.getDefaultToolkit().beep();
			}
		});

		ActionListener tabListener = e -> {
			try {
				model.parseSignatureFieldText();
			}
			catch (Exception ex) {
				if (!handleParseException(ex)) {
					return;
				}
			}
			nameField.requestFocus();
		};

		signatureTextField.setTabListener(tabListener);

		signatureTextField
				.setChangeListener(e -> model.setSignatureFieldText(signatureTextField.getText()));
		return panel;
	}

	protected boolean handleParseException(Exception exception) {
		String message = exception.getMessage();

		String details = CParserUtils.handleParseProblem(exception, signatureTextField.getText());
		if (details != null) {
			message = details;
		}

		if (doPromptToAbortChanges(message)) {
			model.resetSignatureTextField();
			return true;
		}
		return false;
	}

	private boolean promptToAbortChanges() {
		return doPromptToAbortChanges("");
	}

	private boolean doPromptToAbortChanges(String message) {

		if (!StringUtils.isBlank(message)) {
			message += "<BR><BR>";
		}

		message = HTMLUtilities.wrapAsHTML(message +
			"<CENTER><B>Do you want to continue editing or " + "abort your changes?</B></CENTER>");
		int result = OptionDialog.showOptionNoCancelDialog(rootPanel, "Invalid Function Signature",
			message, "Continue Editing", "Abort Changes", OptionDialog.ERROR_MESSAGE);
		return result == OptionDialog.OPTION_TWO; // Option 2 is to abort
	}

	private Component buildAttributePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(0, 5, 15, 15));

		JPanel leftPanel = new JPanel(new PairLayout(4, 8));
		leftPanel.add(new GLabel("Function Name:"));
		leftPanel.add(createNameField());
		leftPanel.add(new GLabel("Calling Convention"));
		leftPanel.add(createCallingConventionCombo());
		leftPanel.setBorder(BorderFactory.createEmptyBorder(14, 0, 0, 10));

		panel.add(leftPanel, BorderLayout.CENTER);
		panel.add(buildTogglePanel(), BorderLayout.EAST);
		return panel;
	}

	private Component buildTogglePanel() {
		JPanel panel = new JPanel(new PairLayout());
		varArgsCheckBox = new GCheckBox("Varargs");
		varArgsCheckBox.addItemListener(e -> model.setHasVarArgs(varArgsCheckBox.isSelected()));
		panel.add(varArgsCheckBox);

		inLineCheckBox = new GCheckBox("In Line");
		panel.add(inLineCheckBox);
		inLineCheckBox.addItemListener(e -> model.setIsInLine(inLineCheckBox.isSelected()));
		inLineCheckBox.setEnabled(model.isInlineAllowed());

		noReturnCheckBox = new GCheckBox("No Return");
		noReturnCheckBox.addItemListener(e -> model.setNoReturn(noReturnCheckBox.isSelected()));
		storageCheckBox = new GCheckBox("Use Custom Storage");
		storageCheckBox
				.addItemListener(e -> model.setUseCustomizeStorage(storageCheckBox.isSelected()));
		panel.add(noReturnCheckBox);
		panel.add(storageCheckBox);
		panel.setBorder(BorderFactory.createTitledBorder("Function Attributes:"));

		return panel;
	}

	private JComponent createCallingConventionCombo() {
		List<String> callingConventionNames = model.getCallingConventionNames();
		String[] names = new String[callingConventionNames.size()];
		callingConventionComboBox = new GComboBox<>(callingConventionNames.toArray(names));
		callingConventionComboBox.setSelectedItem(model.getCallingConventionName());
		callingConventionComboBox.addItemListener(e -> model
				.setCallingConventionName((String) callingConventionComboBox.getSelectedItem()));
		return callingConventionComboBox;
	}

	private JComponent createCallFixupComboPanel() {

		JPanel panel = new JPanel();

		callFixupComboBox = new GComboBox<>();
		String[] callFixupNames = model.getCallFixupNames();

		callFixupComboBox.addItem(FunctionEditorModel.NONE_CHOICE);
		if (callFixupNames.length != 0) {
			callFixupComboBox
					.setToolTipText("Select call-fixup as defined by compiler specification");
			for (String element : callFixupNames) {
				callFixupComboBox.addItem(element);
			}
			callFixupComboBox.addItemListener(
				e -> model.setCallFixupChoice((String) callFixupComboBox.getSelectedItem()));
		}
		else {
			callFixupComboBox.setToolTipText("No call-fixups defined by compiler specification");
			callFixupComboBox.setEnabled(false);
		}

		panel.add(callFixupComboBox);
		return panel;
	}

	private Component buildTable() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(),
			"Function Return/Parameters"));

		paramTableModel = new ParameterTableModel(model);
		parameterTable = new ParameterTable(paramTableModel);
		selectionListener = e -> model.setSelectedParameterRows(parameterTable.getSelectedRows());

		JScrollPane tableScroll = new JScrollPane(parameterTable);
		panel.add(tableScroll, BorderLayout.CENTER);
		panel.add(buildButtonPanel(), BorderLayout.EAST);
		return panel;
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new VerticalLayout(5));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		addButton = new GButton(Icons.ADD_ICON);
		removeButton = new GButton(Icons.DELETE_ICON);
		upButton = new GButton(new GIcon("icon.up"));
		downButton = new GButton(new GIcon("icon.down"));
		addButton.setToolTipText("Add parameter");
		removeButton.setToolTipText("Delete selected parameters");
		upButton.setToolTipText("Move selected parameter up");
		downButton.setToolTipText("Move selected parameter down");

		addButton.addActionListener(e -> model.addParameter());
		removeButton.addActionListener(e -> model.removeParameters());
		upButton.addActionListener(e -> model.moveSelectedParameterUp());
		downButton.addActionListener(e -> model.moveSelectedParameterDown());

		panel.add(addButton);
		panel.add(removeButton);
		panel.add(new JSeparator());
		panel.add(upButton);
		panel.add(downButton);
		return panel;
	}

	private JComponent createNameField() {
		nameField = new JTextField();

		nameFieldDocumentListener = new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				model.setName(nameField.getText());
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				model.setName(nameField.getText());
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				model.setName(nameField.getText());

			}
		};
		nameField.getDocument().addDocumentListener(nameFieldDocumentListener);
		return nameField;
	}

	@Override
	public void dataChanged() {
		if (model.isInParsingMode()) {
			setGlassPane(glassPane);
			glassPane.setVisible(true);
			updateStatusText();
		}
		else {
			glassPane.setVisible(false);
			updateNameField();
			updateCallingConventionCombo();
			updatePreviewField();
			updageVarArgs();
			updateStatusText();
			updateInLineCheckbox();
			updateNoReturnCheckbox();
			updateCallFixupCombo();
			updateOkButton();
			updateParamTable();
			updateTableSelection();
			updateTableButtonEnablement();
			updateStorageEditingEnabled();
			updateOptionalParamCommit();
		}
	}

	private void updateOptionalParamCommit() {
		if (commitFullParamDetailsCheckBox != null) {
			commitFullParamDetailsCheckBox.setSelected(model.hasSignificantParameterChanges());
		}
	}

	private void updateStorageEditingEnabled() {
		boolean canCustomizeStorage = model.canUseCustomStorage();
		if (storageCheckBox.isSelected() != canCustomizeStorage) {
			storageCheckBox.setSelected(canCustomizeStorage);
		}
		paramTableModel.setAllowStorageEditing(canCustomizeStorage);
	}

	private void updateTableButtonEnablement() {
		removeButton.setEnabled(model.canRemoveParameters());
		upButton.setEnabled(model.canMoveParameterUp());
		downButton.setEnabled(model.canMoveParameterDown());
	}

	private void updateTableSelection() {
		int[] selectedRows = model.getSelectedParameterRows();

		if (!Arrays.equals(selectedRows, parameterTable.getSelectedRows())) {
			ListSelectionModel selectionModel = parameterTable.getSelectionModel();
			selectionModel.removeListSelectionListener(selectionListener);
			parameterTable.clearSelection();
			for (int i : selectedRows) {
				if (i < parameterTable.getRowCount()) {
					parameterTable.addRowSelectionInterval(i, i);
				}
			}
			parameterTable.scrollToSelectedRow();
			selectionModel.addListSelectionListener(selectionListener);
		}
	}

	private void updateParamTable() {
		List<ParamInfo> parameterList = model.getParameters();
		ListSelectionModel selectionModel = parameterTable.getSelectionModel();
		selectionModel.removeListSelectionListener(selectionListener);
		paramTableModel.setParameters(parameterList, model.getFormalReturnType(),
			model.getReturnStorage());
		selectionModel.addListSelectionListener(selectionListener);
	}

	private void updateCallFixupCombo() {
		String callFixupName = model.getCallFixupChoice();
		if (!callFixupComboBox.getSelectedItem().equals(callFixupName)) {
			callFixupComboBox.setSelectedItem(callFixupName);
			if (!callFixupComboBox.getSelectedItem().equals(callFixupName)) {
				setStatusText("Invalid Call-Fixup '" + callFixupName + "' will be removed!");
			}
		}
	}

	private void updateCallingConventionCombo() {
		String callingConventionName = model.getCallingConventionName();
		if (!callingConventionComboBox.getSelectedItem().equals(callingConventionName)) {
			callingConventionComboBox.setSelectedItem(callingConventionName);
			if (!callingConventionComboBox.getSelectedItem().equals(callingConventionName)) {
				setStatusText(
					"Invalid Callinging Convention '" + callingConventionName + "' ignored!");
			}
		}
	}

	private void updateInLineCheckbox() {
		boolean inLine = model.isInLine();
		if (inLineCheckBox.isSelected() != inLine) {
			inLineCheckBox.setSelected(inLine);
		}
	}

	private void updateNoReturnCheckbox() {
		boolean noReturn = model.isNoReturn();
		if (noReturnCheckBox.isSelected() != noReturn) {
			noReturnCheckBox.setSelected(noReturn);
		}
	}

	private void updateOkButton() {
		setOkEnabled(model.isValid() && model.hasChanges());
	}

	private void updateStatusText() {
		MessageType messageType = model.isValid() ? MessageType.WARNING : MessageType.ERROR;
		messageType = model.isInParsingMode() ? MessageType.INFO : messageType;
		setStatusText(model.getStatusText(), messageType);
	}

	private void updageVarArgs() {
		if (varArgsCheckBox.isSelected() != model.hasVarArgs()) {
			varArgsCheckBox.setSelected(model.hasVarArgs());
		}
	}

	private void updateNameField() {
		nameField.getDocument().removeDocumentListener(nameFieldDocumentListener);
		int caretPosition = nameField.getCaretPosition();
		String name = model.getName();
		nameField.setText(name);
		if (caretPosition < name.length()) {
			nameField.setCaretPosition(caretPosition);
		}
		nameField.getDocument().addDocumentListener(nameFieldDocumentListener);
	}

	private void updatePreviewField() {
		String preview = model.getFunctionSignatureTextFromModel();
		int caretPosition = signatureTextField.getCaretPosition();

		// don't cause undo/redo updates if the text has not changed
		String oldText = signatureTextField.getText();
		if (!preview.equals(oldText)) {
			signatureTextField.setText(preview);
		}

		if (!model.hasValidName()) {
			signatureTextField.setError(model.getFunctionNameStartPosition(),
				model.getNameString().length());
		}
		if (caretPosition < preview.length()) {
			signatureTextField.setCaretPosition(caretPosition);
		}
	}

	@Override
	public void tableRowsChanged() {
		TableCellEditor cellEditor = parameterTable.getCellEditor();
		if (cellEditor != null) {
			if (!cellEditor.stopCellEditing()) {
				cellEditor.cancelCellEditing();
			}
		}
	}

	private class ParameterDataTypeCellRenderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			super.getTableCellRendererComponent(data);

			Object value = data.getValue();
			JTable table = data.getTable();
			int row = data.getRowViewIndex();
			int column = data.getColumnViewIndex();
			boolean isSelected = data.isSelected();

			ParameterTableModel tableModel = (ParameterTableModel) table.getModel();

			DataType dataType = (DataType) value;
			Color color = isSelected ? table.getSelectionForeground() : table.getForeground();
			if (!tableModel.isCellEditable(row, column)) {
				color = getUneditableForegroundColor(isSelected);
			}
			if (dataType != null) {
				setText(dataType.getName());
				if (dataType.isNotYetDefined()) {
					color = getErrorForegroundColor(isSelected);
				}
				String toolTipText = ToolTipUtils.getToolTipText(dataType);
				String headerText = "<html><b>" +
					HTMLUtilities.friendlyEncodeHTML(dataType.getPathName()) + "</b><BR>";
				toolTipText = toolTipText.replace("<html>", headerText);
				setToolTipText(toolTipText);
			}
			else {
				setText("");
				setToolTipText(null);
			}
			setForeground(color);
			return this;
		}
	}

	private class ParameterTable extends GTable {

		private FocusListener focusListener = new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				Component component = e.getComponent();
				Component opposite = e.getOppositeComponent();
				if (opposite == null) {
					return; // this implies a non-Java app has taken focus
				}
				if (!SwingUtilities.isDescendingFrom(opposite, component)) {
					component.removeFocusListener(this);
					if (cellEditor != null) {
						cellEditor.stopCellEditing();
					}
				}
				else {
					// One of the editor's internal components has gotten focus.  Listen to that as
					// well to know when to stop the edit.
					opposite.removeFocusListener(this);
					opposite.addFocusListener(this);
				}
			}
		};

		ParameterTable(ParameterTableModel model) {
			super(model);
		}

		@Override
		public void setUI(TableUI ui) {
			super.setUI(ui);

			getSelectionModel().addListSelectionListener(selectionListener);
			// set the preferred viewport height smaller that the button panel, otherwise it is huge!
			setPreferredScrollableViewportSize(new Dimension(600, 100));
			setDefaultEditor(DataType.class, new ParameterDataTypeCellEditor(
				FunctionEditorDialog.this, service, model.getProgram().getDataTypeManager()));
			setDefaultRenderer(DataType.class, new ParameterDataTypeCellRenderer());
			setDefaultEditor(VariableStorage.class, new StorageTableCellEditor(model));
			setDefaultRenderer(VariableStorage.class, new VariableStorageCellRenderer());
			setDefaultRenderer(String.class, new VariableStringCellRenderer());
		}

		@Override
		public Component prepareEditor(TableCellEditor editor, int row, int column) {
			Component component = super.prepareEditor(editor, row, column);
			if (component != null && !"Storage".equals(getColumnName(column))) {
				component.removeFocusListener(focusListener);
				component.addFocusListener(focusListener);
			}
			return component;
		}

		@Override
		public boolean editCellAt(int row, int column, EventObject e) {

			if (row < 0 || row >= getRowCount() || column < 1 || column >= getColumnCount()) {
				return false;
			}

			boolean isEditable = super.editCellAt(row, column, e);
			if (!isEditable) {
				if ((e instanceof KeyEvent) ||
					(e instanceof MouseEvent && ((MouseEvent) e).getClickCount() == 2)) {
					FunctionVariableData rowData = paramTableModel.getRowObject(row);
					if (rowData.getStorage().isAutoStorage()) {
						setStatusText("Auto-parameters may not be modified");
					}
					else if (row == 0 && "Name".equals(getColumnName(column))) {
						setStatusText("Return name may not be modified");
					}
					else if ("Storage".equals(getColumnName(column))) {
						boolean blockVoidStorageEdit = (rowData.getIndex() == null) &&
							VoidDataType.isVoidDataType(rowData.getFormalDataType());
						if (!blockVoidStorageEdit) {
							setStatusText(
								"Enable 'Use Custom Storage' to allow editing of Parameter and Return Storage");
						}
						else {
							setStatusText("Void return storage may not be modified");
						}
					}
				}
			}
			return isEditable;
		}
	}

	private class VariableStorageCellRenderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			super.getTableCellRendererComponent(data);

			Object value = data.getValue();
			JTable table = data.getTable();
			int row = data.getRowViewIndex();
			boolean isSelected = data.isSelected();

			VariableStorage storage = (VariableStorage) value;
			if (storage != null) {
				ParameterTableModel tableModel = (ParameterTableModel) table.getModel();
				FunctionVariableData rowData = tableModel.getRowObject(row);
				boolean isInvalidStorage =
					!storage.isValid() || rowData.getFormalDataType().getLength() != storage.size();
				if (isInvalidStorage) {
					setForeground(getErrorForegroundColor(isSelected));
					setToolTipText("Invalid Parameter Storage");
				}
				else if (rowData.hasStorageConflict()) {
					setForeground(getErrorForegroundColor(isSelected));
					setToolTipText("Conflicting Parameter Storage");
				}
				else {
					setForeground(isSelected ? table.getSelectionForeground() : Colors.FOREGROUND);
					setToolTipText("");
				}
				setText(storage.toString());
			}
			else {
				setForeground(isSelected ? table.getSelectionForeground() : Colors.FOREGROUND);
				setText("");
				setToolTipText(null);
			}
			return this;
		}
	}

	private class VariableStringCellRenderer extends GTableCellRenderer {

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			super.getTableCellRendererComponent(data);

			Object value = data.getValue();
			JTable table = data.getTable();
			int row = data.getRowViewIndex();
			int column = data.getColumnViewIndex();
			boolean isSelected = data.isSelected();

			String name = (String) value;

			ParameterTableModel tableModel = (ParameterTableModel) table.getModel();
			if (!tableModel.isCellEditable(row, column)) {
				setForeground(getUneditableForegroundColor(isSelected));
			}
			else {
				if (isSelected) {
					setForeground(table.getSelectionForeground());
				}
				else {
					setForegroundColor(table, table.getModel(), value);
				}
			}
			setText(name);

			return this;
		}
	}

	private class VerticalScrollablePanel extends JPanel implements Scrollable {
		public VerticalScrollablePanel() {
			super(new BorderLayout());
		}

		@Override
		public Dimension getPreferredScrollableViewportSize() {
			return new Dimension(10, 74);
		}

		@Override
		public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return 10;
		}

		@Override
		public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return 10;
		}

		@Override
		public boolean getScrollableTracksViewportWidth() {
			return true;
		}

		@Override
		public boolean getScrollableTracksViewportHeight() {
			return false;
		}
	}

	private class MyGlassPane extends JComponent {

		MyGlassPane() {
			GlassPaneMouseListener listener = new GlassPaneMouseListener();
			addMouseListener(listener);
			addMouseMotionListener(listener);
			setVisible(true);
		}

		@Override
		protected void paintComponent(Graphics g) {
			Rectangle bounds = centerPanel.getBounds();

			Graphics2D g2d = (Graphics2D) g;
			AlphaComposite alphaComposite =
				AlphaComposite.getInstance(AlphaComposite.SrcOver.getRule(), (float) 0.4);
			Composite originalComposite = g2d.getComposite();
			g2d.setComposite(alphaComposite);

			g.setColor(Colors.BACKGROUND);
			g.fillRect(bounds.x, bounds.y, bounds.width, bounds.height);

			g2d.setComposite(originalComposite);
			super.paintComponent(g);
		}

	}

	private class GlassPaneMouseListener implements MouseListener, MouseMotionListener {

		private boolean armed = false;

		@Override
		public void mouseClicked(MouseEvent e) {
			processEvent(e);
		}

		@Override
		public void mousePressed(MouseEvent e) {
			processEvent(e);
			armed = !isTextField(e);
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			if (!armed) {
				return;
			}
			armed = false;

			if (!processEvent(e)) {
				try {
					model.parseSignatureFieldText();
				}
				catch (Exception ex) {
					handleParseException(ex);
				}
			}

		}

		@Override
		public void mouseEntered(MouseEvent e) {
			// stub
		}

		@Override
		public void mouseExited(MouseEvent e) {
			// stub
		}

		private boolean isTextField(MouseEvent e) {
			JDialog window = (JDialog) WindowUtilities.windowForComponent(e.getComponent());
			Component comp =
				SwingUtilities.getDeepestComponentAt(window.getContentPane(), e.getX(), e.getY());
			return comp == signatureTextField;
		}

		private boolean processEvent(MouseEvent e) {
			JDialog window = (JDialog) WindowUtilities.windowForComponent(e.getComponent());
			Component comp =
				SwingUtilities.getDeepestComponentAt(window.getContentPane(), e.getX(), e.getY());
			if (comp == signatureTextField || comp == cancelButton || comp == okButton) {
				MouseEvent convertedMouseEvent =
					SwingUtilities.convertMouseEvent(e.getComponent(), e, comp);
				comp.dispatchEvent(convertedMouseEvent);
				return true;
			}
			else if (comp == scroll.getViewport()) {
				return true;
			}
			return false;
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			processEvent(e);
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			processEvent(e);
		}
	}
}
