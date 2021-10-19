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
package ghidra.app.util;

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.*;

import javax.swing.*;
import javax.swing.border.*;

import org.apache.commons.lang3.StringUtils;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.app.cmd.label.*;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.VerticalLayout;

/**
 * Dialog used to a label or to edit an existing label.
 */
public class AddEditDialog extends DialogComponentProvider {
	private static final int MAX_RETENTION = 10;
	private PluginTool tool;
	private TitledBorder nameBorder;
	private JComboBox<String> labelNameChoices;
	private JComboBox<NamespaceWrapper> namespaceChoices;
	private JCheckBox entryPointCheckBox;
	private JCheckBox primaryCheckBox;

	private List<String> recentLabels = new ArrayList<>();
	private Program program;
	private Symbol symbol;
	private Address addr;
	private JCheckBox pinnedCheckBox;

	public AddEditDialog(String title, PluginTool tool) {
		super(title, true, true, true, false);
		this.tool = tool;
		setHelpLocation(new HelpLocation(HelpTopics.LABEL, "AddEditDialog"));

		addWorkPanel(create());

		setFocusComponent(labelNameChoices);

		addOKButton();
		addCancelButton();

		setDefaultButton(okButton);
	}

	/**
	 * Invokes the dialog to add a new label in the given program at the given address
	 * @param address the address at which to add a new label
	 * @param prog the program in which to add a new label
	 */
	public void addLabel(Address address, Program prog) {
		addLabel(address, prog, tool.getActiveWindow());
	}

	/**
	 * Invokes the dialog to add a new label in the given program at the given address
	 * @param address the address at which to add a new label
	 * @param targetProgram the program in which to add a new label
	 * @param provider the ComponentProvider to parent and center the dialog over.
	 */
	public void addLabel(Address address, Program targetProgram, ComponentProvider provider) {
		initDialogForAdd(targetProgram, address);
		tool.showDialog(this, provider);
	}

	/**
	 * Invokes the dialog to add a new label in the given program at the given address
	 * @param address the address at which to add a new label
	 * @param targetProgram the program in which to add a new label
	 * @param centeredOverComponent the component over which to center the dialog
	 */
	public void addLabel(Address address, Program targetProgram, Component centeredOverComponent) {
		initDialogForAdd(targetProgram, address);
		tool.showDialog(this, centeredOverComponent);
	}

	/**
	 * Invokes the dialog to edit an existing label in the given program
	 * @param targetSymbol the symbol(label) to edit
	 * @param targetProgram the program containing the symbol
	 */
	public void editLabel(Symbol targetSymbol, Program targetProgram) {
		ComponentProvider componentProvider =
			tool.getComponentProvider(PluginConstants.CODE_BROWSER);
		JComponent component = componentProvider.getComponent();
		editLabel(targetSymbol, targetProgram, component);
	}

	/**
	 * Invokes the dialog to edit an existing label in the given program
	 * @param targetSymbol the symbol(label) to edit
	 * @param targetProgram the program containing the symbol
	 * @param centeredOverComponent the component over which to center the dialog
	 */
	public void editLabel(Symbol targetSymbol, Program targetProgram,
			Component centeredOverComponent) {
		initDialogForEdit(targetProgram, targetSymbol);
		tool.showDialog(this, centeredOverComponent);
	}

	/**
	 * Invokes the dialog to edit an existing label in the given program
	 * @param targetSymbol the symbol(label) to edit
	 * @param targetProgram the program containing the symbol
	 * @param provider the ComponentProvider to parent and center the dialog over.
	 */
	public void editLabel(Symbol targetSymbol, Program targetProgram, ComponentProvider provider) {
		initDialogForEdit(targetProgram, targetSymbol);
		tool.showDialog(this, provider);
	}

	@Override
	protected void okCallback() {

		String labelText = getText();
		Namespace namespace = getSelectedNamespace();
		SymbolPath symbolPath = getSymbolPath(labelText);
		if (symbolPath == null) {
			Swing.runLater(() -> checkForRemoveLabel());
			return;
		}

		String symbolName = symbolPath.getName();

		// see if the user specified a namespace path and if so, then get the
		// new namespace name from that path
		Namespace parent = getOrCreateNamespaces(symbolPath, namespace);
		if (parent == null) {
			return;
		}

		boolean isCurrentlyEntryPoint = false;
		boolean isCurrentlyPinned = false;
		CompoundCmd cmd = new CompoundCmd(symbol == null ? "Add Label" : "Edit Label");
		if (symbol == null) {
			cmd.add(new AddLabelCmd(addr, symbolName, parent, SourceType.USER_DEFINED));
		}
		else {
			cmd.add(new RenameLabelCmd(addr, symbol.getName(), symbolName,
				symbol.getParentNamespace(), parent, SourceType.USER_DEFINED));
			isCurrentlyEntryPoint = symbol.isExternalEntryPoint();
			isCurrentlyPinned = symbol.isPinned();
		}

		if (primaryCheckBox.isEnabled() && primaryCheckBox.isSelected()) {
			cmd.add(new SetLabelPrimaryCmd(addr, symbolName, parent));
		}
		if (entryPointCheckBox.isEnabled() &&
			entryPointCheckBox.isSelected() != isCurrentlyEntryPoint) {
			cmd.add(new ExternalEntryCmd(addr, !isCurrentlyEntryPoint));
		}
		if (pinnedCheckBox.isEnabled() && pinnedCheckBox.isSelected() != isCurrentlyPinned) {
			cmd.add(new PinSymbolCmd(addr, symbolName, !isCurrentlyPinned));
		}

		if (cmd.size() > 0) {

			if (!tool.execute(cmd, program)) {
				setStatusText(cmd.getStatusMsg());
				return;
			}
			updateRecentLabels(symbolName);
		}
		program = null;
		close();
	}

	private void checkForRemoveLabel() {

		if (!isEditing()) {
			return; // adding a label; cannot delete existing label
		}

		if (isDefaultLabel()) {
			return; // label is already default; cannot be removed
		}

		if (isExternalLabel()) {
			return; // cannot remove external labels
		}

		int choice = OptionDialog.showYesNoDialog(getParent(), "Remove Label?",
			"You have removed the label text--would you like to remove the existing label?");
		if (choice == OptionDialog.YES_OPTION) {

			Command cmd = new DeleteLabelCmd(addr, symbol.getName(), symbol.getParentNamespace());
			if (!tool.execute(cmd, program)) {
				setStatusText(cmd.getStatusMsg());
			}
			else {
				close();
			}
		}
	}

	private boolean isExternalLabel() {
		return symbol != null && symbol.isExternal();
	}

	private boolean isDefaultLabel() {
		return symbol != null && symbol.getSource() == SourceType.DEFAULT;
	}

	private boolean isEditing() {
		return symbol != null; // always have a symbol when editing
	}

	private SymbolPath getSymbolPath(String symbolName) {

		if (StringUtils.isBlank(symbolName)) {
			setStatusText("Name cannot be blank");
			return null;
		}

		return new SymbolPath(symbolName);
	}

	private Namespace getSelectedNamespace() {
		Object selectedItem = namespaceChoices.getSelectedItem();
		if (selectedItem == null) {
			return null;
		}
		return ((NamespaceWrapper) selectedItem).getNamespace();
	}

	private Namespace getOrCreateNamespaces(SymbolPath symbolPath, Namespace rootNamespace) {
		SymbolPath parentPath = symbolPath.getParent();
		if (parentPath == null) {
			return rootNamespace;
		}

		//
		// Prefer a non-function namespace.  This allows us to put a function inside of a namespace
		// sharing the same name.
		//
		SymbolPath fullPath = new SymbolPath(rootNamespace.getSymbol()).append(parentPath);
		Namespace nonFunctionNs = NamespaceUtils.getNonFunctionNamespace(program, fullPath);
		if (nonFunctionNs != null) {
			return nonFunctionNs;
		}

		//
		// At this point we can either reuse an existing function namespace or we have to create
		// a new non-function namespaces, depending upon the names being used.  Only use an
		// existing function as a namespace if none of namespace path entries match the function
		// name.
		//
		String name = symbolPath.getName();
		if (!parentPath.containsPathEntry(name)) {
			Namespace functionNamespace =
				NamespaceUtils.getFunctionNamespaceContaining(program, parentPath, addr);
			if (functionNamespace != null) {
				return functionNamespace;
			}
		}

		CreateNamespacesCmd cmd =
			new CreateNamespacesCmd(parentPath.getPath(), rootNamespace, SourceType.USER_DEFINED);
		if (tool.execute(cmd, program)) {
			return cmd.getNamespace();
		}

		setStatusText(cmd.getStatusMsg());
		return null;
	}

	private void initRecentChoices() {
		labelNameChoices.removeAllItems();
		Iterator<String> it = recentLabels.iterator();
		while (it.hasNext()) {
			labelNameChoices.addItem(it.next());
		}
		if (recentLabels.size() > 0) {
			labelNameChoices.setSelectedIndex(-1);
		}
	}

// This method only gets the namespace associated with the current address
// and it's tree of namespaces.  It does not walk the namespace tree of
// the symbol, which can be different than that of the address.
	private void initNamespaces() {
		namespaceChoices.removeAllItems();

		if (!namespaceChoices.isEnabled()) {
			namespaceChoices.addItem(new NamespaceWrapper(symbol.getParentNamespace()));
			selectNamespace();
			return;
		}

		Collection<NamespaceWrapper> collection = new HashSet<>();

		// we always add the global namespace
		Namespace globalNamespace = program.getGlobalNamespace();

		NamespaceWrapper composite = new NamespaceWrapper(globalNamespace);
		namespaceChoices.addItem(composite);
		collection.add(composite);

		Namespace currentNamespace = program.getSymbolTable().getNamespace(addr);

		// no symbol or not editing a function symbol
		if ((symbol == null) ||
			(symbol != null && symbol.getSymbolType() != SymbolType.FUNCTION)) {
			// walk the tree of namespaces and collect all of the items
			for (; (currentNamespace != globalNamespace); currentNamespace =
				currentNamespace.getParentNamespace()) {
				composite = new NamespaceWrapper(currentNamespace);

				if (!collection.contains(composite)) {
					collection.add(composite);
					namespaceChoices.addItem(composite);
				}
			}
		}

		if (symbol != null) {
			// we are adding the current namespace of the symbol if it is not in
			// the namespace tree that belongs to the address
			Namespace symbolNamespace = symbol.getParentNamespace();
			composite = new NamespaceWrapper(symbolNamespace);
			if (!collection.contains(composite)) {
				collection.add(composite);
				namespaceChoices.insertItemAt(composite, 1);
			}
		}

		selectNamespace();
	}

	/**
	 * Assumptions:
	 * <ul>
	 *  <li>New label in functions should default to local namespace.
	 *  <li>Editing a default label in a function should default to the local namespace.
	 *  <li>Function symbols user their parent namespace.
	 * </ul>
	 */
	private void selectNamespace() {
		if (symbol != null && symbol.getParentNamespace() != null) {
			namespaceChoices
					.setSelectedItem(new NamespaceWrapper(symbol.getParentNamespace()));
			return;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace localNamespace = symbolTable.getNamespace(addr);
		FunctionSymbol functionSymbol = getFunctionSymbol(addr);

		// functions and labels in functions will use the local namespace
		if (functionSymbol != null) {
			if (symbol != null && symbol.equals(functionSymbol)) {
				namespaceChoices.setSelectedItem(
					new NamespaceWrapper(functionSymbol.getParentNamespace()));
			}
			else if (functionSymbol.getSource() == SourceType.DEFAULT) {
				namespaceChoices.setSelectedItem(
					new NamespaceWrapper(functionSymbol.getParentNamespace()));
			}
			else { // there is a function at the current address
				namespaceChoices.setSelectedItem(new NamespaceWrapper(localNamespace));
			}
		}
		else {
			// are we in a function?
			FunctionManager functionManager = program.getFunctionManager();
			Function function = functionManager.getFunctionContaining(addr);
			if (function != null) {
				namespaceChoices.setSelectedItem(new NamespaceWrapper(localNamespace));
			}
			else { // not in a function
				if (symbol != null) { // editing a label
					namespaceChoices.setSelectedItem(
						new NamespaceWrapper(symbol.getParentNamespace()));
				}
				else {
					// use the global namespace and *not* the lowest-level namespace
					namespaceChoices.setSelectedIndex(0);
				}
			}
		}
	}

	private FunctionSymbol getFunctionSymbol(Address address) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol primary = symbolTable.getPrimarySymbol(address);
		if (primary instanceof FunctionSymbol) {
			return (FunctionSymbol) primary;
		}
		return null;
	}

	private void initDialogForAdd(Program p, Address address) {
		if (!address.isMemoryAddress()) {
			throw new IllegalArgumentException(
				"AddEditDialog.addLabel only valid for memory address");
		}

		this.addr = address;
		this.program = p;
		SymbolTable symbolTable = p.getSymbolTable();
		symbol = null;
		setTitle("Add Label at " + address);
		initRecentChoices();
		entryPointCheckBox.setEnabled(true);
		entryPointCheckBox.setSelected(symbolTable.isExternalEntryPoint(address));
		pinnedCheckBox.setEnabled(true);
		pinnedCheckBox.setSelected(false);

		Symbol primarySymbol = symbolTable.getPrimarySymbol(address);
		if (primarySymbol == null) {
			primaryCheckBox.setSelected(true);
			primaryCheckBox.setEnabled(false);
		}
		else {
			primaryCheckBox.setSelected(false);
			primaryCheckBox.setEnabled(true);
		}

		namespaceChoices.setEnabled(true);
		initNamespaces();
		clearStatusText();

	}

	private void initDialogForEdit(Program p, Symbol s) {
		this.symbol = s;
		this.program = p;
		this.addr = s.getAddress();
		SymbolTable symbolTable = program.getSymbolTable();

		initRecentChoices();
		labelNameChoices.setSelectedItem(symbol.getName());
		if (s.getSymbolType() == SymbolType.FUNCTION) {
			String title;
			if (s.isExternal()) {
				ExternalLocation extLoc =
					program.getExternalManager().getExternalLocation(s);
				Address fnAddr = extLoc.getAddress();
				title = "Rename External Function";
				if (fnAddr != null) {
					title += " at " + fnAddr;
				}
			}
			else {
				title = "Rename Function at " + addr;
			}
			setTitle(title);
			nameBorder.setTitle("Enter Name:");
			entryPointCheckBox.setEnabled(true);
			entryPointCheckBox.setSelected(symbolTable.isExternalEntryPoint(addr));
			primaryCheckBox.setSelected(true);
			primaryCheckBox.setEnabled(false);
			pinnedCheckBox.setEnabled(true);
			pinnedCheckBox.setSelected(s.isPinned());
			namespaceChoices.setEnabled(true);
		}
		else if (addr.isVariableAddress()) {
			String type =
				s.getSymbolType() == SymbolType.PARAMETER ? "Parameter" : "Local Variable";
			setTitle("Rename " + type + ": " + symbol.getName());
			nameBorder.setTitle("Enter Name:");
			entryPointCheckBox.setEnabled(false);
			entryPointCheckBox.setSelected(false);
			pinnedCheckBox.setEnabled(false);
			pinnedCheckBox.setSelected(false);
			primaryCheckBox.setSelected(true);
			primaryCheckBox.setEnabled(false);
			namespaceChoices.setEnabled(false);
		}
		else {
			setTitle("Edit Label at " + addr);
			nameBorder.setTitle("Enter Label:");
			entryPointCheckBox.setEnabled(true);
			entryPointCheckBox.setSelected(symbolTable.isExternalEntryPoint(addr));
			primaryCheckBox.setSelected(s.isPrimary());
			primaryCheckBox.setEnabled(!s.isPrimary());
			pinnedCheckBox.setEnabled(true);
			pinnedCheckBox.setSelected(s.isPinned());
			namespaceChoices.setEnabled(true);
		}
		initNamespaces();
		clearStatusText();

	}

	/**
	 * Define the Main panel for the dialog here.
	 */
	private JPanel create() {
		labelNameChoices = new GhidraComboBox<>();
		GhidraComboBox<NamespaceWrapper> comboBox = new GhidraComboBox<>();
		comboBox.setEnterKeyForwarding(true);
		namespaceChoices = comboBox;

		primaryCheckBox = new GCheckBox("Primary");
		primaryCheckBox.setMnemonic('P');
		primaryCheckBox.setToolTipText(
			"Make this label be the one that shows up in references to this location.");
		entryPointCheckBox = new GCheckBox("Entry Point  ");
		entryPointCheckBox.setMnemonic('E');
		entryPointCheckBox.setToolTipText("Mark this location as an external entry point.");
		pinnedCheckBox = new GCheckBox("Pinned");
		pinnedCheckBox.setMnemonic('A');
		pinnedCheckBox.setToolTipText(
			"Do not allow this label to move when the image base changes or a memory block is moved.");

		labelNameChoices.setEditable(true);

		JPanel mainPanel = new JPanel(new VerticalLayout(4));
		JPanel topPanel = new JPanel(new BorderLayout());
		JPanel midPanel = new JPanel(new BorderLayout());
		JPanel bottomPanel = new JPanel();

		nameBorder =
			BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Enter Label");
		topPanel.setBorder(nameBorder);
		Border border =
			BorderFactory.createTitledBorder(BorderFactory.createEmptyBorder(), "Namespace");
		midPanel.setBorder(border);
		border = BorderFactory.createEmptyBorder(5, 0, 0, 5);
		bottomPanel.setBorder(border);

		mainPanel.add(topPanel);
		mainPanel.add(midPanel);
		mainPanel.add(bottomPanel);

		topPanel.add(labelNameChoices, BorderLayout.NORTH);
		midPanel.add(namespaceChoices, BorderLayout.NORTH);
		bottomPanel.add(entryPointCheckBox);
		bottomPanel.add(primaryCheckBox);
		bottomPanel.add(pinnedCheckBox);
		bottomPanel.setBorder(BorderFactory.createTitledBorder("Properties"));
		addListeners();

		mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

		return mainPanel;
	}

	private void addListeners() {
		labelNameChoices.addActionListener(e -> {
			if (program != null) {
				okCallback();
			}
		});
	}

	private void updateRecentLabels(String label) {
		if (!recentLabels.contains(label)) {
			recentLabels.add(0, label);
			int size = recentLabels.size();
			if (size > MAX_RETENTION) {
				recentLabels.remove(size - 1);
			}
		}
	}

	private String getText() {
		Component comp = labelNameChoices.getEditor().getEditorComponent();
		if (comp instanceof JTextField) {
			JTextField textField = (JTextField) comp;
			return textField.getText().trim();
		}
		throw new AssertException("Using an uneditable JComboBox - this class must be updated.");
	}

	public class NamespaceWrapper {
		private Namespace namespace;

		public NamespaceWrapper(Namespace namespace) {
			this.namespace = namespace;
		}

		public Namespace getNamespace() {
			return namespace;
		}

		@Override
		public String toString() {
			return namespace.getName(true);
		}

		@Override
		public boolean equals(Object object) {
			if (object == this) {
				return true;
			}
			if (object == null) {
				return false;
			}
			if (object.getClass() == getClass()) {
				NamespaceWrapper w = (NamespaceWrapper) object;
				return namespace.equals(w.namespace);
			}
			return false;
		}

		@Override
		public int hashCode() {
			return namespace.hashCode();
		}
	}
}
