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
package ghidra.app.plugin.core.symboltree;

import java.awt.*;
import java.awt.event.ItemListener;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.app.util.AddressInput;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.*;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

/**
 * A panel for creating or editing an external location or external function.
 */
class EditExternalLocationPanel extends JPanel {

	private JButton clearButton;
	private JButton editButton;
	private GhidraComboBox<String> extLibNameComboBox;
	private JLabel extTypeLabel;
	private JTextField extLibPathTextField;
	private JTextField extLabelTextField;
	private AddressInput extAddressInputWidget;
	private JCheckBox functionCheckBox;

	private DocumentListener nameDocumentListener;
	private ItemListener nameItemListener;

	private boolean isValidState;

	private Program program;
	private ExternalLocation externalLocation; // Will be null if doing a Create instead of Edit.
	private String startingExternalLibraryName;
	private String autoDeterminedExternalLibraryPath;
	private String startingLocationName;
	private Address startingLocationAddress;

	private JTextField extOriginalLabelTextField;

	private String startingOriginalName;

	private JButton restoreButton;

	/**
	 * Edits an external location or external function.
	 * @param externalLocation the external location or external function being edited.
	 */
	EditExternalLocationPanel(ExternalLocation externalLocation) {
		program = externalLocation.getSymbol().getProgram();
		this.externalLocation = externalLocation;
		this.startingExternalLibraryName = externalLocation.getLibraryName();
		ExternalManager externalManager = program.getExternalManager();
		this.autoDeterminedExternalLibraryPath =
			externalManager.getExternalLibraryPath(startingExternalLibraryName);
		Symbol s = externalLocation.getSymbol();
		this.startingLocationName = NamespaceUtils.getNamespaceQualifiedName(s.getParentNamespace(),
			externalLocation.getLabel(), true);
		this.startingLocationAddress = externalLocation.getAddress();
		this.startingOriginalName = externalLocation.getOriginalImportedName();
		buildPanel();
		initialize();
	}

	/**
	 * Creates an external location or external function.
	 * @param program the program to which the new external location will be added
	 * @param externalLibraryName the name of the external library that the dialog should use
	 * by default.
	 */
	EditExternalLocationPanel(Program program, String externalLibraryName) {
		this.program = program;
		this.startingExternalLibraryName =
			externalLibraryName != null ? externalLibraryName : Library.UNKNOWN;
		ExternalManager externalManager = program.getExternalManager();
		this.autoDeterminedExternalLibraryPath =
			externalManager.getExternalLibraryPath(startingExternalLibraryName);
		buildPanel();
		initialize();
	}

	private void buildPanel() {

		JPanel topPanel = new JPanel(new PairLayout(5, 10, 160));
		topPanel.setBorder(
			new CompoundBorder(new TitledBorder("External Program"), new EmptyBorder(0, 5, 5, 5)));

		topPanel.add(new GLabel("Name:", SwingConstants.RIGHT));
		extLibNameComboBox = new GhidraComboBox<>();
		extLibNameComboBox.setEditable(true);
		nameDocumentListener = new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				// Do nothing.
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				extProgNameChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				extProgNameChanged();
			}
		};
		extLibNameComboBox.addDocumentListener(nameDocumentListener);
		nameItemListener = e -> {
			extProgNameChanged();
			updateExtLibPath();
		};
		extLibNameComboBox.addItemListener(nameItemListener);
		topPanel.add(extLibNameComboBox);

		extLibPathTextField = new JTextField();
		extLibPathTextField.setBackground(getBackground());
		extLibPathTextField.setEditable(false);
		extLibPathTextField.setFocusable(false);

		clearButton = new JButton("Clear");
		clearButton.setToolTipText("Remove Link to External Program");
		clearButton.addActionListener(e -> extLibPathTextField.setText(null));

		editButton = new JButton("Edit");
		editButton.setToolTipText("Edit Link to External Program");
		editButton.addActionListener(e -> popupProgramChooser());

		JPanel pathPanel = new JPanel(new BorderLayout());
		pathPanel.add(extLibPathTextField, BorderLayout.CENTER);

		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
		buttonPanel.add(clearButton);
		buttonPanel.add(editButton);
		pathPanel.add(buttonPanel, BorderLayout.EAST);

		topPanel.add(new GLabel("Path:", SwingConstants.RIGHT));
		topPanel.add(pathPanel);

		JPanel bottomPanel = new JPanel(new PairLayout(10, 10, 160));
		bottomPanel.setBorder(
			new CompoundBorder(new TitledBorder("External Location"), new EmptyBorder(0, 5, 5, 5)));

		bottomPanel.add(new GLabel("Type:", SwingConstants.RIGHT));

		extTypeLabel = new GDLabel("Function");
		bottomPanel.add(extTypeLabel);

		bottomPanel.add(new GDLabel("Label:", SwingConstants.RIGHT));
		extLabelTextField = new JTextField();
		bottomPanel.add(extLabelTextField);

		bottomPanel.add(new GLabel("Address:", SwingConstants.RIGHT));
		extAddressInputWidget = new AddressInput();
		bottomPanel.add(extAddressInputWidget);

		if (startingOriginalName != null) {
			bottomPanel.add(new GLabel("Original Label:", SwingConstants.RIGHT));
			bottomPanel.add(buildOriginalLableFieldAndRestoreButton());
		}

		setLayout(new VerticalLayout(5));
		add(topPanel);
		add(bottomPanel);

		if (externalLocation == null) {
			functionCheckBox = new GCheckBox("Make External Function");
			add(functionCheckBox);
		}
	}

	private Component buildOriginalLableFieldAndRestoreButton() {
		JPanel panel = new JPanel(new BorderLayout());
		extOriginalLabelTextField = new JTextField("Original");
		extOriginalLabelTextField.setEditable(false);
		panel.add(extOriginalLabelTextField, BorderLayout.CENTER);
		restoreButton = new JButton("Restore");
		restoreButton.addActionListener(e -> restoreOriginalName());
		panel.add(restoreButton, BorderLayout.EAST);
		return panel;
	}

	private void restoreOriginalName() {
		String originalName = extOriginalLabelTextField.getText().trim();
		if (originalName.length() > 0) {
			extLabelTextField.setText(originalName);
		}
	}

	private void extProgNameChanged() {
		boolean hasText = (extLibNameComboBox.getText().trim().length() != 0);
		clearButton.setEnabled(hasText);
		editButton.setEnabled(hasText);
		extLibPathTextField.setText(null);
	}

	private void populateExternalNames() {
		String[] names = program.getExternalManager().getExternalLibraryNames();
		extLibNameComboBox.clearModel();
		extLibNameComboBox.addItem(Library.UNKNOWN);
		Arrays.sort(names);
		for (String name : names) {
			if (Library.UNKNOWN.equals(name)) {
				continue;
			}
			extLibNameComboBox.addItem(name);
		}
	}

	private void updateExtLibPath() {
		SystemUtilities.runSwingNow(() -> {
			String name = extLibNameComboBox.getText().trim();
			if (Library.UNKNOWN.equals(name)) {
				extLibPathTextField.setText("");
				editButton.setEnabled(false);
				clearButton.setEnabled(false);
			}
			else {
				String path = null;
				if (name.length() != 0) {
					name = name.trim();
					ExternalManager externalManager = program.getExternalManager();
					path = externalManager.getExternalLibraryPath(name);
				}
				extLibPathTextField.setText(path);
				editButton.setEnabled(true);
				clearButton.setEnabled(true);
			}
		});
	}

	/**
	 * Pop up the data tree dialog so the user can choose the external program.
	 */
	private void popupProgramChooser() {
		DataTreeDialog d =
			new DataTreeDialog(this.getParent(), "Choose External Program", DataTreeDialog.OPEN);
		final DataTreeDialog dialog = d;
		d.addOkActionListener(e -> {
			DomainFile df = dialog.getDomainFile();
			if (df == null) {
				return;
			}
			String pathName = df.getPathname();
			if (pathName.equals(program.getDomainFile().getPathname())) {
				dialog.setStatusText("Selected program is the same as current program");
				return;
			}
			dialog.close();
			extLibPathTextField.setText(df.getPathname());
		});
		DockingWindowManager.showDialog(this, d);
	}

	private void initialize() {
		populateExternalNames();
		restoreLibraryName();

		extTypeLabel.setText(
			(externalLocation != null && externalLocation.isFunction()) ? "Function" : "Data");

		extLabelTextField.setText(startingLocationName);
		if (extOriginalLabelTextField != null) {
			extOriginalLabelTextField.setText(startingOriginalName);
		}
		extAddressInputWidget.setAddressFactory(program.getAddressFactory());
		if (startingLocationAddress != null) {
			extAddressInputWidget.setAddress(startingLocationAddress);
		}
		else {
			extAddressInputWidget.clear();
		}
		boolean isFunction = (externalLocation != null) ? externalLocation.isFunction() : false;
		if (externalLocation == null) {
			functionCheckBox.setSelected(isFunction);
		}

		extLibNameComboBox.requestFocus();

		isValidState = true;
	}

	private String getExtLibName() {
		String extLibName = null;
		if (extLibNameComboBox != null) {
			extLibName = extLibNameComboBox.getText();
			if (extLibName != null) {
				extLibName = extLibName.trim();
			}
		}
		return extLibName;
	}

	private String getExtLibPath() {
		String extLibPath = extLibPathTextField.getText();
		if (extLibPath != null) {
			extLibPath = extLibPath.trim();
		}
		return extLibPath;
	}

	private String getLocationName() {
		String locationName = extLabelTextField.getText();
		if (locationName != null) {
			locationName = locationName.trim();
		}
		return locationName;
	}

	private boolean validateChanges() {
		return validLibName() && validLibPath() && validLocation();
	}

	private boolean validLibName() {
		String extLibName = getExtLibName();
		if (extLibName == null || extLibName.length() == 0) {
			showInputErr("An external library 'Name' must be specified.");
			return false;
		}
		return true;
	}

	private boolean validLibPath() {
		String extLibPath = getExtLibPath();
		if (extLibPath != null && extLibPath.length() > 0 &&
			!SystemUtilities.isEqual(autoDeterminedExternalLibraryPath, extLibPath)) {

			Project project = AppInfo.getActiveProject();
			ProjectData projectData = project.getProjectData();
			DomainFile file = projectData.getFile(extLibPath);
			if (file == null) {
				showInputErr("Cannot find the program for the specified library 'Path' of " +
					extLibPath + ".");
				return false;
			}
		}
		return true;
	}

	private boolean validLocation() {

		String locationName = getLocationName();
		boolean hasLocationName = locationName != null && locationName.length() > 0;
		boolean hasLocationAddress = extAddressInputWidget.hasInput();
		if (!hasLocationName && !hasLocationAddress) {
			showInputErr(
				"Either (or both) an external 'Label' and/or 'Address' must be specified.");
			return false;
		}
		if (!validLocationName()) { // Empty is considered valid.
			return false;
		}
		if (!validLocationAddress()) { // Empty is considered valid.
			return false;
		}
		return true;
	}

	private boolean validLocationName() {
		// Will this generate a duplicate name conflict?
		String extLibName = getExtLibName();
		if (extLibName == null || extLibName.length() == 0) {
			return true; // Any name is considered valid until we have a external library for it.
		}
		String locationName = getLocationName();
		if (locationName != null && locationName.length() > 0) {
			ExternalManager externalManager = program.getExternalManager();
			List<ExternalLocation> externalLocations =
				externalManager.getExternalLocations(extLibName, locationName);
			externalLocations.remove(externalLocation);
			if (!externalLocations.isEmpty()) {
				int result = OptionDialog.showYesNoDialog(null, "Duplicate External Name",
					"Another symbol named '" + locationName + "' already exists in the '" +
						extLibName + "' library. Are you sure you want to create another?");
				if (result == OptionDialog.NO_OPTION) {
					selectLocationName();
					return false;
				}
			}
		}
		return true;
	}

	private boolean validLocationAddress() {

		AddressSpace locationAddressSpace = extAddressInputWidget.getAddressSpace();
		if (locationAddressSpace != null) {
			if (extAddressInputWidget.hasInput()) {
				Address locationAddress = extAddressInputWidget.getAddress();
				if (locationAddress == null) {
					showInputErr("Invalid address specified, " + locationAddressSpace.getName() +
						" offset must be in range: " +
						locationAddressSpace.getMinAddress().toString(false) + " to " +
						locationAddressSpace.getMaxAddress().toString(false));
					return false;
				}
			}
		}
		return true;
	}

	public boolean applyLocation() {
		if (!isValidState) {
			throw new IllegalStateException();
		}
		if (!validateChanges()) {
			return false;
		}

		String name = extLibNameComboBox.getText();
		if (name == null || name.trim().length() == 0) {
			showInputErr("An external program 'Name' must be specified.");
			return false;
		}
		name = name.trim();

		String libraryProgramPathname = extLibPathTextField.getText();

		Address addr = extAddressInputWidget.getAddress();
		String label = getLocationName();
		if (addr == null && extAddressInputWidget.hasInput()) {
			AddressSpace space = extAddressInputWidget.getAddressSpace();
			showInputErr("Invalid address specified, " + space.getName() +
				" offset must be in range: " + space.getMinAddress().toString(false) + " to " +
				space.getMaxAddress().toString(false));
			return false;
		}
		if (addr == null && (label == null || label.length() == 0)) {
			showInputErr(
				"Either (or both) an external 'Label' and/or 'Address' must be specified.");
			return false;
		}

		try {
			if (externalLocation != null) {
				updateExternalLocation(externalLocation, name, libraryProgramPathname, label, addr);
				return true;
			}

			ExternalLocation extLocation = addExternalLocation(externalLocation, name,
				libraryProgramPathname, label, addr, functionCheckBox.isSelected());
			return (extLocation != null);
		}
		catch (DuplicateNameException | InvalidInputException e) {
			showInputErr(e.getMessage());
		}
		return false;
	}

	private ExternalLocation addExternalLocation(ExternalLocation extLocation, String libraryName,
			String libraryProgramPathname, String label, Address addr, boolean shouldBeFunction)
			throws InvalidInputException, DuplicateNameException {
		int txId = program.startTransaction("Create External Location");
		boolean success = false;
		try {
			ExternalManager externalManager = program.getExternalManager();
			getOrCreateExternalLibrary(libraryName, libraryProgramPathname);

			// Create the location.
			extLocation =
				externalManager.addExtLocation(libraryName, label, addr, SourceType.USER_DEFINED);
			if (shouldBeFunction && !extLocation.isFunction()) {
				extLocation.createFunction();
			}
			success = true;
			return extLocation;
		}
		finally {
			program.endTransaction(txId, success);
		}
	}

	private void updateExternalLocation(ExternalLocation extLocation, String libraryName,
			String libraryProgramPathname, String label, Address addr)
			throws InvalidInputException, DuplicateNameException {
		int txId = program.startTransaction("Create External Location");
		boolean success = false;
		try {
			Library library = getOrCreateExternalLibrary(libraryName, libraryProgramPathname);

			// If the external location is not in the chosen library then move it.
			Symbol symbol = extLocation.getSymbol();
			Namespace parentNamespace = symbol.getParentNamespace();
			if (parentNamespace != library) {
				try {
					symbol.setNamespace(library);
				}
				catch (CircularDependencyException e) {
					throw new AssertException("Unexpected error", e);
				}
			}

			// Update the location.
			extLocation.setLocation(label, addr, SourceType.USER_DEFINED);

			success = true;
		}
		finally {
			program.endTransaction(txId, success);
		}
	}

	private void restoreLibraryName() {
		if (startingExternalLibraryName != null) {
			extLibNameComboBox.setSelectedItem(startingExternalLibraryName);
			ExternalManager externalManager = program.getExternalManager();
			this.autoDeterminedExternalLibraryPath =
				externalManager.getExternalLibraryPath(startingExternalLibraryName);
		}
		extProgNameChanged();
		updateExtLibPath();
	}

	private void selectLibraryName() {
		extLibNameComboBox.requestFocusInWindow();
		if (startingExternalLibraryName != null) {
			extLibNameComboBox.setSelectedItem(startingExternalLibraryName);
			ExternalManager externalManager = program.getExternalManager();
			this.autoDeterminedExternalLibraryPath =
				externalManager.getExternalLibraryPath(startingExternalLibraryName);
		}
	}

	private void selectLocationName() {
		extLabelTextField.requestFocusInWindow();
		extLabelTextField.selectAll();
	}

	private Library getOrCreateExternalLibrary(String libraryName, String libraryProgramPathname)
			throws InvalidInputException {
		if (libraryName == null) {
			return null;
		}
		ExternalManager externalManager = program.getExternalManager();
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol s = symbolTable.getLibrarySymbol(libraryName);
		Library library;
		if (s != null) {
			library = (Library) s.getObject();
		}
		else {
			try {
				library =
					externalManager.addExternalLibraryName(libraryName, SourceType.USER_DEFINED);
			}
			catch (DuplicateNameException e) {
				String message = e.getMessage();
				if (message == null) {
					message = "";
				}
				showInputErr("Couldn't create external library name. " + message);
				restoreLibraryName();
				selectLibraryName();
				return null;
			}
		}
		if (libraryProgramPathname != null && libraryProgramPathname.length() > 0) {
			externalManager.setExternalPath(libraryName, libraryProgramPathname, true);
		}
		return library;
	}

	/**
	 * Display input error
	 * @param error error message
	 */
	protected void showInputErr(String error) {
		Msg.showError(this, this, "Edit External Location Error", error);
	}

	void cleanup() {
		this.program = null;
		extLibNameComboBox.removeDocumentListener(nameDocumentListener);
		nameDocumentListener = null;
		extLibNameComboBox.removeItemListener(nameItemListener);
		nameItemListener = null;
		this.externalLocation = null;
		this.startingExternalLibraryName = null;
		this.startingLocationName = null;
		this.startingLocationAddress = null;
		this.autoDeterminedExternalLibraryPath = null;
	}

}
