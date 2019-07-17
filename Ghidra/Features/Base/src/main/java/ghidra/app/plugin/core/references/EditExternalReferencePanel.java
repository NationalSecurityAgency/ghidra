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
package ghidra.app.plugin.core.references;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.*;
import java.util.Arrays;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;
import ghidra.app.util.AddressInput;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

class EditExternalReferencePanel extends EditReferencePanel {

	private ReferencesPlugin plugin;

	// Fields required for ADD
	private CodeUnit fromCodeUnit;
	private int opIndex;

	// Fields required for EDIT
	private ExternalReference editRef;

	private JButton clearButton;
	private JButton editButton;
	private GhidraComboBox<String> extLibName;
	private JTextField extLibPath;
	private JTextField extLabel;
	private AddressInput extAddr;

	private boolean isValidState;

	EditExternalReferencePanel(ReferencesPlugin plugin) {
		super("EXT");
		this.plugin = plugin;
		buildPanel();
	}

	private void buildPanel() {

		JPanel topPanel = new JPanel(new PairLayout(5, 10, 160));
		topPanel.setBorder(
			new CompoundBorder(new TitledBorder("External Program"), new EmptyBorder(0, 5, 5, 5)));

		topPanel.add(new GLabel("Name:", SwingConstants.RIGHT));
		extLibName = new GhidraComboBox<>();
		extLibName.setEditable(true);
		extLibName.addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				extProgNameChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				extProgNameChanged();
			}
		});
		extLibName.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				extProgNameChanged();
				updateExtLibPath();
			}
		});
		topPanel.add(extLibName);

		extLibPath = new JTextField();
		extLibPath.setBackground(getBackground());
		extLibPath.setEditable(false);
		extLibPath.setFocusable(false);

		clearButton = new JButton("Clear");
		clearButton.setToolTipText("Remove Link to External Program");
		clearButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				extLibPath.setText(null);
			}
		});

		editButton = new JButton("Edit");
		editButton.setToolTipText("Edit Link to External Program");
		editButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				popupProgramChooser();
			}
		});

		JPanel pathPanel = new JPanel(new BorderLayout());
		pathPanel.add(extLibPath, BorderLayout.CENTER);

		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
		buttonPanel.add(clearButton);
		buttonPanel.add(editButton);
		pathPanel.add(buttonPanel, BorderLayout.EAST);

		topPanel.add(new GLabel("Path:", SwingConstants.RIGHT));
		topPanel.add(pathPanel);

		JPanel bottomPanel = new JPanel(new PairLayout(10, 10, 160));
		bottomPanel.setBorder(new CompoundBorder(new TitledBorder("External Reference Data"),
			new EmptyBorder(0, 5, 5, 5)));

		bottomPanel.add(new GLabel("Label:", SwingConstants.RIGHT));
		extLabel = new JTextField();
		bottomPanel.add(extLabel);

		bottomPanel.add(new GLabel("Address:", SwingConstants.RIGHT));
		extAddr = new AddressInput();
		bottomPanel.add(extAddr);

		setLayout(new VerticalLayout(5));
		add(topPanel);
		add(bottomPanel);

	}

	private void extProgNameChanged() {
		boolean hasText = (extLibName.getText().trim().length() != 0);
		clearButton.setEnabled(hasText);
		editButton.setEnabled(hasText);
		extLibPath.setText(null);
	}

	private void populateExternalNames() {
		String[] names = fromCodeUnit.getProgram().getExternalManager().getExternalLibraryNames();
		extLibName.clearModel();
		extLibName.addItem(Library.UNKNOWN);
		Arrays.sort(names);
		for (int i = 0; i < names.length; i++) {
			if (Library.UNKNOWN.equals(extLibName)) {
				continue;
			}
			extLibName.addItem(names[i]);
		}
	}

	private void updateExtLibPath() {
		String name = extLibName.getText().trim();
		String path = null;
		if (name.length() != 0) {
			name = name.trim();
			path = fromCodeUnit.getProgram().getExternalManager().getExternalLibraryPath(name);
		}
		extLibPath.setText(path);
	}

	/**
	 * Pop up the data tree dialog so the user can choose the external program.
	 */
	private void popupProgramChooser() {
		DataTreeDialog d =
			new DataTreeDialog(this.getParent(), "Choose External Program", DataTreeDialog.OPEN);
		final DataTreeDialog dialog = d;
		d.addOkActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				DomainFile df = dialog.getDomainFile();
				if (df == null) {
					return;
				}
				String pathName = df.getPathname();
				if (pathName.equals(fromCodeUnit.getProgram().getDomainFile().getPathname())) {
					dialog.setStatusText("Selected program is the same as current program");
					return;
				}
				dialog.close();
				extLibPath.setText(df.getPathname());
			}
		});
		plugin.getTool().showDialog(d);
	}

	@Override
	public void initialize(CodeUnit fromCu, Reference ref) {
		isValidState = false;
		this.fromCodeUnit = fromCu;

		Program program = fromCu.getProgram();

		Address toAddr = ref.getToAddress();
		if (!toAddr.isExternalAddress()) {
			throw new IllegalArgumentException("Expected external reference");
		}
		this.editRef = (ExternalReference) ref;
		ExternalLocation extLoc = editRef.getExternalLocation();

		populateExternalNames();
		String name = extLoc.getLibraryName();
		extLibName.setSelectedItem(name);
		extProgNameChanged();

		updateExtLibPath();

		extLabel.setText(extLoc.getLabel());
		extAddr.setAddressFactory(program.getAddressFactory());
		Address addr = extLoc.getAddress();
		if (addr != null) {
			extAddr.setAddress(addr);
		}
		else {
			extAddr.clear();
		}

		extLibName.requestFocus();

		isValidState = true;
	}

	@Override
	public boolean initialize(CodeUnit fromCu, int fromOpIndex, int fromSubIndex) {
		isValidState = false;
		this.editRef = null;
		this.fromCodeUnit = fromCu;

		Program program = fromCu.getProgram();

		populateExternalNames();
		extLibName.setSelectedItem(Library.UNKNOWN);
		extProgNameChanged();

		extLibPath.setText(null);

		extLabel.setText(null);
		extAddr.setAddressFactory(program.getAddressFactory());
		extAddr.clear();

		extLibName.requestFocus();

		return setOpIndex(fromOpIndex);
	}

	@Override
	public boolean setOpIndex(int opIndex) {

		if (editRef != null) {
			throw new IllegalStateException("setOpIndex only permitted for ADD case");
		}

		isValidState = false;
		this.opIndex = opIndex;

		if (opIndex == EditReferencesProvider.MNEMONIC_OPINDEX) {
			return false;
		}

		isValidState = true;
		return true;
	}

	@Override
	public boolean applyReference() {
		if (!isValidState) {
			throw new IllegalStateException();
		}

		String name = extLibName.getText();
		if (name == null || name.trim().length() == 0) {
			showInputErr("An external program 'Name' must be specified.");
			return false;
		}
		name = name.trim();

		String libraryProgramPathname = extLibPath.getText();

		Address addr = extAddr.getAddress();
		String label = extLabel.getText();
		if (label != null) {
			label = label.trim();
		}
		if (addr == null && extAddr.hasInput()) {
			AddressSpace space = extAddr.getAddressSpace();
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

// FIXME The following needs to handle labels in external namespaces too.
		if (editRef != null) {
			return plugin.updateReference(editRef, fromCodeUnit, name, libraryProgramPathname, addr,
				label);
		}
		return plugin.addReference(fromCodeUnit, opIndex, name, libraryProgramPathname, addr,
			label);
	}

	@Override
	public void cleanup() {
		isValidState = false;
		fromCodeUnit = null;
		editRef = null;
	}

	@Override
	public boolean isValidContext() {
		return isValidState;
	}
}
