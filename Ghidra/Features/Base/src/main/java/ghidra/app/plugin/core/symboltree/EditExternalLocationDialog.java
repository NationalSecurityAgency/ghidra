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

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;

import docking.DialogComponentProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;

/**
 * Dialog for creating or editing an external location or external function.
 */
public class EditExternalLocationDialog extends DialogComponentProvider {

	static final int PREFERRED_CREATE_PANEL_HEIGHT = 240;
	static final int PREFERRED_EDIT_PANEL_HEIGHT = 220;
	static final int PREFERRED_PANEL_WIDTH = 450;

	private static final HelpLocation CREATE_HELP =
		new HelpLocation("SymbolTreePlugin", "createExternalLocation");
	private static final HelpLocation EDIT_HELP =
		new HelpLocation("SymbolTreePlugin", "editExternalLocation");

	private EditExternalLocationPanel extLocPanel;

	private Program program;
	private ExternalLocation externalLocation;
	private String externalLibraryName;
	private String locationName;
	private Address address;

	/**
	 * Creates a dialog for editing an external location or external function. The external
	 * location must have a location name, or address, or both.
	 * @param externalLocation the external location or external function being edited.
	 */
	public EditExternalLocationDialog(ExternalLocation externalLocation) {
		super("Edit External Location", true);
		this.externalLocation = externalLocation;
		this.program = externalLocation.getSymbol().getProgram();
		setRememberSize(false);

		addWorkPanel(buildMainPanel());
		addApplyButton();
		addCancelButton();

		initDialog();
		setDefaultButton(applyButton);
	}

	/**
	 * Creates a dialog for creating or editing an external location or external function.
	 * @param program the program to which the new external location will be added
	 * @param externalLibraryName the name of the external library the dialog should default 
	 * to when creating the location.
	 */
	public EditExternalLocationDialog(Program program, String externalLibraryName) {
		super("Create External Location", true);
		this.program = program;
		this.externalLibraryName = externalLibraryName;
		setRememberSize(false);

		addWorkPanel(buildMainPanel());
		addApplyButton();
		addCancelButton();

		initDialog();
		setDefaultButton(applyButton);
	}

	/**
	 * Dispose of this dialog.
	 */
	public void dispose() {
		close();
		cleanup();
	}

	private void cleanup() {
		extLocPanel.cleanup();
	}

	private JComponent buildMainPanel() {

		Border panelBorder = new EmptyBorder(5, 10, 5, 10);
		if (externalLocation != null) {
			extLocPanel = new EditExternalLocationPanel(externalLocation); // Edit
		}
		else {
			extLocPanel = new EditExternalLocationPanel(program, externalLibraryName); // Create
		}
		extLocPanel.setBorder(panelBorder);
		int panelHeight = (externalLocation != null) ? PREFERRED_EDIT_PANEL_HEIGHT
				: PREFERRED_CREATE_PANEL_HEIGHT;
		extLocPanel.setPreferredSize(new Dimension(PREFERRED_PANEL_WIDTH, panelHeight));

		JPanel workPanel = new JPanel(new BorderLayout());
		workPanel.add(extLocPanel, BorderLayout.CENTER);

		return workPanel;
	}

	void initDialog() {

		if (externalLocation != null) {
			// Edit location
			setTitle("Edit External Location" + " (" + getEditName() + ")");
			setHelpLocation(EDIT_HELP);

			applyButton.setText("Update");

		}
		else {
			// Create location
			setTitle("Create External Location");
			setHelpLocation(CREATE_HELP);

			applyButton.setText("Create");
		}
	}

	private String getEditName() {
		if (externalLocation != null) {
			Symbol symbol = externalLocation.getSymbol();
			String name = symbol.getName(true);
			Address addr = externalLocation.getAddress();
			if (addr != null) {
				name += " @ " + addr.toString(true);
			}
			return name;
		}
		String editName;
		editName = externalLocation.getSymbol().getParentNamespace().getName(true);
		boolean hasName = locationName != null && locationName.length() > 0;
		if (hasName) {
			editName += "::" + locationName;
		}
		if (address != null) {
			editName += " @ " + address.toString();
		}
		return editName;
	}

	@Override
	protected void applyCallback() {
		if (extLocPanel.applyLocation()) {
			close();
			cleanup();
		}
	}

	@Override
	protected void cancelCallback() {
		close();
		cleanup();
	}

}
