/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.wizard;

import ghidra.feature.vt.gui.wizard.ChooseAddressSetEditorPanel.AddressSetChoice;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

import java.awt.BorderLayout;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.wizard.*;

public class AddressSetPanel extends AbstractMageJPanel<VTWizardStateKey> {

	private final PluginTool tool;
	private final String name;
	private final VTWizardStateKey programDependencyKey;
	private final VTWizardStateKey addressSetViewKey;
	private final VTWizardStateKey selectionKey;
	private final VTWizardStateKey addressSetChoiceKey;
	private ChooseAddressSetEditorPanel panel;
	private Program program;

	public AddressSetPanel(PluginTool tool, String name, VTWizardStateKey programFileDependencyKey,
			VTWizardStateKey programDependencyKey, VTWizardStateKey addressSetViewKey,
			VTWizardStateKey selectionKey, VTWizardStateKey addressSetChoiceKey) {
		this.tool = tool;
		this.name = name;
		this.programDependencyKey = programDependencyKey;
		this.addressSetViewKey = addressSetViewKey;
		this.selectionKey = selectionKey;
		this.addressSetChoiceKey = addressSetChoiceKey;
		setLayout(new BorderLayout());
	}

	@Override
	public void addDependencies(WizardState<VTWizardStateKey> state) {
		// no dependencies
	}

	@Override
	public void dispose() {
		// nothing to do
	}

	// Keep this method for now in case we want it as the default for the entire program address set
	// instead of the program's memory address set.
	@SuppressWarnings("unused")
	private AddressSet getAddressFactoryAddressSet(WizardState<VTWizardStateKey> state) {
		Program programFromState = (Program) state.get(programDependencyKey);
		AddressFactory factory = programFromState.getAddressFactory();
		AddressSet everything = new AddressSet();
		AddressSpace[] addressSpaces = factory.getAddressSpaces();
		for (AddressSpace addressSpace : addressSpaces) {
			Address minAddress = addressSpace.getMinAddress();
			Address maxAddress = addressSpace.getMaxAddress();
			AddressRangeImpl range = new AddressRangeImpl(minAddress, maxAddress);
			everything.add(range);
		}
		return everything;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("VersionTrackingPlugin", "Address_Set_Panel");
	}

	@Override
	public void enterPanel(WizardState<VTWizardStateKey> state) {
		if (panel != null) {
			remove(panel);
		}
		program = (Program) state.get(programDependencyKey);
		AddressSetView addressSetView = (AddressSetView) state.get(addressSetViewKey);
		AddressSetView selection = (AddressSetView) state.get(selectionKey);
		AddressSetChoice addressSetChoice = (AddressSetChoice) state.get(addressSetChoiceKey);
		if (addressSetChoice == null) {
			if (selection != null && !selection.isEmpty()) {
				addressSetChoice = AddressSetChoice.SELECTION;
			}
			else {
				addressSetChoice = AddressSetChoice.ENTIRE_PROGRAM;
			}
		}
		panel =
			new ChooseAddressSetEditorPanel(tool, name, program, selection, addressSetView,
				addressSetChoice);
		panel.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				notifyListenersOfValidityChanged();
			}
		});
		add(panel, BorderLayout.CENTER);
	}

	@Override
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(
			WizardState<VTWizardStateKey> state) {
		Boolean value = (Boolean) state.get(VTWizardStateKey.SHOW_ADDRESS_SET_PANELS);
		boolean showPanel = value == null ? false : value.booleanValue();
		if (!showPanel) {
			return WizardPanelDisplayability.DO_NOT_DISPLAY;
		}
		return WizardPanelDisplayability.CAN_BE_DISPLAYED;
	}

	@Override
	public void leavePanel(WizardState<VTWizardStateKey> state) {
		updateStateObjectWithPanelInfo(state);
	}

	@Override
	public void updateStateObjectWithPanelInfo(WizardState<VTWizardStateKey> state) {
		AddressSetView addressSetView = panel.getAddressSetView();
		state.put(addressSetViewKey, addressSetView);
		state.put(addressSetChoiceKey, panel.getAddressSetChoice());
	}

	@Override
	public String getTitle() {
		return "Select " + name + " Address Range(s)";
	}

	@Override
	public void initialize() {
		// not sure if we need this
	}

	@Override
	public boolean isValidInformation() {
		boolean empty = panel.getAddressSetView().isEmpty();
		String msg = empty ? "At least one address range is required" : "";
		notifyListenersOfStatusMessage(msg);
		return !empty;
	}
}
