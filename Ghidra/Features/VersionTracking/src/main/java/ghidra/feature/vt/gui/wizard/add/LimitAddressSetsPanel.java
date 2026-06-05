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
package ghidra.feature.vt.gui.wizard.add;

import java.awt.GridLayout;

import javax.swing.JPanel;

import ghidra.feature.vt.gui.wizard.add.AddToSessionData.AddressSetChoice;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/**
 * Panel for adjusting address sets for both the source and destination programs at the same time.
 * Used by the {@link LimitAddressSetsStep} of the "add to version tracking session wizard.
 */
public class LimitAddressSetsPanel extends JPanel {

	private ChooseAddressSetEditorPanel sourcePanel;
	private ChooseAddressSetEditorPanel destinationPanel;
	private PluginTool tool;

	public LimitAddressSetsPanel(PluginTool tool) {

		this.tool = tool;
		setLayout(new GridLayout());
	}

	public void initialize(AddToSessionData data) {
		removeAll();

		sourcePanel = buildSourcePanel(data);
		destinationPanel = buildDestinationPanel(data);

		add(sourcePanel);
		add(destinationPanel);
	}

	private ChooseAddressSetEditorPanel buildSourcePanel(AddToSessionData data) {
		Program program = data.getSourceProgram();
		AddressSetView selection = data.getSourceSelection();
		AddressSetView set = data.getCustomSourceAddressSet();
		AddressSetChoice choice = data.getSourceAddressSetChoice();
		return new ChooseAddressSetEditorPanel(tool, "Source", program, selection, set, choice);
	}

	private ChooseAddressSetEditorPanel buildDestinationPanel(AddToSessionData data) {
		Program program = data.getDestinationProgram();
		AddressSetView selection = data.getDestinationSelection();
		AddressSetView set = data.getCustomDestinationAddressSet();
		AddressSetChoice choice = data.getDestinationAddressSetChoice();
		return new ChooseAddressSetEditorPanel(tool, "Destination", program, selection, set,
			choice);
	}

	public void apply(AddToSessionData data) {
		AddressSetChoice sourceChoice = sourcePanel.getAddressSetChoice();
		AddressSetChoice destinationChoice = destinationPanel.getAddressSetChoice();
		data.setSourceAddressSetChoice(sourceChoice);
		data.setDestinationAddressSetChoice(destinationChoice);
		data.setCustomSourceAddressSet(null);
		data.setCustomDestinationAddressSet(null);
		if (sourceChoice == AddressSetChoice.MANUALLY_DEFINED) {
			data.setCustomSourceAddressSet(sourcePanel.getAddressSetView());
		}
		if (destinationChoice == AddressSetChoice.MANUALLY_DEFINED) {
			data.setCustomDestinationAddressSet(destinationPanel.getAddressSetView());
		}

	}
}
