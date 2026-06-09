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

import java.util.*;

import ghidra.feature.vt.api.main.VTProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

/**
 * Wizard data used by the {@link VTAddToSessionWizardModel}  and its steps for the "add to version
 * tracking session" wizard.
 */
public class AddToSessionData {
	public static enum AddressSetChoice {
		ENTIRE_PROGRAM, SELECTION, MANUALLY_DEFINED
	}

	private Program sourceProgram;
	private Program destinationProgram;
	private VTSession session;
	private AddressSetView customSourceAddressSet;
	private AddressSetView customDestinationAddressSet;
	private AddressSetView sourceSelection;
	private AddressSetView destinationSelection;
	private List<VTProgramCorrelatorFactory> correlators;
	private Map<VTProgramCorrelatorFactory, VTOptions> optionsMap = new HashMap<>();
	private boolean shouldExcludeAcceptedMatches;
	private boolean shouldLimitAddressSets;
	private AddressSetChoice sourceAddressSetChoice = AddressSetChoice.ENTIRE_PROGRAM;
	private AddressSetChoice destinationAddressSetChoice = AddressSetChoice.ENTIRE_PROGRAM;

	public void setSourceProgram(Program sourceProgram) {
		this.sourceProgram = sourceProgram;
	}

	public Program getSourceProgram() {
		return sourceProgram;
	}

	public void setDestinationProgram(Program destinationProgram) {
		this.destinationProgram = destinationProgram;
	}

	public Program getDestinationProgram() {
		return destinationProgram;
	}

	public void setSession(VTSession session) {
		this.session = session;
	}

	public VTSession getSession() {
		return session;
	}

	public DomainFile getSourceFile() {
		return sourceProgram.getDomainFile();
	}

	public DomainFile getDestinationFile() {
		return destinationProgram.getDomainFile();
	}

	public AddressSetChoice getSourceAddressSetChoice() {
		return sourceAddressSetChoice;
	}

	public AddressSetChoice getDestinationAddressSetChoice() {
		return destinationAddressSetChoice;
	}

	public void setSourceAddressSetChoice(AddressSetChoice choice) {
		this.sourceAddressSetChoice = choice;
	}

	public void setDestinationAddressSetChoice(AddressSetChoice choice) {
		this.destinationAddressSetChoice = choice;
	}

	public void setSourceSelection(AddressSetView addressSet) {
		this.sourceSelection = addressSet;
		// if a source selection is set, the limit option defaults to true;
		if (addressSet != null && !addressSet.isEmpty()) {
			shouldLimitAddressSets = true;
			sourceAddressSetChoice = AddressSetChoice.SELECTION;
		}
	}

	public void setDestinationSelection(AddressSetView addresseSet) {
		this.destinationSelection = addresseSet;
		// if a destination selection is set, the limit option defaults to true;
		if (addresseSet != null && !addresseSet.isEmpty()) {
			shouldLimitAddressSets = true;
			destinationAddressSetChoice = AddressSetChoice.SELECTION;
		}
	}

	public AddressSetView getCustomSourceAddressSet() {
		return customSourceAddressSet;
	}

	public void setCustomSourceAddressSet(AddressSetView addressSet) {
		customSourceAddressSet = addressSet;
	}

	public void setCustomDestinationAddressSet(AddressSetView addressSet) {
		customDestinationAddressSet = addressSet;
	}

	public AddressSetView getCustomDestinationAddressSet() {
		return customDestinationAddressSet;
	}

	public AddressSetView getSourceSelection() {
		return sourceSelection;
	}

	public AddressSetView getDestinationSelection() {
		return destinationSelection;
	}

	public List<VTProgramCorrelatorFactory> getCorrelators() {
		return correlators;
	}

	public void setCorrelators(List<VTProgramCorrelatorFactory> correlators) {
		if (!correlators.equals(this.correlators)) {
			this.correlators = correlators;
			updateOptionsMap();
		}
	}

	private void updateOptionsMap() {
		optionsMap.keySet().retainAll(correlators);
		for (VTProgramCorrelatorFactory correlator : correlators) {
			if (!optionsMap.containsKey(correlator)) {
				VTOptions defaultOptions = correlator.createDefaultOptions();
				if (defaultOptions != null) {
					optionsMap.put(correlator, defaultOptions);
				}
			}
		}
	}

	public Map<VTProgramCorrelatorFactory, VTOptions> getOptions() {
		return optionsMap;
	}

	public boolean shouldExcludeAcceptedMatches() {
		return shouldExcludeAcceptedMatches;
	}

	public void setShouldExcludeAcceptedMatches(boolean b) {
		shouldExcludeAcceptedMatches = b;
	}

	public boolean shouldLimitAddressSets() {
		return shouldLimitAddressSets;
	}

	public void setShouldLimitAddressSets(boolean b) {
		shouldLimitAddressSets = b;
	}

}
