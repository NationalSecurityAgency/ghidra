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
package ghidra.feature.vt.api.correlator.address;

import java.util.List;

import ghidra.feature.vt.api.correlator.program.*;
import ghidra.feature.vt.api.impl.VTProgramCorrelatorInfo;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.util.AddressCorrelation;
import ghidra.program.util.AddressCorrelator;

public class ExactMatchAddressCorrelator implements AddressCorrelator {

	private static final String CORRELATOR_NAME = "ExactMatchAddressCorrelator";
	private ToolOptions options = new ToolOptions(CORRELATOR_NAME);
	private VTController controller;

	public ExactMatchAddressCorrelator(VTController controller) {
		this.controller = controller;
	}

	@Override
	public synchronized AddressCorrelation correlate(Function sourceFunction,
			Function destinationFunction) {

		VTSession session = controller.getSession();
		VTAssociationManager associationManager = session.getAssociationManager();
		VTAssociation association =
			associationManager.getAssociation(sourceFunction.getEntryPoint(),
				destinationFunction.getEntryPoint());
		List<VTMatch> matches = session.getMatches(association);
		for (VTMatch match : matches) {
			VTMatchSet matchSet = match.getMatchSet();
			VTProgramCorrelatorInfo info = matchSet.getProgramCorrelatorInfo();
			final String correlatorName = info.getName();
			if (correlatorName.equals(ExactMatchBytesProgramCorrelatorFactory.EXACT_MATCH) ||
				correlatorName.equals(ExactMatchInstructionsProgramCorrelatorFactory.EXACT_MATCH) ||
				correlatorName.equals(ExactMatchMnemonicsProgramCorrelatorFactory.EXACT_MATCH)) {
				return new StraightLineCorrelation(sourceFunction, destinationFunction);
			}
		}

		return null;
	}

	@Override
	public AddressCorrelation correlate(Data sourceData, Data destinationData) {
		return null;
	}

	@Override
	public ToolOptions getOptions() {
		return options;
	}

	@Override
	public void setOptions(ToolOptions options) {
		this.options = options.copy();
	}

	@Override
	public Options getDefaultOptions() {
		return new ToolOptions(CORRELATOR_NAME);
	}
}
