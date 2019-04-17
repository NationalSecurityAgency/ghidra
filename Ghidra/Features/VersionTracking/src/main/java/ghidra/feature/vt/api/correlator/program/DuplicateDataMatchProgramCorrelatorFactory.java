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
package ghidra.feature.vt.api.correlator.program;

import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public class DuplicateDataMatchProgramCorrelatorFactory extends VTAbstractProgramCorrelatorFactory {

	static final String DESC =
		"Compares data by iterating over all defined data meeting the minimum size requirement " +
			"in the source program and looking for identical byte matches in the " +
			"destination program. It reports back any that have MORE THAN ONE identical match.";
	static final String DUPLICATE_MATCH = "Duplicate Data Match";

	@Override
	public int getPriority() {
		return 70;
	}

	@Override
	protected VTProgramCorrelator doCreateCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options) {
		return new DataMatchProgramCorrelator(serviceProvider, sourceProgram, sourceAddressSet,
			destinationProgram, destinationAddressSet, options, DUPLICATE_MATCH, false);
	}

	@Override
	public String getName() {
		return DUPLICATE_MATCH;
	}

	@Override
	public VTOptions createDefaultOptions() {
		VTOptions options = new VTOptions(DUPLICATE_MATCH);
		options.setInt(ExactDataMatchProgramCorrelatorFactory.DATA_MINIMUM_SIZE,
			ExactDataMatchProgramCorrelatorFactory.DATA_MINIMUM_SIZE_DEFAULT);
		options.setInt(ExactDataMatchProgramCorrelatorFactory.DATA_MAXIMUM_SIZE,
			ExactDataMatchProgramCorrelatorFactory.DATA_MAXIMUM_SIZE_DEFAULT);
		options.setInt(ExactDataMatchProgramCorrelatorFactory.DATA_ALIGNMENT,
			ExactDataMatchProgramCorrelatorFactory.DATA_ALIGNMENT_DEFAULT);
		options.setBoolean(ExactDataMatchProgramCorrelatorFactory.SKIP_HOMOGENOUS_DATA,
			ExactDataMatchProgramCorrelatorFactory.SKIP_HOMOGENOUS_DATA_DEFAULT);
		return options;
	}

	@Override
	public String getDescription() {
		return DESC;
	}
}
