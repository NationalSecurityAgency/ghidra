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

import generic.lsh.LSHMemoryModel;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public class SimilarDataProgramCorrelatorFactory extends VTAbstractProgramCorrelatorFactory {
	public static final String NAME = "Similar Data Match";

	public static final String MEMORY_MODEL = "Memory model";
	public static final LSHMemoryModel MEMORY_MODEL_DEFAULT = LSHMemoryModel.LARGE;

	public static final String MIN_NAME_LENGTH = "Minimum data length";
	public static final int MIN_NAME_LENGTH_DEFAULT = 8;

	public static final String SKIP_HOMOGENOUS_DATA = "Skip Homogenous Data";
	public static final boolean SKIP_HOMOGENOUS_DATA_DEFAULT = true;

	@Override
	public int getPriority() {
		return 9002;
	}

	@Override
	protected VTProgramCorrelator doCreateCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options) {
		return new SimilarDataProgramCorrelator(serviceProvider, sourceProgram, sourceAddressSet,
			destinationProgram, destinationAddressSet, options);
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public VTOptions createDefaultOptions() {
		VTOptions options = new VTOptions(NAME);
		options.setEnum(MEMORY_MODEL, MEMORY_MODEL_DEFAULT);
		options.setBoolean(SKIP_HOMOGENOUS_DATA, SKIP_HOMOGENOUS_DATA_DEFAULT);
		options.setInt(MIN_NAME_LENGTH, MIN_NAME_LENGTH_DEFAULT);
		return options;
	}

	@Override
	public String getDescription() {
		return "Compares data by iterating over all" +
			" defined data meeting the minimum size requirement in the source" +
			" program and looking for similar data in the destination program." +
			" It reports back any that match closely";
	}

}
