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

import ghidra.app.plugin.match.ExactInstructionsFunctionHasher;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.feature.vt.api.util.VTOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

public class ExactMatchInstructionsProgramCorrelatorFactory extends
		VTAbstractProgramCorrelatorFactory {

	static final String DESC =
		"Compares code by hashing instructions, looking for identical functions. It reports back any that have ONLY ONE identical match.";

	public static final String EXACT_MATCH = "Exact Function Instructions Match";
	public static final String FUNCTION_MINIMUM_SIZE = "Function Minimum Size";
	public static final int FUNCTION_MINIMUM_SIZE_DEFAULT = 10;

	@Override
	public int getPriority() {
		return 30;
	}

	@Override
	protected VTProgramCorrelator doCreateCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options) {
		return new FunctionMatchProgramCorrelator(serviceProvider, sourceProgram, sourceAddressSet,
			destinationProgram, destinationAddressSet, options, EXACT_MATCH, true,
			ExactInstructionsFunctionHasher.INSTANCE);
	}

	@Override
	public String getName() {
		return EXACT_MATCH;
	}

	@Override
	public VTOptions createDefaultOptions() {
		VTOptions options = new VTOptions(EXACT_MATCH);
		options.setInt(FUNCTION_MINIMUM_SIZE, FUNCTION_MINIMUM_SIZE_DEFAULT);
		return options;
	}

	@Override
	public String getDescription() {
		return DESC;
	}
}
