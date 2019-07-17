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

public class DuplicateSymbolNameProgramCorrelatorFactory
		extends VTAbstractProgramCorrelatorFactory {

	static final String DESC =
		"Compares symbols by iterating over all defined function and data symbols " +
			"meeting the minimum size requirement in the source program and looking " +
			"for identical symbol matches in the destination program. It ignores default " +
			"symbols such as those starting with FUN_, DAT_, s_, and u_. It strips off the " +
			"ending address that is sometimes included on symbols.It reports back " +
			"any that have MORE THAN ONE identical match.";
	static final String DUP_SYMBOL_MATCH = "Duplicate Exact Symbol Name Match";

	public static final String MIN_SYMBOL_NAME_LENGTH = "Minimum Symbol Name Length";
	public static final int MIN_SYMBOL_NAME_LENGTH_DEFAULT = 3;

	public static final String INCLUDE_EXTERNAL_SYMBOLS = "Include External Function Symbols";
	public static final boolean INCLUDE_EXTERNAL_SYMBOLS_DEFAULT = true;

	@Override
	public int getPriority() {
		// TODO Auto-generated method stub
		return 90;
	}

	@Override
	protected VTProgramCorrelator doCreateCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, VTOptions options) {
		return new SymbolNameProgramCorrelator(serviceProvider, sourceProgram, sourceAddressSet,
			destinationProgram, destinationAddressSet, options, DUP_SYMBOL_MATCH, false);
	}

	@Override
	public String getName() {
		return DUP_SYMBOL_MATCH;
	}

	@Override
	public VTOptions createDefaultOptions() {
		VTOptions options = new VTOptions(DUP_SYMBOL_MATCH);
		options.setInt(MIN_SYMBOL_NAME_LENGTH, MIN_SYMBOL_NAME_LENGTH_DEFAULT);
		options.setBoolean(INCLUDE_EXTERNAL_SYMBOLS, INCLUDE_EXTERNAL_SYMBOLS_DEFAULT);
		return options;
	}

	@Override
	public String getDescription() {
		return DESC;
	}
}
