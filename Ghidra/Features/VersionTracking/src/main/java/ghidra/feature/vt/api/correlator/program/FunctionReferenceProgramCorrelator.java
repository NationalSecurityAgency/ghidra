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

import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;

/**
 * Correlates functions if they share forward references to previously accepted function matches.
 */
public class FunctionReferenceProgramCorrelator extends VTAbstractReferenceProgramCorrelator {

	/**
	 * Function Reference Correlator class constructor.
	 * @param serviceProvider The {@code ServiceProvider}.
	 * @param sourceProgram The source {@code Program}.
	 * @param sourceAddressSet The {@code AddressSetView} for the source program.
	 * @param destinationProgram The destination {@code Program}.
	 * @param destinationAddressSet The {@code AddressSetView} for the destination program.
	 * @param correlatorName The correlator name string passed from the factory.
	 * @param options {@code ToolOptions}
	 */
	FunctionReferenceProgramCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, String correlatorName, ToolOptions options) {
		super(serviceProvider, sourceProgram, sourceAddressSet, destinationProgram,
			destinationAddressSet, correlatorName, options);
	}

	@Override
	protected boolean isExpectedRefType(VTAssociationType mytype) {
		return mytype.equals(VTAssociationType.FUNCTION);
	}

	@Override
	protected boolean isExpectedRefType(Reference myRef) {
		return myRef.getReferenceType().isCall();
	}
}
