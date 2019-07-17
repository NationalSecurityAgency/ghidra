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

import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.util.*;

/**
 * This is the correlator of last resort. It is the last correlator to be checked when trying to 
 * acquire a correlation.
 */
public class LastResortAddressCorrelator implements AddressCorrelator {

	private static final String CORRELATOR_NAME = "LastResortAddressCorrelator";
	private ToolOptions options = new ToolOptions(CORRELATOR_NAME);

	public LastResortAddressCorrelator() {
	}

	@Override
	public AddressCorrelation correlate(Function sourceFunction, Function destinationFunction) {
		if (sourceFunction.getProgram().getLanguage().getLanguageDescription().getProcessor().equals(
			destinationFunction.getProgram().getLanguage().getLanguageDescription().getProcessor())) {
			return new VTHashedFunctionAddressCorrelation(sourceFunction, destinationFunction);
		}
		return new LinearFunctionAddressCorrelation(sourceFunction, destinationFunction);
	}

	@Override
	public AddressCorrelation correlate(Data sourceData, Data destinationData) {
		return new LinearDataAddressCorrelation(sourceData, destinationData);
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
