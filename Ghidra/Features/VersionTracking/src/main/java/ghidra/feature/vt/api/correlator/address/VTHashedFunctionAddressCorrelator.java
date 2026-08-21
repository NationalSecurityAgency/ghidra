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
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.util.AddressCorrelation;
import ghidra.program.util.AddressCorrelator;

/**
 * An address correlator that may use the {@link VTHashedFunctionAddressCorrelation}.
 */
public class VTHashedFunctionAddressCorrelator implements AddressCorrelator {

	public static final String NAME = "VTHashedFunctionAddressCorrelator";

	private ToolOptions options = new ToolOptions(NAME);

	@Override
	public AddressCorrelation correlate(Function sourceFunction, Function destinationFunction) {

		Language sourceLanguage = sourceFunction.getProgram().getLanguage();
		Language destinationLanguage = destinationFunction.getProgram().getLanguage();
		if (sourceLanguage.getProcessor().equals(destinationLanguage.getProcessor())) {
			return new VTHashedFunctionAddressCorrelation(sourceFunction, destinationFunction);
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
		return new ToolOptions(NAME);
	}

	@Override
	public int getPriority() {
		// Run just above default / discovered correlators.  Correlator authors can change their
		// priority to take precedence over this correlator.
		return DEFAULT_PRIORITY - PRIORITY_OFFSET;
	}
}
