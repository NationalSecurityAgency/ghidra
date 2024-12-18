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
package ghidra.features.codecompare.correlator;

import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.util.AddressCorrelation;
import ghidra.program.util.AddressCorrelator;

public class CodeCompareAddressCorrelator implements AddressCorrelator {

	private static final String OPTIONS_NAME = "CodeCompareAddressCorrelator";

	private ToolOptions options = new ToolOptions(OPTIONS_NAME);

	public CodeCompareAddressCorrelator() {
	}

	@Override
	public synchronized AddressCorrelation correlate(Function sourceFunction,
			Function destinationFunction) {

		Program p1 = sourceFunction.getProgram();
		Program p2 = destinationFunction.getProgram();
		Language l1 = p1.getLanguage();
		Language l2 = p2.getLanguage();
		if (l1.getLanguageID().equals(l2.getLanguageID())) {
			// this correlator is best used with different architectures, assuming we have simpler 
			// and faster correlators that should be run with the same language
			return null;
		}

		return new CodeCompareAddressCorrelation(sourceFunction, destinationFunction);
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
		options = options.copy();
	}

	@Override
	public Options getDefaultOptions() {
		return new ToolOptions(OPTIONS_NAME);
	}

	@Override
	public int getPriority() {
		// Run just above the last chance priority, which allows this correlator to be the fallback,
		// general purpose correlator.
		return LATE_CHANCE_PRIORITY - PRIORITY_OFFSET;
	}
}
