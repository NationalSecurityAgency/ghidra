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
package ghidra.app.plugin.core.analysis;

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/**
 * A version of the demangler analyzer to handle microsoft symbols
 */
public class MicrosoftDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

	private static final String NAME = "Demangler Microsoft";
	private static final String DESCRIPTION =
		"After a function is created, this analyzer will attempt to demangle " +
			"the name and apply datatypes to parameters.";

	private final static String OPTION_NAME_APPLY_SIGNATURE = "Apply Function Signatures";
	private static final String OPTION_DESCRIPTION_APPLY_SIGNATURE =
		"Apply any recovered function signature, in addition to the function name";
	private boolean applyFunctionSignature = true;
	private MicrosoftDemangler demangler = new MicrosoftDemangler();

	public MicrosoftDemanglerAnalyzer() {
		super(NAME, DESCRIPTION);
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return demangler.canDemangle(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_APPLY_SIGNATURE, applyFunctionSignature, null,
			OPTION_DESCRIPTION_APPLY_SIGNATURE);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applyFunctionSignature =
			options.getBoolean(OPTION_NAME_APPLY_SIGNATURE, applyFunctionSignature);
	}

	@Override
	protected DemangledObject doDemangle(String mangled, DemanglerOptions options, MessageLog log)
			throws DemangledException {
		DemangledObject demangled = demangler.demangle(mangled, options);
		return demangled;
	}
}
