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
import ghidra.app.util.demangler.microsoft.MicrosoftDemanglerOptions;
import ghidra.app.util.demangler.microsoft.options.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * A version of the demangler analyzer to handle microsoft symbols
 */
public class MicrosoftDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

	public static final String NAME = "Demangler Microsoft";
	private static final String DESCRIPTION =
		"After a function is created, this analyzer will attempt to demangle " +
			"the name and apply datatypes to parameters.";

	public static final String APPLY_OPTIONS_LABEL = "msdApplyOptions";
	private static final String OUTPUT_OPTIONS_LABEL = "msdOutputOptions";

	private MsdApplyOption applyOption;
	private MsdOutputOption outputOption;
	private MicrosoftDemanglerOptions msOptions;

	public MicrosoftDemanglerAnalyzer() {
		super(NAME, DESCRIPTION);
		msOptions = new MicrosoftDemanglerOptions();
		demangler = new MicrosoftDemangler();
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return demangler.canDemangle(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		HelpLocation help = new HelpLocation("AutoAnalysisPlugin", "Demangler_Analyzer");

		options.registerOption(APPLY_OPTIONS_LABEL, OptionType.CUSTOM_TYPE,
			new MsdApplyOption(msOptions.demangleOnlyKnownPatterns(), msOptions.applySignature(),
				msOptions.applyCallingConvention(), msOptions.getInterpretation()),
			help, "Configures how demangling is applied",
			() -> new MsdApplyOptionsEditor());

		applyOption =
			(MsdApplyOption) options.getCustomOption(APPLY_OPTIONS_LABEL, null);

		options.registerOption(OUTPUT_OPTIONS_LABEL, OptionType.CUSTOM_TYPE,
			new MsdOutputOption(msOptions.getUseEncodedAnonymousNamespace(),
				msOptions.getApplyUdtArgumentTypeTag()),
			help, "Controls demangled output", () -> new MsdOutputOptionsEditor());
		outputOption = (MsdOutputOption) options.getCustomOption(OUTPUT_OPTIONS_LABEL, null);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applyOption = (MsdApplyOption) options.getCustomOption(APPLY_OPTIONS_LABEL, applyOption);
		outputOption =
			(MsdOutputOption) options.getCustomOption(OUTPUT_OPTIONS_LABEL, outputOption);
		msOptions.setApplySignature(applyOption.applySignature());
		msOptions.setApplyCallingConvention(applyOption.applyCallingConvention());
		msOptions.setDemangleOnlyKnownPatterns(applyOption.demangleOnlyKnownPatterns());
		msOptions.setInterpretation(applyOption.getInterpretation());
		msOptions.setUseEncodedAnonymousNamespace(outputOption.getUseEncodedAnonymousNamespace());
		msOptions.setApplyUdtArgumentTypeTag(outputOption.getApplyUdtArgumentTypeTag());
		msOptions.setErrorOnRemainingChars(true);
	}

	@Override
	protected DemanglerOptions getOptions() {
		return msOptions;
	}

	@Override
	protected DemangledObject doDemangle(MangledContext context, MessageLog log)
			throws DemangledException {
		DemangledObject demangled = demangler.demangle(context);
		return demangled;
	}
}
