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

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.gnu.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * A version of the demangler analyzer to handle GNU GCC symbols 
 */
public class GnuDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

	private static final String NAME = "Demangler GNU";
	private static final String DESCRIPTION =
		"After a function is created, this analyzer will attempt to demangle " +
			"the name and apply datatypes to parameters.";

	private static final String OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS =
		"Demangle Only Known Mangled Symbols";
	private static final String OPTION_DESCRIPTION_USE_KNOWN_PATTERNS =
		"Only demangle symbols that follow known compiler mangling patterns. " +
			"Leaving this option off may cause non-mangled symbols to get demangled.";

	private static final String OPTION_NAME_APPLY_SIGNATURE = "Apply Function Signatures";
	private static final String OPTION_DESCRIPTION_APPLY_SIGNATURE =
		"Apply any recovered function signature, in addition to the function name";

	static final String OPTION_NAME_USE_DEPRECATED_DEMANGLER = "Use Deprecated Demangler";
	private static final String OPTION_DESCRIPTION_DEPRECATED_DEMANGLER =
		"Signals to use the deprecated demangler when the modern demangler cannot demangle a " +
			"given string";

	static final String OPTION_NAME_DEMANGLER_PARAMETERS =
		"Use External Demangler Options";
	private static final String OPTION_DESCRIPTION_DEMANGLER_PARAMETERS =
		"Signals to use pass the given parameters to the demangler program";

	private boolean doSignatureEnabled = true;
	private boolean demangleOnlyKnownPatterns = false;
	private boolean useDeprecatedDemangler = false;
	private String demanglerParameters = "";

	private GnuDemangler demangler = new GnuDemangler();

	public GnuDemanglerAnalyzer() {
		super(NAME, DESCRIPTION);
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return demangler.canDemangle(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {

		HelpLocation help = new HelpLocation("AutoAnalysisPlugin", "Demangler_Analyzer");
		options.registerOption(OPTION_NAME_APPLY_SIGNATURE, doSignatureEnabled, help,
			OPTION_DESCRIPTION_APPLY_SIGNATURE);

		options.registerOption(OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS, demangleOnlyKnownPatterns,
			help,
			OPTION_DESCRIPTION_USE_KNOWN_PATTERNS);

		options.registerOption(OPTION_NAME_USE_DEPRECATED_DEMANGLER, useDeprecatedDemangler, help,
			OPTION_DESCRIPTION_DEPRECATED_DEMANGLER);

		options.registerOption(OPTION_NAME_DEMANGLER_PARAMETERS, demanglerParameters, help,
			OPTION_DESCRIPTION_DEMANGLER_PARAMETERS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		doSignatureEnabled = options.getBoolean(OPTION_NAME_APPLY_SIGNATURE, doSignatureEnabled);
		demangleOnlyKnownPatterns =
			options.getBoolean(OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS, demangleOnlyKnownPatterns);

		useDeprecatedDemangler =
			options.getBoolean(OPTION_NAME_USE_DEPRECATED_DEMANGLER, useDeprecatedDemangler);

		demanglerParameters =
			options.getString(OPTION_NAME_DEMANGLER_PARAMETERS, demanglerParameters);
	}

	@Override
	protected DemanglerOptions getOptions() {

		GnuDemanglerOptions options = new GnuDemanglerOptions();
		options.setDoDisassembly(true);
		options.setApplySignature(doSignatureEnabled);
		options.setDemangleOnlyKnownPatterns(demangleOnlyKnownPatterns);
		options.setDemanglerApplicationArguments(demanglerParameters);
		return options;
	}

	@Override
	protected boolean validateOptions(DemanglerOptions demanglerOtions, MessageLog log) {

		GnuDemanglerOptions options = (GnuDemanglerOptions) demanglerOtions;
		String applicationArguments = options.getDemanglerApplicationArguments();
		if (StringUtils.isBlank(applicationArguments)) {
			return true;
		}

		// Check that the supplied arguments will work with at least one of the requested
		// demanglers.  (Different versions of the GNU demangler support different arguments.)
		String demanglerName = options.getDemanglerName();
		try {
			GnuDemanglerNativeProcess.getDemanglerNativeProcess(demanglerName,
				applicationArguments);
			return true;
		}
		catch (IOException e) {
			log.appendMsg(getName(), "Invalid options for GNU dangler '" + demanglerName +
				"': " + applicationArguments);
			log.appendException(e);
		}

		if (useDeprecatedDemangler) {
			// see if the options work in the deprecated demangler
			GnuDemanglerOptions deprecatedOptions = options.withDeprecatedDemangler();
			String deprecatedName = deprecatedOptions.getDemanglerName();
			try {
				GnuDemanglerNativeProcess.getDemanglerNativeProcess(deprecatedName,
					applicationArguments);
				return true;
			}
			catch (IOException e) {
				log.appendMsg(getName(),
					"Invalid options for GNU dangler '" + deprecatedName + "': " +
						applicationArguments);
				log.appendException(e);
			}
		}

		return false;

	}

	@Override
	protected DemangledObject doDemangle(String mangled, DemanglerOptions demanglerOtions,
			MessageLog log)
			throws DemangledException {

		GnuDemanglerOptions options = (GnuDemanglerOptions) demanglerOtions;
		DemangledObject demangled = null;
		try {
			demangled = demangler.demangle(mangled, options);
		}
		catch (DemangledException e) {
			if (!useDeprecatedDemangler) {
				throw e; // let our parent handle this
			}
		}

		if (demangled != null) {
			return demangled;
		}

		if (useDeprecatedDemangler) {
			GnuDemanglerOptions newOptions = options.withDeprecatedDemangler();
			demangled = demangler.demangle(mangled, newOptions);
		}

		return demangled;
	}
}
