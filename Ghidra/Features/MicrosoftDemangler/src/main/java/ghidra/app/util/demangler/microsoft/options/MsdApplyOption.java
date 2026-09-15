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
package ghidra.app.util.demangler.microsoft.options;

import java.util.Objects;

import ghidra.app.plugin.core.analysis.MicrosoftDemanglerAnalyzer;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.microsoft.MicrosoftDemanglerOptions;
import ghidra.app.util.demangler.microsoft.MsCInterpretation;
import ghidra.framework.options.CustomOption;
import ghidra.framework.options.GProperties;

/**
 * Option class that is paired with the {@link MsdApplyOptionsEditor} so that we can have a
 * custom editor for an "Apply" option panel for the {@link MicrosoftDemanglerAnalyzer}.
 * Also see {@link MsdOutputOption}, which is another panel.
 * The results of both get pushed into the {@link MicrosoftDemanglerOptions} to control the
 * analyzer and underlying demangler.
 */
public class MsdApplyOption extends DemanglerOptions implements CustomOption {

	private static final String DEMANGLE_USE_KNOWN_PATTERNS = "demangleOnlyKnownMangledSymbols";
	private static final String APPLY_SIGNATURE = "applyFunctionSignatures";
	private static final String APPLY_CALLING_CONVENTION = "applyFunctionCallingConventions";
	private static final String MS_C_INTERPRETATION = "C-StyleSymbolInterpretation";

	private MsCInterpretation interpretation;

	public MsdApplyOption() {
		// required for persistence, but must set some initial values even though they will
		//  get overridden by writeState.
		this(false, false, false, MsCInterpretation.FUNCTION_IF_EXISTS);
	}

	public MsdApplyOption(boolean demangleOnlyKnownPatternsArg, boolean applySignatureArg,
			boolean applyCallingConventionArg, MsCInterpretation interpretationArg) {
		setDemangleOnlyKnownPatterns(demangleOnlyKnownPatternsArg);
		setApplySignature(applySignatureArg);
		setApplyCallingConvention(applyCallingConventionArg);
		interpretation = interpretationArg;
	}

	/**
	 * Sets the interpretation for processing a C-style mangled symbol if there could be multiple
	 * interpretations
	 * @param interpretationArg the interpretation to use
	 */
	public void setInterpretation(MsCInterpretation interpretationArg) {
		interpretation = interpretationArg;
	}

	/**
	 * Returns the interpretation for processing a C-style mangled symbol if there could be multiple
	 * interpretations
	 * @return the interpretation used
	 */
	public MsCInterpretation getInterpretation() {
		return interpretation;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof MsdApplyOption other)) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		return demangleOnlyKnownPatterns == other.demangleOnlyKnownPatterns &&
			applyCallingConvention == other.applyCallingConvention &&
			applySignature == other.applySignature &&
			interpretation == other.interpretation;
	}

	@Override
	public int hashCode() {
		return Objects.hash(demangleOnlyKnownPatterns, applyCallingConvention,
			applySignature, interpretation);
	}

//==================================================================================================
// Persistence
//==================================================================================================

	@Override
	public void readState(GProperties properties) {
		demangleOnlyKnownPatterns =
			properties.getBoolean(DEMANGLE_USE_KNOWN_PATTERNS, demangleOnlyKnownPatterns);
		applySignature = properties.getBoolean(APPLY_SIGNATURE, applySignature);
		applyCallingConvention =
			properties.getBoolean(APPLY_CALLING_CONVENTION, applyCallingConvention);
		interpretation = properties.getEnum(MS_C_INTERPRETATION, interpretation);
	}

	@Override
	public void writeState(GProperties properties) {
		properties.putBoolean(DEMANGLE_USE_KNOWN_PATTERNS, demangleOnlyKnownPatterns);
		properties.putBoolean(APPLY_SIGNATURE, applySignature);
		properties.putBoolean(APPLY_CALLING_CONVENTION, applyCallingConvention);
		properties.putEnum(MS_C_INTERPRETATION, interpretation);
	}
}
