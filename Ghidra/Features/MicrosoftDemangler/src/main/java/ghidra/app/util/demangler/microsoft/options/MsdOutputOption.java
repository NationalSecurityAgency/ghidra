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
import ghidra.app.util.demangler.microsoft.MicrosoftDemanglerOptions;
import ghidra.framework.options.CustomOption;
import ghidra.framework.options.GProperties;

/**
 * Options class that is paired with the {@link MsdOutputOptionsEditor} so that we can have a
 * custom editor for an "Output" options panel for the {@link MicrosoftDemanglerAnalyzer}.
 * Also see {@link MsdApplyOption}, which is another panel.
 * The results of both get pushed into the {@link MicrosoftDemanglerOptions} to control the
 * analyzer and underlying demangler.
 */
public class MsdOutputOption implements CustomOption {

	private static final String USE_ENCODED_ANONYMOUS_NAMESPACE = "useEncodedAnonymousNamespace";
	private static final String APPLY_TEMPLATE_ARG_TAGS = "applyTagsTemplateArgumentTags";

	private boolean useEncodedAnonymousNamespace;
	private boolean applyUdtArgumentTypeTag;

	public MsdOutputOption() {
		// required for persistence, but must set some initial values even though they will
		//  get overridden by writeState.
		this(false, false);
	}

	public MsdOutputOption(boolean useEncodedAnonymousNamespace, boolean applyUdtArgumentTypeTag) {
		this.useEncodedAnonymousNamespace = useEncodedAnonymousNamespace;
		this.applyUdtArgumentTypeTag = applyUdtArgumentTypeTag;
	}

	/**
	 * Sets the output flag to use an anonymous namespace's encoded number to craft a namespace
	 * containing this number instead of using the generic "`anonymous namespace'" name.  Default
	 * is true (to create a namespace containing the encoded number)
	 * @param useEncodedAnonymousNamespaceArg  {@code true} to use
	 */
	public void setUseEncodedAnonymousNamespace(boolean useEncodedAnonymousNamespaceArg) {
		useEncodedAnonymousNamespace = useEncodedAnonymousNamespaceArg;
	}

	/**
	 * Returns {@code true} if the output flag is set to use an anonymous namespace's encoded
	 * number to craft a namespace containing the number instead of using the generic
	 * "`anonymous namespace'" name.
	 * @return {@code true} if encoded number is used to craft a namespace
	 */
	public boolean getUseEncodedAnonymousNamespace() {
		return useEncodedAnonymousNamespace;
	}

	/**
	 * Sets the output flag for applying user-defined tags (e.g., class, struct, union, enum)
	 * within template and function arguments.  Default is {@code true} (to apply)
	 * @param applyUdtArgumentTypeTagArg {@code true} to apply the tags
	 */
	public void setApplyUdtArgumentTypeTag(boolean applyUdtArgumentTypeTagArg) {
		applyUdtArgumentTypeTag = applyUdtArgumentTypeTagArg;
	}

	/**
	 * Returns {@code true} if the output interpretation is set to apply user-defined type
	 * tags (e.g., class, struct, union, enum) within template and function arguments.
	 * @return {@code true} if applying the tags
	 */
	public boolean getApplyUdtArgumentTypeTag() {
		return applyUdtArgumentTypeTag;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof MsdOutputOption other)) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		return useEncodedAnonymousNamespace == other.useEncodedAnonymousNamespace &&
			applyUdtArgumentTypeTag == other.applyUdtArgumentTypeTag;
	}

	@Override
	public int hashCode() {
		return Objects.hash(applyUdtArgumentTypeTag, useEncodedAnonymousNamespace);
	}

//==================================================================================================
// Persistence
//==================================================================================================

	@Override
	public void readState(GProperties properties) {
		useEncodedAnonymousNamespace =
			properties.getBoolean(USE_ENCODED_ANONYMOUS_NAMESPACE, useEncodedAnonymousNamespace);
		applyUdtArgumentTypeTag =
			properties.getBoolean(APPLY_TEMPLATE_ARG_TAGS, applyUdtArgumentTypeTag);
	}

	@Override
	public void writeState(GProperties properties) {
		properties.putBoolean(USE_ENCODED_ANONYMOUS_NAMESPACE, useEncodedAnonymousNamespace);
		properties.putBoolean(APPLY_TEMPLATE_ARG_TAGS, applyUdtArgumentTypeTag);
	}
}
