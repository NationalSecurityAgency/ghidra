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

import java.util.Objects;

import ghidra.framework.options.CustomOption;
import ghidra.framework.options.SaveState;

/**
 * A simple java bean adapted to the {@link CustomOption} interface.  The public 
 * getters and setters are self-documenting.
 */
public class GnuDemanglerWrappedOption implements CustomOption {

	private static final String USE_DEPRECATED_DEMANGLER = "USE_DEPRECATED_DEMANGLER";
	private static final String USE_DEMANGLER_PARAMETERS = "USE_DEMANGLER_PARAMETERS";
	private static final String DEMANGLER_PARAMETERS = "DEMANGLER_PARAMETERS";

	private boolean useDeprecatedDemangler = false;
	private boolean useDemanglerParameters = false;
	private String demanglerParametersText = null;

	public void setUseDeprecatedDemangler(boolean doUse) {
		this.useDeprecatedDemangler = doUse;
	}

	public boolean useDeprecatedDemangler() {
		return useDeprecatedDemangler;
	}

	public void setDemanglerParametersText(String text) {
		this.demanglerParametersText = text;
	}

	public String getDemanglerParametersText() {
		return demanglerParametersText;
	}

	public void setUseDemanglerParameters(boolean doUse) {
		this.useDemanglerParameters = doUse;
	}

	public boolean useDemanglerParameters() {
		return useDemanglerParameters;
	}

	@Override
	public void readState(SaveState state) {
		useDeprecatedDemangler =
			state.getBoolean(USE_DEPRECATED_DEMANGLER, useDemanglerParameters);
		useDemanglerParameters =
			state.getBoolean(USE_DEPRECATED_DEMANGLER, useDemanglerParameters);
		demanglerParametersText =
			state.getString(DEMANGLER_PARAMETERS, demanglerParametersText);
	}

	@Override
	public void writeState(SaveState state) {
		state.putBoolean(USE_DEPRECATED_DEMANGLER, useDeprecatedDemangler);
		state.putBoolean(USE_DEMANGLER_PARAMETERS, useDemanglerParameters);
		state.putString(USE_DEMANGLER_PARAMETERS, demanglerParametersText);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result +
			((demanglerParametersText == null) ? 0 : demanglerParametersText.hashCode());
		result = prime * result + (useDemanglerParameters ? 1231 : 1237);
		result = prime * result + (useDeprecatedDemangler ? 1231 : 1237);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		GnuDemanglerWrappedOption other = (GnuDemanglerWrappedOption) obj;
		if (!Objects.equals(demanglerParametersText, other.demanglerParametersText)) {
			return false;
		}

		if (useDemanglerParameters != other.useDemanglerParameters) {
			return false;
		}
		if (useDeprecatedDemangler != other.useDeprecatedDemangler) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tuseDeprecatedDemangler: " + useDeprecatedDemangler + ",\n" +
			"\tuseDemanglerParameters: " + useDemanglerParameters + ",\n" +
			"\tdemanglerParametersText: " + demanglerParametersText + ",\n" +
		"}";
		//@formatter:on
	}
}
