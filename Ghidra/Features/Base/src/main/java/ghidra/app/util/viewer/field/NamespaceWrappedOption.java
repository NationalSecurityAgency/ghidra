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
package ghidra.app.util.viewer.field;

import ghidra.framework.options.CustomOption;
import ghidra.framework.options.SaveState;

/**
 * An option class that allows the user to edit a related group of options pertaining to
 * namespace display.
 */
public class NamespaceWrappedOption implements CustomOption {
	private static final String SHOW_LOCAL_NAMESPACE = "showLocalNamespace";
	private static final String SHOW_NON_LOCAL_NAMESPACE = "showNonLocalNamespace";
	private static final String USE_LOCAL_PREFIX_OVERRIDE = "useLocalPrefixOverride";
	private static final String LOCAL_PREFIX = "localPrefix";
	private static final String SHOW_LIBRARY_IN_NAMESPACE = "showLibraryInNamespace";

	private static boolean DEFAULT_SHOW_LOCAL_NAMESPACE = false;
	private static boolean DEFAULT_SHOW_NONLOCAL_NAMESPACE = true;
	private static boolean DEFAULT_USE_LOCAL_PREFIX_OVERRIDE = false;
	private static String DEFAULT_LOCAL_PREFIX_TEXT = "local::";
	private static boolean DEFAULT_SHOW_LIBRARY_IN_NAMESPACE = true;

	// init with default values
	private boolean showLocalNamespace = DEFAULT_SHOW_LOCAL_NAMESPACE;
	private boolean showNonLocalNamespace = DEFAULT_SHOW_NONLOCAL_NAMESPACE;
	private boolean useLocalPrefixOverride = DEFAULT_USE_LOCAL_PREFIX_OVERRIDE;
	private String localPrefixText = DEFAULT_LOCAL_PREFIX_TEXT;
	private boolean showLibraryInNamespace = DEFAULT_SHOW_LIBRARY_IN_NAMESPACE;

	public NamespaceWrappedOption() {
		// required for persistence
	}

	public boolean isShowLocalNamespace() {
		return showLocalNamespace;
	}

	public boolean isShowNonLocalNamespace() {
		return showNonLocalNamespace;
	}

	public String getLocalPrefixText() {
		return localPrefixText;
	}

	public void setShowLocalNamespace(boolean showLocalNamespace) {
		this.showLocalNamespace = showLocalNamespace;
	}

	public void setShowNonLocalNamespace(boolean showNonLocalNamespace) {
		this.showNonLocalNamespace = showNonLocalNamespace;
	}

	public void setUseLocalPrefixOverride(boolean useLocalPrefixOverride) {
		this.useLocalPrefixOverride = useLocalPrefixOverride;
	}

	public boolean isUseLocalPrefixOverride() {
		return useLocalPrefixOverride;
	}

	public void setLocalPrefixText(String localPrefixText) {
		this.localPrefixText = localPrefixText;
	}

	public boolean isShowLibraryInNamespace() {
		return showLibraryInNamespace;
	}

	public void setShowLibraryInNamespace(boolean showLibraryInNamespace) {
		this.showLibraryInNamespace = showLibraryInNamespace;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof NamespaceWrappedOption)) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		NamespaceWrappedOption otherOption = (NamespaceWrappedOption) obj;
		return showLocalNamespace == otherOption.showLocalNamespace &&
			showNonLocalNamespace == otherOption.showNonLocalNamespace &&
			useLocalPrefixOverride == otherOption.useLocalPrefixOverride &&
			localPrefixText.equals(otherOption.localPrefixText) &&
			showLibraryInNamespace == otherOption.showLibraryInNamespace;
	}

	@Override
	public int hashCode() {
		int prime = 31;
		int result = 1;
		result = prime * result + (showLocalNamespace ? 1 : 0);
		result = prime * result + (showNonLocalNamespace ? 1 : 0);
		result = prime * result + (useLocalPrefixOverride ? 1 : 0);
		result = prime * result + (localPrefixText == null ? 0 : localPrefixText.hashCode());
		result = prime * result + (showLibraryInNamespace ? 1 : 0);
		return result;
	}

//==================================================================================================
// Persistence
//==================================================================================================
	@Override
	public void readState(SaveState saveState) {
		showLocalNamespace = saveState.getBoolean(SHOW_LOCAL_NAMESPACE, showLocalNamespace);
		showNonLocalNamespace =
			saveState.getBoolean(SHOW_NON_LOCAL_NAMESPACE, showNonLocalNamespace);
		useLocalPrefixOverride =
			saveState.getBoolean(USE_LOCAL_PREFIX_OVERRIDE, useLocalPrefixOverride);
		localPrefixText = saveState.getString(LOCAL_PREFIX, localPrefixText);
		showLibraryInNamespace =
			saveState.getBoolean(SHOW_LIBRARY_IN_NAMESPACE, DEFAULT_SHOW_LIBRARY_IN_NAMESPACE);
	}

	@Override
	public void writeState(SaveState saveState) {
		saveState.putBoolean(SHOW_LOCAL_NAMESPACE, showLocalNamespace);
		saveState.putBoolean(SHOW_NON_LOCAL_NAMESPACE, showNonLocalNamespace);
		saveState.putBoolean(USE_LOCAL_PREFIX_OVERRIDE, useLocalPrefixOverride);
		saveState.putString(LOCAL_PREFIX, localPrefixText);
		saveState.putBoolean(SHOW_LIBRARY_IN_NAMESPACE, showLibraryInNamespace);
	}
}
