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

import ghidra.app.services.Analyzer;

/**
 * Row objects for the analyzer enablement table
 */
public class AnalyzerEnablementState {
	private final String name;
	private boolean enabled;
	private final boolean defaultEnabled;
	private final boolean isPrototype;

	public AnalyzerEnablementState(Analyzer analyzer, boolean enabled, boolean defaultEnablement) {
		this.name = analyzer.getName();
		this.enabled = enabled;
		this.defaultEnabled = defaultEnablement;
		this.isPrototype = analyzer.isPrototype();
	}

	/**
	 * Returns the analyzer name
	 * @return the analyzer name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns if the analyzer is currently enabled
	 * @return  if the analyzer is currently enabled
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Returns if the analyzer's enablement is the default enablement state
	 * @return if the analyzer's enablement is the default enablement state
	 */
	public boolean isDefaultEnablement() {
		return enabled == defaultEnabled;
	}

	/**
	 * Returns true if the analyzer is a prototype
	 * @return  true if the analyzer is a prototype
	 */
	public boolean isPrototype() {
		return isPrototype;
	}

	/**
	 * Sets the enablement state for the analyzer
	 * @param enabled the new enablement state
	 */
	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}
}
