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
package ghidra.framework.plugintool.util;

public enum PluginStatus {
	RELEASED("Released (Tested and Documented)"),
	STABLE("Useable, but not fully tested or documented"),
	UNSTABLE("This plugin is under Development. Use of this plugin is not recommended."),
	HIDDEN("This plugin is not available via the plugin configuration GUI"),
	/**
	 * Developers should include in the plugin description the version when the plugin became
	 * deprecated and, if subject to removal, the version that removal is expected.
	 */
	DEPRECATED("This plugin is useable, but deprecated and may soon be removed");

	private String description;

	private PluginStatus(String description) {
		this.description = description;
	}

	public String getDescription() {
		return description;
	}
}
