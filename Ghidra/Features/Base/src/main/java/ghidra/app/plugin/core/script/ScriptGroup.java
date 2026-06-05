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
package ghidra.app.plugin.core.script;

/**
 * Categories for organizing scripts in the Script Quick Launch dialog.
 */
public enum ScriptGroup {
	RECENT_SCRIPTS("Recent Scripts"),
	ALL_SCRIPTS("All Scripts");

	private String displayName;

	private ScriptGroup(String displayName) {
		this.displayName = displayName;
	}

	public String getDisplayName() {
		return displayName;
	}

	public static ScriptGroup getGroupByDisplayName(String name) {
		for (ScriptGroup group : values()) {
			if (group.getDisplayName().equals(name)) {
				return group;
			}
		}
		return null;
	}
}
