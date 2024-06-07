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
package docking.actions.dialog;

/**
 * This enum defines the actions category groups. Actions displayed in the {@link ActionChooserDialog}
 * will be organized into these groups.
 */
public enum ActionGroup {
	LOCAL_TOOLBAR("Local Toolbar"),
	LOCAL_MENU("Local Menu"),
	POPUP("Popup Menu"),
	KEYBINDING_ONLY("Keybinding Only"),
	GLOBAL_TOOLBAR("Global Toolbar"),
	GLOBAL_MENU("Global Menu");

	private String displayName;

	private ActionGroup(String displayName) {
		this.displayName = displayName;
	}

	/**
	 * Returns the display name for the action group.
	 * @return the display name for the action group
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * Returns the ActionGroup that has the given display name.
	 * @param name the display name for which to find its corresponding group
	 * @return  the ActionGroup that has the given display name
	 */
	public static ActionGroup getActionByDisplayName(String name) {
		ActionGroup[] values = values();
		for (ActionGroup group : values) {
			if (group.getDisplayName().equals(name)) {
				return group;
			}
		}
		return null;
	}
}
