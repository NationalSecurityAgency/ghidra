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
 * An enum for specifying which actions should be displayed in the {@link ActionChooserDialog}. Each
 * successive level is less restrictive and includes more actions to display.
 */
public enum ActionDisplayLevel {
	// all local menu and toolbar actions,  
	// all local and global popup actions with valid context and addToPopup=true,
	// all local and global keybinding actions that are valid and enabled
	LOCAL,

	// adds local and global actions with a valid context, even if disabled
	GLOBAL,

	// adds local and global actions even if invalid context and disabled
	ALL;

	public ActionDisplayLevel getNextLevel() {
		switch (this) {
			case LOCAL:
				return GLOBAL;
			case GLOBAL:
				return ALL;
			case ALL:
				return LOCAL;
			default:
				return LOCAL;
		}

	}
}
