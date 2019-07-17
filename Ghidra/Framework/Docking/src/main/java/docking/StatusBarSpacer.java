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
package docking;

import javax.swing.Icon;

import docking.widgets.label.GIconLabel;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import resources.ResourceManager;

/**
 * A class to handle the space requirements on the status bar that vary for different OSes.  For 
 * example, the Mac requires extra space on the status bar, due to the drag icon the Mac uses.
 */
public class StatusBarSpacer extends GIconLabel {
	private static Icon EMPTY_ICON = ResourceManager.loadImage("images/EmptyIcon.gif");

	public StatusBarSpacer() {
		super(
			Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X ? EMPTY_ICON
					: (Icon) null);
	}

}
