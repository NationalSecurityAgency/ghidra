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
package ghidra.framework.plugintool;

import java.awt.Desktop;

import docking.DockingWindowManager;
import docking.framework.AboutDialog;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;

/**
 * A plugin-level about handler that serves as the callback from the Dock's 'About' popup action.
 */
public class PluginToolMacAboutHandler {

	private static boolean installed = false; // only install it once

	/**
	 * Applies an about handler which will show our custom about dialog.
	 * 
	 * @param winMgr The docking window manager to use to install the about dialog.
	 */
	public static synchronized void install(DockingWindowManager winMgr) {

		if (installed) {
			return;
		}
		installed = true;

		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.MAC_OS_X) {
			return;
		}

		Desktop.getDesktop().setAboutHandler(
			e -> DockingWindowManager.showDialog(new AboutDialog()));
	}
}
