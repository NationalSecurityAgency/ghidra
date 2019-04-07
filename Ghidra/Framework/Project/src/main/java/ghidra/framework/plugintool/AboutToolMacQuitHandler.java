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

import docking.DockingWindowManager;
import docking.framework.AboutDialog;
import generic.platform.MacAboutHandler;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.SystemUtilities;

/**
 * A plugin-level 'About' handler that serves as the callback from the Dock's 'About' popup action.
 */
public class AboutToolMacQuitHandler extends MacAboutHandler {

	// Note: we only want this handle to be installed once globally for the entire application 
	//       (otherwise, multiple prompts will be displayed).
	private static AboutToolMacQuitHandler INSTANCE = null;

	public static void install() {

		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.MAC_OS_X) {
			return;
		}

		// These calls should all be in the Swing thread; thus, no need for locking.
		SystemUtilities.assertThisIsTheSwingThread("Must install quit handler in the Swing thread");
		if (INSTANCE != null) {
			return;
		}

		// just creating the instance will install it
		AboutToolMacQuitHandler instance = new AboutToolMacQuitHandler();
		INSTANCE = instance;
	}

	private AboutToolMacQuitHandler() {
		// only we can construct
	}

	@Override
	public void about() {
		DockingWindowManager.showDialog(new AboutDialog());
	}

}
