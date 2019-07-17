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

import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;

/**
 * A plugin-level quit handler that serves as the callback from the Dock's 'Quit' popup action.
 * <p>
 * This will also respond to the Command-Q callback.
 * <p>
 * Note: there is a big assumption for this class that the 'front end tool', whatever that may 
 * be for your application, will be installed before all other tools.  Thus, when quit is called
 * on your application, it will go through the main tool of your app, that knows about sub-tools
 * and such.  Moreover, you would not want this handler installed on a subordinate tool; otherwise, 
 * the quit handler would try to close the wrong tool when the handler is activated.
 */
public class PluginToolMacQuitHandler {

	private static boolean installed = false; // only install it once

	/**
	 * Applies a quit handler which will close the given tool.
	 * 
	 * @param tool The tool to close, which should result in the desired quit behavior.
	 */
	public static synchronized void install(PluginTool tool) {

		if (installed) {
			return;
		}
		installed = true;

		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.MAC_OS_X) {
			return;
		}

		Desktop.getDesktop().setQuitHandler((evt, response) -> {
			response.cancelQuit(); // allow our tool to quit the application instead of the OS
			tool.close();
		});
	}
}
