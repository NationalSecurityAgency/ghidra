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
package ghidra.dbg.jdi.rmi.jpda;

import java.io.IOException;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;

/**
 * This is a convenience class for preparing the JDI Client in a stand-alone jshell.
 * 
 * <p>
 * For any of the Ghidra stuff to work (including logging), the application needs to be initialized.
 * If we're in Ghidra's JVM, then we do not need this. Do not call it! If we're in a separate
 * subprocess, e.g., a stand-alone jshell, then we need to call this. Putting it all here lets the
 * scripts/user avoid tons of imports.
 */
public class GhidraJdiInit {
	/**
	 * Initialize the Ghidra application using all the defaults.
	 * 
	 * @throws IOException if the file system can't be read
	 */
	public static void initApp() throws IOException {
		GhidraApplicationLayout layout = new GhidraApplicationLayout();
		GhidraApplicationConfiguration config = new GhidraApplicationConfiguration();
		config.setShowSplashScreen(false);
		Application.initializeApplication(layout, config);
	}

	/**
	 * Initialize the Ghidra application in headless mode.
	 * 
	 * @throws IOException if the file system can't be read
	 */
	public static void initHeadless() throws IOException {
		GhidraApplicationLayout layout = new GhidraApplicationLayout();
		HeadlessGhidraApplicationConfiguration config =
			new HeadlessGhidraApplicationConfiguration();
		Application.initializeApplication(layout, config);
	}
}
