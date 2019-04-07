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
package docking.help;

import docking.DefaultHelpService;
import docking.DockingWindowManager;

/**
 * Creates the HelpManager for the application. This is just a glorified global variable for 
 * the application.
 */
public class Help {

	private static HelpService helpService = new DefaultHelpService();

	/**
	 * Get the help service
	 * 
	 * @return  null if the call to setMainHelpSetURL() failed
	 */
	public static HelpService getHelpService() {
		return helpService;
	}

	// allows help services to install themselves 
	static void installHelpService(HelpService service) {
		helpService = service;
		DockingWindowManager.setHelpService(helpService);
	}

}
