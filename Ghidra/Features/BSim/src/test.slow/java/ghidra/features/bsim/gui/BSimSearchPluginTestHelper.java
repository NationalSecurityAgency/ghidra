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
package ghidra.features.bsim.gui;

import ghidra.features.bsim.gui.search.dialog.BSimServerManager;
import ghidra.features.bsim.query.facade.SFQueryServiceFactory;

public class BSimSearchPluginTestHelper {
	public static BSimServerManager getServerManager(BSimSearchPlugin plugin) {
		return plugin.getServerManager();
	}

	public static void setQueryServiceFactory(BSimSearchPlugin plugin,
		SFQueryServiceFactory factory) {
		plugin.setQueryServiceFactory(factory);
	}
}
