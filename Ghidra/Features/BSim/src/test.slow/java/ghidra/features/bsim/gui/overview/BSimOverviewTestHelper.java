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
package ghidra.features.bsim.gui.overview;

import ghidra.features.bsim.gui.BSimSearchPlugin;
import ghidra.features.bsim.gui.BSimSearchPluginTestHelper;
import ghidra.features.bsim.gui.search.dialog.*;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.facade.TestBSimServerInfo;
import ghidra.features.bsim.query.facade.TestSFQueryServiceFactory;
import ghidra.util.Swing;

public class BSimOverviewTestHelper {

	public static BSimOverviewModel getOverviewModel(BSimOverviewProvider overviewProvider) {
		return overviewProvider.getModel();
	}

	public static void setBSimOVerviewTestServer(BSimSearchPlugin plugin,
		BSimOverviewDialog dialog, FunctionDatabase database) {
		BSimServerInfo serverInfo = new TestBSimServerInfo(database);
		Swing.runNow(() -> {
			TestSFQueryServiceFactory factory = new TestSFQueryServiceFactory(database);
			BSimSearchPluginTestHelper.setQueryServiceFactory(plugin, factory);
			BSimServerManager serverManager = BSimSearchPluginTestHelper.getServerManager(plugin);
			serverManager.addServer(serverInfo);
		});
		Swing.runNow(() -> {
			BSimSearchDialogTestHelper.setSelectedServer(dialog, serverInfo);
		});
	}
}
