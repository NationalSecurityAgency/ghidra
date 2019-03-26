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
package help.screenshot;

import org.junit.Test;

import docking.action.DockingActionIf;
import ghidra.app.plugin.core.scalartable.*;

public class ScalarSearchPluginScreenShots extends GhidraScreenShotGenerator {

	@Test
	public void testSearchAllScalarsDialog() {

		ScalarSearchPlugin plugin = env.getPlugin(ScalarSearchPlugin.class);
		DockingActionIf action = getAction(plugin, "Search for Scalars");
		performAction(action, false);
		captureDialog(ScalarSearchDialog.class);
	}

	@Test
	public void testScalarWindow() {

		ScalarSearchPlugin plugin = env.getPlugin(ScalarSearchPlugin.class);
		DockingActionIf action = getAction(plugin, "Search for Scalars");
		performAction(action, false);
		ScalarSearchDialog dialog = waitForDialogComponent(ScalarSearchDialog.class);
		pressButtonByText(dialog, "Search");
		waitForSwing();

		ScalarSearchProvider provider = getProvider(ScalarSearchProvider.class);
		waitForTableModel(provider.getScalarModel());

		captureIsolatedProvider(provider.getClass(), 800, 500);
	}
}
