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

import docking.action.DockingAction;
import ghidra.app.plugin.core.checksums.ComputeChecksumsPlugin;
import ghidra.app.plugin.core.checksums.ComputeChecksumsProvider;

public class ComputeChecksumsPluginScreenShots extends GhidraScreenShotGenerator {

	public ComputeChecksumsPluginScreenShots() {
		super();
	}

	@Test
	public void testDialog_Blank() {
		positionListingTop(0x4014b0);
		performAction("GenerateChecksum", "ComputeChecksumsPlugin", true);
		captureProvider(ComputeChecksumsProvider.class);
	}

	@Test
	public void testDialog() {
		positionListingTop(0x4014b0);
		performAction("GenerateChecksum", "ComputeChecksumsPlugin", true);
		ComputeChecksumsPlugin plugin = getPlugin(tool, ComputeChecksumsPlugin.class);
		DockingAction computeAction = (DockingAction) getAction(plugin, "Compute Checksum");
		performAction(computeAction, true);
		captureProvider(ComputeChecksumsProvider.class);
	}

}
