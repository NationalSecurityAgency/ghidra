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

import ghidra.bitpatterns.gui.*;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.util.Msg;

public class FunctionBitPatternsExplorerPluginScreenShots extends GhidraScreenShotGenerator {

	@Test
	public void testDataGatheringParams() {
		runSwing(() -> {
			FunctionBitPatternsExplorerPlugin plugin = new FunctionBitPatternsExplorerPlugin(tool);
			try {
				tool.addPlugin(plugin);
			}
			catch (PluginException e) {
				Msg.error(this, e);
			}
		});
		performAction(FunctionBitPatternsMainProvider.EXPLORE_FUNCTION_PATTERNS_TEXT, "TestCodeBrowser", false);
		waitForSwing();
		captureDialog();
		DataGatheringParamsDialog dialogComponent =
			waitForDialogComponent(null, DataGatheringParamsDialog.class, 2000);
		runSwing(() -> dialogComponent.close());
	}

	@Test
	public void testTabbedView() {
		runSwing(() -> {
			FunctionBitPatternsExplorerPlugin plugin = new FunctionBitPatternsExplorerPlugin(tool);
			try {
				tool.addPlugin(plugin);
			}
			catch (PluginException e) {
				Msg.error(this, e);
			}
		});
		performAction(FunctionBitPatternsMainProvider.EXPLORE_FUNCTION_PATTERNS_TEXT, "TestCodeBrowser", false);
		pressOkOnDialog();
		waitForSwing();
		captureIsolatedProvider(FunctionBitPatternsMainProvider.class, 1600, 600);
	}

}
