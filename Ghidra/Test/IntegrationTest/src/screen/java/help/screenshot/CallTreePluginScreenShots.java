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

import javax.swing.JSplitPane;

import org.junit.Test;

import docking.ComponentProvider;
import ghidra.app.plugin.core.calltree.CallTreeProvider;

public class CallTreePluginScreenShots extends GhidraScreenShotGenerator {

	public CallTreePluginScreenShots() {
		super();
	}

@Test
    public void testCallTreeWindow() {
		positionListingTop(0x4014e0);
		performAction("Show Function Call Trees", "CallTreePlugin", true);

		runSwing(new Runnable() {
			@Override
			public void run() {
				ComponentProvider provider = getProvider(CallTreeProvider.class);
				JSplitPane splitPane = (JSplitPane) getInstanceField("splitPane", provider);
				splitPane.setResizeWeight(0.5);
			}
		});

		captureIsolatedProvider(CallTreeProvider.class, 700, 500);
	}

}
