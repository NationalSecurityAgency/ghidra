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

import javax.swing.JTable;

import org.junit.Test;

import docking.ComponentProvider;

public class DataWindowPluginScreenShots extends GhidraScreenShotGenerator {

	public DataWindowPluginScreenShots() {
		super();
	}

@Test
    public void testDataWindow() {

		performAction("Defined Data", "DockingWindows", true);

		ComponentProvider provider = getProvider("Data Window");

		// show some interesting data
		JTable table = findComponent(provider.getComponent(), JTable.class);
		int row = findRowByPartialText(table, "bad allocation");
		scrollToRow(table, row);

		captureIsolatedProviderWindow(provider.getClass(), 500, 300);
	}

@Test
    public void testDataWindowFilter() {
		performAction("Defined Data", "DockingWindows", true);

		performAction("Filter Data Types", "DataWindowPlugin", false);

		captureDialog();
	}

}
