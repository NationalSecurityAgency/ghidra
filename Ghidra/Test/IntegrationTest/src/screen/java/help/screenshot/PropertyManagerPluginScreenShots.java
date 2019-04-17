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

import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.debug.propertymanager.PropertyManagerPlugin;
import ghidra.app.plugin.debug.propertymanager.PropertyManagerProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.model.util.PropertyMapManager;

public class PropertyManagerPluginScreenShots extends GhidraScreenShotGenerator {

	public PropertyManagerPluginScreenShots() {
		super();
	}

	@Override
	public void setUp() throws Exception {
		super.setUp();

		// create some properties
		int id = program.startTransaction("test");
		PropertyMapManager pm = program.getUsrPropertyManager();
		pm.createIntPropertyMap("Foo Property");
		IntPropertyMap map1 = pm.createIntPropertyMap("Bar Property");
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(".text");
		Address addr = block.getStart();
		for (int i = 0; i < 5000; i++) {
			map1.add(addr, i);
			addr = addr.add(10);
		}

		program.endTransaction(id, true);
		loadPlugin(PropertyManagerPlugin.class);
		showProvider(PropertyManagerProvider.class);
		PropertyManagerProvider provider = getProvider(PropertyManagerProvider.class);
		goToListing(0x00401082);
		final JTable table = (JTable) getInstanceField("table", provider);
		runSwing(new Runnable() {

			@Override
			public void run() {
				table.setRowSelectionInterval(0, 0);
			}
		});
	}

@Test
    public void testMarkers() {
		captureProvider(CodeViewerProvider.class);

	}

@Test
    public void testPropertyViewer() {
		captureIsolatedProvider(PropertyManagerProvider.class, 400, 300);
	}
}
