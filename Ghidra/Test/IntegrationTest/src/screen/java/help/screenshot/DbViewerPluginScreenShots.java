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

import javax.swing.JComboBox;

import org.junit.Test;

import ghidra.app.plugin.debug.DbViewerPlugin;
import ghidra.app.plugin.debug.DbViewerProvider;

public class DbViewerPluginScreenShots extends GhidraScreenShotGenerator {

	public DbViewerPluginScreenShots() {
		super();
	}

	@Test
	public void testDatabaseViewer() {
		loadPlugin(DbViewerPlugin.class);
		DbViewerProvider provider = showProvider(DbViewerProvider.class);
		Object comp = getInstanceField("comp", provider);
		final JComboBox<?> combo = (JComboBox<?>) getInstanceField("combo", comp);
		runSwing(new Runnable() {
			@Override
			public void run() {
				int count = combo.getItemCount();
				for (int i = 0; i < count; i++) {
					Object item = combo.getItemAt(i);
					if (item.toString().startsWith("Metadata")) {
						combo.setSelectedIndex(i);
						break;
					}
				}
			}
		});
		captureIsolatedProvider(provider, 1000, 400);
	}

}
