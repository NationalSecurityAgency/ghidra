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

import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import org.junit.Test;

import docking.widgets.table.GTable;
import ghidra.app.plugin.core.functionwindow.FunctionWindowProvider;

public class FunctionWindowPluginScreenShots extends GhidraScreenShotGenerator {

	public FunctionWindowPluginScreenShots() {
		super();
	}

	@Test
	public void testFunctionWindow() {
		showProvider(FunctionWindowProvider.class);
		setColumnSizes();
		captureIsolatedProvider(FunctionWindowProvider.class, 700, 300);
	}

	private void setColumnSizes() {
		// note: these values are rough values found by trial-and-error
		FunctionWindowProvider provider = getProvider(FunctionWindowProvider.class);
		final GTable table = (GTable) getInstanceField("functionTable", provider);
		runSwing(new Runnable() {
			@Override
			public void run() {
				TableColumnModel columnModel = table.getColumnModel();
				int columnCount = columnModel.getColumnCount();
				for (int i = 0; i < columnCount; i++) {
					TableColumn column = columnModel.getColumn(i);
					Object headerValue = column.getHeaderValue();
					if ("Name".equals(headerValue)) {
						column.setPreferredWidth(85);
					}
					else if ("Location".equals(headerValue)) {
						column.setPreferredWidth(70);
					}
					else if ("Function Signature".equals(headerValue)) {
						column.setPreferredWidth(400);
					}
					else if ("Function Size".equals(headerValue)) {
						column.setPreferredWidth(25);
					}
				}
			}
		});

	}
}
