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

import org.junit.Assert;
import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.plugin.core.function.editor.StorageAddressEditorDialog;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Symbol;

public class FunctionPluginScreenShots extends GhidraScreenShotGenerator {

	public FunctionPluginScreenShots() {
		super();
	}

	@Test
	public void testEditStorage() {
		Symbol symbol = getUniqueSymbol(program, "_memcpy");
		Function function = (Function) symbol.getObject();
		Parameter parameter = function.getParameter(0);

		DataTypeManagerService dtService = env.getTool().getService(DataTypeManagerService.class);
		Assert.assertNotNull(dtService);

		final StorageAddressEditorDialog dialog =
			new StorageAddressEditorDialog(program, dtService, parameter, 0);

		runSwing(new Runnable() {
			@Override
			public void run() {
				tool.showDialog(dialog);
			}
		}, false);

		captureDialog(600, 400);
	}

	@Test
	public void testFunctionEditor() {

		Symbol symbol = getUniqueSymbol(program, "_memcpy");
		goToListing(symbol.getAddress().getOffset(), "Function Signature", true);
		performAction("Edit Function", "FunctionPlugin", false);
		captureDialog(700, 550);
	}

	@Test
	public void testSetStackDepthChange() {
		final NumberInputDialog dialog = new NumberInputDialog("Set Stack Depth Change at 0x401482",
			"Stack Depth Change", 5, Integer.MIN_VALUE, Integer.MAX_VALUE, false);

		runSwing(new Runnable() {
			@Override
			public void run() {
				tool.showDialog(dialog);
			}
		}, false);
		captureDialog();

	}

	@Test
	public void testStackDepthChangeOrFunctionPurge() {
		goToListing(0x0040888c); // position at a call
		performAction("Set Stack Depth Change", "FunctionPlugin", false);
		pressOkOnDialog();
		captureDialog();
	}

}
