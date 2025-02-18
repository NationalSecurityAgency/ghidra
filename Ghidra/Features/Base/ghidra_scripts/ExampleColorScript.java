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
// An example of how to color the listing background
//@__params_start
//@category Examples
//@toolbar world.png
//@menupath Tools.Scripts Manager.Example Color Script
//@__params_end

import java.awt.Color;

import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class ExampleColorScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		ColorizingService service = state.getTool().getService(ColorizingService.class);
		if (service == null) {
			println("Can't find ColorizingService service");
			return;
		}

		if (currentSelection != null) {
			service.setBackgroundColor(currentSelection, Palette.PINK);
		}
		else if (currentAddress != null) {
			service.setBackgroundColor(currentAddress, currentAddress, Palette.PINK);
		}
		else {
			println("No selection or current address to color");
			return;
		}

		Address anotherAddress = currentAddress.add(10);
		setBackgroundColor(anotherAddress, Color.YELLOW);

		// create an address set with values you want to change
		AddressSet addresses = new AddressSet();
		addresses.add(currentAddress.add(10));
		addresses.add(currentAddress.add(11));
		addresses.add(currentAddress.add(12));

		setBackgroundColor(addresses, new Color(100, 100, 200));
	}

}
