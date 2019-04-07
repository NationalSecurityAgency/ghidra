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
package ghidra.app.plugin.core.navigation.locationreferences;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * Only shows addresses to the code unit at the address for the current context.  This differs
 * from the normal 'find references' action in that it will find references by inspecting 
 * context for more information, potentially searching for more than just direct references to 
 * the code unit at the current address.
 */
public class FindReferencesToAddressAction extends ListingContextAction {

	private LocationReferencesPlugin plugin;

	public FindReferencesToAddressAction(LocationReferencesPlugin plugin, int subGroupPosition) {
		super("Show References to Address", plugin.getName(), false);

		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "References", "Show References to Address" },
			null, "ShowReferencesTo", MenuData.NO_MNEMONIC, Integer.toString(subGroupPosition)));

		setDescription("Shows references to the current Instruction or Data");
		setHelpLocation(new HelpLocation(plugin.getName(), "Show_Refs_To_Code_Unit"));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {

		Program program = context.getProgram();
		ProgramLocation location = context.getLocation();
		Address address = location.getAddress();
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(address);

		int[] path = location.getComponentPath();
		if (cu instanceof Data) {
			Data outerData = (Data) cu;
			Data data = outerData.getComponent(location.getComponentPath());
			address = data.getMinAddress();
		}

		AddressFieldLocation addressLocation =
			new AddressFieldLocation(program, address, path, address.toString(), 0);
		plugin.showReferencesToLocation(addressLocation, context.getNavigatable());
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		Program program = context.getProgram();
		ProgramLocation location = context.getLocation();
		Address address = location.getAddress();
		if (address == null) {
			return false;
		}

		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(address);
		if (cu == null) {
			return false;
		}

		return true;
	}
}
