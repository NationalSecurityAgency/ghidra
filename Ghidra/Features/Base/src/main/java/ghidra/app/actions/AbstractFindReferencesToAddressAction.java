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
package ghidra.app.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingType;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.ProgramLocationSupplierContext;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Only shows addresses to the code unit at the address for the current context.  This differs
 * from the normal 'find references' action in that it will find references by inspecting 
 * context for more information, potentially searching for more than just direct references to 
 * the code unit at the current address.
 */
public abstract class AbstractFindReferencesToAddressAction extends DockingAction {

	public static final String NAME = "Show References To Address";
	private static final String HELP_TOPIC = "LocationReferencesPlugin";

	private PluginTool tool;

	protected AbstractFindReferencesToAddressAction(PluginTool tool, String owner) {
		super(NAME, owner, KeyBindingType.SHARED);
		this.tool = tool;

		setDescription("Shows references to the current address");
		setHelpLocation(new HelpLocation(HELP_TOPIC, "Show_Refs_To_Code_Unit"));

		setContextClass(ProgramLocationSupplierContext.class, true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		ProgramLocationSupplierContext plc = (ProgramLocationSupplierContext) context;
		Navigatable navigatable = null;
		if (plc instanceof NavigatableActionContext nac) {
			navigatable = nac.getNavigatable();
		}
		else {
			GoToService goToService = tool.getService(GoToService.class);
			if (goToService == null) {
				Msg.showError(this, null, "Missing Plugin",
					"The " + GoToService.class.getSimpleName() + " is not installed.\n" +
						"Please add the plugin implementing this service.");
				return;
			}
			navigatable = goToService.getDefaultNavigatable();
		}

		showReferences(plc, navigatable);
	}

	private void showReferences(ProgramLocationSupplierContext context, Navigatable navigatable) {

		LocationReferencesService service = tool.getService(LocationReferencesService.class);
		if (service == null) {
			Msg.showError(this, null, "Missing Plugin",
				"The " + LocationReferencesService.class.getSimpleName() + " is not installed.\n" +
					"Please add the plugin implementing this service.");
			return;
		}

		ProgramLocation location = context.getLocation();
		Program program = location.getProgram();
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
		service.showReferencesToLocation(addressLocation, navigatable);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		ProgramLocationSupplierContext plc = (ProgramLocationSupplierContext) context;
		if (plc instanceof NavigatableActionContext nac) {
			if (!isMyNavigatable(nac)) {
				return false;
			}
		}

		ProgramLocation location = plc.getLocation();
		if (location == null) {
			return false;
		}

		Address address = location.getAddress();
		if (address == null) {
			return false;
		}

		Program program = location.getProgram();
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(address);
		if (cu == null) {
			return false;
		}

		return true;
	}

	protected abstract boolean isMyNavigatable(NavigatableActionContext context);
}
