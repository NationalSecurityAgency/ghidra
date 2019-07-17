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
package ghidra.app.plugin.core.function.tags;

import docking.ComponentProvider;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.program.model.address.Address;
import ghidra.program.util.FunctionLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * Presents the user with a {@link ComponentProvider} showing all function tags available, 
 * along with all those currently assigned to the selected function.  
 * Users may select, deselect, edit or delete tags.
 */
public class EditFunctionTagsAction extends ListingContextAction {

	private FunctionTagPlugin plugin;

	// Menu option that will show up when right-clicking on a function in
	// the listing.
	private final String MENU_LABEL = "Edit Tags...";

	/**
	 * Constructor.
	 * 
	 * @param name the name for this action.
	 * @param plugin the plugin this action is associated with.
	 */
	public EditFunctionTagsAction(String name, FunctionTagPlugin plugin) {
		super(name, plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(
			new MenuData(new String[] { FunctionPlugin.FUNCTION_MENU_PULLRIGHT, MENU_LABEL }, null,
				FunctionTagPlugin.FUNCTION_TAG_MENU_SUBGROUP));

		setHelpLocation(new HelpLocation("FunctionPlugin", "Functions"));

		setEnabled(true);
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	@Override
	public void actionPerformed(ListingActionContext context) {

		// First find out if we're at a valid function location. If not,
		// just exit.
		Address functionAddress = getFunctionAddress(context.getLocation());
		if (functionAddress == null) {
			return;
		}

		showProvider(context);
	}

	/******************************************************************************
	 * PROTECTED METHODS
	 ******************************************************************************/

	/**
	 * Overridden to only allow this menu option when clicking in a function.
	 * Note that we do not allow external functions to have tags.
	 * 
	 * @param context the listing context
	 * @return
	 */
	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {

		if (context.hasSelection() || context.getAddress() == null) {
			return false;
		}

		if (context.getLocation().getAddress().isExternalAddress()) {
			return false;
		}

		Address funcAddress = getFunctionAddress(context.getLocation());
		if (funcAddress == null) {
			return false;
		}

		return !funcAddress.isExternalAddress();
	}

	/******************************************************************************
	 * PRIVATE METHODS
	 ******************************************************************************/
	/**
	 * Retrieves the address of the function associated with the given program location.
	 * 
	 * @param loc the program location
	 * @return the entry point of the function, or null if not valid
	 */
	private Address getFunctionAddress(ProgramLocation loc) {

		if (loc instanceof FunctionLocation) {
			FunctionLocation functionLocation = (FunctionLocation) loc;
			Address functionAddress = functionLocation.getFunctionAddress();
			return functionAddress;
		}

		return null;
	}

	/**
	 * Displays the provider.
	 * 
	 * @param context the listing context
	 */
	private void showProvider(ListingActionContext context) {
		plugin.getProvider().setVisible(true);
	}
}
