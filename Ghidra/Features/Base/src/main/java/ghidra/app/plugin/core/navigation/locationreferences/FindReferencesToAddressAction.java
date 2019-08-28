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
import ghidra.app.actions.AbstractFindReferencesToAddressAction;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.NavigatableActionContext;

/**
 * Only shows addresses to the code unit at the address for the current context.  This differs
 * from the normal 'find references' action in that it will find references by inspecting 
 * context for more information, potentially searching for more than just direct references to 
 * the code unit at the current address.
 */
public class FindReferencesToAddressAction extends AbstractFindReferencesToAddressAction {

	public FindReferencesToAddressAction(LocationReferencesPlugin plugin, int subGroupPosition) {
		super(plugin.getTool(), plugin.getName());

		setPopupMenuData(new MenuData(new String[] { LocationReferencesService.MENU_GROUP, NAME },
			null, "ShowReferencesTo", MenuData.NO_MNEMONIC, Integer.toString(subGroupPosition)));
	}

	@Override
	public boolean isEnabledForContext(NavigatableActionContext context) {
		if (!(context instanceof ListingActionContext)) {
			// Restrict this action to the Listing.  We have guilty knowledge that there are 
			// other sibling classes to this one for other contexts.
			return false;
		}
		return super.isEnabledForContext(context);
	}
}
