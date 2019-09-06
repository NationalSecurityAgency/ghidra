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

import javax.swing.KeyStroke;

import docking.action.*;
import ghidra.app.actions.AbstractFindReferencesDataTypeAction;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;

/**
 * {@link LocationReferencesPlugin}'s action for finding references to a thing.
 */
public class FindReferencesToAction extends ListingContextAction {

	private LocationReferencesPlugin plugin;
	private int subGroupPosition;

	public FindReferencesToAction(LocationReferencesPlugin plugin, int subGroupPosition) {
		super(AbstractFindReferencesDataTypeAction.NAME, plugin.getName(), KeyBindingType.SHARED);
		this.plugin = plugin;
		this.subGroupPosition = subGroupPosition;

		updateMenuName(null);

		setDescription("Shows references to the item under the cursor");

		KeyStroke defaultkeyStroke = AbstractFindReferencesDataTypeAction.DEFAULT_KEY_STROKE;
		initKeyStroke(defaultkeyStroke);
	}

	private void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.displayProvider(context);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		LocationDescriptor descriptor = getDescriptor(context);
		if (descriptor == null) {
			return false;
		}

		updateMenuName(descriptor);

		return true;
	}

	private LocationDescriptor getDescriptor(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		if (location.getAddress() == null) {
			if (location.getComponentPath() == null) {
				return null;
			}
		}

		LocationDescriptor descriptor = plugin.getLocationDescriptor(location);
		return descriptor;
	}

	@Override
	protected boolean isAddToPopup(ListingActionContext context) {
		if (!super.isAddToPopup(context)) {
			return false;
		}

		LocationDescriptor descriptor = getDescriptor(context);
		if (descriptor == null) {
			return false;
		}

		if (!(descriptor instanceof AddressLocationDescriptor)) {
			return true;
		}

		AddressLocationDescriptor addressDescriptor = (AddressLocationDescriptor) descriptor;
		Address homeAddress = addressDescriptor.getHomeAddress();
		Address actionAddress = context.getAddress();
		if (actionAddress.equals(homeAddress)) {
			// A bit of guilty knowledge here: this is handled by another action, the
			// FindReferencesToAddressAction. For that situation, we don't want two actions 
			// appearing in the popup menu.
			return false;
		}

		return true;
	}

	private void updateMenuName(LocationDescriptor descriptor) {

		String menuName = getMenuPrefix(descriptor);
		if (descriptor != null) {
			String itemName = descriptor.getTypeName();
			menuName += itemName;
		}

		setPopupMenuData(
			new MenuData(new String[] { LocationReferencesService.MENU_GROUP, menuName }, null,
				"ShowReferencesTo", MenuData.NO_MNEMONIC, Integer.toString(subGroupPosition)));
	}

	private String getMenuPrefix(LocationDescriptor descriptor) {
		String menuName = "Show References to ";
		if (descriptor == null) {
			return menuName;
		}

		if (descriptor instanceof DataTypeLocationDescriptor) {
			menuName = "Find Uses of ";
		}

		if (descriptor instanceof StructureMemberLocationDescriptor) {
			menuName = "Find References to ";
		}

		return menuName;
	}
}
