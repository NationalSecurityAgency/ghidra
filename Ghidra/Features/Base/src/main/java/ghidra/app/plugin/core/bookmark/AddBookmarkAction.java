/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.bookmark;

import ghidra.app.context.ListingActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.util.MarkerLocation;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.action.*;

/**
 * <CODE>AddBookmarkAction</CODE> allows the user to add a Note bookmark at the current location.
 */
class AddBookmarkAction extends DockingAction {
	/** the plugin associated with this action. */
	BookmarkPlugin plugin;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param name the name for this action.
	 * @param plugin the plugin this action is associated with.
	 */
	AddBookmarkAction(BookmarkPlugin plugin) {
		super("Add Bookmark", plugin.getName());
		this.plugin = plugin;
		setDescription("Add Notes bookmark to current location");
// ACTIONS - auto generated
		setPopupMenuData(new MenuData(new String[] { "Bookmark..." }, null, "Bookmark"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_D, InputEvent.CTRL_DOWN_MASK));

	}

	/**
	 * Method called when the action is invoked.
	 * @param ActionEvent details regarding the invocation of this action
	 */
	@Override
	public void actionPerformed(ActionContext context) {
		plugin.showAddBookmarkDialog(getAddress(context));
	}

	/**
	 * 
	 * @see docking.DockingAction#isEnabledForContext(java.lang.Object)
	 */
	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (context == null) {
			return false;
		}
		return getAddress(context) != null;
	}

	private Address getAddress(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (MarkerLocation.class.isAssignableFrom(contextObject.getClass())) {
			return ((MarkerLocation) contextObject).getAddr();
		}
		else if (context instanceof ListingActionContext) {
			return ((ListingActionContext) context).getAddress();
		}
		return null;
	}
}
