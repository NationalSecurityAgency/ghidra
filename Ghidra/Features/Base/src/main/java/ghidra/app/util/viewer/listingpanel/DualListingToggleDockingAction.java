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
package ghidra.app.util.viewer.listingpanel;

import docking.ActionContext;
import docking.action.ToggleDockingAction;
import docking.widgets.fieldpanel.FieldPanel;

/**
 * Class that dual listing toggle actions should extend.
 */
abstract class DualListingToggleDockingAction extends ToggleDockingAction {

	/**
	 * Constructor that creates a toggle action for a dual listing.
	 * @param name the name for this action
	 * @param owner the owner of this action
	 * @param supportsKeyBindings true if this action's key binding should be managed
	 */
	public DualListingToggleDockingAction(String name, String owner, boolean supportsKeyBindings) {
		super(name, owner, supportsKeyBindings);
	}

	/**
	 * Constructor that creates a toggle action for a dual listing.
	 * @param name the name for this action
	 * @param owner the owner of this action
	 */
	public DualListingToggleDockingAction(String name, String owner) {
		super(name, owner);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (contextObject instanceof ListingCodeComparisonPanel) {
			Object sourceObject = context.getSourceObject();
			return sourceObject instanceof FieldPanel;
		}
		return false;
	}
}
