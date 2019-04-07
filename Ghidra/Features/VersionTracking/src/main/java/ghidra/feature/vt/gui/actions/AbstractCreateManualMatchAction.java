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
package ghidra.feature.vt.gui.actions;

import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.provider.functionassociation.FunctionAssociationContext;
import docking.ActionContext;
import docking.action.DockingAction;

/**
 * An abstract action that can be extended for each of the actions that create a manual match
 * plus possibly making some follow on changes related to that match.
 * This class provides default action enablement based on context.
 */
abstract class AbstractCreateManualMatchAction extends DockingAction {

	protected static final String MENU_GROUP = "Create";

	protected final VTController controller;

	/**
	 * Constructor.
	 * @param name the action's name
	 * @param owner the action's owner
	 * @param controller the controller for the version tracking session
	 */
	AbstractCreateManualMatchAction(String name, String owner, VTController controller) {
		super(name, owner);
		this.controller = controller;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof FunctionAssociationContext)) {
			return false;
		}

		FunctionAssociationContext providerContext = (FunctionAssociationContext) context;
		return providerContext.canCreateMatch();
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return (context instanceof FunctionAssociationContext);
	}
}
