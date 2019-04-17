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
package ghidra.app.plugin.core.overview;

import java.awt.Component;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.util.HelpLocation;

/**
 * Base class for popup overview bar actions
 */
public abstract class AbstractColorOverviewAction extends DockingAction {

	private Component component;

	/**
	 * Constructor
	 *
	 * @param name the name of the action
	 * @param owner the name of the owner of the action.
	 * @param component the color bar component.
	 * @param help the help location for this action.
	 */
	public AbstractColorOverviewAction(String name, String owner, Component component,
			HelpLocation help) {
		super(name, owner);
		this.component = component;
		setPopupMenuData(new MenuData(new String[] { name }));
		setHelpLocation(help);
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return context.getContextObject() == component;
	}

}
