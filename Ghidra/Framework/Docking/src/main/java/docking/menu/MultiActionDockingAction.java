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
package docking.menu;

import java.util.Collections;
import java.util.List;

import javax.swing.JButton;

import docking.ActionContext;
import docking.action.*;

/**
 * A class that supports multiple sub-actions, as well as a primary action.  This is useful for
 * actions that perform navigation operations.
 * <p>
 * Clients may add actions to this class with the intention that they will be accessible
 * to the user via a GUI; for example, from a popup menu.
 * <p>
 * Actions added must have menu bar data set.
 *
 * <p>This action has a drop-down button that shows a popup menu of all available actions for
 * the user to execute.
 *
 * <p>
 * If the user executes this action directly, then
 * {@link #actionPerformed(ActionContext)} will be called.   Otherwise, the
 * {@link DockingAction#actionPerformed(ActionContext)} method of the sub-action
 * that was executed will be called.
 *
 * @see MultiStateDockingAction
 */
public abstract class MultiActionDockingAction extends DockingAction
		implements MultiActionDockingActionIf {

	private List<DockingActionIf> actionList = Collections.emptyList();
	private boolean performActionOnButtonClick = true;

	public MultiActionDockingAction(String name, String owner) {
		super(name, owner);
	}

	public void setActions(List<DockingActionIf> actionList) {
		if (actionList == null) {
			this.actionList = Collections.emptyList();
		}
		else {
			this.actionList = actionList;
		}
	}

	@Override
	public List<DockingActionIf> getActionList(ActionContext context) {
		return actionList;
	}

	@Override
	public JButton doCreateButton() {
		MultipleActionDockingToolbarButton button = new MultipleActionDockingToolbarButton(this);
		button.setPerformActionOnButtonClick(performActionOnButtonClick);
		return button;
	}

	/**
	 * By default a click on this action will trigger <code>actionPerformed()</code> to be called.
	 * You can call this method to disable that feature.  When called with <code>false</code>, this
	 * method will effectively let the user click anywhere on the button or its drop-down arrow
	 * to show the popup menu.  During normal operation, the user can only show the popup by
	 * clicking the drop-down arrow.
	 * @param performActionOnButtonClick if true, pressing the button calls actionPerformed;
	 * otherwise it pops up the menu.
	 */
	public void setPerformActionOnButtonClick(boolean performActionOnButtonClick) {
		this.performActionOnButtonClick = performActionOnButtonClick;
	}

	public static DockingActionIf createSeparator() {
		DockingAction separatorAction = new DockingAction("", "") {
			@Override
			public void actionPerformed(ActionContext context) {
				// dummy action
			}
		};
		separatorAction.setMenuBarData(new MenuData(new String[] { "" }));
		separatorAction.setEnabled(false);
		return separatorAction;
	}

//==================================================================================================
// DockableAction methods
//==================================================================================================

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return isEnabled();
	}
}
