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

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JButton;

import docking.ActionContext;
import docking.action.*;
import docking.help.Help;
import docking.widgets.EventTrigger;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.exception.AssertException;
import resources.icons.EmptyIcon;

/**
 * An action that can be in one of multiple states.   The button of this action has a
 * drop-down icon that allows users to change the state of the button.  As the user changes the 
 * state of this action, {@link #actionStateChanged(ActionState, EventTrigger)} will be called.  
 * Clients may also use the button of this action to respond to button presses by overriding 
 * {@link #actionPerformed(ActionContext)}.
 *
 * <p>This action is intended primarily for use as toolbar actions.  Alternatively, some clients 
 * use this action to add a button to custom widgets.  In the custom usage case, clients should use
 * {@link NonToolbarMultiStateAction}.
 * 
 * @param <T> the type of the user data
 * @see MultiActionDockingAction
 */
public abstract class MultiStateDockingAction<T> extends DockingAction {

	private static Icon EMPTY_ICON = new EmptyIcon(16, 16);

	private List<ActionState<T>> actionStates = new ArrayList<>();
	private int currentStateIndex = -1;
	private MultiActionDockingActionIf multiActionGenerator;
	private MultipleActionDockingToolbarButton multipleButton;

	private Icon defaultIcon;
	private boolean useCheckboxForIcons;

	/**
	 * Call this constructor with this action will not be added to a toolbar
	 *
	 * @param name the action name
	 * @param owner the owner
	 * @see #MultiStateDockingAction(String, String, boolean)
	 */
	public MultiStateDockingAction(String name, String owner) {
		super(name, owner);
		multiActionGenerator = context -> getStateActions();

		// set this here so we don't have to check for null elsewhere
		super.setToolBarData(new ToolBarData(null));
	}

	/**
	 * Use this constructor explicitly when this action is used in a toolbar, passing true
	 * for <code>isToolbarAction</code> (see the javadoc header note).
	 *
	 * @param name the action name
	 * @param owner the owner
	 * @param isToolbarAction true if this action is a toolbar action
	 * @deprecated use {@link #MultiStateDockingAction(String, String)}
	 */
	@Deprecated(forRemoval = true, since = "10.2")
	protected MultiStateDockingAction(String name, String owner, boolean isToolbarAction) {
		this(name, owner);
	}

	/**
	 * This method will be called as the user changes the selected button state
	 * @param newActionState the newly selected state
	 * @param trigger the source of the event
	 */
	public abstract void actionStateChanged(ActionState<T> newActionState, EventTrigger trigger);

	/**
	 * This method is called when the user clicks the button <B>when this action is used as part of
	 * the default {@link DockingAction} framework.</B> 
	 * 
	 * This is the callback to be overridden when the child wishes to respond to user button
	 * presses that are on the button and not the drop-down.  The default behavior is to show the
	 * popup menu when the button is clicked.
	 */
	@Override
	public void actionPerformed(ActionContext context) {
		Swing.runLater(() -> multipleButton.showPopup());
	}

	/**
	 * Overrides the default icons for actions shown in popup menu of the multi-state action.  By
	 * default, the popup menu items will use the icons as provided by the {@link ActionState}.
	 * By passing true to this method, icons will not be used in the popup menu.  Instead, a
	 * checkbox icon will be used to show the active action state.
	 *
	 * @param useCheckboxForIcons true to use a checkbox
	 */
	public void setUseCheckboxForIcons(boolean useCheckboxForIcons) {
		this.useCheckboxForIcons = useCheckboxForIcons;
	}

	/**
	 * Sets the icon to use if the active action state does not supply an icon.  This is useful if
	 * you wish for your action states to not use icon, but desire the action itself to have an
	 * icon.
	 *
	 * @param icon the icon
	 */
	public void setDefaultIcon(Icon icon) {
		this.defaultIcon = icon;
	}

	protected List<DockingActionIf> getStateActions() {
		ActionState<T> selectedState = actionStates.get(currentStateIndex);
		List<DockingActionIf> actions = new ArrayList<>(actionStates.size());
		for (ActionState<T> actionState : actionStates) {

			//@formatter:off
			boolean isSelected = actionState == selectedState;
			DockingActionIf a = useCheckboxForIcons ?
				new ActionStateToggleAction(actionState, isSelected) :
			    new ActionStateAction(actionState, isSelected);
			actions.add(a);
			//@formatter:on
		}
		return actions;
	}

	public void setGroup(String group) {
		ToolBarData tbd = getToolBarData();
		tbd.setToolBarGroup(group);
	}

	public void setSubGroup(String subGroup) {
		ToolBarData tbd = getToolBarData();
		tbd.setToolBarSubGroup(subGroup);
	}

	/**
	 * add the supplied {@code ActionState}
	 * if {@code fireFirstEvent} is {@code true} the first one will fire its event
	 * @param actionState the {@code ActionState} to add
	 */
	public void addActionState(ActionState<T> actionState) {
		actionStates.add(actionState);
		if (actionStates.size() == 1) {
			setCurrentActionState(actionState);
		}
	}

	public void setActionStates(List<ActionState<T>> newStates) {
		if (newStates.isEmpty()) {
			throw new IllegalArgumentException("You must provide at least one ActionState");
		}
		actionStates = new ArrayList<>(newStates);
		setCurrentActionState(actionStates.get(0));
	}

	public T getCurrentUserData() {
		return actionStates.get(currentStateIndex).getUserData();
	}

	public ActionState<T> getCurrentState() {
		return actionStates.get(currentStateIndex);
	}

	public List<ActionState<T>> getAllActionStates() {
		return new ArrayList<>(actionStates);
	}

	public void setCurrentActionStateByUserData(T t) {
		for (ActionState<T> actionState : actionStates) {

			// Note: most clients will pass a T that is already in our list.  However, to be more
			//       flexible, such as for clients with a T class of String, we should have no
			//       problem using equals() here.
			// if (actionState.getUserData() == t) {
			if (actionState.getUserData().equals(t)) {
				setCurrentActionState(actionState);
				return;
			}
		}

		throw new AssertException(
			"Attempted to set an action state by a user type not contained herein: " + t);
	}

	public void setCurrentActionState(ActionState<T> actionState) {
		setCurrentActionStateWithTrigger(actionState, EventTrigger.API_CALL);
	}

	public void setCurrentActionStateWithTrigger(ActionState<T> actionState, EventTrigger trigger) {
		int indexOf = actionStates.indexOf(actionState);
		if (indexOf < 0) {
			throw new IllegalArgumentException(
				"Attempted to set actionState to unknown ActionState.");
		}
		currentStateIndex = indexOf;

		setButtonState(actionState);

		ToolBarData tbd = getToolBarData();
		tbd.setIcon(getIcon(actionState));

		setDescription(getToolTipText());
		actionStateChanged(actionState, trigger);
	}

	private Icon getIcon(ActionState<T> actionState) {
		Icon icon = actionState.getIcon();
		if (icon != null) {
			return icon;
		}

		if (defaultIcon != null) {
			return defaultIcon;
		}

		return EMPTY_ICON;
	}

	@Override
	public JButton doCreateButton() {
		multipleButton = new MultipleActionDockingToolbarButton(multiActionGenerator);
		if (currentStateIndex >= 0) {
			ActionState<T> actionState = actionStates.get(currentStateIndex);
			setButtonState(actionState);
		}

		return multipleButton;
	}

	private void setButtonState(ActionState<T> actionState) {

		if (multipleButton == null) {
			return;
		}

		if (actionState == null) {
			multipleButton.setIcon(null);
			multipleButton.setToolTipText(null);
			return;
		}

		Icon icon = getIcon(actionState);
		multipleButton.setIcon(icon);
		multipleButton.setToolTipText(actionState.getName());
	}

	@Override
	public void setMenuBarData(MenuData newMenuData) {
		throw new UnsupportedOperationException();
	}

	protected void superSetMenuBarData(MenuData newMenuData) {
		super.setMenuBarData(newMenuData);
	}

	@Override
	public void setPopupMenuData(MenuData newMenuData) {
		throw new UnsupportedOperationException();
	}

	public String getToolTipText() {
		if (actionStates.isEmpty()) {
			return getName() + ": <no action states installed>";
		}
		return getName() + ": " + getCurrentState().getName();
	}

	protected void showPopup() {
		multipleButton.showPopup();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ActionStateToggleAction extends ToggleDockingAction {

		private final ActionState<T> actionState;

		private ActionStateToggleAction(ActionState<T> actionState, boolean isSelected) {
			super(actionState.getName(), "MultiStateAction");

			this.actionState = actionState;

			setSelected(isSelected);

			setMenuBarData(new MenuData(new String[] { actionState.getName() }));
			HelpLocation helpLocation = actionState.getHelpLocation();
			if (helpLocation != null) {
				setHelpLocation(helpLocation);
			}
			else {
				HelpLocation parentHelp =
					Help.getHelpService().getHelpLocation(MultiStateDockingAction.this);
				setHelpLocation(parentHelp);
			}
		}

		@Override
		public String getInceptionInformation() {
			// we want the debug info for these internal actions to be that of the outer class
			return MultiStateDockingAction.this.getInceptionInformation();
		}

		@Override
		public void actionPerformed(ActionContext context) {
			setCurrentActionStateWithTrigger(actionState, EventTrigger.GUI_ACTION);
		}

	}

	private class ActionStateAction extends DockingAction {

		private final ActionState<T> actionState;

		private ActionStateAction(ActionState<T> actionState, boolean isSelected) {
			super(actionState.getName(), "MultiStateAction");
			this.actionState = actionState;

			setMenuBarData(
				new MenuData(new String[] { actionState.getName() }, actionState.getIcon()));
			HelpLocation helpLocation = actionState.getHelpLocation();
			if (helpLocation != null) {
				setHelpLocation(helpLocation);
			}
			else {
				HelpLocation parentHelp =
					Help.getHelpService().getHelpLocation(MultiStateDockingAction.this);
				setHelpLocation(parentHelp);
			}
		}

		@Override
		public String getInceptionInformation() {
			// we want the debug info for these internal actions to be that of the outer class
			return MultiStateDockingAction.this.getInceptionInformation();
		}

		@Override
		public void actionPerformed(ActionContext context) {
			setCurrentActionStateWithTrigger(actionState, EventTrigger.GUI_ACTION);
		}

	}

}
