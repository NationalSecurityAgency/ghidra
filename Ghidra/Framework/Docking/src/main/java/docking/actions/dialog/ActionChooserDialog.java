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
package docking.actions.dialog;

import static ghidra.util.HTMLUtilities.*;

import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.HashSet;
import java.util.Set;
import java.util.function.BiPredicate;

import javax.swing.*;

import docking.*;
import docking.action.*;
import docking.actions.KeyBindingUtils;
import docking.widgets.list.GListCellRenderer;
import docking.widgets.searchlist.SearchList;
import docking.widgets.searchlist.SearchListEntry;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.util.HTMLUtilities;
import ghidra.util.Swing;
import resources.Icons;

/**
 * Dialog for displaying and invoking docking actions. The dialog will display a mix of local
 * and global actions that varies depending on its current {@link ActionDisplayLevel}.
 */
public class ActionChooserDialog extends DialogComponentProvider {
	private ActionsModel model;
	private SearchList<DockingActionIf> searchList;
	private ActionRunner actionRunner;

	/**
	 * Constructor given an ActionsModel.
	 * @param model the ActionsModel to use in the dialog
	 */
	public ActionChooserDialog(ActionsModel model) {
		super("Action Chooser Dialog");
		this.model = model;
		addWorkPanel(buildMainPanel());
		setPreferredSize(600, 600);
		addOKButton();
		addCancelButton();
		updateTitle();
		setAccessibleDescription(
			"This dialog initialy shows only locally relevant actions. Repeat initial keybinding " +
				"to show More. Use up down arrows to scroll through list of actions and press" +
				" enter to invoke selected action. Type text to filter list.");
		setOkEnabled(false);
	}

	@Override
	protected void dialogShown() {
		// showing the dialog causes the docking windows system to clear the mouse over action,
		// so we need to re-establish the mouse over action after the dialog is shown
		Swing.runLater(() -> {
			DockingWindowManager.setMouseOverAction(searchList.getSelectedItem());
		});
	}

	/**
	 * Constructor for when a {@link ComponentProvider} has focus
	 * @param tool the active tool
	 * @param provider the ComponentProvider that has focus
	 * @param context the ActionContext that is active and will be used to invoke the chosen action
	 */
	public ActionChooserDialog(Tool tool, ComponentProvider provider, ActionContext context) {
		this(provider.getLocalActions(), tool.getGlobalActions(), context);
	}

	/**
	 * Constructor for when a {@link DialogComponentProvider} has focus
	 * @param tool the active tool
	 * @param dialog the DialogComponentProvider that has focus
	 * @param context the ActionContext that is active and will be used to invoke the chosen action
	 */
	public ActionChooserDialog(Tool tool, DialogComponentProvider dialog, ActionContext context) {
		this(dialog.getActions(), new HashSet<>(), context);
	}

	private ActionChooserDialog(Set<DockingActionIf> localActions,
			Set<DockingActionIf> globalActions, ActionContext context) {
		this(new ActionsModel(localActions, globalActions, context));
	}

	/**
	 * Returns the current {@link ActionDisplayLevel}
	 * @return the current action display level
	 */
	public ActionDisplayLevel getActionDisplayLevel() {
		return model.getActionDisplayLevel();
	}

	/**
	 * Sets the {@link ActionDisplayLevel} for the dialog which determines which actions to display
	 * @param level the action display level to use.
	 */
	public void setActionDisplayLevel(ActionDisplayLevel level) {
		model.setDisplayLevel(level);
		updateTitle();
	}

	@Override
	protected void okCallback() {
		DockingActionIf action = searchList.getSelectedItem();
		if (action != null) {
			actionChosen(action);
		}
	}

	private void updateTitle() {
		switch (model.getActionDisplayLevel()) {
			case LOCAL:
				setTitle("Relevant Actions (" + model.getSize() + ")");
				break;
			case GLOBAL:
				setTitle("All Valid Local and Global Actions (" + model.getSize() + ")");
				break;
			case ALL:
				setTitle("All Local and Global Actions (" + model.getSize() + ")");
				break;
		}
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(5, 2, 0, 2));
		searchList = new SearchList<DockingActionIf>(model, (a, c) -> actionChosen(a)) {
			@Override
			protected BiPredicate<DockingActionIf, String> createFilter(String text) {
				return new ActionsFilter(text);
			}
		};

		searchList.setSelectionCallback(this::itemSelected);
		searchList.setInitialSelection();  // update selection after adding our listener
		searchList.setItemRenderer(new ActionRenderer());
		searchList.setDisplayNameFunction(
			(t, c) -> getActionDisplayName(t, c) + " " + getKeyBindingString(t));
		panel.add(searchList);
		return panel;
	}

	private void actionChosen(DockingActionIf action) {
		if (!canPerformAction(action)) {
			return;
		}
		ActionContext context = model.getContext();
		close();
		scheduleActionAfterFocusRestored(action, context);
	}

	private void scheduleActionAfterFocusRestored(DockingActionIf action, ActionContext context) {
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		actionRunner = new ActionRunner(action, context);
		kfm.addPropertyChangeListener("permanentFocusOwner", actionRunner);
	}

	// for testing
	ActionRunner getActionRunner() {
		return actionRunner;
	}

	// for testing
	void selectAction(DockingActionIf action) {
		searchList.setSelectedItem(action);
	}

	@Override
	public void dispose() {
		super.dispose();
		searchList.dispose();
	}

	private boolean canPerformAction(DockingActionIf action) {
		if (action == null) {
			return false;
		}
		ActionContext context = model.getContext();
		return action.isValidContext(context) && action.isEnabledForContext(context);
	}

	private void itemSelected(DockingActionIf action) {
		// sets the global mouse over action, so that the tool's help action (F1) and 
		// setKeybinding action (F4) work on the currently selected action in the dialog
		DockingWindowManager.setMouseOverAction(action);
		setOkEnabled(canPerformAction(action));
	}

	private static String getActionsDisplayMenuName(DockingActionIf action, MenuData menuData) {
		return menuData.getMenuPathDisplayString();
	}

	private static String colorKeyBindingString(Color color, DockingActionIf action) {
		String keyStroke = getKeyBindingString(action);
		String keyBindingString = HTMLUtilities.escapeHTML(keyStroke);

		String coloredString = HTMLUtilities.colorString(color, keyBindingString);
		return HTML_SPACE + HTML_SPACE + coloredString;
	}

	private static String getKeyBindingString(DockingActionIf action) {
		KeyStroke keyBinding = action.getKeyBinding();
		if (keyBinding == null) {
			return "";
		}

		return "(" + KeyBindingUtils.parseKeyStroke(keyBinding) + ")";
	}

	private static String getActionDisplayName(DockingActionIf action, String category) {
		ActionGroup group = ActionGroup.getActionByDisplayName(category);
		switch (group) {
			case LOCAL_MENU:
			case GLOBAL_MENU:
				return getActionsDisplayMenuName(action, action.getMenuBarData());
			case POPUP:
				return getActionsDisplayMenuName(action, action.getPopupMenuData());
			default:
				return action.getName();
		}
	}

	// used for testing
	void setFilterText(String string) {
		searchList.setFilterText(string);
	}

	/**
	 * Class for actually invoking the selected action. Creating an instance of this class
	 * causes a listener to be added for when focus changes. This is because we don't want
	 * to invoke the selected action until after this dialog has finished closing and focus
	 * has been returned to the original component that had focus before this dialog was invoked.
	 */
	// class not private to allow test access
	class ActionRunner implements PropertyChangeListener {

		private DockingActionIf action;
		private ActionContext context;

		ActionRunner(DockingActionIf action, ActionContext context) {
			this.action = action;
			this.context = context;
		}

		@Override
		public void propertyChange(PropertyChangeEvent evt) {
			KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
			kfm.removePropertyChangeListener("permanentFocusOwner", this);

			// we need make sure the focus notification is complete before we perform the action
			// in case the action causes a change in focus.
			Swing.runLater(() -> activateAction());
		}

		private void activateAction() {
			// Toggle actions do not toggle their state directly, therefore we have to do it 
			// explicitly before we execute the action.
			if (action instanceof ToggleDockingActionIf toggleAction) {
				toggleAction.setSelected(!toggleAction.isSelected());
			}
			action.actionPerformed(context);
		}
	}

	private class ActionRenderer extends GListCellRenderer<SearchListEntry<DockingActionIf>> {
		{
			setHTMLRenderingEnabled(true);
		}

		@Override
		public Component getListCellRendererComponent(
				JList<? extends SearchListEntry<DockingActionIf>> list,
				SearchListEntry<DockingActionIf> value, int index, boolean isSelected,
				boolean hasFocus) {
			super.getListCellRendererComponent(list, value, index, isSelected, hasFocus);
			if (model.isDisposed()) {
				// Some UIs may call the renderer on focus lost after the dialog is closed.
				return this;
			}
			DockingActionIf action = value.value();
			String category = value.category();
			Icon icon = getIcon(action, category);
			setText(getHtmlText(action, category, isSelected));
			setIcon(icon != null ? icon : Icons.EMPTY_ICON);
			return this;
		}

		private String getHtmlText(DockingActionIf action, String category, boolean isSelected) {
			String actionDisplayName = getActionDisplayName(action, category);
			String escapedActionName = HTMLUtilities.escapeHTML(actionDisplayName);
			String disabledText = "";

			StringBuilder builder = new StringBuilder("<html>");

			Color fgName = getForeground(); // defaults to list foreground; handles selected state
			Color fgKeyBinding = isSelected ? getForeground() : Messages.HINT;

			ActionContext context = model.getContext();
			if (!(action.isValidContext(context) && action.isEnabledForContext(context))) {
				fgName = isSelected ? getForeground() : Colors.FOREGROUND_DISABLED;
				fgKeyBinding = isSelected ? getForeground() : Colors.FOREGROUND_DISABLED;
				disabledText = isSelected ? " <I>disabled</I>" : "";
			}

			builder.append(HTMLUtilities.colorString(fgName, escapedActionName));
			builder.append(colorKeyBindingString(fgKeyBinding, action));
			builder.append(disabledText);

			return builder.toString();
		}

		private Icon getIcon(DockingActionIf action, String category) {
			ActionGroup group = ActionGroup.getActionByDisplayName(category);
			switch (group) {
				case LOCAL_TOOLBAR:
				case GLOBAL_TOOLBAR:
					ToolBarData toolBarData = action.getToolBarData();
					return toolBarData != null ? toolBarData.getIcon() : null;
				case LOCAL_MENU:
				case GLOBAL_MENU:
					MenuData menuBarData = action.getMenuBarData();
					return menuBarData != null ? menuBarData.getMenuIcon() : null;
				case POPUP:
					menuBarData = action.getPopupMenuData();
					return menuBarData != null ? menuBarData.getMenuIcon() : null;
				default:
					return null;
			}
		}
	}

	private static class ActionsFilter implements BiPredicate<DockingActionIf, String> {
		private String filterText;

		ActionsFilter(String filterText) {
			this.filterText = filterText.toLowerCase();
		}

		@Override
		public boolean test(DockingActionIf t, String category) {
			return getActionDisplayName(t, category).toLowerCase().contains(filterText) ||
				getKeyBindingString(t).toLowerCase().contains(filterText);
		}
	}

}
