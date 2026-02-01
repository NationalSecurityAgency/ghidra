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

import static docking.actions.dialog.ActionGroup.*;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import docking.*;
import docking.action.DockingActionIf;
import docking.action.MenuData;
import docking.widgets.searchlist.DefaultSearchListModel;

/** 
 * Model for the SearchList used by the {@link ActionChooserDialog}.  This model is constructed
 * with two sets of actions; local and global. The local actions are actions that are specific to
 * the currently focused {@link ComponentProvider} or {@link DialogComponentProvider}. Global 
 * actions are actions that are added at the tool level and are not specific to a ComponentProvider
 * or DialogComponentProvider.
 * <P>
 * The model supports the concept of a {@link ActionDisplayLevel}. The display level determines
 * which combination of local and global actions to display and takes into account if they are
 * valid for the current context, are enabled for the current context and, for popups, the value of
 * the "addToPopup" value. Each higher display level is less restrictive and adds more actions in
 * the displayed list. See the {@link ActionDisplayLevel} for a description of which actions are
 * displayed for each level
 * 
 */
public class ActionsModel extends DefaultSearchListModel<DockingActionIf> {
	private Set<DockingActionIf> localActions;
	private Set<DockingActionIf> globalActions;
	private ActionDisplayLevel displayLevel = ActionDisplayLevel.LOCAL;
	private ActionContext context;
	private Comparator<DockingActionIf> nameComparator = new ActionNameComparator();
	private Comparator<DockingActionIf> menuPathComparator = new ActionMenuPathComparator();
	private Comparator<DockingActionIf> popupPathComparator = new ActionPopupPathComparator();

	ActionsModel(Set<DockingActionIf> localActions, Set<DockingActionIf> globalActions,
			ActionContext context) {
		this.context = context;
		this.localActions = localActions;
		this.globalActions = globalActions;
		populateActions();
	}

	/**
	 * Sets the display level for the actions dialog. Each higher level includes more actions
	 * in the displayed list of actions.
	 * @param level the {@link ActionDisplayLevel}
	 */
	public void setDisplayLevel(ActionDisplayLevel level) {
		this.displayLevel = level;
		populateActions();
		fireDataChanged();
	}

	/**
	 * Returns the current {@link ActionDisplayLevel} of the dialog.
	 * @return the current display level of the dialog
	 */
	public ActionDisplayLevel getActionDisplayLevel() {
		return displayLevel;
	}

	@Override
	public void dispose() {
		localActions.clear();
		globalActions.clear();
		context = null;
	}

	public boolean isDisposed() {
		return context == null;
	}

	private void populateActions() {
		clearData();
		switch (displayLevel) {
			case LOCAL:
				addLocalActions(LOCAL_TOOLBAR, a -> isValidToolbar(a));
				addLocalActions(LOCAL_MENU, a -> isValidMenu(a));
				addLocalActions(POPUP, a -> isValidPopup(a));
				addGlobalActions(POPUP, a -> isValidPopup(a));
				addLocalActions(KEYBINDING_ONLY, a -> isValidKeybindingOnly(a));
				addGlobalActions(KEYBINDING_ONLY, a -> isValidKeybindingOnly(a));
				break;

			case GLOBAL:
				addLocalActions(LOCAL_TOOLBAR, a -> isValidToolbar(a));
				addGlobalActions(GLOBAL_TOOLBAR, a -> isValidToolbar(a));
				addLocalActions(LOCAL_MENU, a -> isValidMenu(a));
				addGlobalActions(GLOBAL_MENU, a -> isValidMenu(a));
				addLocalActions(POPUP, a -> isValidPopup(a));
				addGlobalActions(POPUP, a -> isValidPopup(a));
				addLocalActions(KEYBINDING_ONLY, a -> isValidKeybindingOnly(a));
				addGlobalActions(KEYBINDING_ONLY, a -> isValidKeybindingOnly(a));
				break;

			case ALL:
				addLocalActions(LOCAL_TOOLBAR, a -> isToolbar(a));
				addGlobalActions(GLOBAL_TOOLBAR, a -> isToolbar(a));
				addLocalActions(LOCAL_MENU, a -> isMenu(a));
				addGlobalActions(GLOBAL_MENU, a -> isMenu(a));
				addLocalActions(POPUP, a -> isPopup(a));
				addGlobalActions(POPUP, a -> isPopup(a));
				addLocalActions(KEYBINDING_ONLY, a -> isKeybindingOnly(a));
				addGlobalActions(KEYBINDING_ONLY, a -> isKeybindingOnly(a));
				break;
		}
	}

	ActionContext getContext() {
		return context;
	}

	private boolean isToolbar(DockingActionIf a) {
		return a.getToolBarData() != null;
	}

	private boolean isValidToolbar(DockingActionIf a) {
		return isToolbar(a) && a.isValidContext(context);
	}

	private boolean isMenu(DockingActionIf a) {
		return a.getMenuBarData() != null;
	}

	private boolean isValidMenu(DockingActionIf a) {
		return isMenu(a) && a.isValidContext(context);
	}

	private boolean isPopup(DockingActionIf a) {
		return a.getPopupMenuData() != null;
	}

	private boolean isValidPopup(DockingActionIf a) {
		return isPopup(a) && a.isValidContext(context) && a.isAddToPopup(context);
	}

	private boolean isKeybindingOnly(DockingActionIf a) {
		return a.getToolBarData() == null && a.getMenuBarData() == null &&
			a.getPopupMenuData() == null;
	}

	private boolean isValidKeybindingOnly(DockingActionIf a) {
		return isKeybindingOnly(a) && a.isValidContext(context) && a.isEnabledForContext(context);
	}

	private void addLocalActions(ActionGroup actionGroup, Predicate<DockingActionIf> filter) {
		List<DockingActionIf> actions =
			localActions.stream().filter(filter).collect(Collectors.toCollection(ArrayList::new));

		actions.sort(getSorter(actionGroup));
		add(actionGroup.getDisplayName(), actions);
	}

	private void addGlobalActions(ActionGroup actionGroup, Predicate<DockingActionIf> filter) {
		List<DockingActionIf> actions =
			globalActions.stream().filter(filter).collect(Collectors.toCollection(ArrayList::new));

		actions.sort(getSorter(actionGroup));
		add(actionGroup.getDisplayName(), actions);
	}

	/**
	 * Returns the appropriate action sorter for the given ActionGroup category. Actions with
	 * a menu path (menu and popup) use the menu path to sort the actions. All others use
	 * the action's name for sorting.
	 * @param actionGroup the type
	 * @return the comparator to use for sorting actions within their category
	 */
	private Comparator<? super DockingActionIf> getSorter(ActionGroup actionGroup) {
		switch (actionGroup) {
			case GLOBAL_MENU:
			case LOCAL_MENU:
				return menuPathComparator;
			case POPUP:
				return popupPathComparator;
			case GLOBAL_TOOLBAR:
			case LOCAL_TOOLBAR:
			case KEYBINDING_ONLY:
			default:
				return nameComparator;
		}
	}

	private class ActionNameComparator implements Comparator<DockingActionIf> {
		@Override
		public int compare(DockingActionIf a1, DockingActionIf a2) {
			return a1.getName().compareTo(a2.getName());
		}
	}

	private class ActionMenuPathComparator implements Comparator<DockingActionIf> {
		@Override
		public int compare(DockingActionIf a1, DockingActionIf a2) {
			MenuData menuData1 = a1.getMenuBarData();
			MenuData menuData2 = a2.getMenuBarData();
			String path1 = menuData1 != null ? menuData1.getMenuPathAsString() : "";
			String path2 = menuData2 != null ? menuData2.getMenuPathAsString() : "";

			return path1.compareTo(path2);
		}
	}

	private class ActionPopupPathComparator implements Comparator<DockingActionIf> {
		@Override
		public int compare(DockingActionIf a1, DockingActionIf a2) {
			MenuData menuData1 = a1.getPopupMenuData();
			MenuData menuData2 = a2.getPopupMenuData();
			String path1 = menuData1 != null ? menuData1.getMenuPathAsString() : "";
			String path2 = menuData2 != null ? menuData2.getMenuPathAsString() : "";

			return path1.compareTo(path2);
		}
	}

}
