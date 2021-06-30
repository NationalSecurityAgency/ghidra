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
package docking;

import java.awt.Window;
import java.util.Set;

import javax.swing.ImageIcon;

import docking.action.DockingActionIf;
import docking.actions.DockingToolActions;
import docking.actions.PopupActionProvider;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;

/**
 * Generic tool interface for managing {@link ComponentProvider}s and
 * {@link DockingActionIf actions}
 */
public interface Tool extends ServiceProvider {

	/**
	 * Returns a combination of the tool name and the instance name of the form
	 * tool name(instance name), e.g., SomeTool(2)
	 * @return the tool name
	 */
	public String getName();

	/**
	 * Returns true if tool is visible
	 * @return true if tool is visible
	 */
	public boolean isVisible();

	/**
	 * Sets the tool visible or invisible.  This method is used by
	 * the Project to make it's tools visible or invisible depending on whether
	 * this tool is in is the active workspace.
	 *
	 * @param visibility true specifies that the tool should be visible
	 */
	public void setVisible(boolean visibility);

	/**
	 * Brings this tool to the front. Places this tool at the top of the
	 * stacking order and shows it in front of any other tools.
	 */
	public void toFront();

	/**
	 * Get the icon that the tool is using
	 * @return the icon that the tool is using
	 */
	public ImageIcon getIcon();

	/**
	 * Adds the ComponentProvider to the tool, optionally making it visible.
	 * @param componentProvider the provider to add to the tool
	 * @param show if true, the component is made visible.
	 */
	public void addComponentProvider(ComponentProvider componentProvider, boolean show);

	/**
	 * Removes the given ComponentProvider from the tool.  When a provider has been removed
	 * from the tool it is considered disposed and should not be reused.
	 * 
	 * @param componentProvider the provider to remove from the tool
	 */
	public void removeComponentProvider(ComponentProvider componentProvider);

	/**
	 * Gets the ComponentProvider with the given name.
	 *
	 * @param name the name of the provider to get
	 * @return the provider
	 */
	public ComponentProvider getComponentProvider(String name);

	/**
	 * Set the status information
	 * @param text non-html string to be displayed in the Status display area
	 */
	public void setStatusInfo(String text);

	/**
	  * Set the status information
	  * @param text string to be displayed in the Status display area
	  * @param beep whether to be or not
	  */
	public void setStatusInfo(String text, boolean beep);

	/**
	 * Clear the status information
	 */
	public void clearStatusInfo();

	/**
	 * Set the menu group associated with a cascaded submenu.  This allows
	 * a cascading menu item to be grouped with a specific set of actions.
	 * <p>
	 * The default group for a cascaded submenu is the name of the submenu.
	 * <p>
	 *
	 * @param menuPath menu name path where the last element corresponds to the specified group name.
	 * @param group group name
	 * @param menuSubGroup the name used to sort the cascaded menu within other menu items at
	 *                     its level
	 */
	public void setMenuGroup(String[] menuPath, String group, String menuSubGroup);

	/**
	 * Adds the action to the tool.
	 * @param action the action to be added.
	 */
	public void addAction(DockingActionIf action);

	/**
	 * Removes the given action from the tool.  When an action is removed from the tool it will
	 * be disposed and should not be reused.
	 * @param action the action to be removed.
	 */
	public void removeAction(DockingActionIf action);

	/**
	 * Adds the action to the given provider as a local action.
	 * @param componentProvider the provider to add the action to.
	 * @param action the DockingAction to add to the componentProvider.
	 */
	public void addLocalAction(ComponentProvider componentProvider, DockingActionIf action);

	/**
	 * Removes the action from the provider
	 * @param componentProvider the component provider from which to remove the action.
	 * @param action the action to remove.
	 */
	public void removeLocalAction(ComponentProvider componentProvider, DockingActionIf action);

	/**
	 * Adds the given popup action provider to this tool.   This provider will be called each
	 * time the popup menu is about to be shown.
	 * @param provider the provider
	 */
	public void addPopupActionProvider(PopupActionProvider provider);

	/**
	 * Removes the given popup action provider
	 * @param provider the provider
	 */
	public void removePopupActionProvider(PopupActionProvider provider);

	/**
	 * Return a set of all actions in the tool.
	 * 
	 * <p>Note: the result may contain conceptually duplicate actions, which is when multiple
	 * actions exist that share the same full name (the full name is the action name with the
	 * owner name, such as "My Action (MyPlugin)".
	 * 
	 * @return set of all actions
	 */
	public Set<DockingActionIf> getAllActions();

	/**
	 * Returns all actions for the given owner
	 * 
	 * <p>Note: the result may contain conceptually duplicate actions, which is when multiple
	 * actions exist that share the same full name (the full name is the action name with the
	 * owner name, such as "My Action (MyPlugin)".
	 * 
	 * @param owner the action owner's name
	 * @return the actions
	 */
	public Set<DockingActionIf> getDockingActionsByOwnerName(String owner);

	/**
	 * Returns the active component provider, that which has focus
	 * @return the active provider
	 */
	public ComponentProvider getActiveComponentProvider();

	/**
	 * Shows or hides the component provider in the tool
	 * @param componentProvider the provider to either show or hide.
	 * @param visible true to show the provider, false to hide it.
	 */
	public void showComponentProvider(ComponentProvider componentProvider, boolean visible);

	/**
	 * Shows the dialog using the tool's root frame as a parent.  Also, remembers any size and location
	 * adjustments made by the user for the next time the dialog is shown.
	 * @param dialogComponent the DialogComponentProvider object to be shown in a dialog.
	 */
	public void showDialog(DialogComponentProvider dialogComponent);

	/**
	 * Returns the parent window for the given provider
	 * @param componentProvider the provider
	 * @return the window
	 */
	public Window getProviderWindow(ComponentProvider componentProvider);

	/**
	 * Makes the given ComponentProvider move to the front if it is tabbed with other components.
	 * @param componentProvider the provider to move to the top of its stacking order.
	 */
	public void toFront(ComponentProvider componentProvider);

	/**
	 * Returns true if the given ComponentProvider is currently visible.
	 * @param componentProvider the provider to check for visibility.
	 * @return true if the given ComponentProvider is currently visible.
	 */
	public boolean isVisible(ComponentProvider componentProvider);

	/**
	 * Returns true if the ComponentProvider is the currently active provider. The active provider
	 * is the provider that has keyboard focus and provides the current action context.
	 * @param componentProvider the provider to check for active.
	 * @return  true if the ComponentProvider is the currently active provider.
	 */
	public boolean isActive(ComponentProvider componentProvider);

	/**
	 * Indicates to the tool that the given componentProvider's title has changed.
	 * @param componentProvider the componentProvider whose title has changed.
	 */
	public void updateTitle(ComponentProvider componentProvider);

	/**
	 * Signals to the tool that the provider's context has changed.  This lets toolbar and
	 * menu actions update enablement based on current context.
	 * 
	 * <p>Pass <code>null</code> to signal that the entire tool's context has changed
	 *
	 * @param provider the provider whose context changed; null to signal the tool's context
	 */
	public void contextChanged(ComponentProvider provider);

	/**
	 * Adds the given context listener to this tool
	 * @param listener the listener to add
	 */
	public void addContextListener(DockingContextListener listener);

	/**
	 * Removes the given context listener to this tool
	 * @param listener the listener to add
	 */
	public void removeContextListener(DockingContextListener listener);

	/**
	 * Returns the DockingWindowManger for this tool.
	 * @return the DockingWindowManger for this tool.
	 */
	public DockingWindowManager getWindowManager();

	/**
	 * Get the options for the given category name; if no options exist with
	 * the given name, then one is created.
	 * @param categoryName the category name
	 * @return the options
	 */
	public ToolOptions getOptions(String categoryName);

	/**
	 * Toggles the "change" state of the tool...
	 * @param changed true indicates that the tool config has changed.
	 */
	public void setConfigChanged(boolean changed);

	/**
	 * Return true if the tool's configuration has changed
	 * @return  true if the tool's configuration has changed
	 */
	public boolean hasConfigChanged();

	/**
	 * Returns the class that manages actions for the tool.
	 * 
	 * <p>Most clients will not need to use this methods.  Instead, actions should be added to
	 * the tool via {@link #addAction(DockingActionIf)} and
	 * {@link #addLocalAction(ComponentProvider, DockingActionIf)}.
	 * 
	 * @return the action manager
	 */
	public DockingToolActions getToolActions();

	/**
	 * Suggests the tool to attempt to close().  This will be as though the user
	 * selected the close menu option on the tool or hit the closeWindow x button in
	 * the upper corner (Windows systems).
	 */
	public void close();

	/**
	 * Returns the default {@link ActionContext} for the tool.  The default context is the context
	 * the default ComponentProvider for the tool.
	 * @return  the default {@link ActionContext} for the tool
	 */
	public ActionContext getDefaultToolContext();

}
