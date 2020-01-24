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

import java.awt.*;
import java.util.*;

import javax.swing.JFrame;

import docking.action.DockingActionIf;
import docking.actions.*;
import ghidra.framework.options.ToolOptions;
import ghidra.util.Swing;

/**
 * A partial implementation of {@link Tool} that serves as a place to share common 
 * functionality
 */
public abstract class AbstractDockingTool implements Tool {

	protected DockingWindowManager winMgr;
	protected ToolActions toolActions;
	protected Map<String, ToolOptions> optionsMap = new HashMap<>();
	protected boolean configChangedFlag;

	@Override
	public boolean isVisible() {
		return winMgr.isVisible();
	}

	@Override
	public void setVisible(boolean visibility) {
		winMgr.setVisible(visibility);
	}

	@Override
	public void toFront() {
		JFrame frame = winMgr.getRootFrame();
		if (frame.getExtendedState() == Frame.ICONIFIED) {
			frame.setExtendedState(Frame.NORMAL);
		}
		frame.toFront();
	}

	@Override
	public void addComponentProvider(ComponentProvider provider, boolean show) {
		Runnable r = () -> {
			winMgr.addComponent(provider, show);
			toolActions.addGlobalAction(provider.getShowProviderAction());
		};
		Swing.runNow(r);
	}

	@Override
	public void removeComponentProvider(ComponentProvider provider) {
		Runnable r = () -> {
			toolActions.removeGlobalAction(provider.getShowProviderAction());
			toolActions.removeActions(provider);
			winMgr.removeComponent(provider);
		};
		Swing.runNow(r);
	}

	@Override
	public ComponentProvider getComponentProvider(String name) {
		return winMgr.getComponentProvider(name);
	}

	@Override
	public void setStatusInfo(String text) {
		winMgr.setStatusText(text);
	}

	@Override
	public void setStatusInfo(String text, boolean beep) {
		winMgr.setStatusText(text);
		if (beep) {
			Toolkit tk = getToolFrame().getToolkit();
			tk.beep();
		}
	}

	@Override
	public void clearStatusInfo() {
		winMgr.setStatusText("");
	}

	@Override
	public void addAction(DockingActionIf action) {
		toolActions.addGlobalAction(action);
	}

	@Override
	public void removeAction(DockingActionIf action) {
		toolActions.removeGlobalAction(action);
	}

	@Override
	public void addLocalAction(ComponentProvider provider, DockingActionIf action) {
		toolActions.addLocalAction(provider, action);
	}

	@Override
	public void removeLocalAction(ComponentProvider provider, DockingActionIf action) {
		toolActions.removeLocalAction(provider, action);
	}

	@Override
	public Set<DockingActionIf> getAllActions() {
		return toolActions.getAllActions();
	}

	@Override
	public void addPopupActionProvider(PopupActionProvider provider) {
		winMgr.addPopupActionProvider(provider);
	}

	@Override
	public void removePopupActionProvider(PopupActionProvider provider) {
		winMgr.removePopupActionProvider(provider);
	}

	@Override
	public Set<DockingActionIf> getDockingActionsByOwnerName(String owner) {
		return toolActions.getActions(owner);
	}

	@Override
	public ComponentProvider getActiveComponentProvider() {
		return winMgr.getActiveComponentProvider();
	}

	@Override
	public void showComponentProvider(ComponentProvider provider, boolean visible) {
		Runnable r = () -> winMgr.showComponent(provider, visible);
		Swing.runNow(r);
	}

	@Override
	public void showDialog(DialogComponentProvider dialogComponent) {
		DockingWindowManager.showDialog(null, dialogComponent);
	}

	public JFrame getToolFrame() {
		return winMgr.getRootFrame();
	}

	@Override
	public Window getProviderWindow(ComponentProvider provider) {
		return winMgr.getProviderWindow(provider);
	}

	@Override
	public void toFront(ComponentProvider provider) {
		Runnable r = () -> winMgr.toFront(provider);
		Swing.runNow(r);
	}

	@Override
	public boolean isVisible(ComponentProvider provider) {
		return winMgr.isVisible(provider);
	}

	@Override
	public boolean isActive(ComponentProvider provider) {
		return winMgr.isActiveProvider(provider);
	}

	@Override
	public void updateTitle(ComponentProvider provider) {
		winMgr.updateTitle(provider);
	}

	/**
	 * Set the menu group associated with a cascaded submenu.  This allows
	 * a cascading menu item to be grouped with a specific set of actions.
	 * The default group for a cascaded submenu is the name of the submenu.
	 *
	 * @param menuPath menu name path where the last element corresponds
	 * to the specified group name.
	 * @param group group name
	 * @see #setMenuGroup(String[], String, String)
	 */
	public void setMenuGroup(String[] menuPath, String group) {
		setMenuGroup(menuPath, group, null);
	}

	@Override
	public void setMenuGroup(String[] menuPath, String group, String menuSubGroup) {
		winMgr.setMenuGroup(menuPath, group, menuSubGroup);
	}

	@Override
	public void contextChanged(ComponentProvider provider) {
		winMgr.contextChanged(provider);
	}

	@Override
	public void addContextListener(DockingContextListener listener) {
		winMgr.addContextListener(listener);
	}

	@Override
	public void removeContextListener(DockingContextListener listener) {
		winMgr.removeContextListener(listener);
	}

	@Override
	public DockingWindowManager getWindowManager() {
		return winMgr;
	}

	@Override
	public void setConfigChanged(boolean changed) {
		configChangedFlag = changed;
	}

	@Override
	public boolean hasConfigChanged() {
		return configChangedFlag;
	}

	@Override
	public DockingToolActions getToolActions() {
		return toolActions;
	}
}
