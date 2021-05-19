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

import java.util.*;

import javax.swing.JMenuBar;

import docking.action.DockingActionIf;
import docking.menu.*;
import ghidra.util.task.SwingUpdateManager;

public class WindowActionManager {
	private Map<DockingActionIf, DockingActionProxy> actionToProxyMap;
	private MenuBarManager menuBarMgr;
	private ToolBarManager toolBarMgr;
	private final WindowNode node;

	private final DockingWindowManager winMgr;
	private boolean disposed;

	private ComponentPlaceholder placeHolderForScheduledActionUpdate;
	private Runnable updateActionsRunnable = () -> processContextChanged();
	private SwingUpdateManager updateManager =
		new SwingUpdateManager(500, 500, "Context Update Manager", updateActionsRunnable);

	public WindowActionManager(WindowNode node, MenuHandler menuBarHandler,
			DockingWindowManager winMgr, MenuGroupMap menuGroupMap) {

		this.node = node;
		this.winMgr = winMgr;
		actionToProxyMap = new HashMap<>();
		menuBarMgr = new MenuBarManager(menuBarHandler, menuGroupMap);
		toolBarMgr = new ToolBarManager(winMgr);
	}

	public void setActions(List<DockingActionIf> actionList) {
		menuBarMgr.clearActions();
		toolBarMgr.clearActions();
		actionToProxyMap.clear();
		for (DockingActionIf action : actionList) {
			addAction(action);
		}
	}

	public void addAction(DockingActionIf action) {
		if (action.getMenuBarData() != null || action.getToolBarData() != null) {
			DockingActionProxy proxyAction = new DockingActionProxy(action);
			actionToProxyMap.put(action, proxyAction);
			menuBarMgr.addAction(proxyAction);
			toolBarMgr.addAction(proxyAction);
		}
	}

	public void removeAction(DockingActionIf action) {
		DockingActionProxy proxyAction = actionToProxyMap.remove(action);
		if (proxyAction != null) {
			menuBarMgr.removeAction(proxyAction);
			toolBarMgr.removeAction(proxyAction);
		}
	}

	public DockingActionIf getToolbarAction(String actionName) {
		return toolBarMgr.getAction(actionName);
	}

	public void update() {
		JMenuBar menuBar = menuBarMgr.getMenuBar();
		if (menuBar.getMenuCount() > 0) {
			node.setMenuBar(menuBar);
		}

		node.setToolBar(toolBarMgr.getToolBar());
		node.validate();
	}

	public synchronized void dispose() {
		disposed = true;
		updateManager.dispose();
		node.setToolBar(null);
		node.setMenuBar(null);
		actionToProxyMap.clear();
		menuBarMgr.dispose();
		toolBarMgr.dispose();
	}

	synchronized void contextChanged(ComponentPlaceholder placeHolder) {

		if (!node.isVisible()) {
			return;
		}

		placeHolderForScheduledActionUpdate = placeHolder;

		// Typically, when we get one contextChanged, we get a flurry of contextChanged calls.
		// In order to make the action updating be as responsive as possible and still be complete,
		// we have chosen a policy that will reduce a flurry of contextChanged call into two
		// actual calls - one that occurs immediately and one when the flurry times out.
		updateManager.update();
	}

	private synchronized void processContextChanged() {
		//
		// This method is called from an invokeLater(), which means that we may be 
		// disposed while before this Swing call executes.
		//
		if (disposed) {
			return;
		}

		ActionContext localContext = getContext();
		ActionContext globalContext = winMgr.getDefaultToolContext();

		// Update actions - make a copy so that we don't get concurrent modification exceptions
		List<DockingActionIf> list = new ArrayList<>(actionToProxyMap.values());
		for (DockingActionIf action : list) {
			if (action.isValidContext(localContext)) {
				action.setEnabled(action.isEnabledForContext(localContext));
			}
			else if (isValidDefaultToolContext(action, globalContext)) {
				action.setEnabled(action.isEnabledForContext(globalContext));
			}
			else {
				action.setEnabled(false);
			}
		}
		// Notify listeners if the context provider is the focused provider
		winMgr.notifyContextListeners(placeHolderForScheduledActionUpdate, localContext);
	}

	private boolean isValidDefaultToolContext(DockingActionIf action, ActionContext toolContext) {
		return action.supportsDefaultToolContext() &&
			action.isValidContext(toolContext);
	}

	private ActionContext getContext() {
		ComponentProvider provider = placeHolderForScheduledActionUpdate == null ? null
				: placeHolderForScheduledActionUpdate.getProvider();

		ActionContext context = provider == null ? null : provider.getActionContext(null);

		if (context == null) {
			context = new ActionContext();
		}
		return context;
	}
}
