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

public class WindowActionManager {
	private Map<DockingActionIf, DockingActionProxy> actionToProxyMap;
	private MenuBarManager menuBarMgr;
	private ToolBarManager toolBarMgr;
	private final WindowNode node;

	private boolean disposed;

	WindowActionManager(WindowNode node, MenuHandler menuBarHandler,
			DockingWindowManager winMgr, MenuGroupMap menuGroupMap) {

		this.node = node;
		actionToProxyMap = new HashMap<>();
		menuBarMgr = new MenuBarManager(menuBarHandler, menuGroupMap);
		toolBarMgr = new ToolBarManager(winMgr);
	}

	void setActions(List<DockingActionIf> actionList) {
		menuBarMgr.clearActions();
		toolBarMgr.clearActions();
		actionToProxyMap.clear();
		for (DockingActionIf action : actionList) {
			addAction(action);
		}
	}

	void addAction(DockingActionIf action) {
		if (action.getMenuBarData() != null || action.getToolBarData() != null) {
			DockingActionProxy proxyAction = new DockingActionProxy(action);
			actionToProxyMap.put(action, proxyAction);
			menuBarMgr.addAction(proxyAction);
			toolBarMgr.addAction(proxyAction);
		}
	}

	void removeAction(DockingActionIf action) {
		DockingActionProxy proxyAction = actionToProxyMap.remove(action);
		if (proxyAction != null) {
			menuBarMgr.removeAction(proxyAction);
			toolBarMgr.removeAction(proxyAction);
		}
	}

	DockingActionIf getToolbarAction(String actionName) {
		return toolBarMgr.getAction(actionName);
	}

	void update() {
		JMenuBar menuBar = menuBarMgr.getMenuBar();
		if (menuBar.getMenuCount() > 0) {
			node.setMenuBar(menuBar);
		}

		node.setToolBar(toolBarMgr.getToolBar());
		node.validate();
	}

	void dispose() {
		disposed = true;
		node.setToolBar(null);
		node.setMenuBar(null);
		actionToProxyMap.clear();
		menuBarMgr.dispose();
		toolBarMgr.dispose();
	}

	void contextChanged(Map<Class<? extends ActionContext>, ActionContext> defaultContextMap,
			ActionContext localContext, Set<DockingActionIf> excluded) {

		if (!node.isVisible() || disposed) {
			return;
		}

		// Update actions - make a copy so that we don't get concurrent modification
		// exceptions during reentrant operations
		List<DockingActionIf> list = new ArrayList<>(actionToProxyMap.keySet());
		for (DockingActionIf action : list) {
			if (excluded.contains(action)) {
				continue;
			}

			DockingActionIf proxyAction = actionToProxyMap.get(action);
			ActionContext context =
				getContextForAction(action, localContext, defaultContextMap);

			if (context != null) {
				proxyAction.setEnabled(proxyAction.isEnabledForContext(context));
			}
			else {
				proxyAction.setEnabled(false);
			}
		}
	}

	private ActionContext getContextForAction(DockingActionIf action, ActionContext localContext,
			Map<Class<? extends ActionContext>, ActionContext> defaultContextMap) {

		if (action.isValidContext(localContext)) {
			return localContext;
		}
		if (action.supportsDefaultContext()) {
			ActionContext context = defaultContextMap.get(action.getContextClass());
			if (context != null && action.isValidContext(context)) {
				return context;
			}
		}
		return null;
	}

	/**
	 * Returns the set of actions for this window.
	 * 
	 * <p>Note this returns the the original passed-in actions and not the proxy actions that the
	 * window uses.
	 * 
	 * @return the set of actions for this window
	 */
	Set<DockingActionIf> getOriginalActions() {
		return new HashSet<>(actionToProxyMap.keySet());
	}
}
