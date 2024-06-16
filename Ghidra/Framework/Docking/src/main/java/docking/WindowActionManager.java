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
import java.util.Map.Entry;

import javax.swing.JMenuBar;

import docking.action.DockingActionIf;
import docking.menu.*;
import generic.concurrent.ReentryGuard;
import generic.concurrent.ReentryGuard.Guarded;
import ghidra.util.Msg;

public class WindowActionManager {
	private Map<DockingActionIf, DockingActionProxy> actionToProxyMap;
	private MenuBarManager menuBarMgr;
	private ToolBarManager toolBarMgr;
	private final WindowNode node;

	private boolean disposed;

	/**
	 * Some actions' {@link DockingActionIf#isEnabledForContext(ActionContext)} methods may
	 * inadvertently display an error dialog, allowing for the Swing thread to reenter and modify
	 * the {@link #actionToProxyMap}. We want to allow this, but detect it and bail early.
	 */
	private ReentryGuard<Throwable> reentryGuard = new ReentryGuard<>() {
		@Override
		protected Throwable violated(boolean nested, Throwable previous) {
			if (previous != null) {
				return previous;
			}
			Throwable t = new Throwable();
			Msg.error(WindowActionManager.this,
				"Modified action list during context change update", t);
			return t;
		}
	};

	WindowActionManager(WindowNode node, MenuHandler menuBarHandler,
			DockingWindowManager winMgr, MenuGroupMap menuGroupMap) {

		this.node = node;
		actionToProxyMap = new HashMap<>();
		menuBarMgr = new MenuBarManager(menuBarHandler, menuGroupMap);
		toolBarMgr = new ToolBarManager(winMgr);
	}

	void setActions(List<DockingActionIf> actionList) {
		reentryGuard.checkAccess();
		menuBarMgr.clearActions();
		toolBarMgr.clearActions();
		actionToProxyMap.clear();
		for (DockingActionIf action : actionList) {
			addAction(action);
		}
	}

	void addAction(DockingActionIf action) {
		reentryGuard.checkAccess();
		if (action.getMenuBarData() != null || action.getToolBarData() != null) {
			DockingActionProxy proxyAction = new DockingActionProxy(action);
			actionToProxyMap.put(action, proxyAction);
			menuBarMgr.addAction(proxyAction);
			toolBarMgr.addAction(proxyAction);
		}
	}

	void removeAction(DockingActionIf action) {
		reentryGuard.checkAccess();
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
		reentryGuard.checkAccess();
		disposed = true;
		node.setToolBar(null);
		node.setMenuBar(null);
		actionToProxyMap.clear();
		menuBarMgr.dispose();
		toolBarMgr.dispose();
	}

	void contextChanged(Map<Class<? extends ActionContext>, ActionContext> defaultContextMap,
			ActionContext localContext, Set<DockingActionIf> excluded) {
		/**
		 * We need the guard against reentrant changes to the actionToProxyMap, lest the iterator
		 * throw a ConcurrentModificationException. If the guard finds a violation, i.e., the map
		 * has changed, we just bail. Whatever changed the map should also trigger an update to
		 * context, and so we should have a fresh go here with the new map.
		 * 
		 * There are three points where there could be reentrant modifications. Those are 1) when
		 * computing an action's context, 2) when checking if the action is enabled for that
		 * context, and 3) when setting the proxy's enabled state. There are minimal performance
		 * trade-offs to consider when deciding which points to check. Critically, we must check
		 * somewhere between the last point and the end of the loop, i.e., before stepping the
		 * iterator. We opt to check only that last point, since reentry is uncommon here.
		 */
		try (Guarded guarded = reentryGuard.enter()) {
			if (!node.isVisible() || disposed) {
				return;
			}

			for (Entry<DockingActionIf, DockingActionProxy> ent : actionToProxyMap.entrySet()) {
				DockingActionIf action = ent.getKey();
				DockingActionIf proxyAction = ent.getValue();
				if (excluded.contains(action)) {
					continue;
				}

				// Reentry point 1
				ActionContext context =
					getContextForAction(action, localContext, defaultContextMap);
				// Reentry point 2
				boolean enabled =
					context == null ? false : proxyAction.isEnabledForContext(context);
				// Reentry point 3, which we check
				proxyAction.setEnabled(enabled);
				if (reentryGuard.isViolated()) {
					break;
				}
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
	 * <p>
	 * Note this returns the the original passed-in actions and not the proxy actions that the
	 * window uses.
	 * 
	 * @return the set of actions for this window
	 */
	Set<DockingActionIf> getOriginalActions() {
		return new HashSet<>(actionToProxyMap.keySet());
	}
}
