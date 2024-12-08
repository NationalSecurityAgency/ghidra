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

import docking.action.DockingActionIf;
import docking.menu.MenuGroupMap;
import docking.menu.MenuHandler;
import ghidra.util.Swing;
import ghidra.util.task.AbstractSwingUpdateManager;
import ghidra.util.task.SwingUpdateManager;

/**
 * Class to manage all the global actions that show up on the main tool menubar or toolbar
 */
public class GlobalMenuAndToolBarManager implements DockingWindowListener {

	private Map<WindowNode, WindowActionManager> windowToActionManagerMap;
	private final MenuHandler menuHandler;
	private final MenuGroupMap menuGroupMap;
	private final DockingWindowManager windowManager;

	// set the max delay low enough so that users can't interact with out-of-date actions before
	// they get updated
	private SwingUpdateManager updateManager =
		new SwingUpdateManager(AbstractSwingUpdateManager.DEFAULT_MIN_DELAY, 500,
			"Context Update Manager", () -> updateActions());

	public GlobalMenuAndToolBarManager(DockingWindowManager windowManager, MenuHandler menuHandler,
			MenuGroupMap menuGroupMap) {

		this.windowManager = windowManager;
		this.menuHandler = menuHandler;
		this.menuGroupMap = menuGroupMap;
		RootNode rootNode = windowManager.getRootNode();
		rootNode.addDockingWindowListener(this);
		WindowActionManager mainWindowActionManager =
			new WindowActionManager(rootNode, menuHandler, windowManager, menuGroupMap);
		windowToActionManagerMap = new HashMap<>();
		windowToActionManagerMap.put(rootNode, mainWindowActionManager);
	}

	public void addAction(DockingActionIf action) {
		for (WindowNode node : windowToActionManagerMap.keySet()) {
			Set<Class<?>> contextTypes = node.getContextTypes();
			if (action.shouldAddToWindow(node instanceof RootNode, contextTypes)) {
				WindowActionManager windowActionManager = windowToActionManagerMap.get(node);
				windowActionManager.addAction(action);
			}
		}
	}

	public void removeAction(DockingActionIf action) {
		for (WindowActionManager actionManager : windowToActionManagerMap.values()) {
			actionManager.removeAction(action);
		}
	}

	public void update() {
		for (WindowActionManager actionManager : windowToActionManagerMap.values()) {
			actionManager.update();
		}
	}

	public DockingActionIf getToolbarAction(String actionName) {

		for (WindowActionManager actionManager : windowToActionManagerMap.values()) {
			DockingActionIf action = actionManager.getToolbarAction(actionName);
			if (action != null) {
				return action;
			}
		}
		return null;
	}

	public void dispose() {
		// make sure this is on the swing thread to avoid clearing stuff while the swing update
		// manager is firing its processContextChanged() call
		Swing.runIfSwingOrRunLater(() -> {
			updateManager.dispose();
			for (WindowActionManager actionManager : windowToActionManagerMap.values()) {
				actionManager.dispose();
			}
			windowToActionManagerMap.clear();
		});
	}

	@Override
	public void dockingWindowAdded(WindowNode windowNode) {
		// don't care
	}

	@Override
	public void dockingWindowRemoved(WindowNode windowNode) {
		removeWindowActionManager(windowNode);
	}

	@Override
	public void dockingWindowChanged(WindowNode windowNode) {
		List<DockingActionIf> actionsForWindow = getActionsForWindow(windowNode);
		if (actionsForWindow.isEmpty()) {
			removeWindowActionManager(windowNode);
			return;
		}
		WindowActionManager actionManager = windowToActionManagerMap.get(windowNode);

		if (actionManager == null) {
			createWindowActionManager(windowNode, actionsForWindow);
		}
		else {
			actionManager.setActions(actionsForWindow);
		}
	}

	@Override
	public void dockingWindowFocusChanged(WindowNode windowNode) {
		updateManager.updateLater();
	}

	private void removeWindowActionManager(WindowNode windowNode) {
		WindowActionManager removedActionManager = windowToActionManagerMap.remove(windowNode);
		if (removedActionManager != null) {
			removedActionManager.dispose();
		}
	}

	private void createWindowActionManager(WindowNode windowNode,
			List<DockingActionIf> actionsForWindow) {
		WindowActionManager newActionManager =
			new WindowActionManager(windowNode, menuHandler, windowManager, menuGroupMap);
		windowToActionManagerMap.put(windowNode, newActionManager);
		newActionManager.setActions(actionsForWindow);
		updateManager.updateLater();
	}

	private List<DockingActionIf> getActionsForWindow(WindowNode windowNode) {
		ActionToGuiMapper actionManager = windowManager.getActionToGuiMapper();
		Collection<DockingActionIf> globalActions = actionManager.getGlobalActions();
		List<DockingActionIf> actionsForWindow = new ArrayList<>(globalActions.size());
		Set<Class<?>> contextTypes = windowNode.getContextTypes();
		for (DockingActionIf action : globalActions) {
			if (action.shouldAddToWindow(windowNode instanceof RootNode, contextTypes)) {
				actionsForWindow.add(action);
			}
		}
		return actionsForWindow;
	}

	public void contextChanged() {
		// schedule an update for all the global actions
		updateManager.updateLater();
	}

	private void updateActions() {

		//
		// The focused window's actions must be notified after all other windows in order to
		// prevent incorrect context updates.   We will first update all non-focused windows,
		// then the focused window and then finally tell the Docking Window Manager to update.
		//
		WindowNode focusedWindowNode = getFocusedWindowNode();
		Set<DockingActionIf> focusedWindowActions = getWindowActions(focusedWindowNode);

		Map<Class<? extends ActionContext>, ActionContext> defaultContextMap =
			windowManager.getDefaultActionContextMap();

		for (WindowNode windowNode : windowToActionManagerMap.keySet()) {
			if (windowNode == focusedWindowNode) {
				continue; // the focused window will be called after this loop later
			}

			WindowActionManager actionManager = windowToActionManagerMap.get(windowNode);
			ActionContext localContext = getContext(windowNode);
			actionManager.contextChanged(defaultContextMap, localContext, focusedWindowActions);
		}

		// now update the focused window's actions
		WindowActionManager actionManager = windowToActionManagerMap.get(focusedWindowNode);
		ActionContext focusedContext = getContext(focusedWindowNode);
		if (actionManager != null) {
			actionManager.contextChanged(defaultContextMap, focusedContext, Collections.emptySet());
		}

		// update the docking window manager ; no focused context when no window is focused
		if (focusedContext != null) {
			windowManager.doContextChanged(focusedContext);
		}
	}

	private ActionContext getContext(WindowNode windowNode) {
		if (windowNode == null) {
			return null;
		}

		ActionContext context = null;
		ComponentPlaceholder placeholder = windowNode.getLastFocusedProviderInWindow();
		if (placeholder != null) {
			ComponentProvider provider = placeholder.getProvider();
			if (provider != null) {
				context = provider.getActionContext(null);
			}
		}
		if (context == null) {
			context = new DefaultActionContext();
		}
		return context;
	}

	private Set<DockingActionIf> getWindowActions(WindowNode windowNode) {
		if (windowNode != null) {
			WindowActionManager windowActionManager = windowToActionManagerMap.get(windowNode);
			if (windowActionManager != null) {
				return windowActionManager.getOriginalActions();
			}
		}
		return Collections.emptySet();
	}

	private WindowNode getFocusedWindowNode() {
		ComponentPlaceholder focusedComponent = windowManager.getFocusedComponent();
		if (focusedComponent == null) {
			return null;
		}
		return focusedComponent.getWindowNode();
	}

}
