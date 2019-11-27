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

public class GlobalMenuAndToolBarManager implements DockingWindowListener {

	private Map<WindowNode, WindowActionManager> windowToActionManagerMap;
	private final MenuHandler menuHandler;
	private final MenuGroupMap menuGroupMap;
	private final DockingWindowManager windowManager;

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
		for (WindowActionManager actionManager : windowToActionManagerMap.values()) {
			actionManager.dispose();
		}
		windowToActionManagerMap.clear();

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
		//update global menus and toolbars for this window
		ComponentPlaceholder lastFocused = windowNode.getLastFocusedProviderInWindow();
		WindowActionManager windowActionManager = windowToActionManagerMap.get(windowNode);
		if (windowActionManager == null) {
			return;
		}
		windowActionManager.contextChanged(lastFocused);
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
		ComponentPlaceholder lastFocused = windowNode.getLastFocusedProviderInWindow();
		newActionManager.contextChanged(lastFocused);
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

	public void contextChangedAll() {
		Swing.runIfSwingOrRunLater(this::updateAllWindowActions);
	}

	private void updateAllWindowActions() {
		for (WindowNode windowNode : windowToActionManagerMap.keySet()) {
			ComponentPlaceholder lastFocused = windowNode.getLastFocusedProviderInWindow();
			windowToActionManagerMap.get(windowNode).contextChanged(lastFocused);
		}
	}

	public void contextChanged(ComponentPlaceholder placeHolder) {
		if (placeHolder == null) {
			return;
		}

		WindowNode topLevelNode = placeHolder.getTopLevelNode();
		if (topLevelNode == null) {
			return;
		}

		if (topLevelNode.getLastFocusedProviderInWindow() != placeHolder) {
			return; // actions in this window are not currently responding to this provider
		}

		WindowActionManager windowActionManager = windowToActionManagerMap.get(topLevelNode);
		if (windowActionManager != null) {
			windowActionManager.contextChanged(placeHolder);
		}
	}
}
