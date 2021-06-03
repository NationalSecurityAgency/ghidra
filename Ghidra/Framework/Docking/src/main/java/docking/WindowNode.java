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

import java.awt.BorderLayout;
import java.awt.Container;
import java.util.*;

import javax.swing.*;

public abstract class WindowNode extends Node {
	private JPanel toolBarPanel;
	private ComponentPlaceholder lastFocusedProviderInWindow;
	private Set<Class<?>> contextTypes;

	WindowNode(DockingWindowManager winMgr) {
		super(winMgr);
	}

	abstract void setMenuBar(JMenuBar menuBar);

	abstract String getTitle();

	abstract void validate();

	abstract Container getContentPane();

	abstract boolean isVisible();

	void setToolBar(JComponent toolBar) {
		Container rootPane = getContentPane();
		if (rootPane == null) {
			return;
		}
		if (toolBarPanel != null) {
			rootPane.remove(toolBarPanel);
			toolBarPanel = null;
		}
		if (toolBar != null) {
			toolBarPanel = new JPanel(new BorderLayout());
			toolBarPanel.add(toolBar, BorderLayout.NORTH);
			toolBarPanel.add(new JSeparator(SwingConstants.HORIZONTAL), BorderLayout.SOUTH);
			rootPane.add(toolBarPanel, BorderLayout.NORTH);
		}
	}

	public void setLastFocusedProviderInWindow(ComponentPlaceholder lastFocusedInWindow) {
		this.lastFocusedProviderInWindow = lastFocusedInWindow;
	}

	public ComponentPlaceholder getLastFocusedProviderInWindow() {
		if (lastFocusedProviderInWindow == null) {
			// We must manually hunt for a DockableComponent, as Java could not find a default focus
			// owner in the given window.
			List<ComponentPlaceholder> activeComponents = getActiveComponents();
			if (activeComponents.size() != 0) {
				lastFocusedProviderInWindow = activeComponents.get(0);
			}
		}

		return lastFocusedProviderInWindow;
	}

	public Set<Class<?>> getContextTypes() {
		if (contextTypes == null) {
			contextTypes = new HashSet<Class<?>>();
			List<ComponentPlaceholder> activeComponents = getActiveComponents();
			for (ComponentPlaceholder placeholder : activeComponents) {
				ComponentProvider provider = placeholder.getProvider();
				Class<?> contextType = provider.getContextType();
				if (contextType != null) {
					contextTypes.add(contextType);
				}
			}
		}
		return contextTypes;
	}

	List<ComponentPlaceholder> getActiveComponents() {
		List<ComponentPlaceholder> activeComponents =
			new ArrayList<ComponentPlaceholder>();
		populateActiveComponents(activeComponents);
		return activeComponents;
	}

	protected void clearContextTypes() {
		contextTypes = null;
	}

	@Override
	void dispose() {
		toolBarPanel = null;

	}

	public void componentRemoved(ComponentPlaceholder placeholder) {
		if (lastFocusedProviderInWindow == placeholder) {
			lastFocusedProviderInWindow = null;
		}
	}

	public void componentAdded(ComponentPlaceholder placeholder) {
		// nothing to do
	}
}
