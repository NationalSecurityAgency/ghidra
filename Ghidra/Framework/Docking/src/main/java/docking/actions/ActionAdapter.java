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
package docking.actions;

import java.awt.event.ActionEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Action;
import javax.swing.Icon;

import docking.ActionContext;
import docking.action.ActionContextProvider;
import docking.action.DockingActionIf;

public class ActionAdapter implements Action, PropertyChangeListener {

	private final DockingActionIf dockingAction;
	private List<PropertyChangeListener> listeners = new ArrayList<PropertyChangeListener>();
	private ActionContextProvider contextProvider;
	private Action defaultAction;

	/**
	 * This is only for use when converting actions from docking actions to those to be used
	 * in Swing components.  The context system does not work as expected in this case.
	 * 
	 * <p>Most clients should use {@link #ActionAdapter(DockingActionIf, ActionContextProvider)}
	 * @param dockingAction the action to adapt
	 */
	ActionAdapter(DockingActionIf dockingAction) {
		this(dockingAction, null);
	}

	public ActionAdapter(DockingActionIf dockingAction, ActionContextProvider provider) {
		this.dockingAction = dockingAction;
		this.contextProvider = provider;
		dockingAction.addPropertyChangeListener(this);
	}

	public void setDefaultAction(Action defaultAction) {
		this.defaultAction = defaultAction;
	}

	@Override
	public void addPropertyChangeListener(PropertyChangeListener listener) {
		listeners.add(listener);
	}

	@Override
	public Object getValue(String key) {
		if (key.equals(NAME)) {
			return dockingAction.getName();
		}
		else if (key.equals(SHORT_DESCRIPTION)) {
			return dockingAction.getDescription();
		}
		else if (key.equals(LONG_DESCRIPTION)) {
			return dockingAction.getDescription();
		}
		else if (key.equals(SMALL_ICON)) {
			return getIcon();
		}
		else if (key.equals(ACCELERATOR_KEY)) {
			return dockingAction.getKeyBinding();
		}
		return null;
	}

	private Icon getIcon() {
		if (dockingAction.getToolBarData() != null) {
			return dockingAction.getToolBarData().getIcon();
		}
		else if (dockingAction.getMenuBarData() != null) {
			return dockingAction.getMenuBarData().getMenuIcon();
		}
		else if (dockingAction.getPopupMenuData() != null) {
			return dockingAction.getPopupMenuData().getMenuIcon();
		}
		return null;
	}

	@Override
	public boolean isEnabled() {
		return dockingAction.isEnabled();
	}

	@Override
	public void putValue(String key, Object value) {
		System.err.println("PutValue key = " + key + " value = " + value);
	}

	@Override
	public void removePropertyChangeListener(PropertyChangeListener listener) {
		listeners.add(listener);
	}

	@Override
	public void setEnabled(boolean b) {
		dockingAction.setEnabled(b);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		ActionContext context = null;
		if (contextProvider != null) {
			context = contextProvider.getActionContext(null);
		}
		if (context == null) {
			context = new ActionContext();
			context.setSourceObject(e.getSource());
		}
		if (dockingAction.isEnabledForContext(context)) {
			dockingAction.actionPerformed(context);
		}
		else if (defaultAction != null) {
			defaultAction.actionPerformed(e);
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		for (PropertyChangeListener listener : listeners) {
			listener.propertyChange(evt);
		}
	}

}
