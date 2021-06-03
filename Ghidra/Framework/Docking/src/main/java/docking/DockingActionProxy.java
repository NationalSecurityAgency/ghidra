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

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.List;
import java.util.Set;

import javax.swing.*;

import docking.action.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;

public class DockingActionProxy
		implements ToggleDockingActionIf, MultiActionDockingActionIf, PropertyChangeListener {
	private WeakSet<PropertyChangeListener> propertyListeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();
	private final DockingActionIf dockingAction;

	public DockingActionProxy(DockingActionIf dockingAction) {
		this.dockingAction = dockingAction;
		dockingAction.addPropertyChangeListener(this);
	}

	public DockingActionIf getAction() {
		return dockingAction;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		dockingAction.actionPerformed(context);
	}

	@Override
	public void addPropertyChangeListener(PropertyChangeListener listener) {
		propertyListeners.add(listener);
	}

	@Override
	public String getDescription() {
		return dockingAction.getDescription();
	}

	@Override
	public String getFullName() {
		return dockingAction.getFullName();
	}

	@Override
	public String getInceptionInformation() {
		return dockingAction.getInceptionInformation();
	}

	@Override
	public KeyBindingData getKeyBindingData() {
		return dockingAction.getKeyBindingData();
	}

	@Override
	public KeyBindingData getDefaultKeyBindingData() {
		return dockingAction.getDefaultKeyBindingData();
	}

	@Override
	public MenuData getMenuBarData() {
		return dockingAction.getMenuBarData();
	}

	@Override
	public String getName() {
		return dockingAction.getName();
	}

	@Override
	public String getOwner() {
		return dockingAction.getOwner();
	}

	@Override
	public MenuData getPopupMenuData() {
		return dockingAction.getPopupMenuData();
	}

	@Override
	public ToolBarData getToolBarData() {
		return dockingAction.getToolBarData();
	}

	@Override
	public boolean isEnabled() {
		return dockingAction.isEnabled();
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return dockingAction.isAddToPopup(context);
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return dockingAction.isValidContext(context);
	}

	@Override
	public void removePropertyChangeListener(PropertyChangeListener listener) {
		propertyListeners.remove(listener);
	}

	@Override
	public void setEnabled(boolean newValue) {
		dockingAction.setEnabled(newValue);
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		PropertyChangeEvent myEvent = new PropertyChangeEvent(this, evt.getPropertyName(),
			evt.getOldValue(), evt.getNewValue());
		firePropertyChanged(myEvent);
	}

	protected void firePropertyChanged(PropertyChangeEvent event) {
		for (PropertyChangeListener listener : propertyListeners) {
			listener.propertyChange(event);
		}
	}

	public DockingActionIf getProxyAction() {
		return dockingAction;
	}

	@Override
	public boolean isSelected() {
		if (dockingAction instanceof ToggleDockingActionIf) {
			return ((ToggleDockingActionIf) dockingAction).isSelected();
		}
		return false; // if not a Toggle action, just return false
	}

	@Override
	public void setSelected(boolean newValue) {
		if (dockingAction instanceof ToggleDockingActionIf) {
			((ToggleDockingActionIf) dockingAction).setSelected(newValue);
		}
		// if not a toggle action, ignore
	}

	@Override
	public List<DockingActionIf> getActionList(ActionContext context) {
		if (dockingAction instanceof MultiActionDockingActionIf) {
			((MultiActionDockingActionIf) dockingAction).getActionList(context);
		}
		throw new AssertException("Attempted to set selection state on non-toggle action!");
	}

	@Override
	public JButton createButton() {
		return dockingAction.createButton();
	}

	@Override
	public JMenuItem createMenuItem(boolean isPopup) {
		return dockingAction.createMenuItem(isPopup);
	}

	@Override
	public boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes) {
		return dockingAction.shouldAddToWindow(isMainWindow, contextTypes);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return dockingAction.isEnabledForContext(context);
	}

	@Override
	public KeyStroke getKeyBinding() {
		return dockingAction.getKeyBinding();
	}

	@Override
	public KeyBindingType getKeyBindingType() {
		return dockingAction.getKeyBindingType();
	}

	@Override
	public void setKeyBindingData(KeyBindingData keyBindingData) {
		dockingAction.setKeyBindingData(keyBindingData);
	}

	@Override
	public void setUnvalidatedKeyBindingData(KeyBindingData newKeyBindingData) {
		dockingAction.setUnvalidatedKeyBindingData(newKeyBindingData);
	}

	@Override
	public void dispose() {
		dockingAction.dispose();
	}

	@Override
	public String getHelpInfo() {
		return dockingAction.getHelpInfo();
	}

	@Override
	public Object getHelpObject() {
		return dockingAction;
	}

	@Override
	public String toString() {
		return dockingAction.toString();
	}

	@Override
	public void setSupportsDefaultToolContext(boolean newValue) {
		dockingAction.setSupportsDefaultToolContext(newValue);
	}

	@Override
	public boolean supportsDefaultToolContext() {
		return dockingAction.supportsDefaultToolContext();
	}
}
