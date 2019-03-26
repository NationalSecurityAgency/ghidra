/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.wizard;

import ghidra.util.HelpLocation;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

import java.awt.Component;
import java.awt.LayoutManager;

import javax.swing.JPanel;

public abstract class AbstractMageJPanel<T> extends JPanel implements MagePanel<T> {
	protected WeakSet<WizardPanelListener> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	public AbstractMageJPanel() {
		super();
	}

	public AbstractMageJPanel(LayoutManager layout) {
		super(layout);
	}

	@Override
	public void addWizardPanelListener(WizardPanelListener l) {
		listeners.add(l);
	}

	@Override
	public void removeWizardPanelListener(WizardPanelListener l) {
		listeners.remove(l);
	}

	/**
	 * Notification that something on the panel has changed.
	 */
	protected void notifyListenersOfValidityChanged() {
		for (WizardPanelListener listener : listeners) {
			listener.validityChanged();
		}
	}

	/**
	 * Notification that a message should be displayed on the panel.
	 * 
	 * @param msg
	 *            message to display
	 */
	protected void notifyListenersOfStatusMessage(String msg) {
		for (WizardPanelListener listener : listeners) {
			listener.setStatusMessage(msg);
		}
	}

	@Override
	public JPanel getPanel() {
		return this;
	}

	@Override
	public Component getDefaultFocusComponent() {
		return null; // no preferred focus component by default
	}

	@Override
	public HelpLocation getHelpLocation() {
		return null;
	}
}
