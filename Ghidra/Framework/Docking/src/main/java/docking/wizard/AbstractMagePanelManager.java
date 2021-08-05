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
package docking.wizard;

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

public abstract class AbstractMagePanelManager<T> implements PanelManager {

	private List<MagePanel<T>> panels;
	private Stack<Integer> panelPath;
	private int currentIndex;
	private WizardState<T> state;

	protected AbstractMagePanelManager(WizardState<T> initialState) {
		panelPath = new Stack<>();
		this.state = initialState;

	}

	protected abstract Collection<? extends MagePanel<T>> createPanels();

	protected WizardState<T> getState() {
		return state;
	}

	private WizardManager wizardManager;

	@Override
	public void cancel() {
		// do nothing by default
	}

	@Override
	public final WizardManager getWizardManager() {
		return wizardManager;
	}

	@Override
	public final void setWizardManager(WizardManager wm) {
		this.wizardManager = wm;
	}

	@Override
	public Dimension getPanelSize() {
		int minWidth = -1;
		int minHeight = -1;
		for (MagePanel<T> panel : getPanels()) {
			JComponent component = (JComponent) panel;
			Dimension preferredSize = component.getPreferredSize();
			if (preferredSize.width > minWidth) {
				minWidth = preferredSize.width;
			}
			if (preferredSize.height > minHeight) {
				minHeight = preferredSize.height;
			}
		}

		// take into account the scrollbar size so we do not get horizontal scrollbars unnecessarily
		Dimension dimension = new Dimension(minWidth, minHeight);
		JScrollBar scrollBar = new JScrollBar(Adjustable.VERTICAL);
		Dimension scrollBarSize = scrollBar.getMinimumSize();
		dimension.width = dimension.width + (scrollBarSize.width * 2); // add some fudge for borders

		return dimension;
	}

	private String statusMessage;

	@Override
	public final String getStatusMessage() {
		String tmp = statusMessage;
		statusMessage = null;
		return tmp;
	}

	protected final void setStatusMessage(String msg) {
		this.statusMessage = msg;
		wizardManager.setStatusMessage(msg);
	}

	protected void initializeHook() {
		// let subclasses add functionality to initialize without losing ours
	}

	@Override
	public final void initialize() {
		for (MagePanel<T> panel : getPanels()) {
			panel.initialize();
		}
		setCurrentIndex(-1);
		panelPath.clear();
		statusMessage = null;
		initializeHook();
	}

	protected final MagePanel<T> getCurrentPanel() {
		int index = getCurrentIndex();
		List<MagePanel<T>> panelList = getPanels();
		if (index < 0 || index >= panelList.size()) {
			return null;
		}
		return panelList.get(index);
	}

	@Override
	@SuppressWarnings("unchecked")
	public final boolean hasNextPanel() {
		MagePanel<T> currentPanel = getCurrentPanel();
		WizardState<T> pretendState = (WizardState<T>) state.clone();
		if (currentPanel != null) {
			currentPanel.updateStateObjectWithPanelInfo(pretendState);
		}
		MagePanel<T> panel = null;
		int index = getCurrentIndex() + 1;
		while (index < getPanels().size()) {
			panel = getPanels().get(index);
			WizardPanelDisplayability displayability =
				panel.getPanelDisplayabilityAndUpdateState(pretendState);
			if (displayability == WizardPanelDisplayability.MUST_BE_DISPLAYED ||
				displayability == WizardPanelDisplayability.CAN_BE_DISPLAYED) {
				return true;
			}
			++index;
		}
		return false;
	}

	@Override
	public final boolean hasPreviousPanel() {
		return panelPath.size() > 0;
	}

	@Override
	@SuppressWarnings("unchecked")
	public final boolean canFinish() {
		MagePanel<T> currentPanel = getCurrentPanel();
		WizardState<T> pretendState = (WizardState<T>) state.clone();
		if (currentPanel != null) {
			currentPanel.updateStateObjectWithPanelInfo(pretendState);
		}
		MagePanel<T> panel = null;
		int index = getCurrentIndex() + 1;
		while (index < getPanels().size()) {
			panel = getPanels().get(index);
			WizardPanelDisplayability displayability =
				panel.getPanelDisplayabilityAndUpdateState(pretendState);
			if (displayability == WizardPanelDisplayability.MUST_BE_DISPLAYED) {
				return false;
			}
			++index;
		}
		return true;
	}

	@Override
	public final WizardPanel getNextPanel() throws IllegalPanelStateException {
		Window window = getWindow();
		Cursor originalCursor = getCursor(window);
		try {
			setCursor(window, Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
			return doGetNextPanel();
		}
		finally {
			setCursor(window, originalCursor);
		}
	}

	@Override
	public WizardPanel getInitialPanel() throws IllegalPanelStateException {
		Window window = getWindow();
		Cursor originalCursor = getCursor(window);
		try {
			setCursor(window, Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
			panelPath.clear();
			MagePanel<T> panel = panels.get(0);
			panel.getPanelDisplayabilityAndUpdateState(state);
			panel.enterPanel(state);
			setCurrentIndex(0);
			return panel;
		}
		finally {
			setCursor(window, originalCursor);
		}
	}

	private WizardPanel doGetNextPanel() throws IllegalPanelStateException {
		MagePanel<T> currentPanel = getCurrentPanel();
		if (currentPanel != null) {
			currentPanel.leavePanel(state);
			panelPath.push(getCurrentIndex());
		}
		MagePanel<T> panel = null;
		int index = getCurrentIndex() + 1;
		while (index < getPanels().size()) {
			panel = getPanels().get(index);
			WizardPanelDisplayability displayability =
				panel.getPanelDisplayabilityAndUpdateState(state);
			if (displayability == WizardPanelDisplayability.MUST_BE_DISPLAYED ||
				displayability == WizardPanelDisplayability.CAN_BE_DISPLAYED) {
				panel.enterPanel(state);
				setCurrentIndex(index);
				return panel;
			}
			++index;
		}
		return null;
	}

	private void setCursor(Window window, Cursor cursor) {
		if (window == null) {
			return; // shouldn't happen
		}

		window.setCursor(cursor);

		if (window instanceof JWindow) {
			JRootPane rootPane = ((JWindow) window).getRootPane();
			rootPane.paintImmediately(rootPane.getBounds());
		}
		else if (window instanceof JDialog) {
			JRootPane rootPane = ((JDialog) window).getRootPane();
			rootPane.paintImmediately(rootPane.getBounds());
		}
		else if (window instanceof JFrame) {
			JRootPane rootPane = ((JFrame) window).getRootPane();
			rootPane.paintImmediately(rootPane.getBounds());
		}

	}

	private Cursor getCursor(Window window) {
		if (window == null) {
			return null;
		}

		return window.getCursor();
	}

	private Window getWindow() {
		KeyboardFocusManager focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		return focusManager.getActiveWindow();
	}

	@Override
	public final WizardPanel getPreviousPanel() throws IllegalPanelStateException {
		Window window = getWindow();
		Cursor originalCursor = getCursor(window);
		try {
			setCursor(window, Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
			return doGetPreviousPanel();
		}
		finally {
			setCursor(window, originalCursor);
		}
	}

	private WizardPanel doGetPreviousPanel() throws IllegalPanelStateException {
		if (hasPreviousPanel()) {
			MagePanel<T> currentPanel = getCurrentPanel();
			if (currentPanel != null) {
				currentPanel.leavePanel(state);
			}
			int previousIndex = panelPath.pop();
			MagePanel<T> panel = getPanels().get(previousIndex);
			panel.enterPanel(state);
			setCurrentIndex(previousIndex);
			return panel;
		}
		return null;
	}

	protected abstract void doFinish() throws IllegalPanelStateException;

	@Override
	public final void finish() throws IllegalPanelStateException {
		getWizardManager().disableNavigation();
		MagePanel<T> currentPanel = getCurrentPanel();
		if (currentPanel != null) {
			currentPanel.leavePanel(state);
		}
		MagePanel<T> panel = null;
		int index = getCurrentIndex() + 1;
		while (index < getPanels().size()) {
			panel = getPanels().get(index);
			panel.getPanelDisplayabilityAndUpdateState(state);
			++index;
		}
		doFinish();
		initialize(); // reset the panels
		wizardManager.enableNavigation();
	}

	protected final List<MagePanel<T>> getPanels() {
		if (panels == null) {
			panels = Collections.unmodifiableList(new ArrayList<MagePanel<T>>(createPanels()));
			for (MagePanel<T> magePanel : this.panels) {
				magePanel.addDependencies(this.state);
			}
		}
		return panels;
	}

	private int getCurrentIndex() {
		return currentIndex;
	}

	private void setCurrentIndex(int currentIndex) {
		this.currentIndex = currentIndex;
	}
}
