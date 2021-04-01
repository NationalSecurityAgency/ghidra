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
package ghidra.graph.viewer.popup;

import java.awt.Component;
import java.awt.Window;
import java.awt.event.*;

import javax.swing.*;

import docking.widgets.PopupWindow;

/**
 * A class to control popups for graph clients, bypassing Java's default tool tip mechanism
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class PopupRegulator<V, E> {

	private int popupDelay = 1000;

	/**
	 * We need this timer because the default mechanism for triggering popups doesn't 
	 * always work.  We use this timer in conjunction with a mouse motion listener to 
	 * get the results we want.
	 */
	private Timer popupTimer;
	private MouseEvent popupMouseEvent;

	/** the current target (vertex or edge) of a popup window */
	private Object nextPopupTarget;

	/** 
	 * This value is not null when the user moves the cursor over a target for which a 
	 * popup is already showing.  We use this value to prevent showing a popup multiple times
	 * while over a single node.
	 */
	private Object lastShownPopupTarget;

	/** The tooltip info used when showing the popup */
	private ToolTipInfo<?> currentToolTipInfo;

	private PopupSource<V, E> popupSource;
	private PopupWindow popupWindow;
	private boolean showPopups = true;

	public PopupRegulator(PopupSource<V, E> popupSupplier) {
		this.popupSource = popupSupplier;
		popupTimer = new Timer(popupDelay, e -> {
			if (isPopupShowing()) {
				return; // don't show any new popups while the user is perusing
			}
			showPopupForMouseEvent(popupMouseEvent);
		});

		popupTimer.setRepeats(false);

		popupSupplier.addMouseMotionListener(new MouseMotionListener() {
			@Override
			public void mouseDragged(MouseEvent e) {
				hidePopupTooltips();
				popupTimer.stop();
				popupMouseEvent = null; // clear any queued popups
			}

			@Override
			public void mouseMoved(MouseEvent e) {
				popupMouseEvent = e;

				// this clears out the current last popup shown so that the user can 
				// move off and on a node to re-show the popup
				savePopupTarget(e);

				// make sure the popup gets triggered eventually
				popupTimer.restart();
			}
		});
	}

	/**
	 * Returns true if this class's popup is showing
	 * @return true if this class's popup is showing
	 */
	public boolean isPopupShowing() {
		return popupWindow != null && popupWindow.isShowing();
	}

	/**
	 * Sets the time between mouse movements to wait before showing this class's popup
	 * @param delayMs the delay
	 */
	public void setPopupDelay(int delayMs) {
		popupTimer.stop();
		popupTimer.setDelay(delayMs);
		popupTimer.setInitialDelay(delayMs);
		popupDelay = delayMs;
	}

	/**
	 * Sets the enablement of this class's popup
	 * @param visible true to have popups enabled
	 */
	public void setPopupsVisible(boolean visible) {
		this.showPopups = visible;
		if (!showPopups) {
			hidePopupTooltips();
		}
	}

	private void showPopupForMouseEvent(MouseEvent event) {
		if (!showPopups) {
			return;
		}

		if (event == null) {
			return;
		}

		Component c = event.getComponent();
		if (!c.isShowing()) {
			// This method is called from a a timer.  It is possible that the graph has been 
			// closed by the time this method is called.
			return;
		}

		ToolTipInfo<?> toolTipInfo = popupSource.getToolTipInfo(event);
		JComponent toolTipComponent = toolTipInfo.getToolTipComponent();
		boolean isCustomJavaTooltip = !(toolTipComponent instanceof JToolTip);
		if (lastShownPopupTarget == nextPopupTarget && isCustomJavaTooltip) {
			// 
			// Kinda Hacky:
			// We don't show repeated popups for the same item (the user has to move away
			// and then come back to re-show the popup).  However, one caveat to this is that
			// we do want to allow the user to see popups for the toolbar actions always.  So,
			// only return here if we have already shown a popup for the item *and* we are 
			// using a custom tooltip (which is used to show a vertex tooltip or an edge 
			// tooltip)
			return;
		}

		currentToolTipInfo = toolTipInfo;
		showTooltip(currentToolTipInfo);
	}

	private void popupShown() {
		lastShownPopupTarget = nextPopupTarget;
		currentToolTipInfo.emphasize();
		popupSource.repaint();
	}

	private void popupHidden() {
		currentToolTipInfo.deEmphasize();
		popupSource.repaint();
	}

	private void savePopupTarget(MouseEvent event) {
		nextPopupTarget = null;
		V vertex = popupSource.getVertex(event);
		if (vertex != null) {
			nextPopupTarget = vertex;
		}
		else {
			E edge = popupSource.getEdge(event);
			nextPopupTarget = edge;
		}

		if (nextPopupTarget == null) {
			// We've moved off of a target. We will clear that last target so the user can
			// mouse off of a vertex and back on in order to trigger a new popup
			lastShownPopupTarget = null;
		}
	}

	private void hidePopupTooltips() {
		if (popupWindow != null && popupWindow.isShowing()) {
			popupWindow.hide();
			// don't call dispose, or we don't get our componentHidden() callback 
			// popupWindow.dispose();
		}
	}

	private void showTooltip(ToolTipInfo<?> info) {
		JComponent tipComponent = info.getToolTipComponent();
		if (tipComponent == null) {
			return;
		}

		MouseEvent event = info.getMouseEvent();
		showPopupWindow(event, tipComponent);
	}

	private void showPopupWindow(MouseEvent event, JComponent component) {
		MenuSelectionManager menuManager = MenuSelectionManager.defaultManager();
		if (menuManager.getSelectedPath().length != 0) {
			return;
		}

		Window parentWindow = popupSource.getPopupParent();
		popupWindow = new PopupWindow(parentWindow, component);

		popupWindow.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentShown(ComponentEvent e) {
				popupShown();
			}

			@Override
			public void componentHidden(ComponentEvent e) {
				popupHidden();
			}
		});

		popupWindow.showPopup(event);
	}
}
