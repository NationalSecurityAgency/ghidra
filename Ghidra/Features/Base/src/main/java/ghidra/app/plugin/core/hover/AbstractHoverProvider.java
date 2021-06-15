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
package ghidra.app.plugin.core.hover;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.DockingUtils;
import docking.widgets.PopupWindow;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.HoverProvider;
import ghidra.app.services.HoverService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;

public abstract class AbstractHoverProvider implements HoverProvider {

	protected List<HoverService> hoverServices = new ArrayList<>();
	protected boolean enabled = true;
	protected Program program;
	protected Field lastField;
	private static final Comparator<HoverService> HOVER_PRIORITY_COMPARATOR =
		(service1, service2) -> service2.getPriority() - service1.getPriority();
	protected HoverService activeHoverService;
	protected PopupWindow popupWindow;

	protected final String windowName;

	public AbstractHoverProvider(String windowName) {
		super();
		this.windowName = windowName;
	}

	protected void addHoverService(HoverService hoverService) {
		hoverServices.add(hoverService);
		Collections.sort(hoverServices, HOVER_PRIORITY_COMPARATOR);
	}

	protected void removeHoverService(HoverService hoverService) {
		hoverServices.remove(hoverService);
	}

	public void setProgram(Program program) {
		this.program = program;
	}

	public Program getProgram() {
		return program;
	}

	public void setHoverEnabled(boolean enabled) {
		if (enabled == this.enabled) {
			return;
		}
		this.enabled = enabled;
		if (enabled && !hasEnabledHoverServices()) {
			Msg.showInfo(getClass(), null, "No Popups Enabled", "You have chosen to " +
				"enable tooltip style popups, but none are currently enabled.\nTo enable these " +
				"popups you must use the options menu: \"Options->Listing Popups\"");
		}
	}

	private boolean hasEnabledHoverServices() {
		for (HoverService hoverService : hoverServices) {
			if (hoverService.hoverModeSelected()) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean isShowing() {
		return popupWindow != null && popupWindow.isShowing();
	}

	@Override
	public void closeHover() {
		activeHoverService = null;
		lastField = null;

		DockingUtils.hideTipWindow();

		if (popupWindow != null) {
			popupWindow.dispose();
			popupWindow = null;
		}
	}

	@Override
	public void scroll(int amount) {
		if (activeHoverService != null) {
			activeHoverService.scroll(amount);
		}
	}

	public void dispose() {
		// we can be disposed from outside the swing thread
		Swing.runLater(() -> {
			closeHover();
			hoverServices.clear();
		});

		program = null;
	}

	protected abstract ProgramLocation getHoverLocation(FieldLocation fieldLocation, Field field,
			Rectangle fieldBounds, MouseEvent event);

	@Override
	public void mouseHovered(FieldLocation fieldLocation, Field field, Rectangle fieldBounds,
			MouseEvent event) {

		if (isShowing() && field == lastField) {
			return;
		}

		if (program == null) {
			return;
		}

		Component component = event.getComponent();
		if (!component.isShowing()) {
			// This can happen since we are using a timer.  When the timer fires, the source 
			// component may have been hidden.
			return;
		}

		ProgramLocation loc = getHoverLocation(fieldLocation, field, fieldBounds, event);
		for (HoverService hoverService : hoverServices) {
			JComponent comp = hoverService.getHoverComponent(program, loc, fieldLocation, field);
			if (comp != null) {
				closeHover();
				activeHoverService = hoverService;
				showPopup(comp, field, event, fieldBounds);
				return;
			}
		}
	}

	protected void showPopup(JComponent comp, Field field, MouseEvent event,
			Rectangle fieldBounds) {
		lastField = field;

		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Window activeWindow = kfm.getActiveWindow();
		if (activeWindow == null) {
			activeWindow = JOptionPane.getRootFrame();
		}

		popupWindow = new PopupWindow(activeWindow, comp);
		popupWindow.setWindowName(windowName);

		popupWindow.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentShown(ComponentEvent e) {
				if (activeHoverService != null) {
					activeHoverService.componentShown();
				}
			}

			@Override
			public void componentHidden(ComponentEvent e) {
				if (activeHoverService != null) {
					activeHoverService.componentHidden();
				}
			}
		});

		boolean isToolTip = comp instanceof JToolTip;
		if (isToolTip) {
			popupWindow.showPopup(event);
		}
		else {

			// 
			// Make an area over which to show the popup.   The popup should not cover this area.
			// The field that is hovered may be too big to be this area, as a big field may cause 
			// the popup to be too far away from the cursor.
			//
			// Use the mouse point and then create an area (based on trial-and-error) that should
			// not be occluded. 
			// 
			int horizontalPad = 100;
			int verticalPad = 50;
			Rectangle keepVisibleArea = new Rectangle(event.getPoint());
			keepVisibleArea.grow(horizontalPad, verticalPad);

			popupWindow.showOffsetPopup(event, keepVisibleArea);
		}
	}

	public void initializeListingHoverHandler(AbstractHoverProvider otherHandler) {
		otherHandler.program = program;
		otherHandler.enabled = enabled;
		otherHandler.hoverServices = new ArrayList<>(hoverServices);
	}

}
