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

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

import org.apache.commons.collections4.map.LazyMap;

import docking.framework.ApplicationInformationDisplayFactory;
import docking.help.HelpDescriptor;
import generic.util.WindowUtilities;
import ghidra.framework.Application;
import ghidra.util.bean.GGlassPane;

// NOTE: this class has a static focus component variable that is set whenever the dialog gets
// activated and is scheduled to get focus at a later time.  This variable is static so that only
// one component at a time is ever scheduled to request focus.  This prevents a possible bug where
// two or more dialogs rapidly and continuously swap activation back and forth.

public class DockingDialog extends JDialog implements HelpDescriptor {
	private static Component focusComponent; // allow only one scheduled focus component. See above.

	private static Map<String, BoundsInfo> dialogBoundsMap =
		LazyMap.lazyMap(new HashMap<>(), () -> new BoundsInfo());

	private WindowListener windowAdapter;
	private DialogComponentProvider component;
	private boolean hasBeenFocused;
	private Runnable requestFocusRunnable = () -> {
		if (focusComponent != null) {
			focusComponent.requestFocus();
			hasBeenFocused = true;
		}
	};
	private DockingWindowManager owningWindowManager;
	private WindowAdapter modalFixWindowAdapter;

	/**
	 * Creates a default parent frame that will appear in the OS's task bar.  Having this frame
	 * gives the user something to click when their dialog is lost.  We attempt to hide this 
	 * frame offscreen.
	 * 
	 * Note: we expect to only get here when there is no parent window found.  This usually
	 * only happens during tests and one-off main methods that are not part of a 
	 * running tool.
	 * 
	 * @param componentProvider the dialog content for this dialog
	 * @return the hidden frame
	 */
	private static JFrame createHiddenParentFrame(DialogComponentProvider componentProvider) {

		//
		// Note: we expect to only get here when there is no parent window found.  This usually
		//       only happens during tests and one-off main methods that are not part of a 
		//       running tool
		//
		HiddenDockingFrame hiddenFrame = new HiddenDockingFrame(Application.getName());
		hiddenFrame.setShowingAllowed(true);
		List<Image> list = ApplicationInformationDisplayFactory.getWindowIcons();
		hiddenFrame.setIconImages(list);
		hiddenFrame.setUndecorated(true);

		hiddenFrame.setBounds(-500, -500, 10, 10);

		// This prevents a window from showing in the taskbar; it is assumed that we the
		// window to appear in the taskbar.  If clients need this in the future, then we would
		// have to make it a value on the DialogComponentProvider
		// frame.setHidden( true ); // make invisible
		hiddenFrame.setVisible(true);
		return hiddenFrame;
	}

	public static DockingDialog createDialog(Window parent, DialogComponentProvider comp,
			Component centeredOnComponent) {
		if (parent instanceof Dialog) {
			return new DockingDialog((Dialog) parent, comp, centeredOnComponent);
		}

		if (parent instanceof Frame) {
			return new DockingDialog((Frame) parent, comp, centeredOnComponent);
		}

		return new DockingDialog(comp, centeredOnComponent);
	}

	private DockingDialog(Dialog parent, DialogComponentProvider comp,
			Component centeredOnComponent) {
		super(parent, comp.getTitle(), comp.isModal());
		owningWindowManager = DockingWindowManager.getInstance(parent);
		init(comp);
		initializeLocationAndSize(centeredOnComponent);
	}

	private DockingDialog(Frame parent, DialogComponentProvider comp,
			Component centeredOnComponent) {
		super(parent, comp.getTitle(), comp.isModal());
		owningWindowManager = DockingWindowManager.getInstance(parent);
		init(comp);
		initializeLocationAndSize(centeredOnComponent);
	}

	private DockingDialog(DialogComponentProvider comp, Component centeredOnComponent) {
		super(createHiddenParentFrame(comp), comp.getTitle(), comp.isModal());
		init(comp);
		initializeLocationAndSize(centeredOnComponent);
	}

	private void initializeLocationAndSize(Component centeredOnComponent) {

		String key = getKey();
		BoundsInfo boundsInfo = dialogBoundsMap.get(key);
		Rectangle lastBounds = boundsInfo.getEndBounds();
		applySize(lastBounds); // apply the size before we try to center

		Point initialLocation = component.getIntialLocation();
		if (initialLocation != null) {
			// NOTE: have to call setLocation() twice because the first time the native peer 
			// component's location is not actually changed; calling setLocation() again 
			// does cause the location to change.
			setLocation(initialLocation);
			setLocation(initialLocation);
		}
		else if (centeredOnComponent != null) {
			setCenteredOnComponent(centeredOnComponent);
		}
		else {
			setCenteredOnComponent(getParent());
		}

		boundsInfo.setStartBounds(new Rectangle(getBounds())); // set the default bounds

		// restore the location after the default positioning
		if (boundsInfo.hasBeenMoved()) {
			applyLocation(lastBounds);
		}
	}

	private void applySize(Rectangle savedBounds) {
		boolean rememberSize = component.getRemberSize();
		if (rememberSize && savedBounds != null) {
			setSize(savedBounds.width, savedBounds.height);
			return;
		}

		Dimension defaultSize = component.getDefaultSize();
		if (defaultSize != null) {
			setSize(defaultSize);
		}
	}

	private void applyLocation(Rectangle savedBounds) {
		if (savedBounds == null) {
			return;
		}

		boolean rememberLocation = component.getRememberLocation();
		if (!rememberLocation) {
			return;
		}
		setLocation(savedBounds.x, savedBounds.y);
	}

	private String getKey() {
		Object scopeObject = null;
		if (component.getUseSharedLocation()) {
			scopeObject = owningWindowManager;
		}
		else {
			scopeObject = getParent();
		}
		return component.getClass().getName() + System.identityHashCode(scopeObject);
	}

	private void init(DialogComponentProvider provider) {
		component = provider;
		provider.setDialog(this);
		getContentPane().setLayout(new BorderLayout());
		getContentPane().add(provider.getComponent(), BorderLayout.CENTER);
		setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
		pack();
		setResizable(provider.isResizeable());
		windowAdapter = new WindowAdapter() {
			@Override
			public void windowActivated(WindowEvent e) {
				if (!hasBeenFocused) {
					Component newFocusComponent = component.getFocusComponent();
					if (newFocusComponent != null) {
						focusComponent = newFocusComponent;
						SwingUtilities.invokeLater(requestFocusRunnable);
					}
				}
			}

			@Override
			public void windowOpened(WindowEvent e) {
				component.dialogShown();
			}

			@Override
			public void windowClosing(WindowEvent e) {
				component.escapeCallback();
			}

			@Override
			public void windowClosed(WindowEvent e) {
				// this call is needed to handle the case where the dialog is closed by Java and
				// not by the user closing the dialog or calling close() through the API
				cleanup();
			}
		};
		this.addWindowListener(windowAdapter);
		modalFixWindowAdapter = new WindowAdapter() {
			@Override
			public void windowOpened(WindowEvent e) {
				WindowUtilities.bringModalestDialogToFront(DockingDialog.this);
			}
		};

		this.addWindowListener(modalFixWindowAdapter);

		if (provider.getDefaultButton() != null) {
			getRootPane().setDefaultButton(provider.getDefaultButton());
		}

		GGlassPane ghidraGlassPane = new GGlassPane();
		setGlassPane(ghidraGlassPane);
		ghidraGlassPane.setVisible(true);
	}

	public DockingWindowManager getOwningWindowManager() {
		return owningWindowManager;
	}

	public DialogComponentProvider getDialogComponent() {
		return component;
	}

	void close() {
		cleanup();
	}

	private void cleanup() {
		if (component.getRemberSize() || component.getRememberLocation()) {
			String key = getKey();
			Rectangle rect = getBounds();
			BoundsInfo boundsInfo = dialogBoundsMap.get(key);
			boundsInfo.setEndBounds(new Rectangle(rect));
		}

		component.setDialog(null);
		removeWindowListener(windowAdapter);

		// this will do nothing if already closed
		setVisible(false);

		component.dialogClosed();
		component = null;
		getContentPane().removeAll();

		dispose();

		disposeHiddenFrame();
	}

	private void disposeHiddenFrame() {
		Container myParent = getParent();
		if (myParent instanceof HiddenDockingFrame) {
			JFrame f = (JFrame) myParent;
			Window[] ownedWindows = f.getOwnedWindows();
			for (Window window : ownedWindows) {
				if (window != this) {
					return;
				}
			}

			((HiddenDockingFrame) myParent).dispose();
		}
	}

	DialogComponentProvider getComponent() {
		return component;
	}

	/**
	 * Centers the dialog on the given component.
	 * @param c the component to center over.
	 */
	public void setCenteredOnComponent(Component c) {
		if (c == null) {
			setCenteredOnScreen();
			return;
		}

		if (c instanceof HiddenDockingFrame) {
			setCenteredOnScreen();
			return; // don't center over a hidden frame, as it may be is offscreen
		}

		if (!c.isVisible()) {
			// hidden frames cause us to be put in the upper-left--don't do that
			setCenteredOnScreen();
			return;
		}

		Rectangle r = getBounds();
		Point p = WindowUtilities.centerOnComponent(c, this);
		r.setLocation(p);
		setBounds(r);
	}

	@Override
	public String getHelpInfo() {
		return "   DIALOG TITLE: " + getTitle() + "\n";
	}

	@Override
	public Object getHelpObject() {
		return this;
	}

	/**
	 * Centers the dialog in the screen.
	 */
	private void setCenteredOnScreen() {
		Dimension size = getSize();
		Point center = WindowUtilities.centerOnScreen(size);
		setLocation(center);
	}

	@Override
	public void setVisible(boolean b) {
		if (b) {
			WindowUtilities.ensureOnScreen(this);
		}
		super.setVisible(b);
	}

	@Override
	public String toString() {
		return getTitle();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/** A simple container object to store multiple values in a map */
	private static class BoundsInfo {
		private Rectangle startBounds;
		private Rectangle endBounds;

		boolean hasBeenMoved() {
			// we have a non-null end location different than the start
			return endBounds != null && !Objects.equals(startBounds, endBounds);
		}

		Rectangle getEndBounds() {
			return endBounds;
		}

		void setStartBounds(Rectangle bounds) {
			this.startBounds = bounds;
		}

		void setEndBounds(Rectangle bounds) {
			if (Objects.equals(startBounds, bounds)) {
				// keep the end bounds unchanged, which helps us later determine if the 
				// dialog was moved
				return;
			}
			this.endBounds = bounds;
		}
	}
}
