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
package docking.framework;

import java.awt.*;
import java.awt.event.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.CompoundBorder;

import org.apache.commons.lang3.StringUtils;

import docking.*;
import docking.widgets.label.GDLabel;
import generic.application.GenericApplicationLayout;
import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.Gui;
import generic.util.WindowUtilities;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.Swing;
import utility.application.ApplicationLayout;

/**
 * Splash screen window to display version information about the current release of
 * the Ghidra application. The window is displayed when Ghidra starts; when
 * initialization is complete, the splash screen is dismissed.
 */
public class SplashScreen extends JWindow {

	private static final Color BG_COLOR = new GColor("color.bg.splashscreen");

	private static final String FONT_ID = "font.splash.status";

	private static SplashScreen splashWindow; // splash window displayed while ghidra is coming up
	private static DockingFrame hiddenFrame;
	private static JLabel statusLabel;
	private static Timer hideSplashWindowTimer;

	/**
	 * Show the splash screen on the Swing thread later.
	 */
	public static void showLater() {

		Swing.runIfSwingOrRunLater(() -> {

			if (splashWindow != null) {
				return; // already showing
			}

			JFrame parentFrame = getParentFrame();
			splashWindow = new SplashScreen(parentFrame);

			initializeSplashWindowAndParent(parentFrame);

			createSplashScreenCloseListeners(parentFrame);

			parentFrame.setVisible(true);
			splashWindow.setVisible(true);

			// this call is needed for the splash screen to initially paint correctly on the Mac
			splashWindow.repaint();
		});
	}

	/**
	 * Show the splash screen on the Swing thread now.  This will block.
	 * @return the new splash screen
	 */
	public static SplashScreen showNow() {
		return Swing.runNow(() -> {
			if (splashWindow != null) {
				return splashWindow; // already showing
			}

			JFrame parentFrame = getParentFrame();
			splashWindow = new SplashScreen(parentFrame);

			initializeSplashWindowAndParent(parentFrame);

			createSplashScreenCloseListeners(parentFrame);

			parentFrame.setVisible(true);
			splashWindow.setVisible(true);

			// this call is needed for the splash screen to initially paint correctly on the Mac
			splashWindow.repaint();
			return splashWindow;
		});
	}

	private static void initializeSplashWindowAndParent(final JFrame parentFrame) {

		Dimension wd = splashWindow.getPreferredSize();
		Point point = WindowUtilities.centerOnScreen(wd);
		splashWindow.setLocation(point);

		// move us when the parent frame moves
		parentFrame.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentMoved(ComponentEvent e) {
				if (splashWindow == null) {
					return;
				}
				Point newPoint = WindowUtilities.centerOnComponent(parentFrame, splashWindow);
				splashWindow.setLocation(newPoint);
			}
		});

		Point framePoint = WindowUtilities.centerOnComponent(splashWindow, parentFrame);
		parentFrame.setBounds(new Rectangle(framePoint.x, framePoint.y, 0, 0));
		parentFrame.setResizable(false);
	}

	private static void createSplashScreenCloseListeners(final JFrame parentFrame) {
		hideSplashWindowTimer = new Timer(500, null);
		ActionListener timerListener = e -> {

			Msg.trace(SplashScreen.class, "Splash Screen - hide timer activated");

			if (isApplicationVisible()) {

				// a docking application has been launched--we are no longer needed
				Msg.trace(SplashScreen.class, "Splash Screen closed due to application launch");
				disposeSplashScreen();
				hideSplashWindowTimer.stop();
			}

			if (hiddenWindowHasModalChildren()) {
				// can't dispose our windows because it will close the modal dialog
				Msg.trace(SplashScreen.class, "Splash Screen has modal children--not closing");
				return;
			}

			if (nonHiddenFrameExists()) {
				// this handles the case where we have some sort of application that does not
				// use the DockingWindowManager--try to do something reasonable
				Msg.trace(SplashScreen.class,
					"Splash Screen closed due to non-docking application launch");
				disposeSplashScreen();
				hideSplashWindowTimer.stop();
			}
		};
		hideSplashWindowTimer.addActionListener(timerListener);
		hideSplashWindowTimer.setRepeats(true);
		hideSplashWindowTimer.start();

		// This listener gives us a more responsive close, but it does not work if the window
		// is deactivated before an application window is launched.  We rely on the timer above to
		// handle that case.
		parentFrame.addWindowListener(new WindowAdapter() {
			@Override
			public void windowDeactivated(WindowEvent e) {

				Msg.trace(SplashScreen.class,
					"Splash Screen - parent window deactivated.  Parent: " + getTitle(parentFrame));
				if (hiddenWindowHasModalChildren()) {
					// can't dispose our windows because it will close the modal dialog
					Msg.trace(SplashScreen.class, "Splash Screen has modal children--not closing");
					return;
				}

				Window window = e.getOppositeWindow();
				if (window != null) {
					// some other window is shown, let's not occlude it
					Msg.trace(SplashScreen.class,
						"Splash Screen new non-splash window showing--closing. Window: " +
							getTitle(window));
					disposeSplashScreen();
				}
			}

		});
	}

	private static String getTitle(Window window) {

		if (window instanceof JDialog) {
			return ((JDialog) window).getTitle() + " - id: " + System.identityHashCode(window);
		}
		else if (window instanceof JFrame) {
			return ((JFrame) window).getTitle() + " - id: " + System.identityHashCode(window);
		}
		return "<No Title> - id: " + System.identityHashCode(window);
	}

	private static boolean isApplicationVisible() {

		List<DockingWindowManager> windowManagers =
			DockingWindowManager.getAllDockingWindowManagers();
		for (DockingWindowManager manager : windowManagers) {
			JFrame frame = manager.getRootFrame();
			if (frame.isShowing()) {
				return true;
			}
		}

		return false;
	}

	private static boolean nonHiddenFrameExists() {

		Frame[] frames = Frame.getFrames();
		for (Frame frame : frames) {
			if (frame instanceof HiddenDockingFrame) {
				continue;
			}

			if (frame == hiddenFrame) {
				continue;
			}

			// found non-hidden frame, is it showing?
			if (frame.isShowing()) {
				Msg.trace(SplashScreen.class,
					"Splash Screen found non-hidden frame: : " + getTitle(frame));
				return true;
			}
		}

		return false;
	}

	private static boolean hiddenWindowHasModalChildren() {

		if (hiddenFrame == null) {
			return false; // disposed
		}

		List<Dialog> modals = WindowUtilities.getOpenModalDialogsFor(hiddenFrame);
		if (modals.isEmpty()) {
			return false;
		}

		modals.forEach(d -> {
			// this is odd, but we want the modal dialogs to always appear on top of the splasher
			d.setAlwaysOnTop(true);
		});
		return true;
	}

	private static void closeSplashScreen() {

		// we have another Java window shown, hide this splash screen so that we
		// don't obscure modal dialogs
		if (splashWindow != null) {
			splashWindow.setVisible(false);
			splashWindow.dispose();
			splashWindow = null;
		}
	}

	private SplashScreen(JFrame parent) {
		super(parent);
		getContentPane().add(createMainPanel());
		pack();
	}

	/**
	 * Returns the frame that is to be used as the splash screen's parent.
	 * This method will lazy load the parent frame and only create it once.
	 *
	 * @return The frame to use as the splash screen's parent.
	 */
	private synchronized static JFrame getParentFrame() {

		if (hiddenFrame == null) {
			// hiddenFrame = new HiddenDockingFrame(Application.getName());
			hiddenFrame = new DockingFrame(Application.getName());
			List<Image> list = ApplicationInformationDisplayFactory.getWindowIcons();
			hiddenFrame.setIconImages(list);
			hiddenFrame.setUndecorated(true);
			hiddenFrame.setTransient();
		}
		return hiddenFrame;
	}

	/**
	 * Remove the splash screen; Ghidra is done loading.
	 */
	public static void disposeSplashScreen() {
		hideSplashWindowTimer.stop();
		closeSplashScreen();
		if (hiddenFrame != null) {
			WindowListener[] windowListeners = hiddenFrame.getWindowListeners();
			for (WindowListener l : windowListeners) {
				hiddenFrame.removeWindowListener(l);
			}
			hiddenFrame.setVisible(false);
			hiddenFrame.dispose();
			hiddenFrame = null;
		}
	}

	/**
	 * Update the load status on the splash screen.
	 * @param status string to put in the message area of the splash screen
	 */
	public static void updateSplashScreenStatus(String status) {
		if (splashWindow == null) {
			return;
		}

		updateStatus(status);
	}

	public static void clearStatus() {
		updateSplashScreenStatus(null);
	}

	private static void updateStatus(String status) {
		// empty strings causes label to lose its height
		String message = StringUtils.isBlank(status) ? " " : status;
		Swing.runIfSwingOrRunLater(() -> {
			statusLabel.setText(message);
			Rectangle bounds = statusLabel.getBounds();
			bounds.x = 0;
			bounds.y = 0;
			statusLabel.paintImmediately(bounds);
		});
	}

	private JPanel createMainPanel() {
		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.setBackground(BG_COLOR);
		mainPanel.add(createContentPanel(), BorderLayout.CENTER);
		return mainPanel;
	}

	private Component createContentPanel() {
		JPanel contentPanel = new JPanel(new BorderLayout());
		contentPanel.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
		contentPanel.add(createInfoComponent(), BorderLayout.CENTER);
		contentPanel.add(createStatusComponent(), BorderLayout.SOUTH);
		return contentPanel;
	}

	private Component createStatusComponent() {
		statusLabel = new GDLabel(" Loading...");
		Gui.registerFont(statusLabel, FONT_ID);
		statusLabel.setFont(Gui.getFont(FONT_ID));

		CompoundBorder border = BorderFactory.createCompoundBorder(
			BorderFactory.createLoweredBevelBorder(), BorderFactory.createEmptyBorder(0, 5, 2, 5));
		statusLabel.setBorder(border);
		statusLabel.setOpaque(true);
		statusLabel.setBackground(Colors.BACKGROUND);
		statusLabel.setForeground(Colors.FOREGROUND);
		return statusLabel;
	}

	private JComponent createInfoComponent() {
		return ApplicationInformationDisplayFactory.createSplashScreenComponent();
	}

	public static void main(String[] args) throws Exception {
		ApplicationLayout layout = new GenericApplicationLayout("Splash Screen Main", "1.0");
		DockingApplicationConfiguration config = new DockingApplicationConfiguration();

		config.setShowSplashScreen(false);
		Application.initializeApplication(layout, config);
		showLater();

// tests that modal dialogs popup on top of the splash screen
//	    new Thread( new Runnable() {
//	        public void run() {
//	            try {
//                    Thread.sleep( 2000 );
//                }
//                catch ( InterruptedException e ) {
//                    e.printStackTrace();
//                }
//
//                try {
//                    SwingUtilities.invokeAndWait( new Runnable() {
//                        public void run() {
//                            JOptionPane.showMessageDialog( null,
//                                "This is a modal dialog - null parent", "MODAL DIALOG", JOptionPane.WARNING_MESSAGE );
//                        }
//                    });
//                }
//                catch ( InterruptedException e ) {
//                    e.printStackTrace();
//                }
//                catch ( InvocationTargetException e ) {
//                    e.printStackTrace();
//                }
//	            hideSplashScreen();
//
//	            System.exit(0);
//	        }
//	    }).start();

		// test of status updates
		new Thread(new Runnable() {

			String[] messages = { "Hi mom...",
				"This is a much longer message to test that we get resized correctly", "I!",
				"Here we go again..." };

			@Override
			public void run() {
				for (int i = 0; i < 100; i++) {
					int index = i % messages.length;
					SplashScreen.updateStatus(messages[index]);
					try {
						Thread.sleep(100 * index);
					}
					catch (InterruptedException e) {
						// don't care
					}
				}
			}
		}).start();
	}

}
