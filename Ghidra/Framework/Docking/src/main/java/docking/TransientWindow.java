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

import java.awt.Color;
import java.awt.MouseInfo;
import java.awt.Point;
import java.awt.Window;

import javax.swing.BorderFactory;
import javax.swing.JToolTip;
import javax.swing.JWindow;

/**
 * Drag feedback indicator class.
 *
 * Once activated, a tool tip will follow the mouse cursor across all the screen.
 *
 * To automatically update its location at a specific polling rate:
 *
 * TransientWindow.activateTransientWindow("Title", pollingRate);
 * TransientWindow.deactivateTransientWindow();
 *
 * To change parameters:
 *
 * TransientWindow.updateTransientWindow("Title");
 * TransientWindow.updateTransientWindow(pollingRate);
 *
 * To manually control the tool tip:
 *
 * TransientWindow.showTransientWindow("Title");
 * TransientWindow.positionTransientWindow();
 * TransientWindow.hideTransientWindow();
 */
public class TransientWindow {

	private static JToolTip transientTip;
	private static JWindow transientWindow;

	private static int defaultPollingRate = 20;

	private static void createTransientWindow(String title) {
		if (transientWindow != null) {
			return;
		}

		transientTip = new JToolTip();
		transientTip.setBorder(BorderFactory.createLineBorder(Color.YELLOW));
		transientTip.setTipText(title);
		transientTip.setVisible(true);
		transientTip.setOpaque(false);

		transientWindow = new JWindow();
		transientWindow.setOpacity(0.7f);
		transientWindow.setAlwaysOnTop(true);
		transientWindow.setType(Window.Type.POPUP);
		transientWindow.setFocusableWindowState(false);
		transientWindow.getContentPane().add(transientTip);

		transientWindow.pack();
	}

	private static void transientWindowListener() {
		while (transientWindow != null) {
			try {
				Thread.sleep(defaultPollingRate);
				positionTransientWindow();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	public static synchronized void positionTransientWindow() {
		if (transientWindow == null) {
			return;
		}
		Point p = MouseInfo.getPointerInfo().getLocation();
		transientWindow.setLocation(p.x + 16, p.y + 16);
	}

	public synchronized static void updateTransientWindow(String title) {
		if (transientWindow == null || transientTip == null) {
			return;
		}
		transientTip.setTipText(title);
		transientWindow.pack();
	}

	public synchronized static void updateTransientWindow(int pollingRate) {
		defaultPollingRate = pollingRate;
	}

	public static void showTransientWindow(String title) {
		createTransientWindow(title);
		positionTransientWindow();
		transientWindow.setVisible(true);
	}

	public static synchronized void hideTransientWindow() {
		if (transientWindow == null) {
			return;
		}
		transientWindow.setVisible(false);
		transientWindow = null;
		transientTip = null;
	}

	public static synchronized void activateTransientWindow(String title, int pollingRate) {
		if (transientWindow != null) {
			return;
		}
		Runnable task = () -> transientWindowListener();
		Thread thread = new Thread(task);
		defaultPollingRate = pollingRate;
		showTransientWindow(title);
		thread.start();
	}

	public static void deactivateTransientWindow() {
		hideTransientWindow();
	}
}
