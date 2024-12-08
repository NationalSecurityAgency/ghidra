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
package docking.action;

import java.awt.KeyboardFocusManager;
import java.awt.Window;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingWindowManager;

/**
 * Action for transferring focus to the next or previous visible window in the application.
 */
public class NextPreviousWindowAction extends DockingAction {

	private boolean forward;

	public NextPreviousWindowAction(KeyStroke keybinding, boolean forward) {
		super(forward ? "Next Window" : "Previous Window",
			DockingWindowManager.DOCKING_WINDOWS_OWNER);

		this.forward = forward;
		createSystemKeyBinding(keybinding);
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Window[] windows = Window.getWindows();
		int currentIndex = getIndexForCurrentWindow(windows);
		Window nextWindow = findNextValidWindow(windows, currentIndex);
		if (nextWindow != null) {
			nextWindow.toFront();
		}
	}

	private int getIndexForCurrentWindow(Window[] windows) {
		Window window = KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();
		for (int i = 0; i < windows.length; i++) {
			if (window == windows[i]) {
				return i;
			}
		}
		return 0;	// this shouldn't happen
	}

	private Window findNextValidWindow(Window[] windows, int currentIndex) {
		int candidateIndex = nextIndex(windows, currentIndex);
		while (candidateIndex != currentIndex) {
			if (isValid(windows[candidateIndex])) {
				return windows[candidateIndex];
			}
			candidateIndex = nextIndex(windows, candidateIndex);
		}
		return null;
	}

	private boolean isValid(Window window) {
		if (!window.isVisible()) {
			return false;
		}
		return true;
	}

	private int nextIndex(Window[] windows, int index) {
		if (forward) {
			int next = index + 1;
			return next >= windows.length ? 0 : next;
		}
		int previous = index - 1;
		return previous < 0 ? windows.length - 1 : previous;
	}

}
