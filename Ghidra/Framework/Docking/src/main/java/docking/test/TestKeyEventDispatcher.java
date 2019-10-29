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
package docking.test;

import java.awt.*;
import java.awt.event.KeyEvent;

import javax.swing.SwingUtilities;

import docking.FocusOwnerProvider;
import generic.test.TestUtils;
import ghidra.util.Msg;

/**
 * A class that helps to delegate key events to the system override key event dispatcher.  This
 * class exists to avoid package restrictions.
 */
public class TestKeyEventDispatcher {

	private static TestFocusOwnerProvider focusProvider = new TestFocusOwnerProvider();

	/**
	 * Uses the system-overridden {@link KeyEventDispatcher} to send the event.
	 * 
	 * @param event the event
	 * @return false if the event was not handled by this class and should continue to be
	 *         processed; true if the the event was handled and no further processing is needed
	 */
	public static boolean dispatchKeyEvent(KeyEvent event) {

		// Note: this will be the KeyBindingOverrideKeyEventDispatcher, if it is installed
		KeyEventDispatcher systemDispatcher = getOverriddenKeyEventDispatcher();
		if (systemDispatcher == null) {
			// not installed; nothing to do
			return false;
		}

		//
		// Notes: timing and focus can produce inconsistent results here.  Be sure when 
		//        you attempt to dispatch key events, that the target component has been fully
		//        realized (parented).
		//
		focusProvider.focusOwner = event.getComponent();
		try {
			boolean success = systemDispatcher.dispatchKeyEvent(event);
			return success;
		}
		finally {
			focusProvider.focusOwner = null;
		}
	}

	private static KeyEventDispatcher getOverriddenKeyEventDispatcher() {

		// Note: our custom key event dispatcher has package access, so we cannot refer to 
		//       it directly
		try {
			Class<?> clazz = Class.forName("docking.KeyBindingOverrideKeyEventDispatcher");
			Object customDispatcher = TestUtils.getInstanceField("instance", clazz);
			if (customDispatcher == null) {
				return null; // not installed
			}

			//
			// Dependency Inject our own focus provider so that we can force the event 
			// dispatcher to deliver events to our component
			// 
			TestUtils.invokeInstanceMethod("setFocusOwnerProvider", customDispatcher,
				FocusOwnerProvider.class, focusProvider);

			return (KeyEventDispatcher) customDispatcher;
		}
		catch (ClassNotFoundException e) {
			Msg.error(TestKeyEventDispatcher.class, "Unable to find the system KeyEventDispatcher",
				e);
			return null;
		}
	}

	private static class TestFocusOwnerProvider implements FocusOwnerProvider {

		private Component focusOwner;

		@Override
		public Component getFocusOwner() {
			return focusOwner;
		}

		@Override
		public Window getActiveWindow() {

			if (focusOwner == null) {
				return null;
			}

			if (focusOwner instanceof Window) {
				return (Window) focusOwner;
			}
			return SwingUtilities.windowForComponent(focusOwner);
		}

	}
}
