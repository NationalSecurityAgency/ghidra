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
package generic.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.awt.*;
import java.awt.event.*;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.swing.*;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import javax.swing.text.JTextComponent;
import javax.swing.tree.*;

import org.junit.Assert;

import ghidra.util.*;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;
import ghidra.util.task.AbstractSwingUpdateManager;
import ghidra.util.task.SwingUpdateManager;
import junit.framework.AssertionFailedError;
import sun.awt.AppContext;
import utility.function.ExceptionalCallback;

/**
 * Base class for tests that need swing support methods. Tests that don't involve Swing/Gui elements
 * should use AbstractGenericTest instead
 */
public class AbstractGuiTest extends AbstractGenericTest {
	/**
	 * Gets all windows in the system (including Frames).
	 *
	 * @return all windows
	 */
	public static Set<Window> getAllWindows() {
		Set<Window> set = new HashSet<>();
		Frame sharedOwnerFrame = (Frame) AppContext.getAppContext()
				.get(new StringBuffer("SwingUtilities.sharedOwnerFrame"));
		if (sharedOwnerFrame != null) {
			set.addAll(getAllWindows(sharedOwnerFrame));
		}

		for (Frame frame : Frame.getFrames()) {
			set.addAll(getAllWindows(frame));
		}

		Window[] windows = Window.getWindows();
		for (Window window : windows) {
			set.add(window);
		}

		return set;
	}

	private static List<Window> getAllWindows(Window parent) {
		List<Window> list = new ArrayList<>();
		list.add(parent);
		for (Window w : parent.getOwnedWindows()) {
			list.add(w);
		}
		return list;
	}

	/**
	 * Waits for all system tasks to complete. These tasks are tracked by the
	 * SystemUtilities during testing only.
	 *
	 * @throws AssertionFailedError if the timeout period expires while waiting
	 *             for tasks
	 */
	public static void waitForTasks() {
		waitForTasks(PRIVATE_LONG_WAIT_TIMEOUT);
	}

	public static void waitForTasks(long timeout) {
		waitForSwing();

		long time = 0;
		while (TaskUtilities.isExecutingTasks()) {
			time += sleep(DEFAULT_WAIT_DELAY);
			if (time >= timeout) {
				Msg.error(AbstractGenericTest.class, createStackTraceForAllThreads());
				throw new AssertionFailedError("Time expired waiting for tasks to complete.");
			}
		}

		// let any pending Swing work finish
		waitForSwing();
	}

	/**
	 * @deprecated Use {@link #waitForSwing()} instead
	 */
	@Deprecated(forRemoval = true, since = "10.3")
	public static void waitForPostedSwingRunnables() {
		waitForSwing();
	}

	public static <T extends Component> T findComponent(Container parent, Class<T> desiredClass) {
		return findComponent(parent, desiredClass, false);
	}

	public static <T extends Component> T findComponent(Container parent, Class<T> desiredClass,
			boolean checkOwnedWindows) {
		Component[] comps = parent.getComponents();
		for (Component element : comps) {
			if (element == null) {
				continue;// this started happening in 1.6, not sure why
			}
			if (desiredClass.isAssignableFrom(element.getClass())) {
				return desiredClass.cast(element);
			}
			else if (element instanceof Container) {
				T c = findComponent((Container) element, desiredClass, checkOwnedWindows);
				if (c != null) {
					return desiredClass.cast(c);
				}
			}
		}
		if (checkOwnedWindows && (parent instanceof Window)) {
			Window[] windows = ((Window) parent).getOwnedWindows();
			for (int i = windows.length - 1; i >= 0; i--) {
				Component c = findComponent(windows[i], desiredClass, checkOwnedWindows);
				if (c != null) {
					return desiredClass.cast(c);
				}
			}
		}
		return null;
	}

	public static <T extends Component> List<T> findComponents(Container parent,
			Class<T> desiredClass) {
		return findComponents(parent, desiredClass, false);
	}

	public static <T extends Component> List<T> findComponents(Container parent,
			Class<T> desiredClass, boolean checkOwnedWindows) {
		Component[] comps = parent.getComponents();
		List<T> list = new ArrayList<>();
		for (Component element : comps) {
			if (element == null) {
				continue;// this started happening in 1.6, not sure why
			}
			if (desiredClass.isAssignableFrom(element.getClass())) {
				list.add(desiredClass.cast(element));
			}
			else if (element instanceof Container) {
				T c = findComponent((Container) element, desiredClass, checkOwnedWindows);
				if (c != null) {
					list.add(desiredClass.cast(c));
				}
			}
		}
		if (checkOwnedWindows && (parent instanceof Window)) {
			Window[] windows = ((Window) parent).getOwnedWindows();
			for (int i = windows.length - 1; i >= 0; i--) {
				Component c = findComponent(windows[i], desiredClass, checkOwnedWindows);
				if (c != null) {
					list.add(desiredClass.cast(c));
				}
			}
		}
		return list;
	}

	public static void findOwnedWindows(Window win, Set<Window> winList) {
		Window[] children = win.getOwnedWindows();
		for (Window element : children) {
			winList.add(element);
			findOwnedWindows(element, winList);
		}
	}

	/**
	 * Finds the button with the indicated TEXT that is a sub-component of the
	 * indicated container, and then programmatically presses the button. <BR>
	 * The following is a sample JUnit test use:
	 *
	 * <PRE>
	 * env.showTool();
	 * OptionDialog dialog = (OptionDialog) env.waitForDialog(OptionDialog.class, 1000);
	 * assertNotNull(dialog);
	 * pressButtonByText(dialog, "OK");
	 * </PRE>
	 *
	 * @param container the container to search. (Typically a dialog.)
	 * @param buttonText the text on the desired JButton.
	 * @throws AssertionError if the button isn't found, isn't showing or isn't
	 *             enabled
	 */
	public static void pressButtonByText(Container container, String buttonText) {
		pressButtonByText(container, buttonText, true);
	}

	/**
	 * Finds the button with the indicated TEXT that is a sub-component of the
	 * indicated container, and then programmatically presses the button.
	 *
	 * @param container the container to search. (Typically a dialog.)
	 * @param buttonText the text on the desired JButton.
	 * @param waitForCompletion if true wait for action to complete before
	 *            returning, otherwise schedule action to be performed and
	 *            return immediately.
	 * @throws AssertionError if the button isn't found, isn't showing or isn't
	 *             enabled
	 */
	public static void pressButtonByText(Container container, String buttonText,
			boolean waitForCompletion) {

		AbstractButton button = findAbstractButtonByText(container, buttonText);
		if (button == null) {
			throw new AssertionError("Couldn't find button " + buttonText + ".");
		}
		if (!runSwing(() -> button.isShowing())) {
			throw new AssertionError("Button " + buttonText + " is not showing.");
		}
		if (!runSwing(() -> button.isEnabled())) {
			throw new AssertionError("Button " + buttonText + " is not enabled.");
		}
		pressButton(button, waitForCompletion);
	}

	/**
	 * Finds the button with the indicated NAME that is a subcomponent of the
	 * indicated container, and then programmatically presses the button.
	 *
	 * @param container the container to search. (Typically a dialog)
	 * @param buttonName the name on the desired AbstractButton (see
	 *            Component.setName())
	 */
	public static void pressButtonByName(Container container, String buttonName) {
		pressButtonByName(container, buttonName, true);
	}

	/**
	 * Finds the button with the indicated NAME that is a subcomponent of the
	 * indicated container, and then programmatically presses the button.
	 *
	 * @param container the container to search. (Typically a dialog.)
	 * @param buttonName the name on the desired AbstractButton (see
	 *            Component.setName()).
	 * @param waitForCompletion if true wait for action to complete before
	 *            returning, otherwise schedule action to be performed and
	 *            return immediately
	 */
	public static void pressButtonByName(Container container, String buttonName,
			boolean waitForCompletion) {

		AbstractButton button = (AbstractButton) findComponentByName(container, buttonName);
		if (button == null) {
			throw new AssertionError("Couldn't find button " + buttonName + ".");
		}
		if (!runSwing(() -> button.isShowing())) {
			throw new AssertionError("Button " + buttonName + " is not showing.");
		}
		if (!runSwing(() -> button.isEnabled())) {
			throw new AssertionError("Button " + buttonName + " is not enabled.");
		}
		pressButton(button, waitForCompletion);
	}

	/**
	 * Programmatically presses the indicated button.
	 *
	 * @param button the button
	 */
	public static void pressButton(AbstractButton button) {
		if (!button.isEnabled()) {
			throw new AssertException("Attempted to press a disabled button");
		}
		pressButton(button, true);
	}

	/**
	 * Programmatically presses the indicated button.
	 *
	 * @param button the button
	 * @param waitForCompletion if true wait for action to complete before
	 *            returning, otherwise schedule action to be performed and
	 *            return immediately.
	 */
	public static void pressButton(AbstractButton button, boolean waitForCompletion) {
		Runnable r = () -> button.doClick(0); // 0 means no sleeping
		runSwing(r, waitForCompletion);
	}

	/**
	 * Searches the subcomponents of the indicated container and returns the
	 * component with the specified name.
	 *
	 * @param container the container to search
	 * @param componentName the name of the desired component
	 *
	 * @return the component, or null if not found
	 */
	public static Component findComponentByName(Container container, String componentName) {
		return findComponentByName(container, componentName, false);
	}

	public static Component findComponentByName(Container container, String componentName,
			boolean checkOwnedWindows) {

		String containerName = container.getName();

		if (containerName != null && container.getName().equals(componentName)) {
			return container;
		}

		Component[] comps = container.getComponents();
		for (Component element : comps) {
			if (element == null) {
				continue;// this started happening in 1.6, not sure why
			}
			String name = element.getName();
			if (name != null && name.equals(componentName)) {
				return element;
			}
			else if (element instanceof Container) {
				Component comp =
					findComponentByName((Container) element, componentName, checkOwnedWindows);
				if (comp != null) {
					return comp;
				}
			}
		}
		if (checkOwnedWindows && (container instanceof Window)) {
			Window[] windows = ((Window) container).getOwnedWindows();
			for (int i = windows.length - 1; i >= 0; i--) {
				Component c = findComponentByName(windows[i], componentName, checkOwnedWindows);
				if (c != null) {
					return c;
				}
			}
		}
		return null;
	}

	public static List<Component> findComponentsByName(Container container, String componentName,
			boolean checkOwnedWindows) {

		List<Component> retList = new ArrayList<>();

		Component[] components = container.getComponents();
		for (Component component : components) {
			if (component == null) {
				continue;
			}
			String name = component.getName();
			if (name != null && name.equals(componentName)) {
				retList.add(component);
			}
			else if (component instanceof Container) {
				retList.addAll(
					findComponentsByName((Container) component, componentName, checkOwnedWindows));
			}

		}
		return retList;
	}

	public static JButton findButtonByIcon(Container container, Icon icon) {
		Component[] comps = container.getComponents();
		for (Component element : comps) {
			if (element instanceof JButton) {
				JButton button = (JButton) element;
				Icon buttonIcon = button.getIcon();
				if (icon.equals(buttonIcon)) {
					return button;
				}
			}
			else if (element instanceof Container) {
				JButton button = findButtonByIcon((Container) element, icon);
				if (button != null) {
					return button;
				}
			}
		}
		return null;

	}

	/**
	 * Searches the subcomponents of the the given container and returns the
	 * JButton that has the specified text.
	 *
	 * @param container the container to search
	 * @param text the button text
	 * @return the JButton, or null the button was not found
	 */
	public static JButton findButtonByText(Container container, String text) {
		Component[] comps = container.getComponents();
		for (Component element : comps) {
			if (element instanceof JButton) {
				JButton button = (JButton) element;
				if (button.getText() != null && button.getText().equals(text)) {
					return button;
				}
			}
			else if (element instanceof Container) {
				JButton button = findButtonByText((Container) element, text);
				if (button != null) {
					return button;
				}
			}
		}
		return null;
	}

	/**
	 * Searches the sub-components of the given container and returns the
	 * AbstractButton that has the specified text.
	 * <p>
	 * This differs from {@link #findButtonByText(Container, String)} in that
	 * this method will find buttons that do not extend from {@link JButton}.
	 * That method is convenient when you do not wish to cast the result from
	 * AbstractButton to JButton. Other than that, this method can handle all
	 * cases the other method cannot.
	 *
	 * @param container container to search
	 * @param text button text
	 * @return null if the button was not found
	 */
	public static AbstractButton findAbstractButtonByText(Container container, String text) {

		Component[] comp = container.getComponents();
		for (Component element : comp) {
			if ((element instanceof AbstractButton) &&
				text.equals(((AbstractButton) element).getText())) {
				return (AbstractButton) element;
			}
			else if (element instanceof Container) {
				AbstractButton b = findAbstractButtonByText((Container) element, text);
				if (b != null) {
					return b;
				}
			}
		}
		return null;
	}

	/**
	 * Searches the sub-components of the given container and returns the
	 * AbstractButton that has the specified name.
	 *
	 * @param container container to search
	 * @param name the button name (you must set this manually).
	 * @return null if the button was not found
	 */
	public static AbstractButton findAbstractButtonByName(Container container, String name) {

		Component[] comp = container.getComponents();
		for (Component element : comp) {
			if ((element instanceof AbstractButton) &&
				name.equals(((AbstractButton) element).getName())) {
				return (AbstractButton) element;
			}
			else if (element instanceof Container) {
				AbstractButton b = findAbstractButtonByName((Container) element, name);
				if (b != null) {
					return b;
				}
			}
		}
		return null;
	}

	public static void leftClick(JComponent comp, int x, int y) {
		clickMouse(comp, MouseEvent.BUTTON1, x, y, 1, 0);
	}

	public static void middleClick(JComponent comp, int x, int y) {
		clickMouse(comp, MouseEvent.BUTTON2, x, y, 1, 0);
	}

	public static void rightClick(JComponent comp, int x, int y) {
		clickMouse(comp, MouseEvent.BUTTON3, x, y, 1, 0, true);
	}

	public static void doubleClick(JComponent comp, int x, int y) {
		clickMouse(comp, MouseEvent.BUTTON1, x, y, 2, 0);
	}

	/**
	 * Simulates click the mouse button.
	 *
	 * @param comp the component to click on.
	 * @param button the mouse button (1, 2, or 3)
	 * @param x the x coordinate of the click location
	 * @param y the y coordinate of the click location
	 * @param clickCount the number of clicks (2 = double click)
	 * @param modifiers additional modifiers (e.g. MouseEvent.SHIFT_MASK)
	 * @param popupTrigger a boolean, true if this event is a trigger for a
	 *            popup menu
	 */
	public static void clickMouse(Component comp, int button, int x, int y, int clickCount,
			int modifiers, boolean popupTrigger) {

		int nonRelesedModifiers = convertToExtendedModifiers(modifiers, button, false);
		int relesedModifiers = convertToExtendedModifiers(modifiers, button, true);
		for (int cnt = 1; cnt <= clickCount; ++cnt) {
			postEvent(new MouseEvent(comp, MouseEvent.MOUSE_PRESSED, System.currentTimeMillis(),
				nonRelesedModifiers, x, y, cnt, false, button));
			postEvent(new MouseEvent(comp, MouseEvent.MOUSE_CLICKED, System.currentTimeMillis(),
				nonRelesedModifiers, x, y, cnt, false, button));
			postEvent(new MouseEvent(comp, MouseEvent.MOUSE_RELEASED, System.currentTimeMillis(),
				relesedModifiers, x, y, cnt, popupTrigger, button));
		}
	}

	/**
	 * Simulates click the mouse button.
	 *
	 * @param comp the component to click on.
	 * @param button the mouse button (1, 2, or 3)
	 * @param x the x coordinate of the click location
	 * @param y the y coordinate of the click location
	 * @param clickCount the number of clicks (2 = double click)
	 * @param modifiers additional modifiers (e.g. MouseEvent.SHIFT_MASK)
	 */
	public static void clickMouse(Component comp, int button, int x, int y, int clickCount,
			int modifiers) {

		clickMouse(comp, button, x, y, clickCount, modifiers, false);
	}

	/**
	 * Simulates a mouse drag action
	 *
	 * @param comp the component to drag on.
	 * @param button the mouse button (1, 2, or 3)
	 * @param startX the x coordinate of the start drag location
	 * @param startY the y coordinate of the start drag location
	 * @param endX the x coordinate of the end drag location
	 * @param endY the y coordinate of the end drag location
	 * @param modifiers additional modifiers (e.g. MouseEvent.SHIFT_MASK)
	 */
	public static void dragMouse(final Component comp, int button, final int startX,
			final int startY, final int endX, final int endY, int modifiers) {

		int nonRelesedModifiers = convertToExtendedModifiers(modifiers, button, false);
		int relesedModifiers = convertToExtendedModifiers(modifiers, button, true);
		postEvent(new MouseEvent(comp, MouseEvent.MOUSE_PRESSED, System.currentTimeMillis(),
			nonRelesedModifiers, startX, startY, 1, false, button));
		postEvent(new MouseEvent(comp, MouseEvent.MOUSE_DRAGGED, System.currentTimeMillis(),
			nonRelesedModifiers, endX, endY, 1, false, button));
		postEvent(new MouseEvent(comp, MouseEvent.MOUSE_RELEASED, System.currentTimeMillis(),
			relesedModifiers, endX, endY, 1, false, button));

	}

	/**
	 * Fire a mouse moved event for the given component.
	 *
	 * @param comp source of the event.
	 * @param x x position relative to the component
	 * @param y y position relative to the component
	 */
	public static void moveMouse(Component comp, int x, int y) {
		postEvent(new MouseEvent(comp, MouseEvent.MOUSE_MOVED, System.currentTimeMillis(), 0, x, y,
			0, false));

	}

	@SuppressWarnings("deprecation")
	private static int convertToExtendedModifiers(int modifiers, int button, boolean isRelease) {

		// TODO: Eliminate duplication of similar modifier modification logic
		// which exists in KeyBindingData

		// remove system-dependent control key mask and transform deprecated modifiers

		int controlMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();

		if ((modifiers & InputEvent.CTRL_DOWN_MASK) == InputEvent.CTRL_DOWN_MASK) {
			modifiers = modifiers ^ InputEvent.CTRL_DOWN_MASK;
			modifiers = modifiers | controlMask;
		}

		if ((modifiers & InputEvent.CTRL_MASK) == InputEvent.CTRL_MASK) {
			modifiers = modifiers ^ InputEvent.CTRL_MASK;
			modifiers = modifiers | controlMask;
		}

		if ((modifiers & ActionEvent.CTRL_MASK) == ActionEvent.CTRL_MASK) {
			modifiers = modifiers ^ ActionEvent.CTRL_MASK;
			modifiers = modifiers | controlMask;
		}

		if ((modifiers & InputEvent.SHIFT_MASK) == InputEvent.SHIFT_MASK) {
			modifiers = modifiers ^ InputEvent.SHIFT_MASK;
			modifiers = modifiers | InputEvent.SHIFT_DOWN_MASK;
		}

		if ((modifiers & InputEvent.ALT_MASK) == InputEvent.ALT_MASK) {
			modifiers = modifiers ^ InputEvent.ALT_MASK;
			modifiers = modifiers | InputEvent.ALT_DOWN_MASK;
		}

		if ((modifiers & InputEvent.META_MASK) == InputEvent.META_MASK) {
			modifiers = modifiers ^ InputEvent.META_MASK;
			modifiers = modifiers | InputEvent.META_DOWN_MASK;
		}

		if (!isRelease) {
			//
			// There are no mouse buttons down on a 'release' in Java's extended event processing.
			// (The original non-extended events did include the button in the release event.)
			//
			switch (button) {
				case 1:
					modifiers |= InputEvent.BUTTON1_DOWN_MASK;
					break;
				case 2:
					modifiers |= InputEvent.BUTTON2_DOWN_MASK;
					break;
				case 3:
					modifiers |= InputEvent.BUTTON3_DOWN_MASK;
					break;
			}
		}
		return modifiers;
	}

	public static void postEvent(final AWTEvent ev) {
		runSwing(() -> {
			EventQueue eq = Toolkit.getDefaultToolkit().getSystemEventQueue();
			eq.postEvent(ev);
		});
		waitForSwing();
	}

	/**
	 * Returns the value from the given {@link Supplier}, invoking the call in
	 * the Swing thread. This is useful when you may have values that are being
	 * changed on the Swing thread and you need the test thread to see the
	 * changes.
	 *
	 * @param s the supplier
	 * @return the value returned by the supplier
	 */
	public static <T> T runSwing(Supplier<T> s) {
		AtomicReference<T> ref = new AtomicReference<>();
		runSwing(() -> ref.set(s.get()));
		return ref.get();
	}

	/**
	 * Run the given code snippet on the Swing thread and wait for it to finish
	 * @param r the runnable code snippet
	 */
	public static void runSwing(Runnable r) {
		runSwing(r, true);
	}

	/**
	 * Run the given code snippet on the Swing thread later, not blocking the current thread.  Use
	 * this if the code snippet causes a blocking operation.
	 *
	 * <P>This is a shortcut for <code>runSwing(r, false);</code>.
	 *
	 * @param r the runnable code snippet
	 */
	public void runSwingLater(Runnable r) {
		runSwing(r, false);
	}

	/**
	 * Call this version of {@link #runSwing(Runnable)} when you expect your runnable <b>may</b>
	 * throw exceptions
	 *
	 * @param callback the runnable code snippet to call
	 * @throws Exception any exception that is thrown on the Swing thread
	 */
	public static <E extends Exception> void runSwingWithException(ExceptionalCallback<E> callback)
			throws Exception {

		if (Swing.isSwingThread()) {
			throw new AssertException("Unexpectedly called from the Swing thread");
		}

		ExceptionHandlingRunner exceptionHandlingRunner = new ExceptionHandlingRunner(callback);
		Throwable throwable = exceptionHandlingRunner.getException();
		if (throwable == null) {
			return;
		}

		if (throwable instanceof Exception) {
			// this is what the client expected
			throw (Exception) throwable;
		}

		// a runtime exception; re-throw
		throw new AssertException(throwable);
	}

	public static void runSwing(Runnable runnable, boolean wait) {

		//
		// Special Case: this check handled re-entrant test code.  That is, an calls to runSwing()
		//               that are made from within a runSwing() call.  Most clients do not do
		//               this, but it can happen when a client makes a test API call (which itself
		//               calls runSwing()) from within a runSwing() call.
		//
		//               Calling the run method directly here ensures that the order of client
		//               requests is preserved.
		//
		if (SwingUtilities.isEventDispatchThread()) {
			runnable.run();
			return;
		}

		if (wait) {
			runSwingAndWait(runnable);
			return;
		}

		// don't wait; invoke later; catch any exceptions ourselves in order to fail-fast
		Runnable swingExceptionCatcher = () -> {
			try {
				runnable.run();
			}
			catch (Throwable t) {
				// submit this failure directly to the handler; fail the test
				ConcurrentTestExceptionHandler.handle(Thread.currentThread(), t);
			}
		};

		SwingUtilities.invokeLater(swingExceptionCatcher);
	}

	protected static class ExceptionHandlingRunner {
		private final ExceptionalCallback<? extends Exception> delegateCallback;
		private Throwable exception;

		ExceptionHandlingRunner(Runnable delegateRunnable) {
			this.delegateCallback = () -> {
				delegateRunnable.run();
			};
			run();
		}

		ExceptionHandlingRunner(ExceptionalCallback<? extends Exception> delegateCallback) {
			this.delegateCallback = delegateCallback;
			run();
		}

		Throwable getException() {
			return exception;
		}

		String getExceptionMessage() {
			Throwable throwable = getException();
			String message = throwable.getMessage();
			if (message != null) {
				return message;
			}

			return getCauseExceptionMessage(throwable);
		}

		protected String getCauseExceptionMessage(Throwable t) {
			if (t == null) {
				return "<No Exception Message>";
			}

			if (t instanceof AssertionError) {
				return t.getMessage();
			}

			String message = t.getMessage();
			if (message != null) {
				return message;
			}

			return getCauseExceptionMessage(t.getCause());
		}

		private void run() {

			Runnable swingExceptionCatcher = () -> {
				try {
					delegateCallback.call();
				}
				catch (Throwable t) {
					exception = t;
				}
			};

			try {
				doRun(swingExceptionCatcher);
			}
			catch (InterruptedException e) {
				// Typically, this InterrruptedException that is caused by our test harness when it
				// is interrupting the test thread after a previous Swing exception that we have
				// detected--we don't care to throw the InterruptedException, as we caused it.
				// Log a message to signal that unusual things may happen when in this state.
				Msg.debug(this, "\n>>>>>>>>>>>>>>>> Test thread interrupted.  Unusual/unexpected " +
					"errors may follow.\n\n");
			}
			catch (InvocationTargetException e) {
				// Assume that if we have an exception reported by our catcher above, then that is
				// the root cause of this exception and do not report this one.   This should not
				// happen, as we are catching the exception above.
			}
		}

		private void doRun(Runnable runnable)
				throws InvocationTargetException, InterruptedException {
			if (SwingUtilities.isEventDispatchThread()) {
				runnable.run();
			}
			else {
				SwingUtilities.invokeAndWait(runnable);
			}
		}
	}

	private static void runSwingAndWait(Runnable runnable) {
		ExceptionHandlingRunner exceptionHandlingRunner = new ExceptionHandlingRunner(runnable);

		Throwable throwable = exceptionHandlingRunner.getException();
		if (throwable == null) {
			return;
		}

		//
		// Handle the exception
		//
		if (!TestThread.isTestThread()) {
			// we have plumbing that checks for this in headed environments
			ConcurrentTestExceptionHandler.handle(Thread.currentThread(), throwable);
			return;
		}

		//
		// When not in batch mode, Eclipse and Gradle will show the exception we build here,
		// which is the most helpful.
		//
		String message = "Exception in Swing thread via runSwingAndWait():";
		if (!BATCH_MODE) {
			TestReportingException exception =
				TestReportingException.fromSwingThread(message, throwable);
			throw exception;
		}

		//
		// When running in batch mode, the report generated by Gradle will not correctly show
		// the stack trace if we throw the exception, so will will trigger a failure instead,
		// which looks good in the test report.
		//
		String string = TestReportingException.getSwingThreadTraceString(throwable);
		Assert.fail(message + "\n" + string + "\nTest Thread stack at that time:");
	}

	/**
	 * Launches the runnable on a new thread so as to not block the calling
	 * thread. This is very useful for performing actions on the Swing thread
	 * that show modal dialogs, which would otherwise block the calling thread,
	 * such as a testing thread.
	 *
	 * @param runnable The runnable that will be executed in a new Thread that
	 *            will place the runnable on the Swing thread.
	 */
	public static void executeOnSwingWithoutBlocking(Runnable runnable) {

		AtomicBoolean didRun = new AtomicBoolean();
		(new Thread() {
			@Override
			public void run() {
				didRun.set(true);
				runSwing(runnable);
			}
		}).start();

		// we can make this call, since any potential modal dialogs are not blocking in the Swing
		// thread, but in the new event queue created by the modal dialog (this is how repainting
		// still works when a modal dialog is shown)
		waitForSwing();

		waitForCondition(() -> didRun.get());

		// pause a bit to let the swing thread process
		sleep(DEFAULT_WAIT_DELAY);

		// make sure any pending Swing events have been processed
		waitForSwing();
	}

	public static void clickTableCell(final JTable table, final int row, final int col,
			int clickCount) {
		runSwing(() -> table.setRowSelectionInterval(row, row));
		waitForSwing();
		Rectangle rect = table.getCellRect(row, col, true);
		clickMouse(table, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, clickCount, 0);
		waitForSwing();
	}

	/**
	 * Clicks a range of items in a list (simulates holding SHIFT and selecting
	 * each item in the range in-turn)
	 *
	 * @param list the list to select from
	 * @param row the initial index
	 * @param count the number of rows to select
	 */
	public static void clickListRange(final JList<?> list, final int row, int count) {
		waitForSwing();
		for (int i = row; i < row + count; i++) {
			Rectangle rect = list.getCellBounds(i, i);
			clickMouse(list, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1,
				InputEvent.SHIFT_DOWN_MASK);
		}
		waitForSwing();
	}

	/**
	 * Clicks a range of items in a table (simulates holding SHIFT and selecting
	 * each item in the range)
	 *
	 * @param table the table to select
	 * @param row the starting row index
	 * @param count the number of rows to select
	 */
	public static void clickTableRange(final JTable table, final int row, int count) {
		waitForSwing();
		for (int i = row; i < row + count; i++) {
			Rectangle rect = table.getCellRect(i, 0, true);
			clickMouse(table, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1,
				InputEvent.SHIFT_DOWN_MASK);
		}
		waitForSwing();
	}

	public static TableCellEditor editCell(final JTable table, final int row, final int col) {

		waitForSwing();

		runSwing(() -> table.setRowSelectionInterval(row, row));
		waitForSwing();

		runSwing(() -> table.editCellAt(row, col));
		waitForSwing();

		TableCellEditor editor = table.getCellEditor(row, col);
		assertNotNull("Unable to edit table cell at " + row + ", " + col, editor);
		return editor;
	}

	/**
	 * Gets the rendered value for the specified table cell.  The actual value at the cell may
	 * not be a String.  This method will get the String display value, as created by the table.
	 *
	 * @param table the table to query
	 * @param row the row to query
	 * @param column the column to query
	 * @return the String value
	 * @throws IllegalArgumentException if there is no renderer or the rendered component is
	 *         something from which this method can get a String (such as a JLabel)
	 */
	public static String getRenderedTableCellValue(JTable table, int row, int column) {

		return runSwing(() -> {

			TableCellRenderer renderer = table.getCellRenderer(row, column);
			if (renderer == null) {
				throw new IllegalArgumentException(
					"No renderer registered for row/col: " + row + '/' + column);
			}
			Component component = table.prepareRenderer(renderer, row, column);
			if (!(component instanceof JLabel)) {
				throw new IllegalArgumentException(
					"Do not know how to get text from a renderer " + "that is not a JLabel");
			}

			return ((JLabel) component).getText();
		});
	}

	public static <T> void setComboBoxSelection(final JComboBox<T> comboField, final T selection) {
		runSwing(() -> comboField.setSelectedItem(selection));
		waitForSwing();
	}

	public static void setText(final JTextComponent field, final String text) {
		runSwing(() -> field.setText(text));
		waitForSwing();
	}

	public static String getText(final JTextComponent field) {
		return runSwing(() -> field.getText());
	}

	/**
	 * Finds the path of a tree node in the indicated tree with the specified
	 * text. The matching tree node is determined by comparing the specified
	 * text with the string returned by the tree node's toString() method. <br>
	 * Note: This method affects the expansion state of the tree. It will expand
	 * nodes starting at the root until a match is found or all of the tree is
	 * checked.
	 *
	 * @param tree the tree
	 * @param text the tree node's text
	 * @return the tree path
	 */
	public static TreePath findTreePathToText(JTree tree, String text) {
		TreeModel tm = tree.getModel();
		TreeNode rootNode = (TreeNode) tm.getRoot();
		TreePath rootPath = new TreePath(rootNode);
		return findPathToText(tree, rootPath, text);
	}

	/**
	 * Performs a depth first search for the named tree node.
	 *
	 * @param tree the tree to search
	 * @param startTreePath path indicating node to begin searching from in the
	 *            tree
	 * @param text the name of the node to find
	 * @return the path to the named node or null if it can't be found.
	 */
	protected static TreePath findPathToText(JTree tree, TreePath startTreePath, String text) {
		if (text.equals(startTreePath.getLastPathComponent().toString())) {
			return startTreePath;
		}
		tree.expandPath(startTreePath);
		int len = startTreePath.getPathCount();
		Object[] tpObjects = new Object[len + 1];
		System.arraycopy(startTreePath.getPath(), 0, tpObjects, 0, len);
		TreeNode treeNode = (TreeNode) startTreePath.getLastPathComponent();
		int num = treeNode.getChildCount();
		for (int i = 0; i < num; i++) {
			TreeNode childNode = treeNode.getChildAt(i);
			tpObjects[len] = childNode;
			TreePath childPath = new TreePath(tpObjects);
			TreePath treePath = findPathToText(tree, childPath, text);
			if (treePath != null) {
				return treePath;
			}
		}
		return null;
	}

	/**
	 * Invoke <code>fixupGUI</code> at the beginning of your JUnit test or in
	 * its setup() method to make your GUI for the JUnit test appear using the
	 * system Look and Feel. The system look and feel is the default that Ghidra
	 * uses. This will also change the default fonts for the JUnit test to be
	 * the same as those in Ghidra.
	 *
	 * @exception InterruptedException if we're interrupted while waiting for
	 *                the event dispatching thread to finish excecuting
	 *                <code>doRun.run()</code>
	 * @exception InvocationTargetException if an exception is thrown while
	 *                running <code>doRun</code>
	 */
	public static void fixupGUI() throws InterruptedException, InvocationTargetException {
		// Make the test look & feel as it would normally.
		SwingUtilities.invokeAndWait(() -> {
			try {
				UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
			}
			catch (ClassNotFoundException e1) {
				// don't care
			}
			catch (InstantiationException e2) {
				// don't care
			}
			catch (IllegalAccessException e3) {
				// don't care
			}
			catch (UnsupportedLookAndFeelException e4) {
				// don't care
			}
		});
		// Fix up the default fonts that Java 1.5.0 changed to Courier, which looked terrible.
		Font f = new Font("monospaced", Font.PLAIN, 12);
		UIManager.put("PasswordField.font", f);
		UIManager.put("TextArea.font", f);
	}

	/**
	 * Asserts that the two colors have the same rgb values (handles GColor)
	 * @param expected the expected color
	 * @param actual the actual color
	 */
	public void assertColorsEqual(Color expected, Color actual) {
		if (expected.getRGB() == actual.getRGB()) {
			return;
		}
		fail("Expected: [" + expected.getClass().getSimpleName() + "]" + expected +
			", but got: [" + actual.getClass().getSimpleName() + "]" + actual);
	}

	public static void printMemory() {
		yieldToSwing();
		System.gc();
		yieldToSwing();
		System.gc();
		yieldToSwing();
		System.gc();

		Runtime runTime = Runtime.getRuntime();
		System.out.println("----------------------");
		System.out.printf("Max:   %,10dK\n", runTime.maxMemory() / 1000);
		System.out.printf("Total: %,10dK\n", runTime.totalMemory() / 1000);
		System.out.printf("Free:  %,10dK\n", runTime.freeMemory() / 1000);
		System.out.printf("Used:  %,10dK\n",
			((runTime.totalMemory() - runTime.freeMemory()) / 1000));
	}

//==================================================================================================
// Swing Methods
//==================================================================================================

	/**
	 * Waits for the Swing thread to process any pending events. This method
	 * also waits for any {@link SwingUpdateManager}s that have pending events
	 * to be flushed.
	 *
	 * @return true if the any {@link SwingUpdateManager}s were busy.
	 */
	public static boolean waitForSwing() {
		if (SwingUtilities.isEventDispatchThread()) {
			throw new AssertException("Can't wait for swing from within the swing thread!");
		}

		Set<AbstractSwingUpdateManager> set = new HashSet<>();
		runSwing(() -> {
			@SuppressWarnings("unchecked")
			WeakSet<SwingUpdateManager> s =
				(WeakSet<SwingUpdateManager>) getInstanceField("instances",
					SwingUpdateManager.class);
			for (AbstractSwingUpdateManager manager : s) {
				set.add(manager);
			}
		});

		/*
		long start = System.nanoTime();
		boolean wasEverBusy = waitForSwing(set, true);
		long end = System.nanoTime();
		Msg.out("\twaitForSwing() - " +
			TimeUnit.MILLISECONDS.convert(end - start, TimeUnit.NANOSECONDS));
		*/

		boolean wasEverBusy = waitForSwing(set, true);
		return wasEverBusy;
	}

	private static boolean waitForSwing(Set<AbstractSwingUpdateManager> managers, boolean flush) {

		// Note: not sure how long is too long to wait for the Swing thread and update managers
		//       to finish.  This is usually less than a second.  We have seen a degenerate
		//       case where this took minutes.  This method is called often, so don't wait too
		//       long.  This will have to be changed through trial-and-error.
		int MAX_SWING_TIMEOUT = 15000;
		int totalTime = 0;

		// flush all managers up front to get them started before we check them
		flushAllManagers(managers, flush);

		boolean wasEverBusy = false;
		boolean keepGoing = true;
		while (keepGoing) {

			// let swing paint and maybe schedule more work on the update managers
			yieldToSwing();
			keepGoing = false;

			for (AbstractSwingUpdateManager manager : managers) {

				if (!manager.isBusy()) {
					// no current or pending work
					continue;
				}

				// Msg.out("busy manager: " + manager.toStringDebug());

				doFlush(flush, manager);

				boolean isBusy = true;
				while (isBusy) {

					keepGoing = true; // true, since we had a busy signal
					wasEverBusy = true;

					totalTime += sleep(DEFAULT_WAIT_DELAY);
					if (totalTime >= MAX_SWING_TIMEOUT) {
						// eject!
						Msg.debug(AbstractGenericTest.class,
							"Timed-out waitinig for Swing after " + totalTime + " ms.  " +
								"The currently waited SwingUpdateManager:\n" +
								manager.toStringDebug());
						return true;
					}

					isBusy = manager.isBusy();
				}
			}
			// let any resulting swing events finish
			yieldToSwing();
		}

		return wasEverBusy;
	}

	private static void flushAllManagers(Set<AbstractSwingUpdateManager> managers, boolean flush) {

		//
		// Some update managers will make an update that causes another manager to schedule an
		// update.  In order to *not* have to wait for each of these, one-at-a-time, loop a
		// few times so that any follow-up scheduling events will be executed as well.  These
		// calls all execute in the Swing thread in a blocking fashion, so when we are done
		// flushing, there should be no more work scheduled due to us flushing.   Due to other
		// potential background threads though, more work may be scheduled as we are working.
		// Thus, for fast tests, you should not have background work happening that is not
		// directly related to your code being tested.
		//

		// arbitrary; we have at least one level of a manager triggering another manager,
		// which would be 2
		int n = 3;
		for (int i = 0; i < n; i++) {
			for (AbstractSwingUpdateManager manager : managers) {
				doFlush(flush, manager);
			}
		}
	}

	private static void doFlush(boolean doFlush, AbstractSwingUpdateManager manager) {
		if (!doFlush) {
			return;
		}

		runSwing(() -> {
			manager.flush();
		}, false);
		yieldToSwing();
	}

	/**
	 * This is only for internal use. If you need to wait for the Swing thread
	 * from your test, then use {@link #waitForSwing()}.
	 *
	 * @deprecated This is not a test writer's method, but instead an
	 *             infrastructure method.
	 */
	@Deprecated
	public static void privatewaitForSwing_SwingSafe() {
		yieldToSwing();
	}

	protected static void yieldToSwing() {

		if (SwingUtilities.isEventDispatchThread()) {
			Msg.error(AbstractGenericTest.class,
				"Incorrectly called yieldToSwing() from the Swing thread");
			return; // shouldn't happen
		}

		Runnable empty = () -> {
			// do nothing...this is just a placeholder runnable that gets put onto the stack
		};

		//
		// Note: the calls below are designed to ignore being interrupted.  Further, if one of
		// the calls is interrupted, the others will still work as expected.
		//
		for (int i = 0; i < 3; i++) {
			try {
				SwingUtilities.invokeAndWait(empty);
			}
			catch (Exception e) {
				// Assumption: since our runnable is empty, this can only an interrupted
				//             exception, which can happen if our test framework decides to
				//             shut the operation down.
				return;
			}
		}
	}

}
