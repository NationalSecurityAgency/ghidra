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

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.text.JTextComponent;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingActionIf;
import docking.actions.DockingToolActions;
import docking.dnd.GClipboard;
import docking.framework.DockingApplicationConfiguration;
import docking.menu.DialogToolbarButton;
import docking.widgets.*;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.threaded.ThreadedTableModel;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.test.AbstractGenericTest;
import generic.test.ConcurrentTestExceptionHandler;
import generic.util.image.ImageUtils;
import ghidra.GhidraTestApplicationLayout;
import ghidra.framework.ApplicationConfiguration;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.worker.Worker;
import junit.framework.AssertionFailedError;
import sun.awt.AppContext;
import util.CollectionUtils;
import utility.application.ApplicationLayout;

public abstract class AbstractDockingTest extends AbstractGenericTest {

	static {
		ConcurrentTestExceptionHandler.registerHandler();
	}

	// tracks the state of whether the error GUI is enabled
	private static boolean useErrorGUI = true;

	// A special wrapper that allows us to grab exceptions from the SUT
	private static final TestFailingErrorDisplayWrapper ERROR_DISPLAY_WRAPPER =
		new TestFailingErrorDisplayWrapper();

	public AbstractDockingTest() {
		super();

		installNonNativeSystemClipboard();
	}

	private void installNonNativeSystemClipboard() {
		setInstanceField("systemClipboard", GClipboard.class, new Clipboard("Test Clipboard"));
	}

	@Before
	// named differently than setUp(), so subclasses do not override it
	public void dockingSetUp() {

		ConcurrentTestExceptionHandler.enable();

		// This call not only toggles the Error GUI on, but also wires our special error
		// display wrapper.
		setErrorGUIEnabled(true);
	}

	@After
	// named differently than tearDown(), so subclasses do not override it
	public void dockingTearDown() {
		// Disable error reporting from non-test threads found during tearDown().  The idea is
		// that odd issue find while coming down are not important, as they are usually
		// timing issues.

		// Note: this doesn't quite work as intended.  This should be run before each other
		//       tearDown() method, but junit offers no way to do that.   If you can figure 
		//       out how to make that work, then update this code.
		ConcurrentTestExceptionHandler.disable();
	}

	@Override
	protected ApplicationLayout createApplicationLayout() {
		try {
			return new GhidraTestApplicationLayout(new File(getTestDirectoryPath()));
		}
		catch (IOException e) {
			throw new AssertException(e);
		}
	}

	@Override
	protected ApplicationConfiguration createApplicationConfiguration() {
		DockingApplicationConfiguration config = new DockingApplicationConfiguration();
		config.setShowSplashScreen(false);
		return config;
	}

	public static void waitForUpdateOnChooser(GhidraFileChooser chooser) throws Exception {
		// make sure swing has handled any pending changes
		waitForSwing();

		// Use an artificially high wait period that won't be reached most of the time.  We
		// need this because file choosers use the native filesystem, which can have 'hiccups'
		int timeoutMillis = PRIVATE_LONG_WAIT_TIMEOUT;
		int totalTime = 0;
		while (pendingUpdate(chooser) && (totalTime < timeoutMillis)) {
			Thread.sleep(DEFAULT_WAIT_DELAY);
			totalTime += DEFAULT_WAIT_DELAY;
		}

		if (totalTime >= timeoutMillis) {
			Assert.fail("Timed-out waiting for directory to load");
		}

		// make sure swing has handled any pending changes
		waitForSwing();
	}

	private static boolean pendingUpdate(GhidraFileChooser chooser) {
		return (Boolean) invokeInstanceMethod("pendingUpdate", chooser);
	}

	public static Window getWindowByTitleContaining(Window parentWindow, String text) {
		Set<Window> winList = getWindows(parentWindow);
		Iterator<Window> iter = winList.iterator();
		while (iter.hasNext()) {
			Window w = iter.next();
			if (!w.isShowing()) {
				continue;
			}
			String titleForWindow = getTitleForWindow(w);
			if (titleForWindow.toLowerCase().contains(text.toLowerCase())) {
				return w;
			}
		}
		return null;
	}

	protected static Window getWindow(String title) {
		return getWindowByTitle(null, title);
	}

	protected static Window getWindowByTitle(Window parentWindow, String title) {
		Set<Window> winList = getWindows(parentWindow);
		Iterator<Window> iter = winList.iterator();
		while (iter.hasNext()) {
			Window w = iter.next();
			if (!w.isShowing()) {
				continue;
			}
			String titleForWindow = getTitleForWindow(w);
			if (title.equals(titleForWindow)) {
				return w;
			}
		}
		return null;
	}

	/**
	 * Waits for the system error dialog to appear
	 * @return the dialog
	 */
	public static AbstractErrDialog waitForErrorDialog() {
		return waitForDialogComponent(AbstractErrDialog.class);
	}

	/**
	 * Waits for the system info dialog to appear
	 * @return the dialog
	 */
	public static OkDialog waitForInfoDialog() {
		return waitForDialogComponent(OkDialog.class);
	}

	public static Window waitForWindow(Class<?> windowClass) {

		if ((!Dialog.class.isAssignableFrom(windowClass)) &&
			(!Frame.class.isAssignableFrom(windowClass))) {
			throw new IllegalArgumentException(
				windowClass.getName() + " does not extend Dialog or Frame.");
		}

		int timeout = DEFAULT_WAIT_TIMEOUT;
		int totalTime = 0;
		while (totalTime <= timeout) {

			Set<Window> winList = getAllWindows();
			Iterator<Window> it = winList.iterator();
			while (it.hasNext()) {
				Window w = it.next();
				if (windowClass.isAssignableFrom(w.getClass()) && w.isShowing()) {
					return w;
				}
			}

			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}

		throw new AssertionFailedError("Timed-out waiting for window of class: " + windowClass);
	}

	public static Window waitForWindowByTitleContaining(String text) {

		// try at least one time
		Window window = getWindowByTitleContaining(null, text);
		if (window != null) {
			return window;// we found it...no waiting required
		}

		int totalTime = 0;
		int timeout = DEFAULT_WAIT_TIMEOUT;
		while (totalTime <= timeout) {

			window = getWindowByTitleContaining(null, text);
			if (window != null) {
				return window;
			}

			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}

		throw new AssertionFailedError(
			"Timed-out waiting for window containg title '" + text + "'");
	}

	/**
	 * Waits for a window with the given name.
	 *
	 * @param title The title of the window for which to search
	 * @param timeoutMS The timeout after which this method will wait no more
	 * @return The window, if found, null otherwise.
	 * @deprecated Instead call one of the methods that does not take a timeout
	 *             (we are standardizing timeouts).  The timeouts passed to this method will
	 *             be ignored in favor of the standard value.
	 */
	@Deprecated
	public static Window waitForWindow(String title, int timeoutMS) {
		return waitForWindow(title);
	}

	/**
	 * Waits for a window with the given name
	 *
	 * @param title The title of the window for which to search
	 * @return The window, if found, null otherwise.
	 */
	public static Window waitForWindow(String title) {
		Window window = getWindow(title);
		if (window != null) {
			return window;// we found it...no waiting required
		}

		int totalTime = 0;
		int timeout = DEFAULT_WAIT_TIMEOUT;
		while (totalTime <= timeout) {

			window = getWindow(title);
			if (window != null) {
				return window;
			}

			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}
		throw new AssertionFailedError("Timed-out waiting for window with title '" + title + "'");
	}

	/**
	 * Waits for a window with the given name.
	 *
	 * @param name The name of the window for which to search
	 * @return The window, if found, null otherwise
	 */
	public static Window waitForWindowByName(String name) {

		int time = 0;
		int timeout = DEFAULT_WAIT_TIMEOUT;
		while (time <= timeout) {
			Set<Window> allWindows = getAllWindows();
			for (Window window : allWindows) {
				String windowName = window.getName();
				if (name.equals(windowName) && window.isShowing()) {
					return window;
				}

				time += sleep(DEFAULT_WAIT_DELAY);
			}
		}

		throw new AssertionFailedError("Timed-out waiting for window with name '" + name + "'");
	}

	/**
	 * Check for and display message component text associated with OptionDialog windows 
	 * @param w any window
	 * @return the message string if one can be found; <code>null</code> otherwise
	 */
	public static String getMessageText(Window w) {
		Component c = findComponentByName(w, OptionDialog.MESSAGE_COMPONENT_NAME);
		if (c instanceof JLabel) {
			return ((JLabel) c).getText();
		}
		else if (c instanceof MultiLineLabel) {
			return ((MultiLineLabel) c).getLabel();
		}
		return null;
	}

	/**
	 * Get the dialog provider's status text
	 * @param provider dialog component provider
	 * @return status text
	 */
	public static String getStatusText(DialogComponentProvider provider) {
		AtomicReference<String> ref = new AtomicReference<>();
		runSwing(() -> {
			ref.set(provider.getStatusText());
		});
		return ref.get();
	}

	/**
	 * Will try to close dialogs prompting for changes to be saved, whether from program changes
	 * or from tool config changes.
	 */
	public static void closeSaveChangesDialog() {
		waitForSwing();
		OptionDialog dialog = getDialogComponent(OptionDialog.class);
		if (dialog == null) {
			return;
		}

		String title = dialog.getTitle();
		boolean isSavePrompt = StringUtils.containsAny(title, "Changed", "Saved");
		if (!isSavePrompt) {
			throw new AssertionError("Unexpected dialog with title '" + title + "'; " +
				"Expected a dialog alerting to program changes");
		}

		if (StringUtils.contains(title, "Program Changed")) {
			// the program is read-only or not in a writable project
			pressButtonByText(dialog, "Continue");
			return;
		}

		if (StringUtils.contains(title, "Save Program?")) {
			pressButtonByText(dialog, "Cancel");
			return;
		}

		throw new AssertionError("Unexpected dialog with title '" + title + "'; " +
			"Expected a dialog alerting to program changes");
	}

	public void close(DialogComponentProvider dialog) {
		if (dialog == null) {
			return;
		}
		runSwing(() -> dialog.close());
	}

	public void close(Window w) {
		if (w == null) {
			return;
		}

		boolean wait = !isOnlyFrame(w);
		runSwing(() -> w.setVisible(false), wait);
	}

	private boolean isOnlyFrame(Window window) {
		if (!(window instanceof Frame)) {
			return false;
		}

		//@formatter:off
		long n = getAllWindows()
			.stream()
			.filter(w -> w instanceof Frame && w != window)
			.count()
			;
		//@formatter:on
		return n > 0;
	}

	public static void closeAllWindows(boolean showError) {
		boolean firstClose = true;
		for (Window window : getAllWindows()) {

			if (!window.isShowing()) {
				continue;
			}

			if (showError) {

				if (firstClose) { // only print once
					firstClose = false;
					printOpenWindows();
				}

				// note: we use System.err here to get more obvious errors in the console
				String title = getDebugTitleForWindow(window);
				System.err.println("DockingTestCase - Forced window closure: " + title);
				String errorMessage = getMessageText(window);
				if (errorMessage != null) {
					System.err.println("\tWindow error message: " + errorMessage);
				}
			}

			Window w = window;
			runSwing(() -> w.dispose());
		}
	}

	/**
	 * A convenience method to close all of the windows and frames that the current Java
	 * windowing environment knows about
	 * 
	 * @deprecated instead call the new {@link #closeAllWindows()}
	 */
	@Deprecated
	public static void closeAllWindowsAndFrames() {
		closeAllWindows(false);
	}

	/**
	 * A convenience method to close all of the windows and frames that the current Java
	 * windowing environment knows about
	 */
	public static void closeAllWindows() {
		closeAllWindows(false);
	}

	public static String getTitleForWindow(Window window) {
		if (window instanceof Frame) {
			return ((Frame) window).getTitle();
		}
		else if (window instanceof Dialog) {
			return ((Dialog) window).getTitle();
		}
		return null;
	}

	private static String getDebugTitleForWindow(Window window) {
		String defaultTitle = "<no title> - id = " + System.identityHashCode(window) +
			"; class = " + window.getClass().getSimpleName();
		String title = getDebugTitleForWindow(window, defaultTitle);
		return title;
	}

	private static String getDebugTitleForWindow(Window window, String defaultTitle) {
		if (window instanceof Frame) {
			return "Frame: '" + ((Frame) window).getTitle() + "'";
		}
		else if (window instanceof Dialog) {
			return "Dialog: '" + ((Dialog) window).getTitle() + "'";
		}
		return "Non-Frame/Dialog window: " + defaultTitle;
	}

	/**
	 * Waits for the JDialog with the given title
	 * <P>
	 * Note: Sometimes the task dialog might have the same title as the dialog you pop up and
	 * you want to get yours instead of the one for the task monitor.
	 *
	 * @param title the title of the dialog
	 * @return the dialog
	 */
	public static JDialog waitForJDialog(String title) {

		int totalTime = 0;
		while (totalTime <= DEFAULT_WINDOW_TIMEOUT) {

			Set<Window> winList = getAllWindows();
			Iterator<Window> iter = winList.iterator();
			while (iter.hasNext()) {
				Window w = iter.next();
				if ((w instanceof JDialog) && w.isShowing()) {
					String windowTitle = getTitleForWindow(w);
					if (title.equals(windowTitle)) {
						return (JDialog) w;
					}
				}
			}

			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}
		throw new AssertionFailedError("Timed-out waiting for window with title '" + title + "'");
	}

	/**
	 * Waits for the JDialog with the indicated title and that is parented to the indicated window
	 * <P>
	 * Note: Sometimes the task dialog might have the same title as the dialog you pop up and
	 * you want to get yours instead of the one for the task monitor.
	 *
	 * @param window the parent window
	 * @param title the title of the dialog
	 * @param timeoutMS Maximum time to wait for the dialog
	 * @return the dialog
	 * @deprecated use {@link #waitForJDialog(String)} instead
	 */
	@Deprecated
	public static JDialog waitForJDialog(Window window, String title, int timeoutMS) {

		int totalTime = 0;
		while (totalTime <= DEFAULT_WAIT_TIMEOUT) {

			Set<Window> winList = getWindows(window);
			Iterator<Window> iter = winList.iterator();
			while (iter.hasNext()) {
				Window w = iter.next();
				if ((w instanceof JDialog) && w.isShowing()) {
					String windowTitle = getTitleForWindow(w);
					if (title.equals(windowTitle)) {
						return (JDialog) w;
					}
				}
			}

			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}
		throw new AssertionFailedError("Timed-out waiting for window with title '" + title + "'");
	}

	/**
	 * Returns the first {@link Component} of the given type inside of the given dialog
	 *
	 * @param provider the dialog
	 * @param desiredClass the class of the component
	 * @return the component; null if none was found
	 */
	public static <T extends Component> T findComponent(DialogComponentProvider provider,
			Class<T> desiredClass) {
		return findComponent(provider.getComponent(), desiredClass);
	}

	/**
	 * Returns the {@link DialogComponentProvider} with the given title.  This method is
	 * not preferred, but instead you should use a {@link #waitForDialogComponent(Class)}
	 * that takes a class so that you can get the correct return type.  This method is meant
	 * for clients that need a dialog, but that type is private of package restricted and thus
	 * cannot be referenced by a test.   Also, code that relies on a title is more subject to
	 * breaking when code is refactored; code that relies on class types will get refactored
	 * along side the referenced code.
	 *
	 * <P>This method will fail if no dialog can be found
	 *
	 * @param title the title of the desired dialog
	 * @return the dialog
	 */
	public static DialogComponentProvider waitForDialogComponent(String title) {
		Window window = waitForWindow(title);
		assertNotNull("No window found with title '" + title + "'", window);

		if (!(window instanceof DockingDialog)) {
			fail("Window is not a DockingDialog - '" + title + "'");
		}

		DockingDialog dd = (DockingDialog) window;
		return dd.getDialogComponent();
	}

	/**
	 * Waits for the first window of the given class.
	 *
	 * @param ghidraClass The class of the dialog the user desires
	 * @return The first occurrence of a dialog that extends the given <code>ghirdraClass</code>
	 * @see #waitForDialogComponent(Window, Class, int)
	 */
	public static <T extends DialogComponentProvider> T waitForDialogComponent(
			Class<T> ghidraClass) {
		return waitForDialogComponent(null, ghidraClass, DEFAULT_WINDOW_TIMEOUT);
	}

	/**
	 * Waits for the first window of the given class.  This method assumes that the desired dialog
	 * is parented by <code>parentWindow</code>.
	 *
	 * @param parentWindow The parent of the desired dialog; may be null
	 * @param clazz The class of the dialog the user desires
	 * @param timeoutMS The max amount of time in milliseconds to wait for the requested dialog
	 *        to appear.
	 * @return The first occurrence of a dialog that extends the given <code>ghirdraClass</code>
	 * @deprecated Instead call one of the methods that does not take a timeout
	 *             (we are standardizing timeouts).  The timeouts passed to this method will
	 *             be ignored in favor of the standard value.
	 */
	@Deprecated
	public static <T extends DialogComponentProvider> T waitForDialogComponent(Window parentWindow,
			Class<T> clazz, int timeoutMS) {
		if (!DialogComponentProvider.class.isAssignableFrom(clazz)) {
			throw new IllegalArgumentException(clazz.getName() + " does not extend " +
				DialogComponentProvider.class.getSimpleName());
		}

		int totalTime = 0;
		while (totalTime <= DEFAULT_WAIT_TIMEOUT) {

			T provider = getDialogComponent(parentWindow, clazz);
			if (provider != null) {
				return provider;
			}
			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}

		throw new AssertionFailedError("Timed-out waiting for window of class: " + clazz);
	}

	private static <T extends DialogComponentProvider> T getDialogComponent(Window parentWindow,
			Class<T> ghidraClass) {
		Set<Window> winList = getWindows(parentWindow);
		Iterator<Window> iter = winList.iterator();
		while (iter.hasNext()) {
			Window w = iter.next();
			DialogComponentProvider dialogComponentProvider =
				getDialogComponentProvider(w, ghidraClass);
			if (dialogComponentProvider != null) {
				return ghidraClass.cast(dialogComponentProvider);
			}

			// try child windows of the given window too (depth-first)
			Set<Window> windows = getWindows(w);
			for (Window window : windows) {
				dialogComponentProvider = getDialogComponentProvider(window, ghidraClass);
				if (dialogComponentProvider != null) {
					return ghidraClass.cast(dialogComponentProvider);
				}
			}
		}
		return null;
	}

	/**
	 * Gets a dialog component provider of the given type
	 *
	 * @param ghidraClass the class of the desired {@link DialogComponentProvider}.
	 * @return the dialog or null if it cannot be found
	 */
	public static <T extends DialogComponentProvider> T getDialogComponent(Class<T> ghidraClass) {
		return getDialogComponent(null, ghidraClass);
	}

	/**
	 * Gets the dialog component provider <b>that is inside the given window</b> or null if a
	 * provider of the given class type is not in the window.
	 *
	 * @param window the window that contains the desired provider.
	 * @param ghidraClass the class of the desired provider
	 * @return the desired provider or null if the window does not contain a provider of the given type.
	 */
	protected static <T extends DialogComponentProvider> T getDialogComponentProvider(Window window,
			Class<T> ghidraClass) {

		if (!(window instanceof DockingDialog)) {
			return null;
		}

		if (!window.isShowing()) {
			return null;
		}

		DialogComponentProvider provider = ((DockingDialog) window).getDialogComponent();
		if (provider == null || !provider.isVisible()) {
			// provider can be null if the DockingDialog is disposed before we can get the provider
			return null;
		}

		if (!ghidraClass.isAssignableFrom(provider.getClass())) {
			return null;
		}

		return ghidraClass.cast(provider);
	}

	/**
	 * Searches for the first occurrence of a {@link ComponentProvider} that is an instance of
	 * the given <code>providerClass</code>.
	 *
	 * @param clazz The class of the ComponentProvider to locate
	 * @return The component provider, or null if one cannot be found
	 */
	public static <T extends ComponentProvider> T getComponentProvider(Class<T> clazz) {

		DockingWindowManager dwm = findActiveDockingWindowManager();
		assertNotNull("Unable to find a DockingWindowManager - is there a tool showing?", dwm);
		return getComponentProvider(dwm, clazz);
	}

	private static <T extends ComponentProvider> T getComponentProvider(
			DockingWindowManager windowManager, Class<T> clazz) {

		T detached = getDetachedWindowProvider(clazz, windowManager);
		if (detached != null) {
			return detached;
		}

		T t = windowManager.getComponentProvider(clazz);
		if (t != null) {
			return t;
		}

		return null;
	}

	/**
	 * Searches for the first occurrence of a {@link ComponentProvider} that is an instance of
	 * the given <code>providerClass</code>.  This method will repeat the search every
	 * {@link #DEFAULT_WAIT_DELAY} milliseconds
	 * until the provider is found, or the maximum number of searches has been reached, where
	 * <code>maximum number of searches = MaxTimeMS / {@link #DEFAULT_WAIT_DELAY} </code>
	 *
	 * @param clazz The class of the ComponentProvider to locate
	 * @return The component provider, or null if one cannot be found
	 */
	public static <T extends ComponentProvider> T waitForComponentProvider(Class<T> clazz) {

		DockingWindowManager dwm = findActiveDockingWindowManager();
		assertNotNull("Unable to find a DockingWindowManager - is there a tool showing?", dwm);

		T provider = doWaitForComponentProvider(dwm, clazz);
		return provider;
	}

	/**
	 * Allows you to find a component provider <b>with the given title</b>.  Most plugins will
	 * only ever have a single provider.   In those cases, use 
	 * {@link #waitForComponentProvider(Class)}.  This version of that method is to allow you to
	 * differentiate between multiple instances of a given provider that have different titles.
	 *
	 * @param clazz The class of the ComponentProvider to locate
	 * @param title the title of the component provider
	 * @return The component provider, or null if one cannot be found
	 */
	public static <T extends ComponentProvider> T waitForComponentProvider(Class<T> clazz,
			String title) {

		DockingWindowManager dwm = findActiveDockingWindowManager();
		assertNotNull("Unable to find a DockingWindowManager - is there a tool showing?", dwm);

		T provider = doWaitForComponentProvider(dwm, clazz, title);
		return provider;
	}

	@SuppressWarnings("unchecked")
	private static DockingWindowManager findActiveDockingWindowManager() {
		DockingWindowManager activeInstance = DockingWindowManager.getActiveInstance();
		if (activeInstance != null) {
			// will not happen if there is a tool showing
			return activeInstance;
		}

		// just in case there is a tool, but it is not visible, grab the tool's manager
		List<DockingWindowManager> managers =
			(List<DockingWindowManager>) getInstanceField("instances", DockingWindowManager.class);
		for (int i = managers.size() - 1; i >= 0; i--) {
			DockingWindowManager m = managers.get(i);
			String title = m.getRootFrame().getTitle();
			if (title.contains("Tool")) {
				return m;
			}
		}

		return null;
	}

	private static <T extends ComponentProvider> T doWaitForComponentProvider(
			DockingWindowManager windowManager, Class<T> clazz) {

		Objects.requireNonNull(windowManager, "DockingWindowManager cannot be null");

		int totalTime = 0;
		while (totalTime <= DEFAULT_WAIT_TIMEOUT) {

			T t = getComponentProvider(windowManager, clazz);
			if (t != null) {
				return t;
			}
			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}

		throw new AssertionFailedError(
			"Timed-out waiting for ComponentProvider of class: " + clazz);
	}

	private static <T extends ComponentProvider> T doWaitForComponentProvider(
			DockingWindowManager windowManager, Class<T> clazz, String title) {

		Objects.requireNonNull(windowManager, "DockingWindowManager cannot be null");

		int totalTime = 0;
		while (totalTime <= DEFAULT_WAIT_TIMEOUT) {

			T t = getComponentProvider(windowManager, clazz);
			if (Objects.deepEquals(title, t.getTitle())) {
				return t;
			}
			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}

		throw new AssertionFailedError(
			"Timed-out waiting for ComponentProvider of class: " + clazz);
	}

	/** These providers are those that appear in dialogs outside of the main frame **/
	private static <T extends ComponentProvider> T getDetachedWindowProvider(
			final Class<T> providerClass, final DockingWindowManager windowManager) {

		Objects.requireNonNull(windowManager, "DockingWindowManager cannot be null");

		AtomicReference<T> ref = new AtomicReference<>();

		runSwing(() -> {
			Object rootNode = getInstanceField("root", windowManager);
			List<?> windowNodeList = (List<?>) invokeInstanceMethod("getDetachedWindows", rootNode);
			for (Object windowNode : windowNodeList) {
				Object childNode = getInstanceField("child", windowNode);
				ComponentProvider provider = getComponentProviderFromNode(childNode, providerClass);

				if (provider != null) {
					ref.set(providerClass.cast(provider));
				}
			}
		});

		return ref.get();
	}

	/**
	 * A recursive method to get the first encountered ComponentProvider instance of the give
	 * component provider class.
	 * <p>
	 * Note: this method assumes the given node is not a RootNode, but a child thereof
	 *
	 * @param node The <code>Node</code> instance that contains the desired <code>ComponentProvider</code>
	 *        or other nodes.
	 * @param providerClass The <code>ComponentProvider</code> class for which to search.
	 */
	private static ComponentProvider getComponentProviderFromNode(Object node,
			Class<? extends ComponentProvider> providerClass) {
		Class<?> nodeClass = node.getClass();
		String className = nodeClass.getName();

		if (className.indexOf("ComponentNode") != -1) {
			List<ComponentPlaceholder> infoList = CollectionUtils.asList(
				(List<?>) getInstanceField("windowPlaceholders", node), ComponentPlaceholder.class);
			for (ComponentPlaceholder info : infoList) {
				ComponentProvider provider = info.getProvider();
				if ((provider != null) && providerClass.isAssignableFrom(provider.getClass())) {
					return provider;
				}
			}
		}
		else if (className.indexOf("WindowNode") != -1) {
			Object childNode = getInstanceField("child", node);
			return getComponentProviderFromNode(childNode, providerClass);// recurse
		}
		else if (className.indexOf("SplitNode") != -1) {
			Object leftNode = getInstanceField("child1", node);
			ComponentProvider leftProvider = getComponentProviderFromNode(leftNode, providerClass);// recurse
			if (leftProvider != null) {
				return leftProvider;
			}

			Object rightNode = getInstanceField("child2", node);
			return getComponentProviderFromNode(rightNode, providerClass);// recurse
		}

		return null;
	}

	/**
	 * Searches for the first occurrence of a {@link ComponentProvider} that is an instance of
	 * the given <code>providerClass</code>.  This method will repeat the search every
	 * {@link #DEFAULT_WAIT_DELAY} milliseconds
	 * until the provider is found, or the maximum number of searches has been reached, where
	 * <code>maximum number of searches = MaxTimeMS / {@link #DEFAULT_WAIT_DELAY} </code>
	 *
	 * @param parentWindow The window that will become the parent window of the provider (this is
	 *        typically the tool's frame).
	 * @param providerClass The class of the ComponentProvider to locate.
	 * @param maxTimeMS The maximum amount of time to wait.  This is an approximation (see above).
	 * @return The component provider, or null if one cannot be found
	 * @deprecated Instead call one of the methods that does not take a timeout
	 *             (we are standardizing timeouts).  The timeouts passed to this method will
	 *             be ignored in favor of the standard value.
	 */
	@Deprecated
	public static <T extends ComponentProvider> T waitForComponentProvider(Window parentWindow,
			Class<T> providerClass, int maxTimeMS) {

		if (parentWindow == null) {
			throw new NullPointerException(
				"parentWindow cannot be null--if you don't have a " + "parent window, then call " +
					"waitForComponentProvider(Class<? extends ComponentProvider> providerClass");
		}

		DockingWindowManager dockingWindowManager = DockingWindowManager.getInstance(parentWindow);
		if (dockingWindowManager == null) {
			throw new NullPointerException("Could not find DockingWindowManager instance for " +
				"window: '" + getTitleForWindow(parentWindow) + "' - " + parentWindow);
		}

		return doWaitForComponentProvider(dockingWindowManager, providerClass);
	}

	protected static Set<Window> getWindows(Window parentWindow) {
		if (parentWindow != null) {
			Set<Window> winList = new HashSet<>();
			findWindows(parentWindow, winList);
			return winList;
		}
		return getAllWindows();
	}

	private static void findWindows(Window win, Set<Window> windowSet) {
		DockingWindowManager winMgr = DockingWindowManager.getInstance(win);
		if (winMgr != null) {
			List<Window> dockableWinList = Collections.emptyList();

			try {
				dockableWinList = winMgr.getWindows(true);
			}
			catch (ConcurrentModificationException cme) {
				// The call to getWindows() relies on a data structure that is modified by the
				// swing thread.  Unfortunately, at this point, we may be waiting for the swing
				// thread to do some work and we don't want to deadlock the test here by using
				// a call to runSwing().
				//
				// So, just ignore the exception.  Client code that *really* wants all windows,
				// like that which waits for windows, should be calling this method repeatedly anyway.
			}
			Iterator<Window> iter = dockableWinList.iterator();
			while (iter.hasNext()) {
				Window w = iter.next();
				windowSet.add(w);
				findOwnedWindows(w, windowSet);
			}
		}
		else {
			findOwnedWindows(win, windowSet);
		}
	}

	/**
	 * Finds the button with the indicated TEXT that is a sub-component
	 * of the indicated container, and then programmatically presses
	 * the button.
	 * <BR>The following is a sample JUnit test use:
	 * <PRE>
	 * 	env.showTool();
	 * 	OptionDialog dialog = (OptionDialog)env.waitForDialog(OptionDialog.class, 1000);
	 * 	assertNotNull(dialog);
	 * 	pressButtonByText(dialog, "OK");
	 * </PRE>
	 *
	 * @param provider the DialogComponentProvider containing the button.
	 * @param buttonText the text on the desired JButton.
	 */
	public static void pressButtonByText(DialogComponentProvider provider, String buttonText) {
		pressButtonByText(provider.getComponent(), buttonText, true);
	}

	/**
	 * Finds the button with the indicated TEXT that is a sub-component
	 * of the indicated container, and then programmatically presses
	 * the button.
	 * @param provider the DialogComponentProvider containing the button.
	 * @param buttonText the text on the desired JButton.
	 * @param waitForCompletion if true wait for action to complete before returning,
	 * otherwise schedule action to be performed and return immediately.
	 */
	public static void pressButtonByText(DialogComponentProvider provider, String buttonText,
			boolean waitForCompletion) {
		pressButtonByText(provider.getComponent(), buttonText, waitForCompletion);
	}

	/**
	 * Finds the toggle button with the given name inside of the given container and then
	 * ensures that the selected state of the button matches <code>selected</code>.
	 * <p>
	 * Note: this works for any instanceof {@link JToggleButton}, such as:
	 * <ul>
	 * 	<li>{@link JCheckBox}</li>
	 *  <li>{@link JRadioButton}</li>
	 * </ul>
	 * as well as {@link EmptyBorderToggleButton}s.
	 *
	 * @param container a container that has the desired button as a descendant
	 * @param buttonName the name of the button (you must set this on the button when it is
	 *                   constructed; if there is no button with the given name found, then this
	 *                   method will search for a button with the given text
	 * @param selected true to toggle the button to selected; false for de-selected
	 */
	public static void setToggleButtonSelected(Container container, String buttonName,
			boolean selected) {

		AbstractButton button = findAbstractButtonByName(container, buttonName);
		if (button == null) {
			button = findAbstractButtonByText(container, buttonName);
		}
		if (button == null) {
			throw new AssertionError("Could not find button by name or text '" + buttonName + "'");
		}

		boolean isToggle =
			(button instanceof JToggleButton) || (button instanceof EmptyBorderToggleButton);
		if (!isToggle) {
			throw new AssertionError(
				"Found a button, but it is not a toggle button.  Text: '" + buttonName + "'");
		}

		setToggleButtonSelected(button, selected);
	}

	/**
	 * Ensures that the selected state of the button matches <code>selected</code>.
	 * <p>
	 * Note: this works for most toggle button implementations which are derived from
	 * AbstractButton and relay on {@link AbstractButton#isSelected()} and
	 * {@link AbstractButton#doClick()} for toggling, such as:
	 * <ul>
	 * 	<li>{@link JCheckBox}</li>
	 *  <li>{@link JRadioButton}</li>
	 *  <li>{@link EmptyBorderToggleButton}</li>
	 * </ul>
	 * @param button the button to select
	 * @param selected true to toggle the button to selected; false for de-selected
	 */
	public static void setToggleButtonSelected(AbstractButton button, boolean selected) {
		boolean isSelected = button.isSelected();
		if (isSelected != selected) {
			pressButton(button);
		}
	}

	/**
	 * Checks the selected state of a JToggleButton in a thread safe way.
	 * @param button the toggle button for which to check the selected state.
	 * @param selected the expected state of the toggle button.
	 */
	public static void assertToggleButtonSelected(JToggleButton button, boolean selected) {
		AtomicBoolean ref = new AtomicBoolean();
		runSwing(() -> ref.set(button.isSelected()));
		Assert.assertEquals("Button not in expected selected state", selected, ref.get());
	}

	/**
	 * Checks the enablement state of a JComponent in a thread safe way.
	 * @param component the component for which to check the enablement state.
	 * @param enabled the expected enablement state for the component.
	 */
	public static void assertEnabled(JComponent component, boolean enabled) {
		AtomicBoolean ref = new AtomicBoolean();
		runSwing(() -> ref.set(component.isEnabled()));
		Assert.assertEquals("Component not in expected enablement state", enabled, ref.get());
	}

	/**
	 * A helper method to find all actions with the given name
	 *
	 * @param tool the tool containing all system actions
	 * @param name the name to match
	 * @return the matching actions; empty list if no matches
	 */
	public static Set<DockingActionIf> getActionsByName(Tool tool, String name) {

		Set<DockingActionIf> result = new HashSet<>();

		Set<DockingActionIf> toolActions = tool.getAllActions();
		for (DockingActionIf action : toolActions) {
			if (action.getName().equals(name)) {
				result.add(action);
			}
		}
		return result;
	}

	/**
	 * A helper method to find all actions with the given owner's name (this will not include
	 * reserved system actions)
	 *
	 * @param tool the tool containing all system actions
	 * @param name the owner's name to match
	 * @return the matching actions; empty list if no matches
	 */
	public static Set<DockingActionIf> getActionsByOwner(Tool tool, String name) {
		return tool.getDockingActionsByOwnerName(name);
	}

	/**
	 * A helper method to find all actions by name, with the given owner's name (this will not 
	 * include reserved system actions)
	 *
	 * @param tool the tool containing all system actions
	 * @param owner the owner's name
	 * @param name the owner's name to match
	 * @return the matching actions; empty list if no matches
	 */
	public static Set<DockingActionIf> getActionsByOwnerAndName(Tool tool, String owner,
			String name) {
		Set<DockingActionIf> ownerActions = tool.getDockingActionsByOwnerName(owner);
		return ownerActions.stream()
				.filter(action -> action.getName().equals(name))
				.collect(Collectors.toSet());
	}

	/**
	 * Finds the singular tool action by the given name.  If more than one action exists with
	 * that name, then an exception is thrown.  If you want more than one matching action,
	 * the call {@link #getActionsByName(Tool, String)} instead.
	 *
	 * <P>Note: more specific test case subclasses provide other methods for finding actions
	 * when you have an owner name (which is usually the plugin name).
	 *
	 * @param tool the tool containing all system actions
	 * @param name the name to match
	 * @return the matching action; null if no matching action can be found
	 */
	public static DockingActionIf getAction(Tool tool, String name) {

		Set<DockingActionIf> actions = getActionsByName(tool, name);
		if (actions.isEmpty()) {
			return null;
		}

		if (actions.size() > 1) {
			throw new AssertionFailedError("Found more than one action for name '" + name + "'");
		}

		return CollectionUtils.any(actions);
	}

	/**
	 * Finds the action by the given owner name and action name.  
	 * If you do not know the owner name, then use  
	 * the call {@link #getActionsByName(Tool, String)} instead  (this will not include
	 * reserved system actions).
	 * 
	 * <P>Note: more specific test case subclasses provide other methods for finding actions 
	 * when you have an owner name (which is usually the plugin name).
	 * 
	 * @param tool the tool containing all system actions
	 * @param owner the owner of the action
	 * @param name the name to match
	 * @return the matching action; null if no matching action can be found
	 */
	public static DockingActionIf getAction(Tool tool, String owner, String name) {
		Set<DockingActionIf> actions = getActionsByOwnerAndName(tool, owner, name);
		if (actions.isEmpty()) {
			return null;
		}

		if (actions.size() > 1) {
			// This shouldn't happen
			throw new AssertionFailedError(
				"Found more than one action for name '" + name + " (" + owner + ")'\n\t" + actions);
		}

		return CollectionUtils.any(actions);
	}

	/**
	 * Returns the action by the given name that belongs to the given provider
	 * 
	 * @param provider the provider
	 * @param actionName the action name
	 * @return the action
	 */
	public static DockingActionIf getLocalAction(ComponentProvider provider, String actionName) {
		Tool tool = provider.getTool();
		DockingToolActions toolActions = tool.getToolActions();
		DockingActionIf action = toolActions.getLocalAction(provider, actionName);
		return action;
	}

	/**
	 * Returns the given dialog's action that has the given name
	 *
	 * @param provider the dialog provider
	 * @param actionName the name of the action
	 * @return the action
	 */
	public static DockingActionIf getAction(DialogComponentProvider provider, String actionName) {

		Set<DockingActionIf> actions = provider.getActions();
		for (DockingActionIf action : actions) {
			if (action.getName().equals(actionName)) {
				return action;
			}
		}
		return null;
	}

	/**
	 * Performs the specified action within the Swing Thread.  This method will block until the
	 * action completes.  Do not use this method if the given actions triggers a modal
	 * dialog.  Instead, call {@link #performAction(DockingActionIf, boolean)} with a false
	 * value.
	 *
	 * <P>If the action results in a modal dialog, then call
	 * {@link #performAction(DockingActionIf, boolean)} with a value of false.
	 *
	 * @param action action to be performed (event will be null)
	 */
	public static void performAction(DockingActionIf action) {
		performAction(action, true);
	}

	/**
	 * Performs the specified action within the Swing Thread.  If the action results
	 * in a modal dialog, waitForCompletion must be false.
	 *
	 * @param action action to be performed
	 * @param waitForCompletion if true wait for action to complete before returning,
	 * otherwise schedule action to be performed and return immediately.
	 */
	public static void performAction(DockingActionIf action, boolean waitForCompletion) {

		ActionContext context = runSwing(() -> {
			ActionContext actionContext = new ActionContext();
			DockingWindowManager activeInstance = DockingWindowManager.getActiveInstance();
			if (activeInstance == null) {
				return actionContext;
			}

			ComponentProvider provider = activeInstance.getActiveComponentProvider();
			if (provider == null) {
				return actionContext;
			}

			ActionContext providerContext = provider.getActionContext(null);
			if (providerContext != null) {
				return providerContext;
			}

			return actionContext;
		});

		doPerformAction(action, context, waitForCompletion);
	}

	private static void doPerformAction(DockingActionIf action, ActionContext context,
			boolean waitForCompletion) {

		assertNotNull("Action cannot be null", action);
		assertNotNull("Action context cannot be null", context);

		runSwing(() -> {

			action.isAddToPopup(context);
			action.isEnabledForContext(context);

			if (action instanceof ToggleDockingActionIf) {
				ToggleDockingActionIf toggleAction = ((ToggleDockingActionIf) action);
				toggleAction.setSelected(!toggleAction.isSelected());
			}

			action.actionPerformed(context);

		}, waitForCompletion);

		if (!SwingUtilities.isEventDispatchThread()) {
			waitForSwing();
		}
	}

	/**
	 * Performs the specified action with context within the Swing Thread.  If the action results
	 * in a modal dialog, waitForCompletion must be false.
	 *
	 * @param action action to be performed
	 * @param provider the component provider from which to get action context; if null,
	 *        then an empty context will used
	 * @param wait if true wait for action to complete before returning,
	 * 		otherwise schedule action to be performed and return immediately.
	 */
	public static void performAction(DockingActionIf action, ComponentProvider provider,
			boolean wait) {

		ActionContext context = runSwing(() -> {
			ActionContext actionContext = new ActionContext();
			if (provider == null) {
				return actionContext;
			}

			ActionContext newContext = provider.getActionContext(null);
			if (newContext == null) {
				return actionContext;
			}

			actionContext = newContext;
			actionContext.setSourceObject(provider.getComponent());

			return actionContext;
		});

		doPerformAction(action, context, wait);
	}

	/**
	 * Performs the specified action with context within the Swing Thread.  If the action results
	 * in a modal dialog, waitForCompletion must be false.
	 *
	 * @param action action to be performed
	 * @param provider the component provider from which to get action context
	 * @param wait if true wait for action to complete before returning,
	 *        otherwise schedule action to be performed and return immediately.
	 */
	public static void performDialogAction(DockingActionIf action, DialogComponentProvider provider,
			boolean wait) {

		ActionContext context = runSwing(() -> {
			ActionContext actionContext = provider.getActionContext(null);
			if (actionContext != null) {
				actionContext.setSourceObject(provider.getComponent());
			}
			return actionContext;
		});

		doPerformAction(action, context, wait);
	}

	/**
	 * Performs the specified action with context within the Swing Thread.  If the action results
	 * in a modal dialog, waitForCompletion must be false.
	 *
	 * @param action action to be performed
	 * @param context the context to use with the action
	 * @param wait if true wait for action to complete before returning,
	 *        otherwise schedule action to be performed and return immediately.
	 */
	public static void performAction(DockingActionIf action, ActionContext context, boolean wait) {
		doPerformAction(action, context, wait);
	}

	/**
	 * Ensures the given toggle action is in the given selected state.  If it is not, then the
	 * action will be performed.  This call will wait for the action to finish.
	 *
	 * @param toggleAction the action
	 * @param context the context for the action
	 * @param selected true if the action is be be selected; false for not selected
	 */
	public static void setToggleActionSelected(ToggleDockingActionIf toggleAction,
			ActionContext context, boolean selected) {
		setToggleActionSelected(toggleAction, context, selected, true);
	}

	/**
	 * Ensures the given toggle action is in the given selected state.  If it is not, then the
	 * action will be performed.  This call will wait for the action to finish.
	 *
	 * @param toggleAction the action
	 * @param context the context for the action
	 * @param selected true if the action is be be selected; false for not selected
	 * @param wait true to wait for the action to finish; false to invoke later
	 */
	public static void setToggleActionSelected(ToggleDockingActionIf toggleAction,
			ActionContext context, boolean selected, boolean wait) {

		boolean shouldPerformAction = runSwing(() -> {
			return toggleAction.isSelected() != selected;
		});

		if (shouldPerformAction) {
			performAction(toggleAction, context, wait);
		}
	}

	/**
	 * Searches the component and subcomponents of the indicated provider and returns the
	 * component with the specified name.
	 *
	 * @param provider the provider of the component to search
	 * @param componentName the name of the desired component
	 *
	 * @return the component, or null if not found
	 */
	public static Component findComponentByName(DialogComponentProvider provider,
			String componentName) {
		return findComponentByName(provider.getComponent(), componentName, false);
	}

	public static JButton findButtonByText(DialogComponentProvider provider, String text) {
		return findButtonByText(provider.getComponent(), text);
	}

	public static JButton findButtonByIcon(DialogComponentProvider provider, Icon icon) {
		return findButtonByIcon(provider.getComponent(), icon);
	}

	public static JButton findButtonByActionName(Container container, String name) {
		Component[] comps = container.getComponents();
		for (Component element : comps) {
			if (element instanceof JButton) {

				JButton button = (JButton) element;
				if (button instanceof DialogToolbarButton) {
					DockingActionIf dockingAction =
						((DialogToolbarButton) button).getDockingAction();
					if (dockingAction.getName().equals(name)) {
						return button;
					}
				}
				Action action = button.getAction();
				if (action != null) {
					Object nameObject = action.getValue("name");
					if (nameObject != null && nameObject.toString().equals(name)) {
						return button;
					}
				}
			}
			else if (element instanceof Container) {
				JButton button = findButtonByActionName((Container) element, name);
				if (button != null) {
					return button;
				}
			}
		}
		return null;
	}

	/**
	 * Simulates a user typing a single key.
	 *
	 * This method should used for the special keyboard keys
	 * (ARROW, F1, END, etc) and alpha keys when associated with actions.
	 *
	 * @param c         the component that should be the receiver of the key event; the event source
	 * @param modifiers the modifier keys down during event (shift, ctrl, alt, meta)
	 *                  Either extended _DOWN_MASK or old _MASK modifiers
	 *                  should be used, but both models should not be mixed
	 *                  in one event. Use of the extended modifiers is
	 *                  preferred.
	 * @param keyCode   the integer code for an actual key.
	 */
	public static void triggerActionKey(Component c, int modifiers, int keyCode) {
		triggerKey(c, modifiers, keyCode, KeyEvent.CHAR_UNDEFINED);
	}

	/**
	 * Really unusual method to call non-public libraries to force the text components to
	 * focus on what we want and not what Java thinks the focus should be.
	 *
	 * @param tc the text component
	 */
	private static void forceTextComponentFocus(JTextComponent tc) {

		Object contextKey = getInstanceField("FOCUSED_COMPONENT", tc);
		AppContext context = AppContext.getAppContext();
		context.put(contextKey, tc);
	}

	/**
	 * Simulates a user initiated keystroke using the keybinding of the given action
	 * 
	 * @param destination the component for the action being executed
	 * @param action The action to simulate pressing
	 */
	public static void triggerActionKey(Component destination, DockingActionIf action) {

		Objects.requireNonNull(destination);

		KeyStroke keyStroke = action.getKeyBinding();
		if (keyStroke == null) {
			throw new IllegalArgumentException("No KeyStroke assigned for the given action");
		}

		int modifiers = keyStroke.getModifiers();
		int keyCode = keyStroke.getKeyCode();
		char keyChar = keyStroke.getKeyChar();
		boolean isDefined = Character.isDefined(keyChar);
		if (!isDefined) {
			keyChar = KeyEvent.VK_UNDEFINED;
		}

		triggerKey(destination, modifiers, keyCode, keyChar);
	}

	public static void triggerEscapeKey(Component c) {
		// text components will not perform built-in actions if they are not focused
		if (c instanceof JTextComponent) {
			triggerFocusGained(c);
		}
		triggerText(c, "\033");
	}

	public static void triggerBackspaceKey(Component c) {
		triggerText(c, "\010");
	}

	/** 
	 * Simulates the user pressing the 'Enter' key on the given text field 
	 * @param c the component
	 */
	public static void triggerEnter(Component c) {
		// text components will not perform built-in actions if they are not focused
		triggerFocusGained(c);
		triggerActionKey(c, 0, KeyEvent.VK_ENTER);
		waitForSwing();
	}

	/**
	 * Simulates a focus event on the given component
	 *
	 * @param component the component upon which to trigger focus
	 */
	private static void triggerFocusGained(Component component) {
		FocusListener[] listeners = component.getFocusListeners();
		FocusEvent e = new FocusEvent(component, (int) System.currentTimeMillis());
		runSwing(() -> {
			for (FocusListener l : listeners) {
				l.focusGained(e);
			}
		});
	}

	/**
	 * Types the indicated string using the
	 * {@link #triggerKey(Component, int, int, char)} method.
	 *
	 * This method should be used when typing into
	 * text components. For example, JTextFields and JTextAreas.
	 * All three events are fired, KEY_PRESSED, KEY_TYPED, and KEY_RELEASED.
	 *
	 * <br>Note: Handles the following characters:
	 * <br>
	 * <br>ABCDEFGHIJKLMNOPQRSTUVWXYZ
	 * <br>abcdefghijklmnopqrstuvwxyz
	 * <br>`1234567890-=[]\;',./
	 * <br>{@literal ~!@#$%^&*()_+{}|:"<>?}
	 * <br>
	 * <br>It also handles '\n', '\t', and '\b'.
	 *
	 * @param destination the component to receive the events
	 * @param string the string to be typed.
	 */
	public static void triggerText(Component destination, String string) {
		triggerText(destination, string, AbstractDockingTest::processEvent);
	}

	/**
	 * Types the indicated string using the
	 * {@link #triggerKey(Component, int, int, char)} method.
	 *
	 * This method should be used when typing into
	 * text components. For example, JTextFields and JTextAreas.
	 * All three events are fired, KEY_PRESSED, KEY_TYPED, and KEY_RELEASED.
	 *
	 * <br>Note: Handles the following characters:
	 * <br>
	 * <br>ABCDEFGHIJKLMNOPQRSTUVWXYZ
	 * <br>abcdefghijklmnopqrstuvwxyz
	 * <br>`1234567890-=[]\;',./
	 * <br>{@literal ~!@#$%^&*()_+{}|:"<>?}
	 * <br>
	 * <br>It also handles '\n', '\t', and '\b'.
	 *
	 * @param destination the component to receive the events
	 * @param string the string to be typed.
	 * @param consumer the consumer of the text to be generated
	 */
	public static void triggerText(Component destination, String string,
			BiConsumer<Component, KeyEvent> consumer) {

		for (int i = 0; i < string.length(); i++) {
			char c = string.charAt(i);
			int mods = 0;
			int keyCode = 0;

			if (Character.isLetter(c)) {
				if (Character.isUpperCase(c)) {
					mods = InputEvent.SHIFT_DOWN_MASK;
					keyCode = KeyEvent.VK_A + (c - 'A');
				}
				else {
					keyCode = KeyEvent.VK_A + (c - 'a');
				}
			}
			else if (Character.isDigit(c)) {
				keyCode = KeyEvent.VK_0 + (c - '0');
			}
			else {
				switch (c) {
					case '~':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = c;
						break;
					case '!':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_EXCLAMATION_MARK;
						break;
					case '@':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_AT;
						break;
					case '#':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_NUMBER_SIGN;
						break;
					case '$':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_DOLLAR;
						break;
					case '%':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_5;
						break;
					case '^':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_CIRCUMFLEX;
						break;
					case '&':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_AMPERSAND;
						break;
					case '*':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_ASTERISK;
						break;
					case '(':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_LEFT_PARENTHESIS;
						break;
					case ')':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_RIGHT_PARENTHESIS;
						break;
					case '_':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_UNDERSCORE;
						break;
					case '+':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_PLUS;
						break;
					case '{':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_BRACELEFT;
						break;
					case '}':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_BRACERIGHT;
						break;
					case '|':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_BACK_SLASH;
						break;
					case ':':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_SEMICOLON;
						break;
					case '"':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_QUOTEDBL;
						break;
					case '<':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_COMMA;
						break;
					case '>':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_PERIOD;
						break;
					case '?':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_SLASH;
						break;
					case '\'':
						mods = InputEvent.SHIFT_DOWN_MASK;
						keyCode = KeyEvent.VK_QUOTE;
						break;
					default:
						mods = 0;
						keyCode = c;
						break;
				}
			}

			triggerKey(destination, mods, keyCode, c, consumer);
		}
	}

	/**
	 * Fires a {@link KeyListener#keyPressed(KeyEvent)}, 
	 * {@link KeyListener#keyTyped(KeyEvent)}
	 * and {@link KeyListener#keyReleased(KeyEvent)} for the given key stroke
	 * 
	 * @param c the destination component
	 * @param ks the key stroke
	 */
	public static void triggerKey(Component c, KeyStroke ks) {
		int modifiers = ks.getModifiers();
		char keyChar = ks.getKeyChar();
		int keyCode = ks.getKeyCode();
		triggerKey(c, modifiers, keyCode, keyChar);
	}

	/**
	 * Fires a {@link KeyListener#keyPressed(KeyEvent)}, {@link KeyListener#keyTyped(KeyEvent)}
	 * and {@link KeyListener#keyReleased(KeyEvent)} for the given key code and char.
	 *
	 * <P>If the key you need is not a character, but is an action, pass
	 * {@link KeyEvent#CHAR_UNDEFINED} for the <CODE>keyChar</CODE> parameter.
	 *
	 * @param c the destination component
	 * @param modifiers any modifiers, like Control
	 * @param keyCode the key code (see {@link KeyEvent}'s VK_xyz values)
	 * @param keyChar the key char or {@link KeyEvent#CHAR_UNDEFINED}
	 */
	public static void triggerKey(Component c, int modifiers, int keyCode, char keyChar) {
		triggerKey(c, modifiers, keyCode, keyChar, AbstractDockingTest::processEvent);
	}

	public static void triggerKey(Component c, int modifiers, int keyCode, char keyChar,
			BiConsumer<Component, KeyEvent> consumer) {

		Objects.requireNonNull(c);
		Objects.requireNonNull(consumer);

		if (c instanceof JTextComponent) {
			JTextComponent tf = (JTextComponent) c;
			forceTextComponentFocus(tf);
		}

		KeyEvent pressedKE = new KeyEvent(c, KeyEvent.KEY_PRESSED, System.currentTimeMillis(),
			modifiers, keyCode, keyChar);
		consumer.accept(c, pressedKE);

		if (!pressedKE.isActionKey()) {
			// action keys are keys like the function (F1) keys

			char updatedKeyChar = (keyChar == KeyEvent.CHAR_UNDEFINED) ? (char) keyCode : keyChar;
			KeyEvent typedKE = new KeyEvent(c, KeyEvent.KEY_TYPED, System.currentTimeMillis(),
				modifiers, KeyEvent.VK_UNDEFINED, updatedKeyChar);
			consumer.accept(c, typedKE);
		}

		KeyEvent releasedKE = new KeyEvent(c, KeyEvent.KEY_RELEASED, System.currentTimeMillis(),
			modifiers, keyCode, keyChar);
		consumer.accept(c, releasedKE);
	}

	private static void processEvent(Component c, KeyEvent e) {

		runSwing(() -> {
			if (TestKeyEventDispatcher.dispatchKeyEvent(e)) {
				return; // already handled
			}

			dispatchKeyEventDirectlyToComponent(c, e);
		}, false);

		// don't wait above (so that we don't get deadlocks on modal dialogs)
		waitForSwing();
	}

	private static void dispatchKeyEventDirectlyToComponent(Component c, KeyEvent e) {
		// we have to call the method directly, but it is restricted, so use some magic
		invokeInstanceMethod("processEvent", c, new Class[] { AWTEvent.class }, new Object[] { e });
	}

	/**
	 * Gets any current text on the clipboard
	 *
	 * @return the text on the clipboard; null if no text is on the clipboard
	 * @throws Exception if there are any issues copying from the clipboard
	 */
	public String getClipboardText() throws Exception {
		Clipboard c = GClipboard.getSystemClipboard();
		Transferable t = c.getContents(null);

		try {
			String text = (String) t.getTransferData(DataFlavor.stringFlavor);
			return text;
		}
		catch (UnsupportedFlavorException e) {
			Msg.error(this, "Unsupported data flavor - 'string'.  Supported flavors: ");
			DataFlavor[] flavors = t.getTransferDataFlavors();
			for (DataFlavor dataFlavor : flavors) {
				Msg.error(this, "\t" + dataFlavor.getHumanPresentableName());
			}
			throw e;
		}
	}

	public static boolean isUseErrorGUI() {
		return useErrorGUI;
	}

	/**
	 * By default Ghidra will use a modal error dialog to display errors when running tests.  This
	 * method should be used to disable this feature, as opposed to calling:
	 * <pre>
	 *      Err.setErrorDisplay( new ConsoleErrorDisplay() );
	 * </pre>
	 * @param enable true to use the GUI; false to use the error console
	 */
	public static void setErrorGUIEnabled(boolean enable) {
		ErrorDisplay display = enable ? new DockingErrorDisplay() : new ConsoleErrorDisplay();

		// this wrapper will catch errors in non-test code and report them to the test framework
		ERROR_DISPLAY_WRAPPER.setErrorDisplayDelegate(display);
		Msg.setErrorDisplay(ERROR_DISPLAY_WRAPPER);
		useErrorGUI = enable;
	}

	/**
	 * Turns off the gui displays for errors.  This does not change the "isUseErrorGUI()" value for
	 * other tests in the TestCase.
	 */
	public static void disposeErrorGUI() {
		Msg.setErrorDisplay(new ConsoleErrorDisplay());
	}

	/**
	 * Shows the provider by the given name.
	 *
	 * @param tool the tool in which the provider lives
	 * @param name the name of the provider to show
	 * @return the newly shown provider
	 */
	public ComponentProvider showProvider(Tool tool, String name) {
		ComponentProvider provider = tool.getComponentProvider(name);
		tool.showComponentProvider(provider, true);
		return provider;
	}

	/**
	 * Closes the given provider.  You could just call
	 * {@link Tool#removeComponentProvider(ComponentProvider)}, but some providers have extra
	 * logic that happens when {@link ComponentProvider#closeComponent()} is called.   This will
	 * likely change in the future.
	 *
	 * @param p the provider to close
	 */
	public void closeProvider(ComponentProvider p) {
		runSwing(() -> p.closeComponent());
	}

	/**
	 * Performs a single left mouse click in the center of the given provider.  This is
	 * useful when trying to  make a provider the active provider, while making sure
	 * that one of the provider's components has focus.
	 *
	 * @param provider The provider to click
	 * @return the actual Java JComponent that was clicked.
	 * @see #clickComponentProvider(ComponentProvider, int, int, int, int, int, boolean)
	 */
	public static Component clickComponentProvider(ComponentProvider provider) {

		JComponent component = provider.getComponent();
		DockableComponent dockableComponent = getDockableComponent(component);
		selectTabIfAvailable(dockableComponent);
		Rectangle bounds = component.getBounds();
		int centerX = (bounds.x + bounds.width) >> 1;
		int centerY = (bounds.y + bounds.height) >> 1;

		return clickComponentProvider(provider, MouseEvent.BUTTON1, centerX, centerY, 1, 0, false);
	}

	/**
	 * If this dockable component is in a tabbed pane then select the associated tab.
	 * @param dockableComponent the dockable component of interest
	 */
	protected static void selectTabIfAvailable(final DockableComponent dockableComponent) {
		Container parent = (dockableComponent != null) ? dockableComponent.getParent() : null;
		if (parent instanceof JTabbedPane) {
			final JTabbedPane tabbedPane = (JTabbedPane) parent;
			runSwing(() -> tabbedPane.setSelectedComponent(dockableComponent), true);
		}
	}

	/**
	 * Get the dockable component that contains this component if there is one.
	 * @param component the component that may be within a dockable component.
	 * @return the dockable component or null
	 */
	protected static DockableComponent getDockableComponent(JComponent component) {
		Container parent = component.getParent();
		while (parent != null) {
			if (parent instanceof DockableComponent) {
				return (DockableComponent) parent;
			}
			parent = parent.getParent();
		}
		return null;
	}

	/**
	 * Clicks the JComponent at the given point from within the given provider.
	 *
	 * @param provider The provider to be clicked.
	 * @param button The mouse button to use (left, center, right)
	 * @param x the x location of the click
	 * @param y the y location of the click
	 * @param clickCount the number of times to click
	 * @param modifiers the modifiers to apply (Ctrl, Alt, etc; 0 is none)
	 * @param popupTrigger true if this click should show a popup menu
	 * @return the actual Java JComponent that was clicked
	 */
	public static Component clickComponentProvider(ComponentProvider provider, int button, int x,
			int y, int clickCount, int modifiers, boolean popupTrigger) {

		JComponent component = provider.getComponent();
		final Component clickComponent = SwingUtilities.getDeepestComponentAt(component, x, y);
		clickMouse(clickComponent, MouseEvent.BUTTON1, x, y, clickCount, modifiers, popupTrigger);
		return clickComponent;
	}

	/**
	 * Prints all found windows that are showing, nesting by parent-child relationship.
	 */
	public static void printOpenWindows() {
		Msg.debug(AbstractDockingTest.class, "Open windows: " + getOpenWindowsAsString());
	}

	/**
	 * Returns a pretty-print string of all found windows that are showing, nesting by
	 * parent-child relationship.
	 *
	 * @return the result string
	 */
	public static String getOpenWindowsAsString() {
		Set<Window> allFoundWindows = getAllWindows();

		//@formatter:off
		List<Window> roots = allFoundWindows
				.stream()
				.filter(w -> w.getParent() == null)
				.collect(Collectors.toList())
				;
		//@formatter:on

		StringBuilder buffy = new StringBuilder("\n");
		for (Window w : roots) {
			if (!isHierarchyShowing(w)) {
				continue;
			}
			windowToString(w, 0, buffy);
		}
		return buffy.toString();
	}

	private static boolean isHierarchyShowing(Window w) {

		if (w.isShowing()) {
			return true;
		}

		Window[] children = w.getOwnedWindows();
		for (Window child : children) {
			if (child.isShowing()) {
				return true;
			}
		}

		return false;
	}

	private static void windowToString(Window w, int depth, StringBuilder buffy) {

		String title = getDebugTitleForWindow(w);
		String prefix = StringUtils.repeat('\t', depth);
		String visibility = w.isShowing() ? "" : " (not showing)";
		String padded = prefix + title + visibility;
		buffy.append(padded).append('\n');

		Window[] children = w.getOwnedWindows();
		for (Window child : children) {
			windowToString(child, depth + 1, buffy);
		}
	}

	public static <T> void waitForTableModel(ThreadedTableModel<T, ?> model) {

		/*
		// Debug timing of waiting for tree
		long start = System.nanoTime();
		doWaitForTableModel(model);
		long end = System.nanoTime();
		Msg.out(
			"waitForTable() - " + TimeUnit.MILLISECONDS.convert(end - start, TimeUnit.NANOSECONDS));
		*/
		doWaitForTableModel(model);
	}

	private static <T> void doWaitForTableModel(ThreadedTableModel<T, ?> model) {

		// Always wait for Swing at least once.  There seems to be a race condition for 
		// incremental threaded models where the table is not busy at the time this method
		// is called, but there is an update pending via an invokeLater().
		waitForSwing();

		boolean didWait = false;
		int waitTime = 0;
		while (model.isBusy()) {
			didWait = true;
			waitTime += sleep(DEFAULT_WAIT_DELAY);

			// model loading may take longer than normal waits
			if (waitTime >= PRIVATE_LONG_WAIT_TIMEOUT) {
				Msg.error(AbstractDockingTest.class, createStackTraceForAllThreads()); // debug				
				String busyState = getBusyState(model);
				Msg.error(AbstractDockingTest.class, busyState);
				throw new AssertException(
					"Timed-out waiting for table model to load in " + waitTime + "ms");
			}
		}

		waitForSwing();

		if (didWait) {
			// try again (the idea is that we may have had a small window where the model was
			// not busy, but more work may be pushed on)
			waitForTableModel(model);
		}
	}

	private static String getBusyState(ThreadedTableModel<?, ?> model) {
		// ThreadedTableModelUpdateMgr<ROW_OBJECT>
		Object updateManager = getInstanceField("updateManager", model);
		SwingUpdateManager sum =
			(SwingUpdateManager) getInstanceField("addRemoveUpdater", updateManager);
		Worker worker = (Worker) getInstanceField("worker", model);
		String workerState = worker == null ? "<no worker>" : Boolean.toString(worker.isBusy());
		return "Table model busy state - Swing Update Manager? " + sum.isBusy() + "; worker?" +
			workerState;
	}

	public static GTreeNode getNode(GTree tree, String... path) {
		GTreeNode rootNode = tree.getModelRoot();
		String rootName = path[0];
		if (!rootNode.getName().equals(rootName)) {
			throw new RuntimeException(
				"When selecting paths by name the first path element must be the " +
					"name of the root node - path: " + StringUtils.join(path, '.'));
		}
		GTreeNode node = rootNode;
		for (int i = 1; i < path.length; i++) {
			GTreeNode child = node.getChild(path[i]);
			if (child == null) {
				throw new RuntimeException(
					"Can't find path " + StringUtils.join(path, '.') + "   failed at " + path[i]);
			}
			node = child;
		}
		return node;
	}

	public static void expandPath(GTree tree, String... path) {
		GTreeNode node = getNode(tree, path);
		tree.expandPath(node);
		waitForTree(tree);
	}

	public static void expandTree(GTree tree, String... path) {
		GTreeNode node = getNode(tree, path);
		tree.expandTree(node);
		waitForTree(tree);
	}

	public static void selectPath(GTree tree, String... path) {
		tree.setSelectedNodeByNamePath(path);
		waitForTree(tree);
	}

	public static void waitForTree(GTree gTree) {

		/*  // Debug timing of waiting for tree
			long start = System.nanoTime();
			doWaitForTree(gTree);
			long end = System.nanoTime();
			Msg.out(
				"waitForTree() - " + TimeUnit.MILLISECONDS.convert(end - start,
				TimeUnit.NANOSECONDS));
		*/
		doWaitForTree(gTree);
	}

	private static void doWaitForTree(GTree gTree) {

		waitForSwing();
		boolean didWait = false;
		int waitTime = 0;
		while (gTree.isBusy()) {
			didWait = true;
			waitTime += sleep(DEFAULT_WAIT_DELAY);

			if (waitTime >= DEFAULT_WAIT_TIMEOUT) {
				createStackTraceForAllThreads(); // this may help debug indecent table models
				throw new AssertException("Timed out waiting for table model to load");
			}
		}
		waitForSwing();

		if (didWait) {
			// The logic here is that if we ever had to wait for the tree, then some other events
			// may have been buffered while we were allowing the work to happen.  Just to be sure
			// that there are no buffered actions, lets try to wait again.  If things are really
			// settled down, then the extra call to wait should not have any effect.  This 'try
			// again' approach is an effort to catch update calls that can be schedule by actions
			// from the Swing thread, which the test thread does not handle flawlessly.
			waitForTree(gTree);
		}
	}

	public static boolean isEnabled(DockingActionIf action) {
		return runSwing(() -> action.isEnabledForContext(new ActionContext()));
	}

	public static boolean isEnabled(AbstractButton button) {
		return runSwing(() -> button.isEnabled());
	}

	public static boolean isSelected(AbstractButton button) {
		return runSwing(() -> button.isSelected());
	}

	/**
	 * Creates a generic action context with no provider, with the given context object
	 * @param contextObject the generic object to put in the context
	 * @return the new context
	 */
	public ActionContext createContext(Object contextObject) {
		return new ActionContext().setContextObject(contextObject);
	}

	/**
	 * Creates a generic action context with the given provider, with the given context object
	 * @param provider the provider
	 * @param contextObject the generic object to put in the context
	 * @return the new context
	 */
	public ActionContext createContext(ComponentProvider provider, Object contextObject) {
		return new ActionContext(provider).setContextObject(contextObject);
	}

//==================================================================================================
// Screen Capture
//==================================================================================================

	/**
	 * Creates and writes to file an image of the given component.  The file will be written
	 * to the reports directory (this differs depending upon how the test was run), nested
	 * inside a directory structure of the form {test class name}/{test name}.  A console
	 * statement will be written indicating the location of the written file.
	 *
	 * @param c the component to capture
	 * @param name the file name suffix
	 * @throws Exception if there is any issue capturing the component
	 */
	public void capture(Component c, String name) throws Exception {

		// old way of grabbing images--still need this if you want to capture a window's
		// decorations
		// Image image = createScreenImage(c);

		Image image = createRenderedImage(c);
		writeImage(image, name);
	}

	protected void writeImage(Image image, String name) throws IOException {
		File debugDir = getDebugFileDirectory();
		File testDir = new File(debugDir, getClass().getSimpleName());
		File dir = new File(testDir, testName.getMethodName());
		dir.mkdirs();

		writeImage(image, dir, name);
	}

	private void writeImage(Image image, File dir, String name) throws IOException {

		if (!FilenameUtils.isExtension(name, "png")) {
			name += ".png";
		}

		File imageFile = new File(dir, name);
		writeImage(image, imageFile);
	}

	/**
	 * Creates a png of the given component <b>by capturing a screenshot of the image</b>.  This
	 * differs from creating the image by rendering it via a {@link Graphics} object.
	 *
	 * @param c the component
	 * @return the new image
	 * @throws AWTException if there is a problem creating the image
	 */
	public static Image createScreenImage(Component c) throws AWTException {

		yieldToSwing();

		Rectangle r = c.getBounds();
		Point p = r.getLocation();
		if (!(c instanceof Window)) {
			SwingUtilities.convertPointToScreen(p, c.getParent());
		}
		r.setLocation(p);
		Robot robot = new Robot();
		sleep(100);
		Image image = robot.createScreenCapture(r);
		sleep(100);
		return image;
	}

	public static Image createRenderedImage(Component c) {

		yieldToSwing();

		Image i = runSwing(() -> {
			try {
				return doCreateRenderedImage(c);
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
		return i;
	}

	private static Image doCreateRenderedImage(Component c) {
		Rectangle r = c.getBounds();
		BufferedImage bufferedImage =
			new BufferedImage(r.width, r.height, BufferedImage.TYPE_INT_ARGB);
		Graphics graphics = bufferedImage.getGraphics();
		c.paint(graphics);
		graphics.dispose();
		return bufferedImage;
	}

	/**
	 * Writes the given image to the given file
	 *
	 * @param image the image
	 * @param imageFile the file
	 * @throws IOException if there is any issue writing the image
	 */
	public static void writeImage(Image image, File imageFile) throws IOException {
		ImageUtils.writeFile(image, imageFile);
		Msg.info(AbstractDockingTest.class, "Wrote image to " + imageFile.getCanonicalPath());
	}
}
