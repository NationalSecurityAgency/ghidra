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
package ghidra.util;

import java.awt.Font;
import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Objects;
import java.util.StringTokenizer;
import java.util.function.Supplier;

import javax.swing.SwingUtilities;

import ghidra.util.exception.AssertException;
import utilities.util.reflection.ReflectionUtilities;

/**
 * General purpose class to provide convenience methods for doing "System" type
 * stuff, e.g., find resources, date/time, etc. All methods in this class are
 * static.
 */
public class SystemUtilities {

	private static String userName;

	/**
	 * System property that signals to override the font settings for Java and
	 * Ghidra components.
	 */
	public static final String FONT_SIZE_OVERRIDE_PROPERTY_NAME = "font.size.override";
	private static final Integer FONT_SIZE_OVERRIDE_VALUE =
		Integer.getInteger(SystemUtilities.FONT_SIZE_OVERRIDE_PROPERTY_NAME);

	/**
	 * The system property that can be checked during testing to determine if
	 * the system is running in test mode.
	 */
	public static final String TESTING_PROPERTY = "SystemUtilities.isTesting";

	/**
	 * The system property that can be checked during testing to determine if
	 * the system is running in batch, automated test mode.
	 */
	public static final String TESTING_BATCH_PROPERTY = "ghidra.test.property.batch.mode";

	/**
	 * The system property that can be checked during runtime to determine if we
	 * are running with a GUI or headless.
	 */
	public static final String HEADLESS_PROPERTY = "SystemUtilities.isHeadless";

	/**
	 * The system property that can be checked during runtime to determine if we
	 * are running in single-jar mode.
	 */
	public static final String SINGLE_JAR_MODE_PROPERTY = "SystemUtilities.isSingleJarMode";

	private static final boolean IS_IN_DEVELOPMENT_MODE = checkForDevelopmentMode();
	private static final boolean IS_IN_TESTING_BATCH_MODE =
		Boolean.TRUE.toString().equalsIgnoreCase(System.getProperty(TESTING_BATCH_PROPERTY));

	/**
	 * isInTestingMode - lazy load value - must allow time for runtime property to be set
	 * by GenericTestCase
	 */
	private static volatile Boolean isInTestingMode;

	private static boolean checkForDevelopmentMode() {
		Class<?> myClass = SystemUtilities.class;
		ClassLoader loader = myClass.getClassLoader();
		if (loader == null) {
			// Can happen when called from the Eclipse GhidraDev plugin 
			return false;
		}
		String name = myClass.getName().replace('.', '/') + ".class";
		String protocol = loader.getResource(name).getProtocol();
		switch(protocol) {
			case "file": // Source repository mode (class files)
				return true;
			case "jar": // Release mode (jar files)
			case "bundleresource": // Eclipse GhidraDev mode
				return false;
			default: // Unexpected protocol...assume a development mode
				return true;
		}
	}

	/**
	 * Get the user that is running the ghidra application
	 * @return the user name
	 */
	public static String getUserName() {
		if (userName == null) {
			String uname = System.getProperty("user.name");

			// remove the spaces since some operating systems allow
			// spaces and some do not, Java's File class doesn't
			if (uname.indexOf(" ") >= 0) {
				userName = "";
				StringTokenizer tokens = new StringTokenizer(uname, " ", false);
				while (tokens.hasMoreTokens()) {
					userName += tokens.nextToken();
				}
			}
			else {
				userName = uname;
			}
		}
		return userName;
	}

	/**
	 * Gets the boolean value of the  system property by the given name.  If the property is
	 * not set, the defaultValue is returned.   If the value is set, then it will be passed
	 * into {@link Boolean#parseBoolean(String)}.
	 *
	 * @param name the property name to check
	 * @param defaultValue the default value
	 * @return true if the property is set and has a value of 'true', ignoring case
	 */
	public static boolean getBooleanProperty(String name, boolean defaultValue) {

		String value = System.getProperty(name);
		if (value == null) {
			return defaultValue;
		}

		return Boolean.parseBoolean(value);
	}

	/**
	 * Returns a non-null value if the system property is set that triggers the
	 * font override setting, which makes all Java and Ghidra component fonts
	 * the same size.
	 *
	 * @return a non-null value if the system property is set that triggers the
	 *         font override setting, which makes all Java and Ghidra component
	 *         fonts the same size.
	 * @see #FONT_SIZE_OVERRIDE_PROPERTY_NAME
	 */
	public static Integer getFontSizeOverrideValue() {
		return FONT_SIZE_OVERRIDE_VALUE;
	}

	/**
	 * Checks to see if the font size override setting is enabled and adjusts
	 * the given font as necessary to match the override setting. If the setting
	 * is not enabled, then <code>font</code> is returned.
	 *
	 * @param font
	 *            The current font to adjust, if necessary.
	 * @return a font object with the proper size.
	 */
	public static Font adjustForFontSizeOverride(Font font) {
		if (FONT_SIZE_OVERRIDE_VALUE == null) {
			return font;
		}

		return font.deriveFont((float) FONT_SIZE_OVERRIDE_VALUE.intValue());
	}

	/**
	 * Returns true if the system is running during a test.
	 *
	 * @return true if the system is running during a test.
	 */
	public static boolean isInTestingMode() {
		if (isInTestingMode == null) {
			isInTestingMode =
				Boolean.TRUE.toString().equalsIgnoreCase(System.getProperty(TESTING_PROPERTY));
		}
		return isInTestingMode;
	}

	/**
	 * Returns true if the system is running during a batch, automated test.
	 *
	 * @return true if the system is running during a batch, automated test.
	 */
	public static boolean isInTestingBatchMode() {
		return IS_IN_TESTING_BATCH_MODE;
	}

	/**
	 * Returns true if the system is running without a GUI.
	 *
	 * @return true if the system is running without a GUI.
	 */
	public static boolean isInHeadlessMode() {
		String headlessProperty = System.getProperty(HEADLESS_PROPERTY, Boolean.TRUE.toString());
		return Boolean.parseBoolean(headlessProperty);
	}

	/**
	 * Calls the given suppler on the Swing thread, blocking with a
	 * {@link SwingUtilities#invokeAndWait(Runnable)}.  Use this method when you need to get
	 * a value while being on the Swing thread.
	 *
	 * <pre>{@literal
	 * 		String value = runSwingNow(() -> label.getText());
	 * }</pre>
	 *
	 * @param s the supplier that will be called on the Swing thread
	 * @return the result of the supplier
	 * @see #runSwingNow(Runnable)
	 */
	public static <T> T runSwingNow(Supplier<T> s) {
		return Swing.runNow(s);
	}

	/**
	 * Calls the given runnable on the Swing thread.
	 *
	 * @param r the runnable
	 * @see #runSwingNow(Supplier) if you need to return a value from the Swing thread.
	 */
	public static void runSwingNow(Runnable r) {
		Swing.runNow(r);
	}

	/**
	 * Calls the given runnable on the Swing thread in the future by putting the request on
	 * the back of the event queue.
	 *
	 * @param r the runnable
	 */
	public static void runSwingLater(Runnable r) {
		Swing.runLater(r);
	}

	public static void runIfSwingOrPostSwingLater(Runnable r) {
		Swing.runIfSwingOrRunLater(r);
	}

	/**
	 * Returns true if we are running in development mode. The assumption is
	 * that if this class is in a jar file, then we are in production mode.
	 *
	 * @return true if we are running in development mode
	 */
	public static boolean isInDevelopmentMode() {
		return IS_IN_DEVELOPMENT_MODE;
	}

	/**
	 * Returns true if the application is a release and not in development or testing
	 * @return true if the application is a release and not in development or testing
	 */
	public static boolean isInReleaseMode() {
		return !isInDevelopmentMode() && !isInTestingMode() && !isInTestingBatchMode();
	}

	/**
	 * Returns whether or not the two indicated objects are equal. It allows
	 * either or both of the specified objects to be null.
	 *
	 * @param o1 the first object or null
	 * @param o2 the second object or null
	 * @return true if the objects are equal.
	 */
	public static boolean isEqual(Object o1, Object o2) {
		return Objects.equals(o1, o2);
	}

	public static <T extends Comparable<T>> int compareTo(T c1, T c2) {
		if (c1 == null) {
			return c2 == null ? 0 : 1;
		}
		else if (c2 == null) {
			return -1;
		}
		return c1.compareTo(c2);
	}

	public static boolean isArrayEqual(Object[] array1, Object[] array2) {
		if (array1 == null) {
			return (array2 == null);
		}
		if (array2 == null) {
			return false;
		}
		if (array1.length != array2.length) {
			return false;
		}
		for (int i = 0; i < array1.length; i++) {
			if (!isEqual(array1[i], array2[i])) {
				return false;
			}
		}
		return true;
	}

	public static void assertTrue(boolean booleanValue, String string) {
		boolean isProductionMode = !isInTestingMode() && !isInDevelopmentMode();
		if (isProductionMode) {
			return; // squash during production mode
		}

		if (!booleanValue) {
			Exception e = new AssertException(string);
			Msg.error(SystemUtilities.class, "Assertion failed: " + string, e);
		}
	}

	/**
	 * A development/testing time method to make sure the current thread is the swing thread.
	 * @param errorMessage The message to display when the assert fails
	 */
	public static void assertThisIsTheSwingThread(String errorMessage) {
		boolean isProductionMode = !isInTestingMode() && !isInDevelopmentMode();
		if (isProductionMode) {
			return; // squash during production mode
		}

		if (!SwingUtilities.isEventDispatchThread()) {
			Throwable t =
				ReflectionUtilities.filterJavaThrowable(new AssertException(errorMessage));
			Msg.error(SystemUtilities.class, errorMessage, t);
		}
	}

	/**
	 * Returns a file that contains the given class. If the class is in a jar file, then 
	 * the jar file will be returned. If the file is in a .class file, then the directory 
	 * containing the package root will be returned (i.e. the "bin" directory).
	 * 
	 * @param classObject the class for which to get the location
	 * @return the containing location
	 */
	public static File getSourceLocationForClass(Class<?> classObject) {
		String name = classObject.getName().replace('.', '/') + ".class";
		URL url = classObject.getClassLoader().getResource(name);

		String urlFile = url.getFile();
		try {
			urlFile = URLDecoder.decode(urlFile, "UTF-8");
		}
		catch (UnsupportedEncodingException e) {
			// can't happen, since we know the encoding is correct
		}

		if ("file".equals(url.getProtocol())) {
			int packageLevel = getPackageLevel(classObject);
			File file = new File(urlFile);
			for (int i = 0; i < packageLevel + 1; i++) {
				file = file.getParentFile();
			}
			return file;
		}

		if ("jar".equals(url.getProtocol())) {
			// Running from Jar file
			String jarPath = urlFile;
			if (!jarPath.startsWith("file:")) {
				return null;
			}

			// strip off the 'file:' prefix and the jar path suffix after the
			// '!'
			jarPath = jarPath.substring(5, jarPath.indexOf('!'));
			return new File(jarPath);
		}

		return null;
	}

	private static int getPackageLevel(Class<?> classObject) {
		int dotCount = 0;
		Package package1 = classObject.getPackage();
		if (package1 == null) {
			return 0;
		}
		String packageName = package1.getName();
		for (int i = 0; i < packageName.length(); i++) {
			if (packageName.charAt(i) == '.') {
				dotCount++;
			}
		}
		return dotCount + 1;
	}

	/**
	 * Returns true if this is the event dispatch thread. Note that this method returns true in
	 * headless mode because any thread in headless mode can dispatch its own events. In swing
	 * environments, the swing thread is usually used to dispatch events.
	 *
	 * @return  true if this is the event dispatch thread -OR- is in headless mode.
	 */
	public static boolean isEventDispatchThread() {
		return Swing.isSwingThread();
	}

	/**
	 * A debugging utility that allows you to create a conditional breakpoint in Eclipse that
	 * will print items for you while it is performing its tests.  This method always returns
	 * false.  This means to use it you will have to OR (||) your conditional breakpoint
	 * expressions if you want them to pass.  Otherwise, you can make this method be the
	 * only breakpoint expression and it will never stop on the breakpoint, but will still
	 * print your debug.
	 * <p>
	 * This method is useful to print values of code that you cannot edit while debugging.
	 * <p>
	 * Example, inside of your conditional breakpoint for a method on a Sun Java file you
	 * can put something like: <code>printString("Value of first arg: " + arg0, System.err)</code>
	 * <p>
	 * Note: Don't remove this method simply because no code is referencing it, as it is used
	 * by conditional breakpoints.
	 *
	 * @param string The string to print
	 * @param printStream The stream to print to (System.our or err)
	 * @return The string passed in so that you can use this method in an evaluation
	 */
	public static boolean printString(String string, PrintStream printStream) {
		printStream.println(string);
		return false;
	}

	/**
	 * Returns the default size (in number of threads) for a <b>CPU processing bound</b>
	 * thread pool.
	 *
	 * @return the default pool size.
	 */
	public static int getDefaultThreadPoolSize() {

		Integer cpuOverride = getCPUOverride();
		if (cpuOverride != null) {
			return cpuOverride;
		}

		//
		// The basic choice of (available processors + 1) is based upon the book
		// Java: Concurrency in Practice.  This is for CPU-bound processing.  Further, the basic
		// idea is that there is enough overhead with context switching that you can add an
		// extra thread over the number of cores so that you can maximize usage while context
		// switching is taking place.
		//
		int numProcessors = Math.max(1, Runtime.getRuntime().availableProcessors() + 1);

		//
		// We enforce an upper bound here.  There is likely diminishing returns with
		// more threads, and if there are too many, other resource limits can be hit.
		//
		// Note: the user can still override this with the tool option *for GUI usage*.
		//       Users can set the system property cpu.core.override to specify an exact
		//       value to use for non-GUI usage.
		//
		if (numProcessors > 10) {
			// TODO: This bound is fairly arbitrary, probably could be made even lower
			numProcessors = 10;
		}

		// Note:  this serves only to limit the number of cores possible, not to increase
		Integer cpuCoreLimit = getCPUCoreLimit();
		if (cpuCoreLimit == null) {
			return numProcessors;
		}

		int parseInt = Math.max(1, cpuCoreLimit + 1);
		return Math.min(parseInt, numProcessors);
	}

	private static Integer getCPUOverride() {
		String cpuOverrideString = System.getProperty("cpu.core.override");
		if (cpuOverrideString == null || cpuOverrideString.trim().isEmpty()) {
			return null;
		}

		try {
			return Integer.parseInt(cpuOverrideString);
		}
		catch (NumberFormatException e) {
			Msg.debug(SystemUtilities.class,
				"Unable to parse cpu.core.override value: " + cpuOverrideString, e);
		}
		return null;
	}

	private static Integer getCPUCoreLimit() {
		String cpuLimitString = System.getProperty("cpu.core.limit");
		if (cpuLimitString == null || cpuLimitString.trim().isEmpty()) {
			return null;
		}

		try {
			return Integer.parseInt(cpuLimitString);
		}
		catch (Exception e) {
			Msg.debug(SystemUtilities.class,
				"Unable to parse cpu.core.limit value: " + cpuLimitString, e);
		}
		return null;
	}
}
