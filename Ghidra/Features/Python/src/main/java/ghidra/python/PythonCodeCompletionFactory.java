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
package ghidra.python;

import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.Toolkit;
import java.awt.font.TextAttribute;
import java.lang.reflect.Method;
import java.text.AttributedString;
import java.util.*;

import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.SwingUtilities;

import org.python.core.PyInstance;
import org.python.core.PyObject;

import docking.widgets.label.GDLabel;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.framework.options.Options;
import ghidra.util.Msg;

/**
 * Generates CodeCompletions from Python objects.
 * 
 * 
 *
 */
public class PythonCodeCompletionFactory {
	private static List<Class<?>> classes = new ArrayList<>();
	private static Map<Class<?>, Color> classToColorMap = new HashMap<>();
	/* necessary because we only want to show the user the simple class name
	 * Well, that, and the Options.DELIMITER is a '.' which totally messes
	 * things up.
	 */
	private static Map<String, Class<?>> simpleNameToClass = new HashMap<>();
	private static Map<Class<?>, String> classDescription = new HashMap<>();
	public static final String COMPLETION_LABEL = "Code Completion Colors";

	/* package-level accessibility so that PythonPlugin can tell this is
	 * our option
	 */
	final static String INCLUDE_TYPES_LABEL = "Include type names in code completion popup?";
	private final static String INCLUDE_TYPES_DESCRIPTION =
		"Whether or not to include the type names (classes) of the possible " +
			"completions in the code completion window.  The class name will be " +
			"parenthesized after the completion.";
	private final static boolean INCLUDE_TYPES_DEFAULT = true;
	private static boolean includeTypes = INCLUDE_TYPES_DEFAULT;

	public static final Color NULL_COLOR = new Color(255, 0, 0);
	public static final Color FUNCTION_COLOR = new Color(0, 128, 0);
	public static final Color PACKAGE_COLOR = new Color(128, 0, 0);
	public static final Color CLASS_COLOR = new Color(0, 0, 255);
	public static final Color METHOD_COLOR = new Color(0, 128, 128);
	/* anonymous code chunks */
	public static final Color CODE_COLOR = new Color(0, 64, 0);
	public static final Color INSTANCE_COLOR = new Color(128, 0, 128);
	public static final Color SEQUENCE_COLOR = new Color(128, 96, 64);
	public static final Color MAP_COLOR = new Color(64, 96, 128);
	public static final Color NUMBER_COLOR = new Color(64, 64, 64);
	/* for weird Jython-specific stuff */
	public static final Color SPECIAL_COLOR = new Color(64, 96, 64);

	static {
		/* Order matters!  This is the order in which classes are checked for
		 * coloring.
		 */
		setupClass("org.python.core.PyNone", NULL_COLOR, "'None' (null) Objects");

		setupClass("org.python.core.PyReflectedFunction", FUNCTION_COLOR,
			"Python functions written in Java");
		/* changed for Jython 2.5 */
//		setupClass("org.python.core.BuiltinFunctions", FUNCTION_COLOR,
//				"Python's built-in functions collection (note that many are " +
//				"re-implemented in Java)");
		setupClass("org.python.core.__builtin__", FUNCTION_COLOR,
			"Python's built-in functions collection (note that many are " +
				"re-implemented in Java)");
		setupClass("org.python.core.PyFunction", FUNCTION_COLOR, "functions written in Python");
		setupClass("org.python.core.PyMethodDescr", FUNCTION_COLOR,
			"unbound Python builtin instance methods (they take an " +
				"Object as the first argument)");

		setupClass("org.python.core.PyJavaPackage", PACKAGE_COLOR, "Java packages");
		setupClass("org.python.core.PyModule", PACKAGE_COLOR, "Python modules");

		/* Even though the latter is a subclass of the former, this allows
		 * the user to differentiate visually Java classes from Python classes
		 * if they so wish.  But we don't do this by default.  
		 */
		/* changed for Jython 2.5 */
//		setupClass("org.python.core.PyJavaClass", CLASS_COLOR,
//		"Java classes");
		setupClass("org.python.core.PyJavaType", CLASS_COLOR, "Java classes");
		setupClass("org.python.core.PyClass", CLASS_COLOR, "Python classes");
		setupClass("org.python.core.PyType", CLASS_COLOR, "core Python types");

		setupClass("org.python.core.PyMethod", METHOD_COLOR, "methods");
		setupClass("org.python.core.PyBuiltinFunction", METHOD_COLOR,
			"core Python methods, often inherited from Python's Object " +
				"(overriding these methods is very powerful)");

		setupClass("org.python.core.PySequence", SEQUENCE_COLOR,
			"iterable sequences, including arrays, list, and strings");

		setupClass("org.python.core.PyDictionary", MAP_COLOR, "arbitrary Python mapping type");
		setupClass("org.python.core.PyStringMap", MAP_COLOR, "Python String->Object mapping type");

		setupClass("org.python.core.PyInteger", NUMBER_COLOR, "integers");
		setupClass("org.python.core.PyLong", NUMBER_COLOR, "long integers");
		setupClass("org.python.core.PyFloat", NUMBER_COLOR, "floating-point (decimal) numbers");
		setupClass("org.python.core.PyComplex", NUMBER_COLOR, "complex numbers");

		setupClass("org.python.core.PyCompoundCallable", SPECIAL_COLOR,
			"special Python properties for " +
				"assigning Python functions as EventListeners on Java objects");

		/* changed for Jython 2.5 */
		setupClass("org.python.core.PyObjectDerived", INSTANCE_COLOR, "Java Objects");
		setupClass("org.python.core.PyInstance", INSTANCE_COLOR, "Python Objects");

		setupClass("org.python.core.PyCode", CODE_COLOR, "chunks of Python code");
	}

	/**
	 * Returns the actual class name for a Class.
	 * 
	 * @param klass a Class
	 * @return The actual class name.
	 */
	private static String getSimpleName(Class<?> klass) {
		return getSimpleName(klass.getName());
	}

	/**
	 * Returns the actual class name for a Class.
	 * 
	 * @param className name of a Class
	 * @return The actual class name.
	 */
	private static String getSimpleName(String className) {
		/* lastIndexOf returns -1 on not found, so this works whether or not
		 * a period is actually in className
		 */
		return className.substring(className.lastIndexOf('.') + 1);
	}

	/**
	 * Sets up a Class mapping.
	 * 
	 * @param className Class name
	 * @param defaultColor default Color for this Class
	 * @param description description of the Class
	 */
	private static void setupClass(String className, Color defaultColor, String description) {
		try {
			Class<?> klass = Class.forName(className);
			classes.add(klass);
			classToColorMap.put(klass, defaultColor);
			simpleNameToClass.put(getSimpleName(klass), klass);
			classDescription.put(klass, description);
		}
		catch (ClassNotFoundException cnfe) {
			Msg.debug(PythonCodeCompletionFactory.class, "Unable to find class: " + className,
				cnfe);
		}
	}

	/**
	 * Creates a new CodeCompletion from the given Python objects.
	 * 
	 * @param description description of the new CodeCompletion
	 * @param insertion what will be inserted to make the code complete
	 * @param pyObj a Python Object
	 * @return A new CodeCompletion from the given Python objects.
	 * @deprecated use {@link #newCodeCompletion(String, String, PyObject, String)} instead,
	 *             it allows creation of substituting code completions
	 */
	@Deprecated
	public static CodeCompletion newCodeCompletion(String description, String insertion,
			PyObject pyObj) {
		return newCodeCompletion(description, insertion, pyObj, "");
	}
	
	/**
	 * Creates a new CodeCompletion from the given Python objects.
	 * 
	 * @param description description of the new CodeCompletion
	 * @param insertion what will be inserted to make the code complete
	 * @param pyObj a Python Object
	 * @param userInput a word we want to complete, can be an empty string.
	 *        It's used to determine which part (if any) of the input should be 
	 *        removed before the insertion of the completion
	 * @return A new CodeCompletion from the given Python objects.
	 */
	public static CodeCompletion newCodeCompletion(String description, String insertion,
			PyObject pyObj, String userInput) {
		JComponent comp = null;
		int charsToRemove = userInput.length();

		if (pyObj != null) {
			if (includeTypes) {
				/* append the class name to the end of the description */
				String className = getSimpleName(pyObj.getClass());
				if (pyObj instanceof PyInstance) {
					/* get the real class */
					className = getSimpleName(((PyInstance) pyObj).instclass.__name__);
				}
				else if (className.startsWith("Py")) {
					/* strip off the "Py" */
					className = className.substring("Py".length());
				}
				description = description + " (" + className + ")";
			}

			int highlightStart = description.toLowerCase().indexOf(userInput.toLowerCase());
			int highlightEnd = highlightStart + userInput.length();
			comp = new CodeCompletionEntryLabel(description, highlightStart, highlightEnd);

			Iterator<Class<?>> iter = classes.iterator();
			while (iter.hasNext()) {
				Class<?> testClass = iter.next();
				if (testClass.isInstance(pyObj)) {
					comp.setForeground(classToColorMap.get(testClass));
					break;
				}
			}
		}

		return new CodeCompletion(description, insertion, comp, charsToRemove);
	}

	/**
	 * Sets up Python code completion Options.
	 * @param plugin python plugin as options owner
	 * @param options an Options handle
	 */
	public static void setupOptions(PythonPlugin plugin, Options options) {
		includeTypes = options.getBoolean(INCLUDE_TYPES_LABEL, INCLUDE_TYPES_DEFAULT);
		options.registerOption(INCLUDE_TYPES_LABEL, INCLUDE_TYPES_DEFAULT, null,
			INCLUDE_TYPES_DESCRIPTION);

		Iterator<?> iter = classes.iterator();
		while (iter.hasNext()) {
			Class<?> currentClass = (Class<?>) iter.next();
			options.registerOption(
				COMPLETION_LABEL + Options.DELIMITER + getSimpleName(currentClass),
				classToColorMap.get(currentClass), null,
				"Color to use for " + classDescription.get(currentClass) + ".");
			classToColorMap.put(currentClass,
				options.getColor(COMPLETION_LABEL + Options.DELIMITER + getSimpleName(currentClass),
					classToColorMap.get(currentClass)));
		}
	}

	/**
	 * Handle an Option change.
	 * 
	 * This is named slightly differently because it is a static method, not
	 * an instance method.
	 * 
	 * By the time we get here, we assume that the Option changed is indeed
	 * ours. 
	 * 
	 * @param options the Options handle
	 * @param name name of the Option changed
	 * @param oldValue the old value
	 * @param newValue the new value
	 */
	public static void changeOptions(Options options, String name, Object oldValue,
			Object newValue) {
		String classSimpleName = name.substring((COMPLETION_LABEL + Options.DELIMITER).length());
		Class<?> klass = simpleNameToClass.get(classSimpleName);

		if (classToColorMap.containsKey(klass)) {
			classToColorMap.put(klass, (Color) newValue);
		}
		else if (name.equals(INCLUDE_TYPES_LABEL)) {
			includeTypes = ((Boolean) newValue).booleanValue();
		}
		else {
			Msg.error(PythonCodeCompletionFactory.class, "unknown option '" + name + "'");
		}
	}

	/**
	 * Returns the Java __call__ methods declared for a Python object.
	 * 
	 * Some Python "methods" in the new-style Python objects are actually
	 * classes in and of themselves, re-implementing __call__ methods to
	 * tell us how to call them.  This returns an array of those Methods
	 * (for code completion help).
	 * 
	 * @param obj a PyObject
	 * @return the Java __call__ methods declared for the Python object
	 */
	public static Object[] getCallMethods(PyObject obj) {
		List<Method> callMethodList = new ArrayList<>();
		Method[] declaredMethods = obj.getClass().getDeclaredMethods();

		for (Method declaredMethod : declaredMethods) {
			if (declaredMethod.getName().equals("__call__")) {
				callMethodList.add(declaredMethod);
			}
		}

		return callMethodList.toArray();
	}

	/* The class represents a simple JLabel used as an entry in the CodeCompletion pop-up window.
	 * The main feature is the ability to highlight a certain area of the text in bold.
	 * (i.e. "some<b>Highlighted</b>Text"). Icons are not supported.
	 * 
	 * There are two reasons why we use it (and not simply JLabel with HTML):
	 * 1) Performance. Using JLabel with HTML appears to be too slow for our case when we might
	 * need to create 200+ labels in a reasonable time (faster than, say, 50 ms).
	 * 2) Text Visibility. Various Look and Feels may have different background and highlighting
	 * colors that may not look good enough with and match the text colors that we've selected
	 * for the entries. This class lets us choose more appropriate colors at runtime. 
	 */
	private static class CodeCompletionEntryLabel extends GDLabel {
		private Rectangle paintTextRect = new Rectangle();

		private int highlightStart;
		private int highlightEnd;

		public CodeCompletionEntryLabel(String description, int highlightStart, int highlightEnd) {
			super(description);

			int textLength = description.length();
			this.highlightStart = Math.max(0, Math.min(textLength, highlightStart));
			this.highlightEnd = Math.max(0, Math.min(textLength, highlightEnd));
		}

		/* Calculates the final (relative) position of the label and returns its visible text
		 * (after clipping, if any). This method is effectively a cleaned up copy of the private
		 * Swing method "javax.swing.plaf.basic.BasicLabelUI.layout" for the "Basic" look and feel.
		 */
		private String layoutLabel(FontMetrics fm) {
			Insets insets = this.getInsets(null);
			String text = this.getText();
			Icon icon = this.isEnabled() ? this.getIcon() : this.getDisabledIcon();
			Rectangle paintIconR = new Rectangle(0, 0, 0, 0);
			paintTextRect.x = paintTextRect.y = paintTextRect.width = paintTextRect.height = 0;

			int viewWidth = getWidth() - (insets.left + insets.right);
			int viewHeight = getHeight() - (insets.top + insets.bottom);
			Rectangle paintViewR = new Rectangle(insets.left, insets.top, viewWidth, viewHeight);

			return SwingUtilities.layoutCompoundLabel((JComponent) this, fm,
				text, icon, this.getVerticalAlignment(), this.getHorizontalAlignment(),
				this.getVerticalTextPosition(), this.getHorizontalTextPosition(),
				paintViewR, paintIconR, paintTextRect, this.getIconTextGap());
		}

		/* Returns the most appropriate text color (either black or white) for the background
		 * when the currently selected color is not distinct enough.
		 */
		private Color getMostVisibleTextColor(Color bgColor, Color currentTextColor) {
			float[] bgRgb = bgColor.getRGBColorComponents(null);
			float[] fgRgb = currentTextColor.getRGBColorComponents(null);

			double bgGrayscale = 0.299 * bgRgb[0] + 0.587 * bgRgb[1] + 0.114 * bgRgb[2];
			double fgGrayscale = 0.299 * fgRgb[0] + 0.587 * fgRgb[1] + 0.114 * fgRgb[2];

			// very simple method, but it seems enough; the constants are arbitrary
			Color newColor;
			if (Math.abs(bgGrayscale - fgGrayscale) < 0.42) {
				newColor = bgGrayscale > 0.73 ? Color.black : Color.white;
			}
			else {
				newColor = currentTextColor;
			}

			return newColor;
		}

		@Override
		protected void paintComponent(Graphics g) {
			Graphics2D g2d = (Graphics2D) g.create();

			// apply the standard text anti-aliasing settings for the system
			var desktopHints = (RenderingHints) Toolkit.getDefaultToolkit()
					.getDesktopProperty("awt.font.desktophints");
			if (desktopHints != null) {
				g2d.setRenderingHints(desktopHints);
			}

			// the background color depends on the current LookAndFeel and whether this completion
			// item is selected/highlighted in the CodeCompletion window
			Color bgColor = getBackground();
			g2d.setColor(bgColor);
			g2d.fillRect(0, 0, getWidth(), getHeight());

			Color potentialTextColor = getForeground();
			Color textColor = getMostVisibleTextColor(bgColor, potentialTextColor);
			g2d.setColor(textColor);

			FontMetrics fm = g2d.getFontMetrics();
			String clippedText = layoutLabel(fm);
			AttributedString text = new AttributedString(clippedText);
			if (highlightStart < highlightEnd) {
				Font boldFont = g2d.getFont().deriveFont(Font.BOLD);
				text.addAttribute(TextAttribute.FONT, boldFont, highlightStart, highlightEnd);
			}
			g2d.drawString(text.getIterator(), paintTextRect.x, paintTextRect.y + fm.getAscent());

			g2d.dispose();
		}
	}
}
