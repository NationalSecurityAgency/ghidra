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
package ghidra.feature.vt.api.util;

import java.lang.reflect.Field;
import java.util.*;

import docking.widgets.table.DisplayStringProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.AssertException;

/**
 * Generically, this represents the concept that the implementation of this class is an item
 * that can be turned into a String and restored from String form.  This is similar to 
 * Java's Bean serialization mechanism, which allows you to turn object to Strings and then 
 * back again.
 */
public abstract class Stringable implements ExtensionPoint, DisplayStringProvider {

//==================================================================================================
// Static Initialization
//==================================================================================================    

	private static Map<String, Class<? extends Stringable>> shortNameToClassnameMap;

	private static void initializeNameMap() {
		shortNameToClassnameMap = new HashMap<String, Class<? extends Stringable>>();
		List<Class<? extends Stringable>> classes = ClassSearcher.getClasses(Stringable.class);
		for (Class<? extends Stringable> clazz : classes) {
			String name = getShortNameFieldValue(clazz);
			shortNameToClassnameMap.put(name, clazz);
		}
	}

	private static String getShortNameFieldValue(Class<? extends Stringable> clazz) {
		Field field;
		try {
			field = clazz.getField("SHORT_NAME");
			if (field == null) {
				throw new AssertException("Found a Stringable that did not define a " +
					"public static field named \"SHORT_NAME\"");
			}

			String name = (String) field.get(null);
			if (name == null) {
				throw new AssertException("Error reading Stringable SHORT_NAME field for class: ");
			}
			return name;
		}
		catch (SecurityException e) {
			throw new AssertException(
				"Error reading Stringable SHORT_NAME field for class: " + clazz, e);
		}
		catch (NoSuchFieldException e) {
			throw new AssertException(
				"Error reading Stringable SHORT_NAME field for class: " + clazz, e);
		}
		catch (IllegalArgumentException e) {
			throw new AssertException(
				"Error reading Stringable SHORT_NAME field for class: " + clazz, e);
		}
		catch (IllegalAccessException e) {
			throw new AssertException(
				"Error reading Stringable SHORT_NAME field for class: " + clazz, e);
		}
	}

	private static Map<String, Class<? extends Stringable>> getNameMap() {
		if (shortNameToClassnameMap == null) {
			initializeNameMap();
		}
		return shortNameToClassnameMap;
	}

//==================================================================================================
// End Initialization
//==================================================================================================    

	public static final String DELIMITER = "\t";
	public static final String DOUBLE_DELIMITER = "\n";

	private final String shortName;

	protected Stringable(String shortName) {
		this.shortName = shortName;
		getNameMap().put(shortName, getClass());
	}

	/**
	 * getDisplayString() returns a display string for this stringable.<br>
	 * Note: It must not return a null. Instead it should return an empty string if it has no value.
	 */
	@Override
	public abstract String getDisplayString();

	protected abstract String doConvertToString(Program program);

	protected abstract void doRestoreFromString(String string, Program program);

	public static String getString(Stringable stringable, Program program) {
		if (stringable == null) {
			return null;
		}
		return stringable.shortName + DELIMITER + stringable.doConvertToString(program);
	}

	public static Stringable getStringable(String valueString, Program program) {
		if (valueString == null) {
			return null;
		}
		int delimiterIndex = valueString.indexOf(DELIMITER);
		String shortName = valueString.substring(0, delimiterIndex);
		Stringable newInstance = createStringable(shortName);
		int contentOffset = delimiterIndex + DELIMITER.length();
		newInstance.doRestoreFromString(valueString.substring(contentOffset), program);
		return newInstance;
	}

	private static Stringable createStringable(String name) {
		Class<? extends Stringable> clazz = getNameMap().get(name);
		try {
			return clazz.newInstance();
		}
		catch (Exception e) {
			// handled later by null
		}
		return null;
	}

	@Override
	public abstract boolean equals(Object other);

	@Override
	public abstract int hashCode();

	@Override
	public String toString() {
		return getDisplayString();
	}

	/**
	 * Encodes a comment string that may contain tabs, carriage returns, and linefeeds so that it 
	 * can be saved as part of a Stringable. Tabs, carriage returns, and linefeeds are typically 
	 * used as delimiters for separating tokens within the Stringable.
	 * @param unencodedComment the actual comment text containing tabs, etc.
	 * @return the encoded comment to be saved as part of the stringable.
	 */
	protected static String encodeString(String unencodedComment) {
		StringBuffer buffer = new StringBuffer();
		int startIndex = 0;
		int length = unencodedComment.length();
		int i = 0;
		for (; i < length; i++) {
			char charAt = unencodedComment.charAt(i);
			switch (charAt) {
				case '\t':
					startIndex = saveSubStringAndEscapedCharacter(unencodedComment, buffer,
						startIndex, i, 't');
					break;
				case '\r':
					startIndex = saveSubStringAndEscapedCharacter(unencodedComment, buffer,
						startIndex, i, 'r');
					break;
				case '\n':
					startIndex = saveSubStringAndEscapedCharacter(unencodedComment, buffer,
						startIndex, i, 'n');
					break;
				case '\f':
					startIndex = saveSubStringAndEscapedCharacter(unencodedComment, buffer,
						startIndex, i, 'f');
					break;
				default:
					break;
			}
		}
		if (i > startIndex) {
			buffer.append(unencodedComment.substring(startIndex, i));
		}
		return buffer.toString();
	}

	private static int saveSubStringAndEscapedCharacter(String comment, StringBuffer buffer,
			int startIndex, int endIndex, char escapedChar) {
		buffer.append(comment.substring(startIndex, endIndex));
		buffer.append('\\');
		buffer.append(escapedChar);
		startIndex = endIndex + 1;
		return startIndex;
	}

	/**
	 * Decodes a encoded comment string that may contain encoded tabs, carriage returns, and 
	 * linefeeds back to its original form where tabs, carriage returns, and linefeeds were 
	 * not intended as delimiters for separating tokens within a Stringable.
	 * @param encodedComment the encoded comment that was saved as part of the stringable.
	 * @return the actual unencoded comment text containing tabs, etc.
	 */
	protected static String decodeString(String encodedComment) {
		if (encodedComment == null) {
			return null;
		}
		StringBuffer buffer = new StringBuffer();
		int startIndex = 0;
		int index = encodedComment.indexOf('\\', startIndex);
		while (index != -1) {
			buffer.append(encodedComment.substring(startIndex, index));
			char charAt = encodedComment.charAt(++index);
			switch (charAt) {
				case 't':
					buffer.append('\t');
					break;
				case 'r':
					buffer.append('\r');
					break;
				case 'n':
					buffer.append('\n');
					break;
				case 'f':
					buffer.append('\f');
					break;
				default:
					// TODO What should we do here? Got an unexpected escaped character.
					buffer.append('\\' + charAt);
					break;
			}
			startIndex = ++index;
			index = encodedComment.indexOf('\\', startIndex);
		}
		if (startIndex < encodedComment.length()) {
			buffer.append(encodedComment.substring(startIndex));
		}
		return buffer.toString();
	}
}
