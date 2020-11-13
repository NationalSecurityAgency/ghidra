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

import java.util.Set;

import ghidra.framework.store.local.LocalFileSystem;
import util.CollectionUtils;

/**
 * Utility class with static methods for validating project file names.
 */
public final class NamingUtilities {

	/**
	 * Max length for a name.
	 */
	public final static int MAX_NAME_LENGTH = 60;

	private final static char MANGLE_CHAR = '_';

	private final static Set<Character> VALID_NAME_SET = CollectionUtils.asSet('.', '-', ' ', '_');

	private NamingUtilities() {
	}

	/**
	 * Tests whether the given string is a valid.
	 * Rules:
	 * <ul>
	 * <li>All characters must be a letter, digit (0..9), period, hyphen, underscore or space</li>
	 * <li>May not exceed a length of 60 characters</li>
	 * </ul>
	 * @param name name to validate
	 * @return true if specified name is valid, else false
	 * @deprecated method has been deprecated due to improper and widespread use.  
	 * New methods include {@link NamingUtilities#isValidProjectName(String)} and 
	 * {@link LocalFileSystem#testValidName(String,boolean)}.
	 */
	@Deprecated
	public static boolean isValidName(String name) {

		if (name == null) {
			return false;
		}

		if ((name.length() < 1) || (name.length() > MAX_NAME_LENGTH)) {
			return false;
		}

		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (!Character.isLetterOrDigit(c) && !VALID_NAME_SET.contains(c)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Tests whether the given string is a valid project name.
	 * Rules:
	 * <ul>
	 * <li>Name may not start with period</li>
	 * <li>All characters must be a letter, digit (0..9), period, hyphen, underscore or space</li>
	 * <li>May not exceed a length of 60 characters</li>
	 * </ul>
	 * @param name name to validate
	 * @return true if specified name is valid, else false
	 */
	public static boolean isValidProjectName(String name) {
		if (name == null) {
			return false;
		}

		if (name.startsWith(".")) {
			return false;
		}

		if ((name.length() < 1) || (name.length() > MAX_NAME_LENGTH)) {
			return false;
		}

		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (!Character.isLetterOrDigit(c) && !VALID_NAME_SET.contains(c)) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Find the invalid character in the given name.
	 * <p>
	 * This method should only be used with {@link #isValidName(String)}} and <b>not</b>
	 * {@link #isValidProjectName(String)}
	 * 
	 * @param name the name with an invalid character
	 * @return the invalid character or 0 if no invalid character can be found
	 * @see #isValidName(String)
	 * @deprecated this method may be removed in a subsequent release due to 
	 * limited use and applicability (project names and project file names have
	 * different naming restrictions).
	 */
	@Deprecated
	public static char findInvalidChar(String name) {
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (!Character.isLetterOrDigit(c) && !VALID_NAME_SET.contains(c)) {
				return c;
			}
		}
		return (char) 0;
	}

	/**
	 * Returns a string such that all uppercase characters in the given string are
	 * replaced by the MANGLE_CHAR followed by the lowercase version of the character.
	 * MANGLE_CHARs are replaced by 2 MANGLE_CHARs.
	 *
	 * This method is to get around the STUPID windows problem where filenames are
	 * not case sensitive.  Under Windows, Foo.exe and foo.exe represent
	 * the same filename.  To fix this we mangle names first such that Foo.exe becomes
	 * _foo.exe.
	 * 
	 * @param name name string to be mangled
	 * @return mangled name
	 */
	public static String mangle(String name) {
		int len = name.length();
		StringBuffer buf = new StringBuffer(2 * len);

		for (int i = 0; i < len; i++) {
			char c = name.charAt(i);
			if (c == MANGLE_CHAR) {
				buf.append(MANGLE_CHAR);
				buf.append(MANGLE_CHAR);
			}
			else if (Character.isUpperCase(c)) {
				buf.append(MANGLE_CHAR);
				buf.append(Character.toLowerCase(c));
			}
			else {
				buf.append(c);
			}
		}
		return buf.toString();
	}

	/**
	 * Performs the inverse of the mangle method.  A string is returned such that
	 * all characters following a MANGLE_CHAR are converted to uppercase.  Two MANGLE
	 * chars in a row are replace by a single MANGLE_CHAR.
	 * 
	 * @param mangledName mangled name string
	 * @return demangle name
	 */
	public static String demangle(String mangledName) {
		int len = mangledName.length();
		StringBuffer buf = new StringBuffer(len);
		boolean foundMangle = false;

		for (int i = 0; i < len; i++) {
			char c = mangledName.charAt(i);
			if (foundMangle) {
				foundMangle = false;
				if (c == MANGLE_CHAR) {
					buf.append(c);
				}
				else {
					buf.append(Character.toUpperCase(c));
				}
			}
			else if (c == MANGLE_CHAR) {
				foundMangle = true;
			}
			else {
				buf.append(c);
			}
		}
		return buf.toString();
	}

	/**
	 * Performs a validity check on a mangled name
	 * @param name mangled name
	 * @return true if name can be demangled else false
	 */
	public static boolean isValidMangledName(String name) {
		int len = name.length();
		for (int i = 0; i < len; i++) {
			char c = name.charAt(i);
			if (Character.isUpperCase(c)) {
				return false;
			}
		}
		return true;
	}

}
