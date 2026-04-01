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

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.StringUtils;

/**
 * {@link NamingUtilities} is a static utility class with methods for validating project file 
 * names or constrained file path elements.
 */
public final class NamingUtilities {

	private final static char MANGLE_CHAR = '_';

	// Restricted character set for Ghidra related file paths.
	//
	// NOTE: When adding additional characters great care must be taken with Ghidra URI/URL encode/decode
	// to ensure that proper roundtrip for path, query and ref/fragment fields work as expected.
	// This is particularly a concern with the '+' character.

	public final static Set<Character> VALID_NAME_CHARSET =
		Collections.unmodifiableSet(
			Set.of('.', '-', '=', '@', ' ', '_', '(', ')', '[', ']'));

	private NamingUtilities() {
	}

	/**
	 * Tests whether the given string is a valid project name.
	 * <p>
	 * Rules:
	 * <ul>
	 * <li>Name may not be blank (i.e., no characters or all space characters)</li>
	 * <li>Name may not start with period</li>
	 * <li>All characters must be a letter, digit (0..9), or within the allowed character set:
	 *    '.', '-', '=', '@', ' ', '_', '(', ')', '[', ']' </li>
	 * </ul>
	 * 
	 * @param name name to validate
	 * @return true if specified name is valid, else false
	 */
	public static boolean isValidProjectName(String name) {
		try {
			checkProjectName(name);
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}

	/**
	 * Check the specified project name for character restrictions.
	 * 
	 * @param name project name
	 * @throws IllegalArgumentException if name restrictions are violated
	 */
	public static void checkProjectName(String name) throws IllegalArgumentException {
		checkName(name, "Project name");
	}

	/**
	 * Check the specified project or file path element name for character restrictions.
	 * The specified path element must exclude any path separators and must nut include any Windows
	 * drive specification (e.g., {@code C:}).  If this naming restriction needs to be imposed on
	 * an entire path, it must be invoked on each path element separately.
	 * <p>
	 * Restrictions include:
	 * <ul>
	 * <li>Path element may not be blank (i.e., no characters or all space characters).</li>
	 * <li>Path element may not start with a '.' which may result in path traversal or hidden 
	 *     file/folder use.</li>
	 * <li>Path element may only contain the letters, numbers, or the following characters:
	 *     '.', '-', '=', '@', ' ', '_', '(', ')', '[', ']'</li>
	 * </ul>
	 * 
	 * @param pathElement project or file path element (use of leading and trailing spaces should be 
	 * avoided but is not prohibited).
	 * @param elementType descriptive name for type of path element or null for default: "Path element"
	 * @throws IllegalArgumentException if name restrictions are violated
	 */
	public static void checkName(String pathElement, String elementType)
			throws IllegalArgumentException {

		String type = StringUtils.isBlank(elementType) ? "Path element" : elementType;

		if (StringUtils.isBlank(pathElement)) {
			throw new IllegalArgumentException("A blank " + type + " is not allowed");
		}
		if (pathElement.startsWith(".")) { // also prevents '.' and '..' path elements
			throw new IllegalArgumentException(type + " starting with '.' is not permitted");
		}
		String invalidChar = findInvalidChar(pathElement);
		if (invalidChar != null) {
			throw new IllegalArgumentException(
				type + " contains invalid character: '" + invalidChar + "'");
		}
	}

	/**
	 * Identify an invalid/unsupported character which may be present in the specific name.
	 * This method applies to project and individual path name elements only.
	 * 
	 * @param name string to be scanned
	 * @return an invalid/unsupported character found or null.  A string is used to allow for 
	 * rendering of non-ASCII characters.
	 */
	public static String findInvalidChar(String name) {
		AtomicReference<String> invalidChar = new AtomicReference<>();
		name.codePoints().forEach(cp -> {
			if (Character.isLetterOrDigit(cp)) {
				return;
			}
			// Allow only ASCII symbols from the whitelist
			if (cp <= 0x7F && VALID_NAME_CHARSET.contains((char) cp)) {
				return;
			}
			invalidChar.set(new String(Character.toChars(cp)));
		});
		return invalidChar.get();
	}

	/**
	 * Returns a string such that all uppercase characters in the given string are
	 * replaced by the MANGLE_CHAR followed by the lowercase version of the character.
	 * MANGLE_CHARs are replaced by 2 MANGLE_CHARs.
	 * <p>
	 * This method is to get around case-insensitive filesystems since Ghidra is case-sensitive.
	 * To fix this we mangle names first such that "Foo.exe" becomes "_foo.exe".
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
	 * 
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
