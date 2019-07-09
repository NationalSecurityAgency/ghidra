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
package ghidra.program.model.data;

import java.util.*;

import org.apache.commons.collections4.CollectionUtils;

/**
 * A category path is the full path to a particular data type
 */
public class CategoryPath implements Comparable<CategoryPath> {

	public static final char DELIMITER_CHAR = '/';
	public static final String DELIMITER_STRING = "" + DELIMITER_CHAR;
	public static final String ESCAPED_DELIMITER_STRING = "\\" + DELIMITER_STRING;

	public static final CategoryPath ROOT = new CategoryPath();

	private static final String ILLEGAL_STRING = DELIMITER_STRING + DELIMITER_STRING;
	private static final int DIFF = ESCAPED_DELIMITER_STRING.length() - DELIMITER_STRING.length();

	// parent can only be null for ROOT
	private final CategoryPath parent;
	private final String name;

	/**
	 * Converts a non-escaped String into an escaped string suitable for being passed in as a
	 * component of a single category path string to the constructor that takes a single
	 * escaped category path string.  The user is responsible for constructing the single
	 * category path string from the escaped components.
	 * @param nonEscapedString String that might need escaping for characters used for delimiting
	 * @return escaped String
	 * @see #unescapeString(String)
	 */
	public static String escapeString(String nonEscapedString) {
		return nonEscapedString.replace(DELIMITER_STRING, ESCAPED_DELIMITER_STRING);
	}

	/**
	 * Converts an escaped String suitable for being passed in as a component of a single category
	 * path string into an non-escaped string.  
	 * @param escapedString String that might need unescaping for characters used for delimiting
	 * @return non-escaped String
	 * @see #escapeString(String)
	 */
	public static String unescapeString(String escapedString) {
		return escapedString.replace(ESCAPED_DELIMITER_STRING, DELIMITER_STRING);
	}

	/**
	 * Constructor for internal creation of ROOT.
	 */
	private CategoryPath() {
		// parent can only be null for ROOT
		parent = null;
		name = "";
	}

	/**
	 * Construct a CategoryPath from a parent and a hierarchical array of strings where each
	 * string is the name of a category in the category path.
	 *
	 * @param parent the parent CategoryPath.  Choose {@code ROOT} if needed.
	 * @param subPathElements the array of names of sub-categories of the parent.
	 * @throws IllegalArgumentException if the given array is null or empty.
	 */
	public CategoryPath(CategoryPath parent, String... subPathElements) {
		this(parent, Arrays.asList(subPathElements));
	}

	/**
	 * Construct a CategoryPath from a parent and a hierarchical list of strings where each
	 * string is the name of a category in the category path.
	 *
	 * @param parent the parent CategoryPath.  Choose {@code ROOT} if needed.
	 * @param subPathElements the hierarchical array of sub-categories of the parent.
	 * @throws IllegalArgumentException if the given list is null or empty.
	 */
	public CategoryPath(CategoryPath parent, List<String> subPathElements) {
		Objects.requireNonNull(parent);
		if (CollectionUtils.isEmpty(subPathElements)) {
			throw new IllegalArgumentException(
				"Category list must contain at least one string name!");
		}
		name = subPathElements.get(subPathElements.size() - 1);
		if (subPathElements.size() == 1) {
			this.parent = parent;
		}
		else {
			this.parent =
				new CategoryPath(parent, subPathElements.subList(0, subPathElements.size() - 1));
		}
	}

	/**
	 * Creates a category path given a forward-slash-delimited string (e.g., {@code "/aa/bb"}).
	 * If an individual path component has one or more '/' characters in it, then it can be
	 * <I><B>escaped</B></I> using the {@link #escapeString(String)} utility method.  The
	 * {@link #unescapeString(String)} method can be used to unescape an individual component.
	 * <P>
	 * <B>Refrain</B> from using this constructor in production code, and instead use one of the
	 * other constructors that does not require escaping.  Situations where using this constructor
	 * is OK is in simple cases where a literal is passed in, such as in testing methods or in
	 * scripts.
	 * @param path category path string, delimited with '/' characters where individual components
	 * may have '/' characters escaped.  Must start with the '/' character.
	 */
	// NOTE: We purposefully did not create a constructor that takes varags only, as that
	// constructor, called with a single argument that would not be escaped, would conflict with
	// this constructor, which requires an escaped argument. 
	public CategoryPath(String path) {
		if (path == null || path.length() == 0 || path.equals(DELIMITER_STRING)) {
			// parent can only be null for ROOT
			parent = null;
			name = "";
			return;
		}
		else if (path.charAt(0) != DELIMITER_CHAR) {
			throw new IllegalArgumentException("Paths must start with " + DELIMITER_STRING);
		}
		else if (endsWithNonEscapedDelimiter(path)) {
			throw new IllegalArgumentException("Paths must not end with " + DELIMITER_STRING);
		}
		else if (path.indexOf(ILLEGAL_STRING) >= 0) {
			throw new IllegalArgumentException("Paths must have non-empty elements");
		}

		int delimiterIndex = findIndexOfLastNonEscapedDelimiter(path);
		this.parent = new CategoryPath(path.substring(0, delimiterIndex));
		this.name = unescapeString(path.substring(delimiterIndex + 1));
	}

	private boolean endsWithNonEscapedDelimiter(String string) {
		return (string.charAt(string.length() - 1) == DELIMITER_CHAR &&
			string.lastIndexOf(ESCAPED_DELIMITER_STRING) != string.length() -
				ESCAPED_DELIMITER_STRING.length());
	}

	private int findIndexOfLastNonEscapedDelimiter(String string) {
		int escapedIndex = string.length();
		int delimiterIndex = escapedIndex;
		while (delimiterIndex > 0) {
			escapedIndex = string.lastIndexOf(ESCAPED_DELIMITER_STRING, escapedIndex - 1);
			delimiterIndex = string.lastIndexOf(DELIMITER_CHAR, delimiterIndex - 1);
			if (delimiterIndex != escapedIndex + DIFF) {
				break;
			}
		}
		return delimiterIndex;
	}

	/**
	 * Determine if this category path corresponds to the root category
	 * @return true if this is a root category path
	 */
	public boolean isRoot() {
		// parent can only be null for ROOT
		return parent == null;
	}

	/**
	 * Return the parent category path.
	 * @return the parent
	 */
	public CategoryPath getParent() {
		return parent;
	}

	/**
	 * Return the terminating name of this category path.
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Return the {@link String} representation of this category path including the category name,
	 * where components are delimited with a forward slash.  Any component that contains a forward
	 * slash will be have the forward slash characters escaped.
	 * @return the full category path
	 */
	public String getPath() {
		if (isRoot()) {
			return DELIMITER_STRING;
		}
		if (parent.isRoot()) {
			return DELIMITER_CHAR + escapeString(name);
		}
		return parent.getPath() + DELIMITER_CHAR + escapeString(name);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		CategoryPath other = (CategoryPath) obj;
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		}
		else if (!name.equals(other.name)) {
			return false;
		}
		if (parent == null) {
			if (other.parent != null) {
				return false;
			}
		}
		else if (!parent.equals(other.parent)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((parent == null) ? 0 : parent.hashCode());
		return result;
	}

	/**
	 * Tests if the specified categoryPath is the same as, or an ancestor of, this category path.
	 * @param candidateAncestorPath the category path to be checked.
	 * @return true if the given path is the same as, or an ancestor of, this category path.
	 */
	public boolean isAncestorOrSelf(CategoryPath candidateAncestorPath) {

		// Result categoryPath          This
		// ------ --------------------- ------------------------
		// True   /                     /
		// True   /                     /apple
		// False  /apple                /
		// True   /apple                /apple/sub
		// True   /apple                /apple
		// False  /app                  /apple
		// False  /pear                 /apple

		if (candidateAncestorPath.isRoot()) {
			return true;
		}

		CategoryPath path = this;
		while (!path.isRoot()) {
			if (candidateAncestorPath.equals(path)) {
				return true;
			}
			path = path.getParent();
		}
		return false;
	}

	/**
	 * Returns array of names in category path.
	 * @return array of names
	 */
	public String[] getPathElements() {
		return asArray();
	}

	/* (non-Javadoc)
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(CategoryPath other) {
		if (isRoot() && other.isRoot()) {
			return 0;
		}

		if (isRoot() || other.isRoot()) {
			return isRoot() ? -1 : 1;
		}

		int result = parent.compareTo(other.getParent());

		if (result == 0) {
			result = name.compareTo(other.getName());
		}
		return result;
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return getPath();
	}

	/**
	 * Returns a hierarchical list of names of the categories in the category path, starting with
	 * the name just below the {@code ROOT} category.
	 *
	 * @return  a hierarchical list of names of the category in the category path.
	 */
	public List<String> asList() {
		if (isRoot()) {
			return new ArrayList<>();
		}
		List<String> list = parent.asList();
		list.add(name);
		return list;
	}

	/**
	 * Returns a hierarchical array of names of the categories in the category path, starting with
	 * the name just below the {@code ROOT} category.
	 *
	 * @return a hierarchical array of names of the categories in the category path.
	 */
	public String[] asArray() {
		List<String> list = asList();
		return list.toArray(new String[list.size()]);
	}

}
