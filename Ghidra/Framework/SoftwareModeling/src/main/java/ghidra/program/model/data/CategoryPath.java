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

	// parentPath can only be null for ROOT
	private final CategoryPath parentPath;
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
		// parentPath can only be null for ROOT
		parentPath = null;
		name = "";
	}

	/**
	 * Construct a CategoryPath from a parent and a hierarchical array of strings where each
	 * string is the name of a category in the category path.
	 *
	 * @param parentPathIn the parent CategoryPath.  Choose {@code ROOT} if needed.
	 * @param categoryPath the array of names of categories.
	 * @throws IllegalArgumentException if the given array is null or empty.
	 */
	public CategoryPath(CategoryPath parentPathIn, String... categoryPath) {
		this(parentPathIn, Arrays.asList(categoryPath));
	}

	/**
	 * Construct a CategoryPath from a parent and a hierarchical list of strings where each
	 * string is the name of a category in the category path.
	 *
	 * @param parentPathIn the parent CategoryPath.  Choose {@code ROOT} if needed.
	 * @param categoryList the hierarchical array of categories to place after parentPath.
	 * @throws IllegalArgumentException if the given list is null or empty.
	 */
	public CategoryPath(CategoryPath parentPathIn, List<String> categoryList) {
		Objects.requireNonNull(parentPathIn);
		if (categoryList == null || categoryList.isEmpty()) {
			throw new IllegalArgumentException(
				"Category list must contain at least one string name!");
		}
		name = categoryList.get(categoryList.size() - 1);
		if (categoryList.size() == 1) {
			parentPath = parentPathIn;
		}
		else {
			parentPath =
				new CategoryPath(parentPathIn, categoryList.subList(0, categoryList.size() - 1));
		}
	}

	/**
	 * Creates a category path given a forward-slash-delimited string (e.g., {@code "/aa/bb"}).
	 * If an individual component has one or more '/' characters in it, then it can be
	 * <I><B>escaped</B></I> using the {@link #escapeString(String)} utility method.  The
	 * {@link #unescapeString(String)} method can be used to unescape an individual component.
	 * <P>
	 * <B>Refrain</B> from using this constructor in production code, and instead use one of the
	 * other constructors that does not require escaping.  Situations where using this constructor
	 * is OK is in simple cases where a literal is passed in, such as in testing methods or in
	 * scripts.
	 * @param path category path string, delimited with '/' characters where individual components
	 * may have '/' characters escaped.
	 */
	public CategoryPath(String path) {
		if (path == null || path.length() == 0 || path.equals(DELIMITER_STRING)) {
			// parentPath can only be null for ROOT
			parentPath = null;
			name = "";
			return;
		}
		else if (path.charAt(0) != DELIMITER_CHAR) {
			throw new IllegalArgumentException("Paths must start with " + DELIMITER_STRING);
		}
		else if (path.charAt(path.length() - 1) == DELIMITER_CHAR &&
			path.lastIndexOf(ESCAPED_DELIMITER_STRING) != path.length() -
				ESCAPED_DELIMITER_STRING.length()) {
			throw new IllegalArgumentException("Paths must not end with " + DELIMITER_STRING);
		}
		else if (path.indexOf(ILLEGAL_STRING) >= 0) {
			throw new IllegalArgumentException("Paths must have non-empty elements");
		}
		else {
			int escapedIndex = path.length();
			int delimiterIndex = path.length();
			while (delimiterIndex > 0) {
				escapedIndex = path.lastIndexOf(ESCAPED_DELIMITER_STRING, escapedIndex - 1);
				delimiterIndex = path.lastIndexOf(DELIMITER_CHAR, delimiterIndex - 1);
				if (delimiterIndex != escapedIndex + DIFF) {
					break;
				}
			}
			this.parentPath = new CategoryPath(path.substring(0, delimiterIndex));
			this.name = unescapeString(path.substring(delimiterIndex + 1));
		}
	}

	/**
	 * Determine if this category path corresponds to the root category
	 * @return true if this is a root category path
	 */
	public boolean isRoot() {
		// parentPath can only be null for ROOT
		return parentPath == null;
	}

	/**
	 * Return the parent category path.
	 * @return the parent
	 */
	public CategoryPath getParent() {
		return parentPath;
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
		if (parentPath.isRoot()) {
			return DELIMITER_CHAR + escapeString(name);
		}
		return parentPath.getPath() + DELIMITER_CHAR + escapeString(name);
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
		if (parentPath == null) {
			if (other.parentPath != null) {
				return false;
			}
		}
		else if (!parentPath.equals(other.parentPath)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((parentPath == null) ? 0 : parentPath.hashCode());
		return result;
	}

	/**
	 * Tests if the specified categoryPath is the same as, or an ancestor of, this category path.
	 * @param categoryPath the category path to be checked.
	 * @return true if the given path is the same as, or an ancestor of, this category path.
	 */
	public boolean isAncestorOrSelf(CategoryPath categoryPath) {

		// Result categoryPath          This
		// ------ --------------------- ------------------------
		// True   /                     /
		// True   /                     /apple
		// False  /apple                /
		// True   /apple                /apple/sub
		// True   /apple                /apple
		// False  /app                  /apple
		// False  /pear                 /apple

		if (categoryPath.isRoot()) {
			return true;
		}

		CategoryPath path = this;
		while (!path.isRoot()) {
			if (categoryPath.equals(path)) {
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
		CategoryPath otherParentPath = other.getParent();
		int result = 0;
		if (parentPath == null) {
			if (otherParentPath != null) {
				return -1;
			}
		}
		else if (otherParentPath == null) {
			return 1;
		}
		else {
			result = parentPath.compareTo(otherParentPath);
		}
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
		List<String> list = new ArrayList<>();
		addToList(list);
		return list;
	}

	/**
	 * Returns a hierarchical array of names of the categories in the category path, starting with
	 * the name just below the {@code ROOT} category.
	 *
	 * @return a hierarchical array of names of the categories in the category path.
	 */
	public String[] asArray() {
		List<String> list = new ArrayList<>();
		addToList(list);
		return list.toArray(new String[list.size()]);
	}

	private void addToList(List<String> list) {
		if (!parentPath.isRoot()) {
			parentPath.addToList(list);
		}
		list.add(name);
	}

	/**
	 * This constructor is purposefully private and asserting.  We do not want anyone to implement
	 * this constructor, as it would confuse the notion of the constructor that takes a single
	 * {@link String} that has escaped delimiters vs. what this constructor would have to require,
	 * which is non-escaped {@link String Strings}.  There would be no way for the two Constructors
	 * to be distinguished from each other when passing a single argument.
	 *
	 * @param categoryPath varargs hierarchical list of names of categories.
	 */
	@SuppressWarnings("unused") // for categoryPath varargs
	private CategoryPath(String... categoryPath) {
		assert false;
		parentPath = null;
		name = "";
	}

}
