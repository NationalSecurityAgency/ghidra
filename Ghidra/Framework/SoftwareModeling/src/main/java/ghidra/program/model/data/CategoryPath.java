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

import java.util.StringTokenizer;

/**
 * A category path is the full path to a particular data type
 */
public class CategoryPath implements Comparable<CategoryPath> {

	public static final char DELIMITER_CHAR = '/';
	public static final String DELIMITER_STRING = "" + DELIMITER_CHAR;

	public static final CategoryPath ROOT = new CategoryPath(null);

	private static final String ILLEGAL_STRING = DELIMITER_STRING + DELIMITER_STRING;

	private final String parentPath;
	private final String name;

	/**
	 * Create a category path given a string.
	 *
	 * @param path category path string.
	 */
	public CategoryPath(String path) {
		if (path == null || path.length() == 0 || path.equals(DELIMITER_STRING)) {
			this.parentPath = this.name = "";
		}
		else if (path.charAt(0) != DELIMITER_CHAR) {
			throw new IllegalArgumentException("Paths must start with " + DELIMITER_STRING);
		}
		else if (path.charAt(path.length() - 1) == DELIMITER_CHAR) {
			throw new IllegalArgumentException("Paths must not end with " + DELIMITER_STRING);
		}
		else if (path.indexOf(ILLEGAL_STRING) >= 0) {
			throw new IllegalArgumentException("Paths must have non-empty elements");
		}
		else {
			int index = path.lastIndexOf(DELIMITER_CHAR);
			this.parentPath = path.substring(0, index);
			this.name = path.substring(index + 1);
		}
	}

	/**
	 * Create a category path given a parent category and name.
	 *
	 * @param parent parent category this path will reside in.
	 * @param name name of the category within the parent category.
	 */
	public CategoryPath(CategoryPath parent, String name) {
		if (name == null || name.length() == 0 || name.indexOf(DELIMITER_CHAR) >= 0) {
			throw new IllegalArgumentException("Bad name: " + name);
		}
		this.parentPath = parent.isRoot() ? "" : parent.getPath();
		this.name = name;
	}

	/**
	 * Determine if this category path corresponds to the root category
	 * @return true if this is a root category path
	 */
	public boolean isRoot() {
		return parentPath.length() == 0 && name.length() == 0;
	}

	/**
	 * Return the name of this category path
	 */
	public String getName() {
		return name;
	}

	/**
	 * Return the full path to the category including the category name as a string.
	 */
	public String getPath() {
		return parentPath + DELIMITER_CHAR + name;
	}

	/**
	 * Return the parent category path.
	 */
	public CategoryPath getParent() {
		if (parentPath.length() == 0 && name.length() == 0) {
			return null;
		}
		return new CategoryPath(parentPath);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CategoryPath) {
			CategoryPath cp = (CategoryPath) obj;
			return cp.parentPath.equals(parentPath) && cp.name.equals(name);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return parentPath.hashCode() + name.hashCode();
	}

	/**
	 * Tests if the specified categoryPath is the same as, or an ancestor of, this category path.
	 * @param categoryPath the category path to be checked.
	 * @return true if the given path is the same as, or an ancestor of, this category path.
	 */
	public boolean isAncestorOrSelf(CategoryPath categoryPath) {

		// Result categoryPath This
		// ------ --------------------- ------------------------
		// True   /                     /apple
		// False  /apple                /
		// True   /apple                /apple/sub
		// True   /apple                /apple
		// False  /app                  /apple
		// False  /pear                 /apple

		if (categoryPath.isRoot()) {
			return true;
		}

		if (isRoot()) {
			return false;
		}

		String otherCategory = categoryPath.getPath();
		String myCategory = getPath();
		if (!myCategory.startsWith(otherCategory)) {
			return false;
		}

		if (myCategory.length() == otherCategory.length()) {
			// categoryPath is the same as this 
			return true;
		}

		return myCategory.charAt(otherCategory.length()) == DELIMITER_CHAR;
	}

	public String[] getPathElements() {
		StringTokenizer tokenizer = new StringTokenizer(getPath(), DELIMITER_STRING);
		String[] tokens = new String[tokenizer.countTokens()];
		for (int i = 0; i < tokens.length; i++) {
			tokens[i] = tokenizer.nextToken();
		}
		return tokens;
	}

	/* (non-Javadoc)
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(CategoryPath otherPath) {
		return getPath().compareTo(otherPath.getPath());
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return getPath();
	}

}
