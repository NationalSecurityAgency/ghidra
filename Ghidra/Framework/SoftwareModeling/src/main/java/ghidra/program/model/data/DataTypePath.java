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

/**
 * Object to hold a category path and a datatype name.  They are held separately so that
 * the datatype name can contain a categoryPath delimiter ("/") character.
 */
public class DataTypePath {
	private final CategoryPath categoryPath;
	private final String dataTypeName;

	/**
	 * Create DatatypePath
	 * @param categoryPath the category path for the datatype
	 * @param dataTypeName the name of the datatype.
	 * @throws IllegalArgumentException if an invalid category path or dataTypeName is given.
	 */
	public DataTypePath(String categoryPath, String dataTypeName) {
		this(new CategoryPath(categoryPath), dataTypeName);
	}

	/**
	 * Create DatatypePath
	 * @param categoryPath the category path for the datatype
	 * @param dataTypeName the name of the datatype.
	 * @throws IllegalArgumentException if a null category path or dataTypeName is given.
	 */
	public DataTypePath(CategoryPath categoryPath, String dataTypeName) {
		if (dataTypeName == null || categoryPath == null) {
			throw new IllegalArgumentException("null not allowed for categoryPath or datatypeName");
		}
		this.categoryPath = categoryPath;
		this.dataTypeName = dataTypeName;
	}

	/**
	 * Returns the categoryPath for the datatype represented by this datatype path.
	 * (ie. the CategoryPath that contains the DataType that this DataTypePath points to).
	 *
	 * @return the parent {@link CategoryPath} of the {@link DataType} that this DataTypePath
	 * points to.
	 */
	public CategoryPath getCategoryPath() {
		return categoryPath;
	}

	/**
	 * Determine if the specified otherCategoryPath is an ancestor of this data type
	 * path (i.e., does this data types category or any of its parent hierarchy correspond
	 * to the specified categoryPath).
	 * @param otherCategoryPath category path
	 * @return true if otherCategoryPath is an ancestor of this data type path, else false
	 */
	public boolean isAncestor(CategoryPath otherCategoryPath) {
		return categoryPath.isAncestorOrSelf(otherCategoryPath);
	}

	/**
	 * Returns the name of the datatype.
	 * @return the name
	 */
	public String getDataTypeName() {
		return dataTypeName;
	}

	/**
	 * Returns the full path of this datatype.  NOTE: if the datatype name contains any
	 * "/" characters, then the resulting path string may be ambiguous as to where the
	 * category path ends and the datatype name begins.
	 * @return the full path
	 */
	public String getPath() {
		StringBuffer buf = new StringBuffer(categoryPath.getPath());
		if (buf.charAt(buf.length() - 1) != CategoryPath.DELIMITER_CHAR) {
			buf.append(CategoryPath.DELIMITER_CHAR);
		}

		buf.append(dataTypeName);

		return buf.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + categoryPath.hashCode();
		result = prime * result + dataTypeName.hashCode();
		return result;
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
		DataTypePath other = (DataTypePath) obj;

		if (!categoryPath.equals(other.categoryPath)) {
			return false;
		}
		if (!dataTypeName.equals(other.dataTypeName)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return getPath();
	}

}
