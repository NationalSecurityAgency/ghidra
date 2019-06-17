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
package ghidra.pdb.pdbreader;

/**
 * This class is used for creating dependency order of types, items, and symbols.
 *  Dependency order is not a PDB feature.  It is something we added (and might be removed
 *  in the future) as we have investigated how to analyze and apply the PDB.
 *  <P>
 * It is composed of a {@link CategoryIndex.Category} enum and an index under that enum.  The
 *  index is just a record number (as in the case of data type or item type; it is a made up,
 *  one-up number for symbols).
 */
public class CategoryIndex implements Comparable<CategoryIndex> {

	/**
	 * Enum for categories: DATA, ITEM, and SYMBOL.
	 */
	public enum Category {
		DATA, ITEM, SYMBOL
	}

	private Category category;
	private int index;

	/**
	 * Constructor.
	 * @param category {@link CategoryIndex.Category} to be assigned.
	 * @param index Index (record number) to be assigned.
	 */
	public CategoryIndex(Category category, int index) {
		this.category = category;
		this.index = index;
	}

	/**
	 * Returns the enum type {@link CategoryIndex.Category} (DATA, ITEM, or SYMBOL)
	 * @return {@link CategoryIndex.Category} enum.
	 */
	public Category getCategory() {
		return category;
	}

	/**
	 * Returns the index value.
	 * @return Index (record number).
	 */
	public int getIndex() {
		return index;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + index;
		result = prime * result + ((category == null) ? 0 : category.hashCode());
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
		CategoryIndex other = (CategoryIndex) obj;
		if (index != other.index) {
			return false;
		}
		if (category != other.category) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		String string = "";
		switch (category) {
			case DATA:
				string = "D:";
				break;
			case ITEM:
				string = "I:";
				break;
			case SYMBOL:
				string = "S:";
				break;
		}
		string += index;
		return string;
	}

	@Override
	public int compareTo(CategoryIndex other) {
		int catVal = this.category.compareTo(other.getCategory());
		return (catVal != 0) ? catVal : this.index - other.index;
	}
}
