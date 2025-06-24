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
package ghidra.program.model.gclass;

import java.util.Objects;

import ghidra.app.util.SymbolPath;
import ghidra.program.model.data.CategoryPath;

/**
 * Unique ID of a Program Class Type.  Not sure if there will be different implementation for
 *  definition vs. compiled vs. program vs. debug.
 */
public class ClassID implements Comparable<ClassID> {
	// All of the internals of this might change, but we need something to work with for now.
	//  It might end up being a hash/guid/long value.
	// We were trying to use DataTypePath, but that doesn't work in light of conflicts, as we
	//  started with a DataTypePath for the type, which later got resolved to a .conflict (so
	//  DataTypePath changed out from underneath us).
	private final SymbolPath symbolPath;
	private final CategoryPath categoryPath;
	static final int classNameHash = Objects.hash(ClassID.class.getName());

	/**
	 * Constructor
	 * @param categoryPath the category path for the claass
	 * @param symbolPath the symbol path for the class
	 */
	public ClassID(CategoryPath categoryPath, SymbolPath symbolPath) {
		this.categoryPath = categoryPath;
		this.symbolPath = symbolPath;
	}

	/**
	 * Returns the category path
	 * @return the category path
	 */
	public CategoryPath getCategoryPath() {
		return categoryPath;
	}

	/**
	 * Returns the symbol path
	 * @return the symbol path
	 */
	public SymbolPath getSymbolPath() {
		return symbolPath;
	}

	// Might want to do something with data type ID if resolved
//	long doIt(DataTypeManager dtm, DataType dt) {
//		int x = DataTypeUtilities.getConflictValue(dt);
//		long dataTypeID;
//		dataTypeID = dtm.getID(dt);
//		UniversalID uid = dt.getUniversalID();
//		return dataTypeID;
//	}

	@Override
	public String toString() {
		return String.format("%s --- %s", categoryPath, symbolPath);
	}

	@Override
	public int compareTo(ClassID o) {
		int ret;
		ret = symbolPath.compareTo(o.symbolPath);
		if (ret != 0) {
			return ret;
		}
		return categoryPath.compareTo(o.categoryPath);
	}

	@Override
	public int hashCode() {
		return Objects.hash(categoryPath, symbolPath);
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
		ClassID other = (ClassID) obj;
		return Objects.equals(categoryPath, other.categoryPath) &&
			Objects.equals(symbolPath, other.symbolPath);
	}

}
