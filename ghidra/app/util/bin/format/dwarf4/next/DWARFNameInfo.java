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
package ghidra.app.util.bin.format.dwarf4.next;

import java.util.List;

import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolType;

/**
 * A immutable hierarchical path based name implementation that can be viewed as either
 * {@link Namespace namespaces} or {@link CategoryPath categorypaths}.
 * <p>
 */
public class DWARFNameInfo {

	private final DWARFNameInfo parent;
	private final CategoryPath organizationalCategoryPath;
	private final NamespacePath namespacePath;
	private final String originalName;

	public static DWARFNameInfo createRoot(CategoryPath rootCategory) {
		return new DWARFNameInfo(null, rootCategory, NamespacePath.ROOT, null);
	}

	public static DWARFNameInfo fromDataType(DataType dataType) {
		return new DWARFNameInfo(null, dataType.getCategoryPath(),
			NamespacePath.create(null, dataType.getName(), null), dataType.getName());
	}

	public static DWARFNameInfo fromList(DWARFNameInfo parent, List<String> names) {
		for (String s : names) {
			DWARFNameInfo tmp = new DWARFNameInfo(parent, s, s, SymbolType.NAMESPACE);
			parent = tmp;
		}
		return parent;
	}

	private DWARFNameInfo(DWARFNameInfo parent, CategoryPath organizationalCategoryPath,
			NamespacePath namespacePath, String originalName) {
		this.parent = parent;
		this.organizationalCategoryPath =
			(organizationalCategoryPath != null) ? organizationalCategoryPath : CategoryPath.ROOT;
		this.namespacePath = (namespacePath != null) ? namespacePath : NamespacePath.ROOT;
		this.originalName = originalName;
	}

	private DWARFNameInfo(DWARFNameInfo parent, String originalName, String name, SymbolType type) {
		this.parent = parent;
		this.organizationalCategoryPath = parent.getOrganizationalCategoryPath();
		this.namespacePath = NamespacePath.create(parent.getNamespacePath(), name, type);
		this.originalName = originalName;
	}

	public DWARFNameInfo getParent() {
		return parent;
	}

	public boolean isRoot() {
		return parent == null;
	}

	public CategoryPath getOrganizationalCategoryPath() {
		return organizationalCategoryPath;
	}

	public NamespacePath getNamespacePath() {
		return namespacePath;
	}

	public CategoryPath getParentCP() {
		return getParent().asCategoryPath();
	}

	public String getName() {
		return namespacePath.getName();
	}

	public DWARFNameInfo replaceName(String newName, String newOriginalName) {
		return new DWARFNameInfo(getParent(), newOriginalName, newName, getType());
	}

	public DWARFNameInfo replaceType(SymbolType newType) {
		return new DWARFNameInfo(parent, originalName, getName(), newType);
	}

	public SymbolType getType() {
		return namespacePath.getType();
	}

	/**
	 * Converts this object into an equiv {@link CategoryPath}.
	 *
	 * @return {@link CategoryPath}: "/organizational_cat_path/namespace1/namespace2/obj_name"
	 */
	public CategoryPath asCategoryPath() {
		return new CategoryPath(FSUtilities.appendPath(organizationalCategoryPath.getPath(),
			namespacePath.isRoot() ? null : namespacePath.asCategoryPathString()));
	}

	/**
	 * Converts this object into an equiv {@link DataTypePath}.
	 *
	 * @return {@link DataTypePath}: { "/organizational_cat_path/namespace1/namespace2", "obj_name" }
	 */
	public DataTypePath asDataTypePath() {
		return !isRoot() ? new DataTypePath(getParentCP(), getName()) : null;
	}

	public Namespace getParentNamespace(Program program) {
		return getParent().asNamespace(program);
	}

	/**
	 * Converts this object into an equiv Ghidra {@link Namespace}, omitting the organizational
	 * category path (which only applies to DataTypes).
	 *
	 * @param program {@link Program} where the namespace lives.
	 * @return {@link Namespace}: "ROOT::namespace1::namespace2::obj_name"
	 */
	public Namespace asNamespace(Program program) {
		return namespacePath.getNamespace(program);
	}

	@Override
	public String toString() {
		return organizationalCategoryPath.toString() + " || " + namespacePath.toString();
	}

	public boolean isAnon() {
		return originalName == null;
	}

	public String getOriginalName() {
		return originalName;
	}

	/**
	 * Returns true if this instance's {@link #getName() name} value is different
	 * than its {@link #getOriginalName() original} form.
	 * <p>
	 *
	 * @return
	 */
	public boolean isNameModified() {
		return originalName == null || !originalName.equals(namespacePath.getName());
	}

	public DWARFNameInfo createChild(String childOriginalName, String childName,
			SymbolType childType) {
		return new DWARFNameInfo(this, childOriginalName, childName, childType);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((namespacePath == null) ? 0 : namespacePath.hashCode());
		result = prime * result +
			((organizationalCategoryPath == null) ? 0 : organizationalCategoryPath.hashCode());
		result = prime * result + ((originalName == null) ? 0 : originalName.hashCode());
		result = prime * result + ((parent == null) ? 0 : parent.hashCode());
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
		if (!(obj instanceof DWARFNameInfo)) {
			return false;
		}
		DWARFNameInfo other = (DWARFNameInfo) obj;
		if (namespacePath == null) {
			if (other.namespacePath != null) {
				return false;
			}
		}
		else if (!namespacePath.equals(other.namespacePath)) {
			return false;
		}
		if (organizationalCategoryPath == null) {
			if (other.organizationalCategoryPath != null) {
				return false;
			}
		}
		else if (!organizationalCategoryPath.equals(other.organizationalCategoryPath)) {
			return false;
		}
		if (originalName == null) {
			if (other.originalName != null) {
				return false;
			}
		}
		else if (!originalName.equals(other.originalName)) {
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
}
