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
import java.util.Objects;

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

	/**
	 * Create a root name entry that will serve as the parent for all children.
	 * 
	 * @param rootCategory {@link CategoryPath} in the data type manager that will contain
	 * any sub-categories that represent namespaces
	 * @return a new {@link DWARFNameInfo} instance
	 */
	public static DWARFNameInfo createRoot(CategoryPath rootCategory) {
		return new DWARFNameInfo(null, rootCategory, NamespacePath.ROOT, null);
	}

	/**
	 * Create a {@link DWARFNameInfo} instance using the specified {@link DataType}'s name.
	 * 
	 * @param dataType {@link DataType}
	 * @return new {@link DWARFNameInfo} using the same name / CategoryPath as the data type
	 */
	public static DWARFNameInfo fromDataType(DataType dataType) {
		return new DWARFNameInfo(null, dataType.getCategoryPath(),
			NamespacePath.create(null, dataType.getName(), null), dataType.getName());
	}

	/**
	 * Create a child {@link DWARFNameInfo} instance of the specified parent.
	 * <p>
	 * Example:<br>
	 * <pre>fromList(parent, List.of("name1", "name2")) &rarr; parent_name/name1/name2</pre>
	 *  
	 * @param parent {@link DWARFNameInfo} parent
	 * @param names list of names
	 * @return new {@link DWARFNameInfo} instance that is a child of the parent
	 */
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
			Objects.requireNonNullElse(organizationalCategoryPath, CategoryPath.ROOT);
		this.namespacePath = Objects.requireNonNullElse(namespacePath, NamespacePath.ROOT);
		this.originalName = originalName;
	}

	private DWARFNameInfo(DWARFNameInfo parent, String originalName, String name, SymbolType type) {
		this.parent = parent;
		this.organizationalCategoryPath = parent.getOrganizationalCategoryPath();
		this.namespacePath = NamespacePath.create(parent.getNamespacePath(), name, type);
		this.originalName = originalName;
	}

	/**
	 * Returns the parent name
	 * 
	 * @return parent
	 */
	public DWARFNameInfo getParent() {
		return parent;
	}

	/**
	 * Returns true if this instance has no parent and is considered the root.
	 * 
	 * @return boolean true if root name, false if not root
	 */
	public boolean isRoot() {
		return parent == null;
	}

	/**
	 * Returns the organizational category path.
	 * 
	 * @return organizational category path for dwarf names
	 */
	public CategoryPath getOrganizationalCategoryPath() {
		return organizationalCategoryPath;
	}

	/**
	 * Returns the NamespacePath of this instance.
	 * 
	 * @return {@link NamespacePath} of this instance
	 */
	public NamespacePath getNamespacePath() {
		return namespacePath;
	}

	/**
	 * Returns the parent's CategoryPath.
	 * 
	 * @return parent name's CategoryPath
	 */
	public CategoryPath getParentCP() {
		return getParent().asCategoryPath();
	}

	/**
	 * Returns the name of this entry.
	 * 
	 * @return string name of this entry, safe to use to name a Ghidra object (datatype, namespace,
	 * etc)
	 */
	public String getName() {
		return namespacePath.getName();
	}

	/**
	 * Creates a new DWARFNameInfo instance, using this instance as the template, replacing
	 * the name with a new name.
	 * 
	 * @param newName name for the new instance
	 * @param newOriginalName originalName for the new instance
	 * @return new instance with new name
	 */
	public DWARFNameInfo replaceName(String newName, String newOriginalName) {
		return new DWARFNameInfo(getParent(), newOriginalName, newName, getType());
	}

	/**
	 * Creates a new DWARFNameInfo instance, using this instance as the template, replacing
	 * the SymbolType with a new value.
	 * 
	 * @param newType new SymbolType value
	 * @return new instance with the specified SymbolType
	 */
	public DWARFNameInfo replaceType(SymbolType newType) {
		return new DWARFNameInfo(parent, originalName, getName(), newType);
	}

	/**
	 * Returns the SymbolType of this name.
	 * 
	 * @return {@link SymbolType} of this entry
	 */
	public SymbolType getType() {
		return namespacePath.getType();
	}

	/**
	 * Converts this object into an equiv {@link CategoryPath}.
	 *
	 * @return {@link CategoryPath}: "/organizational_cat_path/namespace1/namespace2/obj_name"
	 */
	public CategoryPath asCategoryPath() {
		List<String> nsParts = namespacePath.getParts();
		return nsParts.isEmpty()
				? organizationalCategoryPath
				: new CategoryPath(organizationalCategoryPath, nsParts);
	}

	/**
	 * Converts this object into an equiv {@link DataTypePath}.
	 *
	 * @return {@link DataTypePath}: { "/organizational_cat_path/namespace1/namespace2", "obj_name" }
	 */
	public DataTypePath asDataTypePath() {
		return !isRoot() ? new DataTypePath(getParentCP(), getName()) : null;
	}

	/**
	 * Returns the Ghidra {@link Namespace} that represents this entry's parent.
	 * 
	 * @param program the Ghidra program that contains the namespace
	 * @return {@link Namespace} representing this entry's parent
	 */
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

	/**
	 * Returns true if the original name of this entry was blank.
	 * 
	 * @return boolean true if there was no original name
	 */
	public boolean isAnon() {
		return originalName == null;
	}

	/**
	 * Returns the original name (unmodified by Ghidra-isms) of this entry.
	 * 
	 * @return original name
	 */
	public String getOriginalName() {
		return originalName;
	}

	/**
	 * Returns true if this instance's {@link #getName() name} value is different
	 * than its {@link #getOriginalName() original} form.
	 * <p>
	 *
	 * @return boolean true if the original name doesn't match the ghidra-ized name
	 */
	public boolean isNameModified() {
		return originalName == null || !originalName.equals(namespacePath.getName());
	}

	/**
	 * Creates a {@link DWARFNameInfo} instance, which has a name that is contained with
	 * this instance's namespace, using the specified name and symbol type.
	 * 
	 * @param childOriginalName the unmodified name
	 * @param childName the ghidra-ized name of the type/symbol/namespace/etc
	 * @param childType the type of the object being named
	 * @return new DWARFNameInfo instance
	 */
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
