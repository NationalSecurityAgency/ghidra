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
package ghidra.app.util.pdb;

import java.util.*;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbDebugInfo;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;

/**
 * Sets up PDB base {@link CategoryPath} information for the PDB file and provides
 * {@link CategoryPath CategoryPaths} based on {@link SymbolPath SymbolPaths}, name lists, and
 * qualified namespace strings.  Also maintains the state of the active Module {@link CategoryPath}
 * while parsing a PDB and the count (state) of anonymous functions for their creation within
 * the particular PDB's {@link Category}.
 */
public class PdbCategories {

	private CategoryPath pdbRootCategory;
	private CategoryPath pdbUncategorizedCategory;
	private CategoryPath anonymousFunctionsCategory;
	private CategoryPath anonymousTypesCategory;
	private CategoryPath baseModuleTypedefsCategory;
	private List<CategoryPath> typedefCategories = new ArrayList<>();

//	private int anonymousFunctionCount;

	//==============================================================================================
	// NOTE: a TODO could be to add optional GUID and AGE values.  This could be as sub-categories
	// or combined with the file name.  This could be helpful when allowing multiple PDBs to be
	// loaded (at least their data types).
	/**
	 * Constructor
	 * @param pdbCategoryName pathname of the PDB file that this category represents.
	 * @param moduleNames module names
	 */
	public PdbCategories(String pdbCategoryName, List<String> moduleNames) {
		Objects.requireNonNull(pdbCategoryName, "pdbCategoryName cannot be null");

		pdbRootCategory = new CategoryPath(CategoryPath.ROOT, pdbCategoryName);

		pdbUncategorizedCategory = new CategoryPath(pdbRootCategory, "_UNCATEGORIZED_");

		setTypedefCategoryPaths(moduleNames);

		anonymousFunctionsCategory = new CategoryPath(pdbRootCategory, "!_anon_funcs_");
//		anonymousFunctionCount = 0;

		anonymousTypesCategory = new CategoryPath(pdbRootCategory, "!_anon_types_");
	}

	/**
	 * Get root CategoryPath for the PDB.
	 * @return the root CategoryPath.
	 */
	public CategoryPath getRootCategoryPath() {
		return pdbRootCategory;
	}

	/**
	 * Get uncategorized CategoryPath for the PDB.
	 * @return the uncategorized CategoryPath.
	 */
	public CategoryPath getUnCategorizedCategoryPath() {
		return pdbUncategorizedCategory;
	}

	private void setTypedefCategoryPaths(List<String> moduleNames) {
		baseModuleTypedefsCategory = new CategoryPath(pdbRootCategory, "!_module_typedefs_");
		// non-module typedefs go with all other global types, not in
		//  baseModuleTypedefsCategory.
		typedefCategories.add(pdbRootCategory);
		for (String name : moduleNames) {
			CategoryPath categoryPath = (name == null) ? baseModuleTypedefsCategory
					: new CategoryPath(baseModuleTypedefsCategory, name);
			typedefCategories.add(categoryPath);
		}
	}

//	/**
//	 * Get the name with any namespace stripped.
//	 * @param name Name with optional namespace prefix.
//	 * @return Name without namespace prefix.
//	 */
//	public String stripNamespace(String name) {
//		int index = name.lastIndexOf(Namespace.DELIMITER);
//		if (index <= 0) {
//			return name;
//		}
//		return name.substring(index + Namespace.DELIMITER.length());
//	}
//
//	/**
//	 * Get the name with any namespace stripped.
//	 * @param name Name with optional namespace prefix.
//	 * @return Name without namespace prefix.
//	 */
//	public String stripNamespaceBetter(String name) {
//		List<String> names = SymbolPathParser.parse(name);
//		return names.get(names.size() - 1);
//	}
//
	/**
	 * Get the {@link CategoryPath} associated with the {@link SymbolPath} specified, rooting
	 *  it either at the PDB Category.
	 * @param symbolPath Symbol path to be used to create the CategoryPath. Null represents global
	 *  namespace.
	 * @return {@link CategoryPath} created for the input.
	 */
	public CategoryPath getCategory(SymbolPath symbolPath) {

		CategoryPath category = pdbRootCategory;

		if (symbolPath == null) { // global namespace
			return category;
		}
		return recurseGetCategoryPath(category, symbolPath);
	}

	/**
	 * Returns the {@link CategoryPath} for a typedef with the give {@link SymbolPath} and
	 * module number; 1 <= moduleNumber <= {@link PdbDebugInfo#getNumModules()},
	 * except that modeleNumber of 0 represents publics/globals.
	 * @param moduleNumber module number
	 * @param symbolPath SymbolPath of the symbol
	 * @return the CategoryPath
	 */
	public CategoryPath getTypedefsCategory(int moduleNumber, SymbolPath symbolPath) {
		CategoryPath category = null;
		if (moduleNumber >= 0 && moduleNumber < typedefCategories.size()) {
			category = typedefCategories.get(moduleNumber);
		}
		if (category == null) {
			// non-module typedefs go with all other global types, not in
			//  baseModuleTypedefsCategory.
			category = pdbRootCategory;
		}

		if (symbolPath == null) { // global namespace
			return category;
		}

		return recurseGetCategoryPath(category, symbolPath);
	}

	/**
	 * Recursion method used by {@link #getCategory(SymbolPath)} and
	 *  {@link #getTypedefsCategory(int, SymbolPath)}. Returns a
	 * new {@link CategoryPath} for the
	 * @param category the {@ink CategoryPath} on which to build
	 * @param symbolPath the current {@link SymbolPath} from which the current name is pulled.
	 * @return the new {@link CategoryPath} for the recursion level
	 */
	private CategoryPath recurseGetCategoryPath(CategoryPath category, SymbolPath symbolPath) {
		SymbolPath parent = symbolPath.getParent();
		if (parent != null) {
			category = recurseGetCategoryPath(category, parent);
		}
		return new CategoryPath(category, symbolPath.getName());
	}

	/**
	 * Returns the {@link CategoryPath} for Anonymous Functions Category for the PDB.
	 * @return the {@link CategoryPath}
	 */
	public CategoryPath getAnonymousFunctionsCategory() {
		return anonymousFunctionsCategory;
	}

	/**
	 * Returns the {@link CategoryPath} for Anonymous Types Category for the PDB.
	 * @return the {@link CategoryPath}
	 */
	public CategoryPath getAnonymousTypesCategory() {
		return anonymousTypesCategory;
	}

//	/**
//	 * Returns the name of what should be the next Anonymous Function (based on the count of
//	 * the number of anonymous functions) so that there is a unique name for the function.
//	 * @return the name for the next anonymous function.
//	 */
//	public String getNextAnonymousFunctionName() {
//		return String.format("_func_%08X", anonymousFunctionCount);
//	}
//
//	/**
//	 * Updates the count of the anonymous functions.  This is a separate call from
//	 * {@link #getNextAnonymousFunctionName()} because the count should only be updated after
//	 * the previous anonymous function has been successfully created/stored.
//	 */
//	public void incrementNextAnonymousFunctionName() {
//		anonymousFunctionCount++;
//	}

}
