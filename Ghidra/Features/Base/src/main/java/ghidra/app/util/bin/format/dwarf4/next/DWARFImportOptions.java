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

import ghidra.app.plugin.core.analysis.DWARFAnalyzer;

/**
 * Import options exposed by the {@link DWARFAnalyzer}
 */
public class DWARFImportOptions {
	private static final int DEFAULT_IMPORT_LIMIT_DIE_COUNT = 2_000_000;
	private boolean outputDWARFLocationInfo = false;
	private boolean outputDWARFDIEInfo = false;
	private boolean elideTypedefsWithSameName = true;
	private boolean importDataTypes = true;
	private boolean importFuncs = true;
	private int importLimitDIECount = DEFAULT_IMPORT_LIMIT_DIE_COUNT;
	private int nameLengthCutoff = DWARFProgram.DEFAULT_NAME_LENGTH_CUTOFF;
	private boolean preloadAllDIEs = false;
	private boolean outputInlineFuncComments = false;
	private boolean outputLexicalBlockComments = false;
	private boolean copyRenameAnonTypes = true;
	private boolean createFuncSignatures = true;
	private boolean organizeTypesBySourceFile = true;

	public DWARFImportOptions() {
		// nada
	}

	/**
	 * Option to control tagging data types and functions with their source code
	 * location (ie. filename : line number ) if the information is present in the DWARF record.
	 *
	 * @return boolean true if the DWARF importer should tag items with their source code location
	 * info.
	 */
	public boolean isOutputSourceLocationInfo() {
		return outputDWARFLocationInfo;
	}

	/**
	 * Option to control tagging data types and functions with their source code
	 * location (ie. filename : line number ) if the information is present in the DWARF record.
	 *
	 * @param output_DWARF_location_info boolean to set
	 */
	public void setOutputSourceLocationInfo(boolean output_DWARF_location_info) {
		this.outputDWARFLocationInfo = output_DWARF_location_info;
	}

	/**
	 * Option to control tagging data types and functions with their DWARF DIE
	 * record number.
	 *
	 * @return boolean true if the DWARF importer should tag items with their DIE record
	 * number.
	 */
	public boolean isOutputDIEInfo() {
		return outputDWARFDIEInfo;
	}

	/**
	 * Option to control tagging data types and functions with their DWARF DIE
	 * record number.
	 *
	 * @param output_DWARF_die_info boolean to set
	 */
	public void setOutputDIEInfo(boolean output_DWARF_die_info) {
		this.outputDWARFDIEInfo = output_DWARF_die_info;
	}

	/**
	 * Option to control eliding typedef creation if the dest type has the same name.
	 *
	 * @return boolean true if the DWARF importer should skip creating a typedef if its
	 * dest has the same name.
	 */
	public boolean isElideTypedefsWithSameName() {
		return elideTypedefsWithSameName;
	}

	/**
	 * Option to control eliding typedef creation if the dest type has the same name.
	 *
	 * @param elide_typedefs_with_same_name boolean to set
	 */
	public void setElideTypedefsWithSameName(boolean elide_typedefs_with_same_name) {
		this.elideTypedefsWithSameName = elide_typedefs_with_same_name;
	}

	/**
	 * Option to turn on/off the import of data types.
	 *
	 * @return boolean true if import should import data types.
	 */
	public boolean isImportDataTypes() {
		return importDataTypes;
	}

	/**
	 * Option to turn on/off the import of data types.
	 *
	 * @param importDataTypes boolean to set
	 */
	public void setImportDataTypes(boolean importDataTypes) {
		this.importDataTypes = importDataTypes;
	}

	/**
	 * Option to turn on/off the import of funcs.
	 *
	 * @return boolean true if import should import funcs.
	 */
	public boolean isImportFuncs() {
		return importFuncs;
	}

	public void setImportFuncs(boolean output_Funcs) {
		this.importFuncs = output_Funcs;
	}

	/**
	 * Option to skip DWARF import if the DWARF record count is too large.
	 *
	 * @return integer count of the max number of DWARF records that will be attempted to import.
	 */
	public int getImportLimitDIECount() {
		return importLimitDIECount;
	}

	/**
	 * Option to skip DWARF import if the DWARF record count is too large.
	 *
	 * @param import_limit_die_count integer record count
	 */
	public void setImportLimitDIECount(int import_limit_die_count) {
		this.importLimitDIECount = import_limit_die_count;
	}

	/**
	 * Option to control how long DWARF symbol names are allowed to be before being truncated.
	 *
	 * @return integer max length of symbol names from DWARF.
	 */
	public int getNameLengthCutoff() {
		return nameLengthCutoff;
	}

	/**
	 * Option to control how long DWARF symbol names are allowed to be before being truncated.
	 *
	 * @param name_length_cutoff integer max length.
	 */
	public void setNameLengthCutoff(int name_length_cutoff) {
		this.nameLengthCutoff = name_length_cutoff;
	}

	/**
	 * Option to cause the DWARF parser to load all DWARF records into memory, instead of
	 * processing one compile unit at a time.  Needed to handle binaries created by some
	 * toolchains.  The import pre-check will warn the user if this needs to be turned on.
	 *
	 * @return boolean flag
	 */
	public boolean isPreloadAllDIEs() {
		return preloadAllDIEs;
	}

	/**
	 * Option to cause the DWARF parser to load all DWARF records into memory, instead of
	 * processing one compile unit at a time.  Needed to handle binaries created by some
	 * toolchains.  The import pre-check will warn the user if this needs to be turned on.
	 *
	 * @param b boolean flag to set
	 */
	public void setPreloadAllDIEs(boolean b) {
		this.preloadAllDIEs = b;
	}

	/**
	 * Option to control tagging inlined-functions with comments.
	 *
	 * @return boolean flag.
	 */
	public boolean isOutputInlineFuncComments() {
		return outputInlineFuncComments;
	}

	public void setOutputInlineFuncComments(boolean output_InlineFunc_comments) {
		this.outputInlineFuncComments = output_InlineFunc_comments;
	}

	/**
	 * Option to control tagging lexical blocks with Ghidra comments.
	 *
	 * @return boolean flag.
	 */
	public boolean isOutputLexicalBlockComments() {
		return outputLexicalBlockComments;
	}

	/**
	 * Option to control tagging lexical blocks with Ghidra comments.
	 *
	 * @param output_LexicalBlock_comments boolean flag to set.
	 */
	public void setOutputLexicalBlockComments(boolean output_LexicalBlock_comments) {
		this.outputLexicalBlockComments = output_LexicalBlock_comments;
	}

	/**
	 * Option to control a feature that copies anonymous types into a structure's "namespace"
	 * CategoryPath and giving that anonymous type a new name based on the structure's field's
	 * name.
	 *
	 * @return boolean flag.
	 */
	public boolean isCopyRenameAnonTypes() {
		return copyRenameAnonTypes;
	}

	/**
	 * Option to control a feature that copies anonymous types into a structure's "namespace"
	 * CategoryPath and giving that anonymous type a new name based on the structure's field's
	 * name.
	 *
	 * @param b boolean flag to set.
	 */
	public void setCopyRenameAnonTypes(boolean b) {
		this.copyRenameAnonTypes = b;
	}

	/**
	 * Option to control creating FunctionSignature datatypes for each function defintion
	 * found in the DWARF debug data.
	 *
	 * @return boolean flag.
	 */
	public boolean isCreateFuncSignatures() {
		return createFuncSignatures;
	}

	/**
	 * Option to control creating FunctionSignature datatypes for each function defintion
	 * found in the DWARF debug data.
	 *
	 * @param createFuncSignatures boolean flag to set.
	 */
	public void setCreateFuncSignatures(boolean createFuncSignatures) {
		this.createFuncSignatures = createFuncSignatures;
	}

	/**
	 * Option to organize imported datatypes into sub-folders based on their source file name.
	 *
	 * @return boolean flag
	 */
	public boolean isOrganizeTypesBySourceFile() {
		return organizeTypesBySourceFile;
	}

	/**
	 * Option to organize imported datatypes into sub-folders based on their source file name.
	 *
	 * @param organizeTypesBySourceFile boolean flag to set.
	 */
	public void setOrganizeTypesBySourceFile(boolean organizeTypesBySourceFile) {
		this.organizeTypesBySourceFile = organizeTypesBySourceFile;
	}
}
