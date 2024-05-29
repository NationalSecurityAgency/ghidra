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
package ghidra.app.util.bin.format.dwarf;

import ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater;
import ghidra.app.plugin.core.analysis.DWARFAnalyzer;
import ghidra.app.services.Analyzer;
import ghidra.framework.options.Options;

/**
 * Import options exposed by the {@link DWARFAnalyzer}
 */
public class DWARFImportOptions {
	private static final String OPTION_IMPORT_DATATYPES = "Import Data Types";
	private static final String OPTION_IMPORT_DATATYPES_DESC =
		"Import data types defined in the DWARF debug info.";

	private static final String OPTION_IMPORT_FUNCS = "Import Functions";
	private static final String OPTION_IMPORT_FUNCS_DESC =
		"Import function information defined in the DWARF debug info\n" +
			"(implies 'Import Data Types' is selected).";

	private static final String OPTION_OUTPUT_SOURCE_INFO = "Output Source Info";
	private static final String OPTION_OUTPUT_SOURCE_INFO_DESC =
		"Include source code location info (filename:linenumber) in comments attached to the " +
			"Ghidra datatype or function or variable created.";

	private static final String OPTION_SOURCE_LINEINFO = "Output Source Line Info";
	private static final String OPTION_SOURCE_LINEINFO_DESC =
		"Place end-of-line comments containg the source code filename and line number at " +
			"each location provided in the DWARF data";

	private static final String OPTION_OUTPUT_DWARF_DIE_INFO = "Output DWARF DIE Info";
	private static final String OPTION_OUTPUT_DWARF_DIE_INFO_DESC =
		"Include DWARF DIE offset info in comments attached to the Ghidra datatype or function " +
			"or variable created.";

	private static final String OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS = "Add Lexical Block Comments";
	private static final String OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_DESC =
		"Add comments to the start of lexical blocks";

	private static final String OPTION_OUTPUT_INLINE_FUNC_COMMENTS =
		"Add Inlined Functions Comments";
	private static final String OPTION_OUTPUT_INLINE_FUNC_COMMENTS_DESC =
		"Add comments to the start of inlined functions";

	private static final String OPTION_OUTPUT_FUNC_SIGS = "Create Function Signatures";
	private static final String OPTION_OUTPUT_FUNC_SIGS_DESC =
		"Create function signature data types for each function encountered in the DWARF debug " +
			"data.";

	private static final String OPTION_TRY_PACK_STRUCTS = "Try To Pack Structs";
	private static final String OPTION_TRY_PACK_STRUCTS_DESC =
		"Try to pack structure/union data types.";

	private static final String OPTION_IMPORT_LOCAL_VARS = "Import Local Variable Info";
	private static final String OPTION_IMPORT_LOCAL_VARS_DESC =
		"Import local variable information from DWARF and attempt to create Ghidra local variables.";

	//==================================================================================================
	// Old Option Names - Should stick around for multiple major versions after 10.2
	//==================================================================================================

	private static final String OPTION_IMPORT_DATATYPES_OLD = "Import data types";
	private static final String OPTION_IMPORT_FUNCS_OLD = "Import functions";
	private static final String OPTION_OUTPUT_SOURCE_INFO_OLD = "Output Source info";
	private static final String OPTION_OUTPUT_DWARF_DIE_INFO_OLD = "Output DWARF DIE info";
	private static final String OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_OLD = "Lexical block comments";
	private static final String OPTION_OUTPUT_INLINE_FUNC_COMMENTS_OLD =
		"Inlined functions comments";
	private static final String OPTION_OUTPUT_FUNC_SIGS_OLD = "Output function signatures";

	//==================================================================================================
	// End Old Option Names
	//==================================================================================================	

	private AnalysisOptionsUpdater optionsUpdater = new AnalysisOptionsUpdater();

	private boolean outputDWARFLocationInfo = false;
	private boolean outputDWARFDIEInfo = false;
	private boolean elideTypedefsWithSameName = true;
	private boolean importDataTypes = true;
	private boolean importFuncs = true;
	private boolean outputInlineFuncComments = false;
	private boolean outputLexicalBlockComments = false;
	private boolean copyRenameAnonTypes = true;
	private boolean createFuncSignatures = true;
	private boolean organizeTypesBySourceFile = true;
	private boolean tryPackStructs = true;
	private boolean specialCaseSizedBaseTypes = true;
	private boolean importLocalVariables = true;
	private boolean useBookmarks = true;
	private boolean outputSourceLineInfo = false;

	/**
	 * Create new instance
	 */
	public DWARFImportOptions() {
		optionsUpdater.registerReplacement(OPTION_IMPORT_DATATYPES, OPTION_IMPORT_DATATYPES_OLD);
		optionsUpdater.registerReplacement(OPTION_IMPORT_FUNCS, OPTION_IMPORT_FUNCS_OLD);
		optionsUpdater.registerReplacement(OPTION_OUTPUT_SOURCE_INFO,
			OPTION_OUTPUT_SOURCE_INFO_OLD);
		optionsUpdater.registerReplacement(OPTION_OUTPUT_DWARF_DIE_INFO,
			OPTION_OUTPUT_DWARF_DIE_INFO_OLD);
		optionsUpdater.registerReplacement(OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS,
			OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_OLD);
		optionsUpdater.registerReplacement(OPTION_OUTPUT_INLINE_FUNC_COMMENTS,
			OPTION_OUTPUT_INLINE_FUNC_COMMENTS_OLD);
		optionsUpdater.registerReplacement(OPTION_OUTPUT_FUNC_SIGS, OPTION_OUTPUT_FUNC_SIGS_OLD);
	}

	/**
	 * See {@link Analyzer#getOptionsUpdater()}
	 * 
	 * @return {@link AnalysisOptionsUpdater}
	 */
	public AnalysisOptionsUpdater getOptionsUpdater() {
		return optionsUpdater;
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
	 * CategoryPath and giving that anonymousfunction.getEntryPoint() type a new name based on the structure's field's
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

	/**
	 * Option to enable packing on structures/unions created during the DWARF import.  If packing
	 * would change the structure's details, packing is left disabled.
	 * 
	 * @return boolean flag
	 */
	public boolean isTryPackStructs() {
		return tryPackStructs;
	}

	/**
	 * Option to enable packing on structures created during the DWARF import.  If packing
	 * would change the structure's details, packing is left disabled.
	 * 
	 * @param tryPackStructs boolean flag to set
	 */
	public void setTryPackDataTypes(boolean tryPackStructs) {
		this.tryPackStructs = tryPackStructs;
	}

	/**
	 * Option to recognize named base types that have an explicit size in the name (eg "int32_t)
	 * and use statically sized data types instead of compiler-dependent data types.
	 * 
	 * @return boolean true if option is turned on
	 */
	public boolean isSpecialCaseSizedBaseTypes() {
		return specialCaseSizedBaseTypes;
	}

	/**
	 * Option to recognize named base types that have an explicit size in the name (eg "int32_t)
	 * and use statically sized data types instead of compiler-dependent data types.
	 * 
	 * @param b true to turn option on, false to turn off
	 */
	public void setSpecialCaseSizedBaseTypes(boolean b) {
		this.specialCaseSizedBaseTypes = b;
	}

	public boolean isImportLocalVariables() {
		return importLocalVariables;
	}

	public void setImportLocalVariables(boolean importLocalVariables) {
		this.importLocalVariables = importLocalVariables;
	}

	public boolean isUseBookmarks() {
		return useBookmarks;
	}

	public boolean isOutputSourceLineInfo() {
		return outputSourceLineInfo;
	}

	public void setOutputSourceLineInfo(boolean outputSourceLineInfo) {
		this.outputSourceLineInfo = outputSourceLineInfo;
	}

	/**
	 * See {@link Analyzer#registerOptions(Options, ghidra.program.model.listing.Program)}
	 * 
	 * @param options {@link Options}
	 */
	public void registerOptions(Options options) {
		options.registerOption(OPTION_IMPORT_DATATYPES, isImportDataTypes(), null,
			OPTION_IMPORT_DATATYPES_DESC);

		options.registerOption(OPTION_IMPORT_FUNCS, isImportFuncs(), null,
			OPTION_IMPORT_FUNCS_DESC);

		options.registerOption(OPTION_OUTPUT_DWARF_DIE_INFO, isOutputDIEInfo(), null,
			OPTION_OUTPUT_DWARF_DIE_INFO_DESC);

		options.registerOption(OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS, isOutputLexicalBlockComments(),
			null, OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_DESC);

		options.registerOption(OPTION_OUTPUT_INLINE_FUNC_COMMENTS, isOutputInlineFuncComments(),
			null, OPTION_OUTPUT_INLINE_FUNC_COMMENTS_DESC);

		options.registerOption(OPTION_OUTPUT_SOURCE_INFO, isOutputSourceLocationInfo(), null,
			OPTION_OUTPUT_SOURCE_INFO_DESC);

		options.registerOption(OPTION_OUTPUT_FUNC_SIGS, isCreateFuncSignatures(), null,
			OPTION_OUTPUT_FUNC_SIGS_DESC);

		options.registerOption(OPTION_TRY_PACK_STRUCTS, isTryPackStructs(), null,
			OPTION_TRY_PACK_STRUCTS_DESC);

		options.registerOption(OPTION_IMPORT_LOCAL_VARS, isImportLocalVariables(), null,
			OPTION_IMPORT_LOCAL_VARS_DESC);

		options.registerOption(OPTION_SOURCE_LINEINFO, isOutputSourceLineInfo(), null,
			OPTION_SOURCE_LINEINFO_DESC);
	}

	/**
	 * See {@link Analyzer#optionsChanged(Options, ghidra.program.model.listing.Program)}
	 * 
	 * @param options {@link Options}
	 */
	public void optionsChanged(Options options) {
		setOutputDIEInfo(options.getBoolean(OPTION_OUTPUT_DWARF_DIE_INFO, isOutputDIEInfo()));
		setOutputSourceLocationInfo(
			options.getBoolean(OPTION_OUTPUT_SOURCE_INFO, isOutputSourceLocationInfo()));
		setOutputLexicalBlockComments(options.getBoolean(OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS,
			isOutputLexicalBlockComments()));
		setOutputInlineFuncComments(
			options.getBoolean(OPTION_OUTPUT_INLINE_FUNC_COMMENTS, isOutputInlineFuncComments()));
		setImportDataTypes(options.getBoolean(OPTION_IMPORT_DATATYPES, isImportDataTypes()));
		setImportFuncs(options.getBoolean(OPTION_IMPORT_FUNCS, isImportFuncs()));
		setCreateFuncSignatures(
			options.getBoolean(OPTION_OUTPUT_FUNC_SIGS, isCreateFuncSignatures()));
		setTryPackDataTypes(options.getBoolean(OPTION_TRY_PACK_STRUCTS, isTryPackStructs()));
		setImportLocalVariables(
			options.getBoolean(OPTION_IMPORT_LOCAL_VARS, isImportLocalVariables()));
		setOutputSourceLineInfo(
			options.getBoolean(OPTION_SOURCE_LINEINFO, isOutputSourceLineInfo()));

	}
}
