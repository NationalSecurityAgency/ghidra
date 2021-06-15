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
package ghidra.app.util;

/**
 * Topics for Help. The strings correspond to a folder under the "topics"
 * resource.
 * 
 */
public interface HelpTopics {

	/**
	 * Help Topic for "About."
	 */
	public final static String ABOUT = GenericHelpTopics.ABOUT;

	/**
	 * Help Topic for auto analysis.
	 */
	public final static String AUTO_ANALYSIS = "AutoAnalysisPlugin";

	/**
	 * Help Topic for block models.
	 */
	public final static String BLOCK_MODEL = "BlockModel";

	/**
	 * Help Topic for bookmarks.
	 */
	public final static String BOOKMARKS = "BookmarkPlugin";

	/**
	 * Help Topic for the byte viewer.
	 */
	public final static String BYTE_VIEWER = "ByteViewerPlugin";

	/**
	 * Help Topic for the code browser.
	 */
	public final static String CODE_BROWSER = "CodeBrowserPlugin";

	/**
	 * Help Topic for comments.
	 */
	public final static String COMMENTS = "CommentsPlugin";

	/**
	 * Help Topic for data.
	 */
	public final static String DATA = "DataPlugin";
	/**
	 * Help Topic for the data manager.
	 */
	public final static String DATA_MANAGER = "DataManagerPlugin";

	/**
	 * Help Topic for the data type editors.
	 */
	public final static String DATA_TYPE_EDITORS = "DataTypeEditors";

	/**
	 * Help Topic for the decompiler
	 */
	public final static String DECOMPILER = "DecompilePlugin";

	/**
	 * Help Topic for doing diffs between programs.
	 */
	public final static String DIFF = "Diff";

	/**
	 * Help Topic for equates.
	 */
	public final static String EQUATES = "EquatePlugin";

	/**
	 * Help Topic for the exporters.
	 */
	public final static String EXPORTER = "ExporterPlugin";

	/**
	 * Help Topic for references searching
	 */
	public final static String FIND_REFERENCES = "LocationReferencesPlugin";

	/**
	 * Name of options for the help topic for the front end (Ghidra
	 * Project Window).
	 */
	public final static String FRONT_END = GenericHelpTopics.FRONT_END;

	/**
	 * Help Topic for the glossary.
	 */
	public final static String GLOSSARY = GenericHelpTopics.GLOSSARY;

	/**
	 * Help Topic for highlighting.
	 */
	public final static String HIGHLIGHT = "SetHighlightPlugin";

	/**
	 * Help Topic for the importers.
	 */
	public final static String IMPORTER = "ImporterPlugin";

	/**
	 * Help for Intro topics.
	 */
	public final static String INTRO = GenericHelpTopics.INTRO;
	/**
	 * Help Topic for the add/edit label.
	 */
	public final static String LABEL = "LabelMgrPlugin";

	/**
	 * Help Topic for navigation.
	 */
	public final static String NAVIGATION = "Navigation";
	/**
	 * Help Topic for the memory map.
	 */
	public final static String MEMORY_MAP = "MemoryMapPlugin";

	/**
	 * Help Topic for the P2 to XML exporter.
	 */
	public final static String PE2XML = "PE2XMLPlugin";

	/**
	 * Help Topic for programs (open, close, save, etc.).
	 */
	public final static String PROGRAM = "ProgramManagerPlugin";

	/**
	 * Help Topic for the program tree.
	 */
	public final static String PROGRAM_TREE = "ProgramTreePlugin";

	/**
	 * Help Topic for references.
	 */
	public final static String REFERENCES = "ReferencesPlugin";

	/**
	 * Help Topic for the relocation table.
	 */
	public final static String RELOCATION_TABLE = "RelocationTablePlugin";

	/**
	 * Help Topic for the project repository.
	 */
	public final static String REPOSITORY = GenericHelpTopics.REPOSITORY;

	/** 
	 * Help Topic for search functions.
	 */
	public final static String SEARCH = "Search";

	/**
	 * Help Topic for selection.
	 */
	public final static String SELECTION = "Selection";

	/**
	 * Help Topic for the symbol table.
	 */
	public final static String SYMBOL_TABLE = "SymbolTablePlugin";

	/**
	 * Help Topic for the symbol tree.
	 */
	public final static String SYMBOL_TREE = "SymbolTreePlugin";

	/**
	 * Help Topic for tools.
	 */
	public final static String TOOL = GenericHelpTopics.TOOL;
}
