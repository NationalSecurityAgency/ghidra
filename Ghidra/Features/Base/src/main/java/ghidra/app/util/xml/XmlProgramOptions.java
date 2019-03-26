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
package ghidra.app.util.xml;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.OptionException;

/**
 * A class to hold XML options.
 *
 */
public class XmlProgramOptions {
	/**Flag to indicate reading/writing memory blocks*/
	public final static long OPT_MEMORY_BLOCKS = 0x00000001L;
	/**Flag to indicate reading/writing memory contents*/
	public final static long OPT_MEMORY_CONTENTS = 0x00000002L;
	/**Flag to indicate reading/writing instructions*/
	public final static long OPT_CODE = 0x00000004L;
	/**Flag to indicate reading/writing data*/
	public final static long OPT_DATA = 0x00000008L;
	/**Flag to indicate reading/writing symbols*/
	public final static long OPT_SYMBOLS = 0x00000010L;
	/**Flag to indicate reading/writing equates*/
	public final static long OPT_EQUATES = 0x00000020L;
	/**Flag to indicate reading/writing comments*/
	public final static long OPT_COMMENTS = 0x00000040L;
	/**Flag to indicate reading/writing properties*/
	public final static long OPT_PROPERTIES = 0x00000080L;
	/**Flag to indicate reading/writing trees*/
	public final static long OPT_TREES = 0x00000100L;
	/**Flag to indicate reading/writing empty program tree nodes*/
	public final static long OPT_EMPTY_TREE_NODES = 0x00000200L;
	/**Flag to indicate reading/writing references*/
	public final static long OPT_REFERENCES = 0x00000400L;
	/**Flag to indicate reading/writing functions*/
	public final static long OPT_FUNCTIONS = 0x00000800L;
	/**
	 * Used to signify that symbols should be overwritten when
	 * necessary. This value is not being included in
	 * the <code>ALL</code> constant.
	 */
	public final static long OVERWRITE_SYMBOLS = 0x20000000L;

	/**
	 * Used to signify that references should be overwritten when
	 * necessary. This value is not being included in
	 * the <code>ALL</code> constant.
	 */
	public final static long OVERWRITE_REFS = 0x40000000L;

	/**
	 * Used to signify that an existing program is being
	 * updated. This value is not being included in
	 * the <code>ALL</code> constant.
	 */
	public final static long ADD_2_PROG = 0x80000000L;

	private boolean addToProgram = false;
	private boolean memoryBlocks = true;
	private boolean memoryContents = true;
	private boolean overwriteMemoryConflicts = false;
	private boolean instructions = true;
	private boolean overwriteDataConflicts = true;
	private boolean data = true;
	private boolean symbols = true;
	private boolean overwriteSymbolConflicts = true;
	private boolean equates = true;
	private boolean comments = true;
	private boolean properties = true;
	private boolean overwritePropertyConflicts = true;
	private boolean bookmarks = true;
	private boolean overwriteBookmarkConflicts = true;
	private boolean trees = true;
	private boolean references = true;
	private boolean overwriteReferenceConflicts = true;
	private boolean functions = true;
	private boolean registers = true;
	private boolean relocationTable = true;
	private boolean entryPoints = true;
	private boolean externalLibraries = true;

	/**
	 * Returns an array of importer options representing
	 * the flags in this class.
	 * @param isAddToProgram if true then adding to existing program
	 * @return the array of importer options
	 */
	public List<Option> getOptions(boolean isAddToProgram) {
		this.addToProgram = isAddToProgram;

		ArrayList<Option> optionList = new ArrayList<>();

		optionList.add(new Option("Memory Blocks", new Boolean(isMemoryBlocks())));
		optionList.add(new Option("Memory Contents", new Boolean(isMemoryContents())));
		if (isAddToProgram) {
			optionList.add(new Option("Overwrite Memory Conflicts",
				new Boolean(isOverwriteMemoryConflicts())));
		}
		optionList.add(new Option("Instructions", new Boolean(isInstructions())));
		optionList.add(new Option("Data", new Boolean(isData())));
		if (isAddToProgram) {
			optionList.add(
				new Option("Overwrite Data Conflicts", new Boolean(isOverwriteDataConflicts())));
		}
		optionList.add(new Option("Symbols", new Boolean(isSymbols())));
		if (isAddToProgram) {
			optionList.add(new Option("Overwrite Symbol Conflicts",
				new Boolean(isOverwriteSymbolConflicts())));
		}
		optionList.add(new Option("Equates", new Boolean(isEquates())));
		optionList.add(new Option("Comments", new Boolean(isComments())));
		optionList.add(new Option("Properties", new Boolean(isProperties())));
		if (isAddToProgram) {
			optionList.add(new Option("Overwrite Property Conflicts",
				new Boolean(isOverwritePropertyConflicts())));
		}
		optionList.add(new Option("Bookmarks", new Boolean(isBookmarks())));
		if (isAddToProgram) {
			optionList.add(new Option("Overwrite Bookmark Conflicts",
				new Boolean(isOverwriteBookmarkConflicts())));
		}
		optionList.add(new Option("Trees", new Boolean(isTrees())));
		optionList.add(new Option("References", new Boolean(isReferences())));
		if (isAddToProgram) {
			optionList.add(new Option("Overwrite Reference Conflicts",
				new Boolean(isOverwriteReferenceConflicts())));
		}
		optionList.add(new Option("Functions", new Boolean(isFunctions())));
		optionList.add(new Option("Registers", new Boolean(isRegisters())));
		optionList.add(new Option("Relocation Table", new Boolean(isRelocationTable())));
		optionList.add(new Option("Entry Points", new Boolean(isEntryPoints())));
		optionList.add(new Option("External Libraries", new Boolean(isExternalLibraries())));

		return optionList;
	}

	/**
	 * Sets the options. This method is not for defining the options, but
	 * rather for setting the values of options. If invalid options
	 * are passed in, then OptionException should be thrown.
	 * @param options the option values for XML
	 * @throws OptionException if invalid options are passed in
	 */
	public void setOptions(List<Option> options) throws OptionException {
		for (Option option : options) {
			String optName = option.getName();
			Object optValue = option.getValue();

			if (!(optValue instanceof Boolean)) {
				throw new OptionException("Invalid type for option: " + optName);
			}

			boolean val = ((Boolean) optValue).booleanValue();

			if (optName.equals("Memory Blocks")) {
				setMemoryBlocks(val);
			}
			else if (optName.equals("Memory Contents")) {
				setMemoryContents(val);
			}
			else if (optName.equals("Overwrite Memory Conflicts")) {
				setOverwriteMemoryConflicts(val);
			}
			else if (optName.equals("Instructions")) {
				setInstructions(val);
			}
			else if (optName.equals("Data")) {
				setData(val);
			}
			else if (optName.equals("Overwrite Data Conflicts")) {
				setOverwriteDataConflicts(val);
			}
			else if (optName.equals("Symbols")) {
				setSymbols(val);
			}
			else if (optName.equals("Overwrite Symbol Conflicts")) {
				setOverwriteSymbolConflicts(val);
			}
			else if (optName.equals("Equates")) {
				setEquates(val);
			}
			else if (optName.equals("Comments")) {
				setComments(val);
			}
			else if (optName.equals("Properties")) {
				setProperties(val);
			}
			else if (optName.equals("Overwrite Property Conflicts")) {
				setOverwritePropertyConflicts(val);
			}
			else if (optName.equals("Bookmarks")) {
				setBookmarks(val);
			}
			else if (optName.equals("Overwrite Bookmark Conflicts")) {
				setOverwriteBookmarkConflicts(val);
			}
			else if (optName.equals("Trees")) {
				setTrees(val);
			}
			else if (optName.equals("References")) {
				setReferences(val);
			}
			else if (optName.equals("Overwrite Reference Conflicts")) {
				setOverwriteReferenceConflicts(val);
			}
			else if (optName.equals("Functions")) {
				setFunctions(val);
			}
			else if (optName.equals("Registers")) {
				setRegisters(val);
			}
			else if (optName.equals("Relocation Table")) {
				setRelocationTable(val);
			}
			else if (optName.equals("Entry Points")) {
				setEntryPoints(val);
			}
			else if (optName.equals("External Libraries")) {
				setExternalLibraries(val);
			}
			else {
				throw new OptionException("Unknown option: " + optName);
			}
		}
	}

	/**
	 * Returns true if importing to an existing program.
	 * Importing to an existing program creates a new
	 * set of potential conflicts. For example, memory block
	 * may collide. When this options is true, additional
	 * options are visible.
	 * @return true if importing to an existing program
	 */
	boolean isAddToProgram() {
		return addToProgram;
	}

	/**
	 * If true, then instructions should be read/written.
	 * @return true if instructions should be read/written
	 */
	public boolean isInstructions() {
		return instructions;
	}

	/**
	 * If true, then comments should be read/written.
	 * @return true if comments should be read/written
	 */
	public boolean isComments() {
		return comments;
	}

	/**
	 * If true, then data should be read/written.
	 * @return true if data should be read/written
	 */
	public boolean isData() {
		return data;
	}

	/**
	 * If true, then equates should be read/written.
	 * @return true if equates should be read/written
	 */
	public boolean isEquates() {
		return equates;
	}

	/**
	 * If true, then functions should be read/written.
	 * @return true if functions should be read/written
	 */
	public boolean isFunctions() {
		return functions;
	}

	/**
	 * If true, then memory blocks should be read/written.
	 * @return true if memory blocks should be read/written
	 */
	public boolean isMemoryBlocks() {
		return memoryBlocks;
	}

	/**
	 * If true, then memory contents should be read/written.
	 * @return true if memory contents should be read/written
	 */
	public boolean isMemoryContents() {
		return memoryContents;
	}

	/**
	 * If true, then properties should be read/written.
	 * @return true if properties should be read/written
	 */
	public boolean isProperties() {
		return properties;
	}

	/**
	 * If true, then references (memory, stack, external) should be read/written.
	 * @return true if references should be read/written
	 */
	public boolean isReferences() {
		return references;
	}

	/**
	 * If true, then symbols should be read/written.
	 * @return true if symbols should be read/written
	 */
	public boolean isSymbols() {
		return symbols;
	}

	/**
	 * If true, then program trees should be read/written.
	 * @return true if program trees should be read/written
	 */
	public boolean isTrees() {
		return trees;
	}

	/**
	 * Sets instructions to be read/written.
	 * @param b true if instructions should read/written
	 */
	public void setInstructions(boolean b) {
		instructions = b;
	}

	/**
	 * Sets comments to be read/written.
	 * @param b true if comments should read/written
	 */
	public void setComments(boolean b) {
		comments = b;
	}

	/**
	 * Sets data to be read/written.
	 * @param b true if data should read/written
	 */
	public void setData(boolean b) {
		data = b;
	}

	/**
	 * Sets equates to be read/written.
	 * @param b true if equates should read/written
	 */
	public void setEquates(boolean b) {
		equates = b;
	}

	/**
	 * Sets functions to be read/written.
	 * @param b true if functions should read/written
	 */
	public void setFunctions(boolean b) {
		functions = b;
	}

	/**
	 * Sets memory blocks to be read/written.
	 * @param b true if memory blocks should read/written
	 */
	public void setMemoryBlocks(boolean b) {
		memoryBlocks = b;
	}

	/**
	 * Sets memory contents to be read/written.
	 * @param b true if memory contents should read/written
	 */
	public void setMemoryContents(boolean b) {
		memoryContents = b;
	}

	/**
	 * Sets properties to be read/written.
	 * @param b true if properties should read/written
	 */
	public void setProperties(boolean b) {
		properties = b;
	}

	/**
	 * Sets references to be read/written.
	 * @param b true if references should read/written
	 */
	public void setReferences(boolean b) {
		references = b;
	}

	/**
	 * Sets symbols to be read/written.
	 * @param b true if symbols should read/written
	 */
	public void setSymbols(boolean b) {
		symbols = b;
	}

	/**
	 * Sets program trees to be read/written.
	 * @param b true if program trees should read/written
	 */
	public void setTrees(boolean b) {
		trees = b;
	}

	/**
	 * If true, then bookmarks should be read/written.
	 * @return true if bookmarks should be read/written
	 */
	public boolean isBookmarks() {
		return bookmarks;
	}

	/**
	 * If true, then registers should be read/written.
	 * @return true if registers should be read/written
	 */
	public boolean isRegisters() {
		return registers;
	}

	/**
	 * If true, then the relocation table should be read/written.
	 * @return true if the relocation table should be read/written
	 */
	public boolean isRelocationTable() {
		return relocationTable;
	}

	/**
	 * Sets bookmarks to be read/written.
	 * @param b true if bookmarks should read/written
	 */
	public void setBookmarks(boolean b) {
		bookmarks = b;
	}

	/**
	 * Sets registers to be read/written.
	 * @param b true if registers should read/written
	 */
	public void setRegisters(boolean b) {
		registers = b;
	}

	/**
	 * Sets relocation tables to be read/written.
	 * @param b true if relocation table should read/written
	 */
	public void setRelocationTable(boolean b) {
		relocationTable = b;
	}

	/**
	 * If true, then the entry points should be read/written.
	 * @return true if the entry points should be read/written
	 */
	public boolean isEntryPoints() {
		return entryPoints;
	}

	/**
	 * If true, then the external libraries should be read/written.
	 * @return true if the external libraries should be read/written
	 */
	public boolean isExternalLibraries() {
		return externalLibraries;
	}

	/**
	 * Sets entry points to be read/written.
	 * @param b true if entry points should read/written
	 */
	public void setEntryPoints(boolean b) {
		entryPoints = b;
	}

	/**
	 * Sets external libraries to be read/written.
	 * @param b true if external libraries should read/written
	 */
	public void setExternalLibraries(boolean b) {
		externalLibraries = b;
	}

	/**
	 * If true, then property conflicts will be overwritten.
	 * @return true if property conflicts will be overwritten
	 */
	public boolean isOverwritePropertyConflicts() {
		return overwritePropertyConflicts;
	}

	/**
	 * If true, then bookmark conflicts will be overwritten.
	 * @return true if bookmark conflicts will be overwritten
	 */
	public boolean isOverwriteBookmarkConflicts() {
		return overwriteBookmarkConflicts;
	}

	/**
	 * If true, then symbol conflicts will be overwritten.
	 * @return true if symbol conflicts will be overwritten
	 */
	public boolean isOverwriteSymbolConflicts() {
		return overwriteSymbolConflicts;
	}

	/**
	 * If true, then reference conflicts will be overwritten.
	 * @return true if reference conflicts will be overwritten
	 */
	public boolean isOverwriteReferenceConflicts() {
		return overwriteReferenceConflicts;
	}

	/**
	 * If true, then memory conflicts will be overwritten.
	 * @return true if memory conflicts will be overwritten
	 */
	public boolean isOverwriteMemoryConflicts() {
		return overwriteMemoryConflicts;
	}

	/**
	 * If true, then data conflicts will be overwritten.
	 * @return true if data conflicts will be overwritten
	 */
	public boolean isOverwriteDataConflicts() {
		return overwriteDataConflicts;
	}

	/**
	 * Sets bookmark conflicts to always be overwritten.
	 * @param b true if bookmark conflicts should always be overwritten
	 */
	public void setOverwriteBookmarkConflicts(boolean b) {
		overwriteBookmarkConflicts = b;
	}

	/**
	 * Sets memory conflicts to always be overwritten.
	 * @param b true if memory conflicts should always be overwritten
	 */
	public void setOverwriteMemoryConflicts(boolean b) {
		overwriteMemoryConflicts = b;
	}

	/**
	 * Sets data conflicts to always be overwritten.
	 * @param b true if data conflicts should always be overwritten
	 */
	public void setOverwriteDataConflicts(boolean b) {
		overwriteDataConflicts = b;
	}

	/**
	 * Sets property conflicts to always be overwritten.
	 * @param b true if property conflicts should always be overwritten
	 */
	public void setOverwritePropertyConflicts(boolean b) {
		overwritePropertyConflicts = b;
	}

	/**
	 * Sets reference conflicts to always be overwritten.
	 * @param b true if reference conflicts should always be overwritten
	 */
	public void setOverwriteReferenceConflicts(boolean b) {
		overwriteReferenceConflicts = b;
	}

	/**
	 * Sets symbol conflicts to always be overwritten.
	 * @param b true if symbol conflicts should always be overwritten
	 */
	public void setOverwriteSymbolConflicts(boolean b) {
		overwriteSymbolConflicts = b;
	}

	public void setAddToProgram(boolean addToProgram) {
		this.addToProgram = addToProgram;
	}

}
