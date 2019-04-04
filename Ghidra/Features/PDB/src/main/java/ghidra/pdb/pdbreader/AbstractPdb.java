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

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.pdb.*;
import ghidra.pdb.msfreader.AbstractMsf;
import ghidra.pdb.msfreader.MsfStream;
import ghidra.pdb.pdbreader.symbol.*;
import ghidra.pdb.pdbreader.type.AbstractMsType;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.DependencyGraph;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents the the Windows PDB file.  This class is only suitable for reading; not
 *  for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public abstract class AbstractPdb implements AutoCloseable {

	private static final int PDB_DIRECTORY_STREAM_NUMBER = 1;

	// Items below begin in Pdb200
	private static final int VERSION_NUMBER_SIZE = 4;

	// Items below begin in Pdb400
	// "MINI" = 0x4d 0x49 0x4e 0x49 = 0x494e494d  featMinimalDbgInfo
	private static final int MINIMAL_DEBUG_INFO_PARAM = 0x494e494d;
	// "NOTM" = 0x4e 0x4f 0x54 0x4d = 0x4d544f4e  featNoTypeMerge
	private static final int NO_TYPE_MERGE_PARAM = 0x4d544f4e;

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected AbstractMsf msf;

	// Items below begin in Pdb200
	protected int versionNumber = 0;
	protected int signature = 0;
	//Number of times PDB updated.
	protected int age = 0;

	protected AbstractTypeProgramInterface typeProgramInterface;
	protected AbstractDatabaseInterface databaseInterface;

	protected int targetProcessorIndexNumber = 0xffff;

	// Items below begin in Pdb400
	protected boolean minimalDebugInfo = false;
	protected boolean noTypeMerge = false;
	protected boolean hasIdStream = false;
	protected List<String> strings;
	protected List<Integer> parameters;
	protected NameTable nameTable;

	protected AbstractTypeProgramInterface itemProgramInterface;  //IPI seems to be a TPI.

	// Items below begin in Pdb700
	protected GUID guid; // We can return null by not initializing the guid.
	//protected GUID guid =
	//  new GUID(0, (short) 0, (short) 0, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });

	protected boolean substreamsDeserialized = false;

	//==============================================================================================
	private TypeParser typeParser;
	private SymbolParser symbolParser;
	//==============================================================================================
	private Stack<CategoryIndex> dependencyStack = new Stack<>();
	private DependencyGraph<CategoryIndex> dependencyGraph = new DependencyGraph<>();
	private List<CategoryIndex> orderedDependenyIndices = new ArrayList<>();

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Closes the {@link AbstractPdb} and resources that it uses.
	 * @throws IOException for file I/O reasons.
	 */
	@Override
	public void close() throws IOException {
		if (msf != null) {
			msf.close();
		}
	}

	/**
	 * Returns the main {@link PdbIdentifiers} found in the PDB Directory. 
	 * @return {@link PdbIdentifiers} of information.
	 */
	public PdbIdentifiers getIdentifiers() {
		return new PdbIdentifiers(versionNumber, signature, age, guid);
	}

	/**
	 * Deserializes this PDB from the underlying {@link AbstractMsf}.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon error in processing components.
	 * @throws CancelledException Upon user cancellation.
	 */
	public void deserialize(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		// msf should only be null for testing versions of PDB.
		if (msf == null) {
			return;
		}
		deserializeDirectory(monitor);

		//directoryStream.dump(Integer.MAX_VALUE);
		//System.out.println(pdb.dumpDirectory());

		//pdb.dumpStream(2, Integer.MAX_VALUE);
//		pdb.dumpStream(2, 0x400);
		//		pdb.dumpStream(3, 0x400);
//		pdb.dumpStream(4, 0x400);

		deserializeSubstreams(monitor);
//		pdb.dumpSubStreams();

		// pdb.dumpGlobalSymbols(); //TODO: evaluate where/who calls.
		//  Currently in dumpSubStreams() and parsed in deserializeSubStreams()
	}

	/**
	 * Return some post-processing metrics on the PDB
	 * @return {@link String} of pretty output.
	 */
	public String getPostProcessingReport() {
		StringBuilder builder = new StringBuilder();
		String dataTypesReport = typeParser.getNewDataTypesLog();
		if (!dataTypesReport.isEmpty()) {
			builder.append(dataTypesReport);
			builder.append("\n");
		}
		String symbolTypesReport = symbolParser.getNewSymbolTypesLog();
		if (!symbolTypesReport.isEmpty()) {
			builder.append(symbolTypesReport);
			builder.append("\n");
		}
		return builder.toString();
	}

	/**
	 * Returns the {@link TypeParser} created for this PDB.
	 * @return {@link TypeParser} for this PDB.
	 */
	public TypeParser getTypeParser() {
		return typeParser;
	}

	/**
	 * Returns the {@link SymbolParser} created for this PDB.
	 * @return {@link SymbolParser} for this PDB.
	 */
	public SymbolParser getSymbolParser() {
		return symbolParser;
	}

	/**
	 * Returns the Version Number of the PDB.
	 * @return Version Number of the PDB.
	 */
	public int getVersionNumber() {
		return versionNumber;
	}

	/**
	 * Returns the Signature of the PDB.
	 * @return Signature of the PDB.
	 */
	public int getSignature() {
		return signature;
	}

	/**
	 * Returns the Age of the PDB.
	 * @return Age of the PDB.
	 */
	public int getAge() {
		return age;
	}

	/**
	 * Returns the GUID for the PDB.
	 * @return {@link GUID} for the PDB.
	 */
	public GUID getGuid() {
		return guid;
	}

	/**
	 * Tells whether the PDB file has been completely deserialized yet.
	 * @return True if has been deserialized.
	 */
	public boolean isDeserialized() {
		return substreamsDeserialized;
	}

	/**
	 * Get the index number of the target processor used for compilation. Also see
	 * {@link ProcessorName} and {@link RegisterName}.
	 * @return Index number of the target processor used for compilation.
	 */
	public int getTargetProcessorIndexNumber() {
		return targetProcessorIndexNumber;
	}

	/**
	 * Set the index number of the target processor used for compilation. Also see
	 * {@link ProcessorName} and {@link RegisterName}.
	 * @param targetProcessorIndexNumberIn Processor identifier.
	 */
	public void setTargetProcessorIndexNumber(int targetProcessorIndexNumberIn) {
		targetProcessorIndexNumber = targetProcessorIndexNumberIn;
	}

	/**
	 * Returns the {@link AbstractTypeProgramInterface} component.
	 * @return {@link AbstractTypeProgramInterface} component.
	 */
	public AbstractTypeProgramInterface getTypeProgramInterface() {
		return typeProgramInterface;
	}

	/**
	 * Returns the ItemProgramInterface (of type {@link AbstractTypeProgramInterface})
	 *  component.
	 * @return ItemProgramInterface (of type {@link AbstractTypeProgramInterface}) component.
	 */
	public AbstractTypeProgramInterface getItemProgramInterface() {
		return itemProgramInterface;
	}

	/**
	 * Returns the {@link AbstractDatabaseInterface} component.
	 * @return {@link AbstractDatabaseInterface} component.
	 */
	public AbstractDatabaseInterface getDatabaseInterface() {
		return databaseInterface;
	}

	/**
	 * Returns the {@link SymbolRecords} component of the PDB.
	 * @return {@link SymbolRecords} component.
	 */
	public SymbolRecords getSymbolRecords() {
		return databaseInterface.getSymbolRecords();
	}

	/**
	 * Returns List of {@link AbstractMsSymbol} encountered everywhere in the PDB
	 *  (public an module).
	 * @return Symbols ({@link AbstractMsSymbol}).
	 */
	public List<AbstractMsSymbol> getComprehensiveSymbolsList() {
		return databaseInterface.getComprehensiveSymbolsList();
	}

	/**
	 * Returns the type associated with the record number from the Type Program Interface (TPI).
	 * @param recordNumber Record Number requested.
	 * @return "Type" ({@link AbstractMsType}) for the record number.
	 */
	public AbstractMsType getTypeRecord(int recordNumber) {
		return typeProgramInterface.getRecord(recordNumber);
	}

	/**
	 * Returns a name from the {@link NameTable} pertaining to the index argument.
	 * @param index Index of the name.
	 * @return Name.
	 */
	public String getNameFromNameIndex(int index) {
		return nameTable.getNameFromStreamNumber(index);
	}

	/**
	 * Returns an index of the {@link String} name argument in the {@link NameTable}.
	 * @param name Name for which to find the index.
	 * @return Index of the name argument.
	 */
	public int getNameIndexFromName(String name) {
		return nameTable.getStreamNumberFromName(name);
	}

	/**
	 * Returns a name from the {@link NameTable} pertaining to the byte-offset in the block of
	 *  names for the table.
	 * @param offset Byte-offset of the name in the {@link NameTable} block.
	 * @return Name at the byte offset in the Name Table.
	 */
	public String getNameStringFromOffset(int offset) {
		return nameTable.getNameStringFromOffset(offset);
	}

	/**
	 * Returns the Item of type {@link AbstractMsType} associated with the record number from the
	 *  Item Program Interface (IPI).
	 * @param recordNumber Record number.
	 * @return "Item" ({@link AbstractMsType}) for the record number.
	 */
	public AbstractMsType getItemRecord(int recordNumber) {
		if (hasIdStream) {
			return itemProgramInterface.getRecord(recordNumber);
		}
		return null;
	}

	/**
	 * Returns an {@link AbstractMsSymbol} based upon a made-up (non-PDB) record number that
	 *  we created in order to have a unique identifier across all symbols (whether public or
	 *  from any of the modules).  These numbers were created in a one-up fashion as the
	 *  records were encountered.  This method returns the specific symbol record for that number.
	 * @param recordNumber Record number.
	 * @return {@link AbstractMsSymbol} for the record number.
	 */
	public AbstractMsSymbol getComprehensiveSymbolRecord(int recordNumber) {
		return databaseInterface.getComprehensiveSymbolRecord(recordNumber);
	}

	/**
	 * Returns the {@link AbstractParsableItem} (either an {@link AbstractMsType} for DATA or
	 * ITEM or an {@link AbstractMsSymbol} for a SYMBOL) identified by the categoryIndex.
	 * Note that {@link CategoryIndex} is not a standard part of the PDB, but something we
	 * use for Dependency Graph/Order in an investigation of how to analyze and apply the PDB.
	 * @param categoryIndex Identifier for the record to be returned.
	 * @return {@link AbstractParsableItem} (either an {@link AbstractMsType} for DATA or
	 * ITEM or an {@link AbstractMsSymbol} for SYMBOL).
	 */
	public AbstractParsableItem getParsableItemFromCategoryIndex(CategoryIndex categoryIndex) {
		if (categoryIndex.getCategory() == CategoryIndex.Category.DATA) {
			return getTypeRecord(categoryIndex.getIndex());
		}
		if (categoryIndex.getCategory() == CategoryIndex.Category.ITEM) {
			return getItemRecord(categoryIndex.getIndex());
		}
		return getComprehensiveSymbolRecord(categoryIndex.getIndex());
	}

	/**
	 * Returns the {@link DependencyGraph}<{@link CategoryIndex}>.  Dependency order is not
	 *  a PDB feature.  It is something we added (and might be removed in the future) as we
	 *  have investigated how to analyze and apply the PDB.
	 * @return {@link DependencyGraph}<{@link CategoryIndex}>.
	 */
	public DependencyGraph<CategoryIndex> getDependencyGraphCopy() {
		return dependencyGraph.copy();
	}

	/**
	 * Method to be called during the creation of the {@link DependencyGraph} whenever this node is
	 *  starting to be processes, in which case it might be a dependent of some parent, or it might
	 *  have dependents of its own.
	 *  <P>
	 *  Only should be called for {@link AbstractParsableItem} that could be DATA or ITEM
	 *  ({@link AbstractMsType}) or SYMBOL ({@link AbstractMsSymbol}) type.
	 *  <P>
	 *  There is no situation where a DATA or ITEM is dependent on a SYMBOL.
	 * @param dependeeCategoryIndex {@link CategoryIndex} for the new node.  ({@link CategoryIndex}
	 *  contains the record index and an identifier of which list the index belongs: DATA, ITEM,
	 *  or SYMBOL.)
	 */
	public void pushDependencyStack(CategoryIndex dependeeCategoryIndex) {

//		// DO NOT REMOVE
//		// The following code is for developmental investigations;
//		//  set break point on "int a = 1;" instead of a
//		//  conditional break point.
//		if ((dependeeCategoryIndex.getIndex() == 4774 ||
//			dependeeCategoryIndex.getIndex() == 4775) &&
//			dependeeCategoryIndex.getCategory() == CategoryIndex.Category.DATA) {
//			int a = 1;
//			a = a + 1;
//		}
		if (dependencyStack.isEmpty()) {
			dependencyGraph.addValue(dependeeCategoryIndex);
		}
		else {
			CategoryIndex dependentCategoryIndex = dependencyStack.peek();
			dependencyGraph.addDependency(dependentCategoryIndex, dependeeCategoryIndex);
		}
		dependencyStack.add(dependeeCategoryIndex);
	}

	/**
	 * Method to be called during the creation of {@link DependencyGraph}<{@link CategoryIndex}>
	 *  whenever a node (see {@link #pushDependencyStack(CategoryIndex)}) will have no more
	 *  dependents of its own (or is done being processed).
	 */
	public void popDependencyStack() {
		dependencyStack.pop();
	}

	public void processDependencyGraph() {
		if (dependencyGraph.hasCycles()) {
			return;
		}
		DependencyGraph<CategoryIndex> mutableCopy = dependencyGraph.copy();
		Stack<CategoryIndex> stack = new Stack<>();
		while (!mutableCopy.isEmpty()) {
			CategoryIndex dependencyIndex = mutableCopy.pop();
			stack.push(dependencyIndex);
		}
		while (!stack.isEmpty()) {
			CategoryIndex dependencyIndex = stack.pop();
			orderedDependenyIndices.add(dependencyIndex);
		}
		// Template of how one might process the data
//		for (CategoryIndex categoryIndex : orderedDependenyIndices) {
//			int index = categoryIndex.getIndex();
//			if (categoryIndex.getIndexType() == CategoryIndex.Category.DATA) {
//				AbstractMsType type = getTypeRecord(index);
//			}
//			else if (categoryIndex.getIndexType() == CategoryIndex.Category.ITEM) {
//				AbstractMsType item = getItemRecord(index);
//			}
//			else { // dependencyIndex.getIndexType() == IndexType.SYMBOL
//				AbstractMsSymbol symbol = getComprehensiveSymbolRecord(index);
//			}
//		}
	}

	/**
	 * Dumps the {@link DependencyGraph}<{@link CategoryIndex}> information.  The
	 *  {@link DependencyGraph}<{@link CategoryIndex}> is not a PDB feature.  It is
	 *  something we added (and might be removed in the future) as we have investigated how to
	 *  analyze and apply the PDB.  This package-protected method is for debugging only.
	 * @return {@link String} of pretty output.
	 */
	public String dumpDependencyGraph() {
		StringBuilder builder = new StringBuilder();
		builder.append("DependencyGraph---------------------------------------------");
		builder.append("\nSize: ");
		builder.append(dependencyGraph.size());
		builder.append("\n");
		if (dependencyGraph.hasCycles()) {
			builder.append("Has cycles\n");
		}
		else {
			builder.append("Has no cycles\n");
		}
		DependencyGraph<CategoryIndex> mutableCopy = dependencyGraph.copy();
		while (!mutableCopy.isEmpty()) {
			CategoryIndex categoryIndex = mutableCopy.pop();
			int index = categoryIndex.getIndex();
			if (categoryIndex.getCategory() == CategoryIndex.Category.DATA) {
				AbstractMsType type = getTypeRecord(index);
				builder.append(String.format("Dependency (data index: %d) [%s]: %s\n", index,
					type.getClass().getSimpleName(), type.toString()));
			}
			else if (categoryIndex.getCategory() == CategoryIndex.Category.ITEM) {
				AbstractMsType item = getItemRecord(index);
				builder.append(String.format("Dependency (item index: %d) [%s]: %s\n", index,
					item.getClass().getSimpleName(), item.toString()));
			}
			else { // dependencyIndex.getIndexType() == IndexType.SYMBOL
				AbstractMsSymbol symbol = getComprehensiveSymbolRecord(index);
				builder.append(String.format("Dependency (symbol index: %d) [%s]: %s\n", index,
					symbol.getClass().getSimpleName(), symbol.toString()));
			}
		}
		return builder.toString();
	}

	/**
	 * Dumps the Dependency Order information as found in the
	 *  {@link DependencyGraph}<{@link CategoryIndex}>.  Dependency order is not a PDB feature.
	 *  It is something we added (and might be removed in the future) as we have investigated
	 *  how to analyze and apply the PDB.  This package-protected method is for debugging only.
	 * @return {@link String} of pretty output.
	 */
	protected String dumpDependencyOrder() {
		StringBuilder builder = new StringBuilder();
		builder.append("DependencyOrder---------------------------------------------");
		builder.append("\nSize: ");
		builder.append(orderedDependenyIndices.size());
		builder.append("\n");
		for (CategoryIndex categoryIndex : orderedDependenyIndices) {
			int index = categoryIndex.getIndex();
			if (categoryIndex.getCategory() == CategoryIndex.Category.DATA) {
				AbstractMsType type = getTypeRecord(index);
				builder.append(String.format("Dependency (data index: %d) [%s]: %s\n", index,
					type.getClass().getSimpleName(), type.toString()));
			}
			else if (categoryIndex.getCategory() == CategoryIndex.Category.ITEM) {
				AbstractMsType item = getItemRecord(index);
				builder.append(String.format("Dependency (item index: %d) [%s]: %s\n", index,
					item.getClass().getSimpleName(), item.toString()));
			}
			else { // dependencyIndex.getIndexType() == ICategoryIndex.Category.SYMBOL
				AbstractMsSymbol symbol = getComprehensiveSymbolRecord(index);
				builder.append(String.format("Dependency (symbol index: %d) [%s]: %s\n", index,
					symbol.getClass().getSimpleName(), symbol.toString()));
			}
		}
		return builder.toString();
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Returns the number of bytes needed to store a PDB version number.
	 *  location.
	 * @return Number of bytes needed to store a PDV version number.
	 */
	static int getVersionNumberSize() {
		return VERSION_NUMBER_SIZE;
	}

	/**
	 * Deserializes PDB Version Number from the PDB Directory Stream in the {@link AbstractMsf}.
	 * @param msf {@link AbstractMsf} underlying the PDB of which to probe.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @return Version number.
	 * @throws IOException on file I/O issues.
	 * @throws PdbException on parsing issues. 
	 * @throws CancelledException Upon user cancellation.
	 */
	static int deserializeVersionNumber(AbstractMsf msf, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		MsfStream directoryStream = msf.getStream(PDB_DIRECTORY_STREAM_NUMBER);
		if (directoryStream.getLength() < AbstractPdb.getVersionNumberSize()) {
			throw new PdbException("Directory Stream too short");
		}
		byte[] bytes = directoryStream.read(0, AbstractPdb.getVersionNumberSize(), monitor);
		PdbByteReader pdbDirectoryReader = new PdbByteReader(bytes);
		return pdbDirectoryReader.parseInt();
//			int versionNumber = AbstractPdb.deserializeVersionNumber(pdbDirectoryReader);
//			return versionNumber;
//		}
	}

	/**
	 * Constructor.
	 * @param msf {@link AbstractMsf} foundation for the PDB.
	 * @throws IOException Upon file IO seek/read issues.
	 * @throws PdbException Upon unknown value for configuration or error in processing components.
	 */
	AbstractPdb(AbstractMsf msf) throws IOException, PdbException {
		this.msf = msf;
		strings = new ArrayList<>();
		parameters = new ArrayList<>();
		nameTable = new NameTable(this);

		typeParser = new TypeParser(this);
		symbolParser = new SymbolParser(this);
	}

	/**
	 * Deserializes the main {@link PdbIdentifiers} found in the PDB Directory from the
	 *  {@link PdbByteReader}. 
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	abstract void deserializeIdentifiersOnly(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException;

	/**
	 * Returns the {@link AbstractMsf} foundation for the PDB.
	 * @return {@link AbstractMsf} foundation of the PDB.
	 */
	AbstractMsf getMsf() {
		return msf;
	}

	//TODO  Not sure if we will keep this method or if more gets added to it. 
	/**
	 * Deserializes the sub-streams for this {@link AbstractPdb} object.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon error in processing components.
	 * @throws CancelledException Upon user cancellation.
	 */
	void deserializeSubstreams(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {

		if (substreamsDeserialized) {
			return;
		}

		TypeProgramInterfaceParser tpiParser = new TypeProgramInterfaceParser();
		DatabaseInterfaceParser dbiParser = new DatabaseInterfaceParser();

		typeProgramInterface = tpiParser.parse(this, monitor);
		if (typeProgramInterface != null) {
			typeProgramInterface.deserialize(monitor);
		}

		databaseInterface = dbiParser.parse(this, monitor);
		if (databaseInterface != null) {
			databaseInterface.deserialize(monitor);
		}

		if (hasIdStream) {
			ItemProgramInterfaceParser ipiParser = new ItemProgramInterfaceParser();
			itemProgramInterface = ipiParser.parse(this, monitor);
			if (itemProgramInterface != null) {
				itemProgramInterface.deserialize(monitor);
			}
			//processDependencyIndexPairList();
			//dumpDependencyGraph();
		}

		//processDependencyGraph();
		//dumpDependencyGraph();

		substreamsDeserialized = true;
	}

	/**
	 * Debug method to dump the number of bytes for the specified stream to a {@link String}.
	 * @param streamNumber The stream number to dump.
	 * @param maxOut The maximum number of bytes to dump.
	 * @return {@link String} of pretty output.
	 */
	String dumpStream(int streamNumber, int maxOut) {
		StringBuilder builder = new StringBuilder();
		builder.append(msf.getStream(streamNumber).dump(maxOut));
		return builder.toString();
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Deserializes PDB Directory from the {@link PdbByteReader}.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException upon error parsing a field.
	 * @throws CancelledException Upon user cancellation.
	 */
	abstract void deserializeDirectory(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException;

	/**
	 * Dumps the PDB Directory to {@link Writer}.  This package-protected method is for
	 *  debugging only.
	 * @param writer {@link Writer}.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	abstract void dumpDirectory(Writer writer) throws IOException;

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================

	/**
	 * Reads the Directory stream and returns a {@link PdbByteReader} of its contents.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @return {@link PdbByteReader} requested.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected PdbByteReader getDirectoryReader(TaskMonitor monitor)
			throws IOException, CancelledException {
		MsfStream directoryStream = msf.getStream(PDB_DIRECTORY_STREAM_NUMBER);
		int length = directoryStream.getLength();
		byte[] bytes = directoryStream.read(0, length, monitor);
		return new PdbByteReader(bytes);
	}

	/**
	 * Deserializes the Version, Signature, and Age.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected void deserializeVersionSignatureAge(PdbByteReader reader) throws PdbException {
		versionNumber = reader.parseInt();
		signature = reader.parseInt();
		age = reader.parseInt();
	}

	/**
	 * Dumps the Version Signature and Age.  This package-protected method is for debugging only.
	 * @return {@link String} of pretty output.
	 */
	protected String dumpVersionSignatureAge() {
		StringBuilder builder = new StringBuilder();
		builder.append("DirectoryHeader---------------------------------------------");
		builder.append("\nversionNumber: ");
		builder.append(versionNumber);
		builder.append("\nsignature: ");
		builder.append(signature);
		builder.append("\nage: ");
		builder.append(age);
		return builder.toString();
	}

	/**
	 * Deserializes the Parameters.
	 * @param reader {@link PdbByteReader} from which to deserialize the data.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException upon error parsing a string.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected void deserializeParameters(PdbByteReader reader, TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		nameTable.deserializeDirectory(reader, monitor);
		// Read the parameters.
		while (reader.hasMore()) {
			monitor.checkCanceled();
			int val = reader.parseInt();
			parameters.add(val);
		}
		// Check the parameters for IDs
		for (int param : parameters) {
			monitor.checkCanceled();
			if (param == MINIMAL_DEBUG_INFO_PARAM) {
				minimalDebugInfo = true;
			}
			else if (param == NO_TYPE_MERGE_PARAM) {
				noTypeMerge = true;
			}
			// Putting all of these >= ID after the specific == tests above
			//  so that no >= tests in the ID section trigger off of any
			//  of the above flags
			else if (param >= PdbParser.VC110_ID) {
				hasIdStream = true;
			}
		}
	}

	/**
	 * Dumps the Parameters to a {@link String}.  This package-protected method is for
	 *  debugging only.
	 * @return {@link String} of pretty output.
	 */
	protected String dumpParameters() {
		StringBuilder builder = new StringBuilder();
		builder.append(nameTable.dump());
		builder.append("\nParameters--------------------------------------------------\n");
		for (int i = 0; i < parameters.size(); i++) {
			builder.append(String.format("parameter[%d]: 0x%08x %d\n", i, parameters.get(i),
				parameters.get(i)));
		}
		builder.append("Booleans----------------------------------------------------");
		builder.append("\nminimalDebugInfo: ");
		builder.append(minimalDebugInfo);
		builder.append("\nnoTypeMerge: ");
		builder.append(noTypeMerge);
		builder.append("\nhasIdStream: ");
		builder.append(hasIdStream);
		builder.append("\n");
		return builder.toString();
	}

	/**
	 * Dumps the Sub-Streams to a {@link Writer}.  This package-protected method is for
	 *  debugging only.
	 * @param writer {@link Writer}.
	 * @throws IOException On issue writing to the {@link Writer}.
	 */
	protected void dumpSubStreams(Writer writer) throws IOException {
		writer.write("SubStreams--------------------------------------------------\n");
		if (typeProgramInterface != null) {
			writer.write("TypeProgramInterface----------------------------------------\n");
			typeProgramInterface.dump(writer);
			writer.write("End TypeProgramInterface------------------------------------\n");
			writer.write("\n");
		}
		if (databaseInterface != null) {
			writer.write("DatabaseInterface-------------------------------------------\n");
			databaseInterface.dump(writer);
			writer.write("End DatabaseInterface---------------------------------------\n");
		}
		if (itemProgramInterface != null) {
			writer.write("ItemProgramInterface----------------------------------------\n");
			itemProgramInterface.dump(writer);
			writer.write("End ItemProgramInterface------------------------------------\n");
		}
	}

}
