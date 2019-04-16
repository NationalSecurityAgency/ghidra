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
import java.util.ArrayList;
import java.util.List;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents Symbol Records component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public class SymbolRecords {

	//==============================================================================================
	// Internals
	//==============================================================================================
	private AbstractPdb pdb;
	private List<AbstractMsSymbol> symbolList;
	private List<List<AbstractMsSymbol>> moduleSymbolLists = new ArrayList<>();
	private int comprehensiveSymbolCount = 0;
	private List<AbstractMsSymbol> comprehensiveSymbolList = new ArrayList<>();

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} to which the {@link SymbolRecords} belong.
	 */
	public SymbolRecords(AbstractPdb pdb) {
		this.pdb = pdb;
	}

	/**
	 * Return a comprehensive list of Symbols, including from modules.
	 * <P>
	 * Note: This is Ghidra-added functionality that might eventually go away; it is implemented
	 *  for investigating how to mine the information we need from the PDB. This might go away in
	 *  future implementations.
	 * @return Comprehensive list of {@link AbstractMsSymbol}s seen. 
	 */
	protected List<AbstractMsSymbol> getComprehensiveSymbolsList() {
		return comprehensiveSymbolList;
	}

	/**
	 * Returns a specific Symbol based on a ghidra-specific recordNumber parameter.  The record
	 *  number is not part of a normal PDB, but we assigned a one-up numbering.
	 * <P>
	 * Note: This is Ghidra-added functionality that might eventually go away; it is implemented
	 *  for investigating how to mine the information we need from the PDB. This might go away in
	 *  future implementations.
	 * @param recordNumber The ghidra-specific record number for the {@link AbstractMsSymbol}.
	 * @return {@link AbstractMsSymbol} for the recordNumber 
	 */
	protected AbstractMsSymbol getComprehensiveSymbolRecord(int recordNumber) {
		return comprehensiveSymbolList.get(recordNumber);
	}

	/**
	 * Returns the list of regular symbols.
	 * @return Regular {@link AbstractMsSymbol} symbols.
	 */
	protected List<AbstractMsSymbol> getSymbolsList() {
		return symbolList;
	}

	/**
	 * Returns the symbol list for the module as specified by moduleNumber.
	 * @param moduleNumber The number ID of the module for which to return the list.
	 * @return {@link AbstractMsSymbol} Symbols  in the specified module.
	 */
	protected List<AbstractMsSymbol> getModuleSymbolLists(int moduleNumber) {
		return moduleSymbolLists.get(moduleNumber);
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Deserializes the {@link SymbolRecords} from the stream noted in the DBI header.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	void deserialize(TaskMonitor monitor) throws IOException, PdbException, CancelledException {
		int streamNumber;
		PdbByteReader reader;

		streamNumber = pdb.databaseInterface.getSymbolRecordsStreamNumber();
		reader = pdb.getReaderForStreamNumber(streamNumber, monitor);
		symbolList = deserializeSymbolRecords(reader);

		for (AbstractModuleInformation module : pdb.databaseInterface.moduleInformationList) {
			streamNumber = module.getStreamNumberDebugInformation();
			if (streamNumber != 0xffff) {
//				System.out.println("\n\nStreamNumber: " + streamNumber);
				reader = pdb.getReaderForStreamNumber(streamNumber, monitor);
				int x = reader.parseInt(); // TODO: do not know what this value is.
				int sizeDebug = module.getSizeLocalSymbolsDebugInformation();
				sizeDebug -= x; //TODO: seems right, but need to evaluate this
				PdbByteReader debugReader = reader.getSubPdbByteReader(sizeDebug);
				List<AbstractMsSymbol> moduleList = deserializeSymbolRecords(debugReader);
//				System.out.println(reader.dump(4));
//				System.out.println("stream: " + streamNumber + ", current index: " +
//					reader.getIndex() + ", index limit: " + reader.getLimit());
//				System.out.println(reader.dump(0x100));
				// TODO: figure out the rest of the bytes in the stream (index of reader)
				moduleSymbolLists.add(moduleList);
			}
			else {
				moduleSymbolLists.add(null);
			}
		}

	}

	/**
	 * Deserializes the {@link AbstractMsSymbol} symbols from the {@link PdbByteReader}.
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize.
	 * @return {@link AbstractMsSymbol} symbols.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public List<AbstractMsSymbol> deserializeSymbolRecords(PdbByteReader reader)
			throws PdbException {
		int recordNumber = 0;
		//System.out.println(reader.dump(0x400));
		SymbolParser parser = pdb.getSymbolParser();
		List<AbstractMsSymbol> mySymbolList = new ArrayList<>();
		while (reader.hasMore()) {
//			//System.out.println("Symbol Record: " + recordNumber);
//			// DO NOT REMOVE
//			// The following code is for developmental investigations;
//			//  set break point on "int a = 1;" instead of a
//			//  conditional break point.
//			if (recordNumber == 839) {
//				int a = 1;
//				a = a + 1;
//				//System.out.println(reader.dump(0x200));
//			}
			// Including length in byte array for alignment purposes. 
			int recordLength = reader.parseUnsignedShortVal();
			PdbByteReader recordReader = reader.getSubPdbByteReader(recordLength);
			pdb.pushDependencyStack(
				new CategoryIndex(CategoryIndex.Category.SYMBOL, comprehensiveSymbolCount));
			AbstractMsSymbol symbol = parser.parse(recordReader);
			pdb.popDependencyStack();
			mySymbolList.add(symbol);
			recordNumber++;
			comprehensiveSymbolList.add(symbol);
			comprehensiveSymbolCount++;
		}
		return mySymbolList;
	}

	/**
	 * Debug method for dumping information from this Symbol Records instance.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dump(Writer writer) throws IOException {
		writer.write("SymbolRecords-----------------------------------------------\n");
		writer.write(dumpSymbolList(symbolList));
		for (int i = 0; i < moduleSymbolLists.size(); i++) {
			List<AbstractMsSymbol> list = moduleSymbolLists.get(i);
			if (list != null) {
				writer.write("Module(" + i + ") List:\n");
				writer.write(dumpSymbolList(list));
			}
		}
		writer.write("\nEnd SymbolRecords-------------------------------------------\n");
	}

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Debug method for dumping the symbols from a symbol list
	 * @param list The symbol list to dump.
	 * @return {@link String} of pretty output of symbols dumped.
	 */
	protected String dumpSymbolList(List<AbstractMsSymbol> list) {
		StringBuilder builder = new StringBuilder();
		builder.append("SymbolList--------------------------------------------------");
		for (AbstractMsSymbol symbol : list) {
			builder.append("\n------------------------------------------------------------\n");
			builder.append(symbol);
		}
		builder.append("\nEnd SymbolList----------------------------------------------\n");
		return builder.toString();
	}

}
