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
package ghidra.app.util.pdb.pdbapplicator;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.exception.CancelledException;

/**
 * This class represents a particular group of Symbols that came from the same PDB stream.  This
 * wraps the internal structure and offers mechanisms for accessing records.  It does not map
 * directly to an MSFT structure.
 */
public class SymbolGroup {

	public static final int PUBLIC_GLOBAL_MODULE_NUMBER = 0;

	private AbstractPdb pdb;

	private Map<Long, AbstractMsSymbol> symbolsByOffset;
	private int moduleNumber;
	private List<Long> offsets;
	private Map<Long, Integer> indexByOffset;

	/**
	 * Constructor
	 * @param pdb the containing the symbols
	 * @param moduleNumber The Module number (0 (PUBLIC_GLOBAL_MODULE_NUMBER) for public/global)
	 */
	public SymbolGroup(AbstractPdb pdb, int moduleNumber) {
		this.pdb = pdb;
		this.moduleNumber = moduleNumber;
	}

	/**
	 * Constructor. The starting offset is set to zero.
	 * @param symbolsByOffset the Map used to initialize the constructor.
	 * @param moduleNumber The Module number corresponding to the initializing Map
	 * (0 for public/global Map).
	 */
	public SymbolGroup(Map<Long, AbstractMsSymbol> symbolsByOffset, int moduleNumber) {
		this(symbolsByOffset, moduleNumber, 0);
	}

	/**
	 * Constructor.
	 * @param symbolsByOffset the Map used to initialize the constructor.
	 * @param moduleNumber The Module number corresponding to the initializing Map
	 * (0 (PUBLIC_GLOBAL_MODULE_NUMBER) for public/global).
	 * @param offset the offset location to start.
	 */
	public SymbolGroup(Map<Long, AbstractMsSymbol> symbolsByOffset, int moduleNumber, long offset) {
		this.symbolsByOffset = symbolsByOffset;
		this.moduleNumber = moduleNumber;
		initOffsets();
	}

	/**
	 * Returns the list of symbols.  These may not be in the order that they were seen.
	 * @return the list of symbols.
	 */
	List<AbstractMsSymbol> getSymbols() {
		return new ArrayList<>(symbolsByOffset.values());
	}

	/**
	 * Returns the module number.
	 * @return the module number.
	 */
	int getModuleNumber() {
		return moduleNumber;

	}

	/**
	 * Returns the number of symbols.
	 * @return the number of symbols.
	 */
	int size() {
		return symbolsByOffset.size();
	}

	/**
	 * Returns the list of symbol offsets in the order they were seen.
	 * @return the list of symbol offsets.
	 */
	List<Long> getOrderedOffsets() {
		return new ArrayList<>(symbolsByOffset.keySet());
	}

	/**
	 * Returns the set of symbol offsets.
	 * @return the set of symbol offsets.
	 */
	Set<Long> getOffsets() {
		return symbolsByOffset.keySet();
	}

	/**
	 * Returns the list of symbols in the order they were seen.
	 * @return the list of symbols.
	 */
	List<AbstractMsSymbol> getOrderedSymbols() {
		List<AbstractMsSymbol> symbols = new ArrayList<>();
		for (long offset : offsets) {
			symbols.add(symbolsByOffset.get(offset));
		}
		return symbols;
	}

	/**
	 * Initialized the offsets list used for requesting the symbols in sequence.
	 */
	private void initOffsets() {
		offsets = new ArrayList<>();
		indexByOffset = new HashMap<>();
		int index = 0;
		for (Map.Entry<Long, AbstractMsSymbol> entry : symbolsByOffset.entrySet()) {
			offsets.add(index, entry.getKey());
			indexByOffset.put(entry.getKey(), index++);
		}
	}

	/**
	 * Debug method for dumping the symbol group
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dump(Writer writer) throws IOException {
		writer.write("SymbolGroup-------------------------------------------------");
		for (Map.Entry<Long, AbstractMsSymbol> entry : symbolsByOffset.entrySet()) {
			StringBuilder builder = new StringBuilder();
			builder.append("\n------------------------------------------------------------\n");
			builder.append(String.format("Offset: 0X%08X\n", entry.getKey()));
			builder.append(entry.getValue());
			writer.write(builder.toString());
		}
		writer.write("\nEnd SymbolGroup---------------------------------------------\n");
	}

	//==============================================================================================
	public MsSymbolIterator getSymbolIterator() throws PdbException {
		int streamNumber;
		int startingOffset;
		int lengthSymbols;
		if (moduleNumber == 0) {
			streamNumber = pdb.getDebugInfo().getSymbolRecordsStreamNumber();
			startingOffset = 0;
			lengthSymbols = Integer.MAX_VALUE;
		}
		else {
			ModuleInformation moduleInfo =
				pdb.getDebugInfo().getModuleInformation(moduleNumber);
			streamNumber = moduleInfo.getStreamNumberDebugInformation();
			lengthSymbols = moduleInfo.getSizeLocalSymbolsDebugInformation();
			try {
				startingOffset = pdb.getDebugInfo().getSymbolRecords().getCvSigLength(streamNumber);
			}
			catch (CancelledException e) {
				startingOffset = 0;
				lengthSymbols = 0; // essentially null out iterator with zero length
			}
		}
		return new MsSymbolIterator(pdb, streamNumber, startingOffset, lengthSymbols);
	}

	//==============================================================================================

}
