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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.io.IOException;
import java.io.Writer;
import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.exception.CancelledException;

/**
 * This class represents Symbol Records component of a PDB file.  This class is only
 *  suitable for reading; not for writing or modifying a PDB.
 *  <P>
 *  We have intended to implement according to the Microsoft PDB API (source); see the API for
 *   truth.
 */
public class SymbolRecords {

	private AbstractPdb pdb;
	private Map<Long, AbstractMsSymbol> symbolsByOffset;
	private List<Map<Long, AbstractMsSymbol>> moduleSymbolsByOffset = new ArrayList<>();

	/**
	 * Constructor
	 * @param pdb {@link AbstractPdb} to which the {@link SymbolRecords} belong
	 */
	public SymbolRecords(AbstractPdb pdb) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
	}

	/**
	 * Returns the list of symbols
	 * @return {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols
	 */
	protected Map<Long, AbstractMsSymbol> getSymbolsByOffset() {
		return symbolsByOffset;
	}

	/**
	 * Returns the buffer-offset-to-symbol map for the module as specified by moduleNumber
	 * @param moduleNumber the number ID of the module for which to return the list
	 * @return {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols for the specified module
	 */
	protected Map<Long, AbstractMsSymbol> getModuleSymbolsByOffset(int moduleNumber) {
		return moduleSymbolsByOffset.get(moduleNumber);
	}

	/**
	 * Deserializes the {@link SymbolRecords} from the stream noted in the DBI header
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	void deserialize() throws IOException, PdbException, CancelledException {
		processSymbols();
		processModuleSymbols();
	}

	private void processSymbols()
			throws IOException, PdbException, CancelledException {
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}
		int streamNumber = debugInfo.getSymbolRecordsStreamNumber();
		if (streamNumber <= 0) {
			return;
		}
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber);
		symbolsByOffset = deserializeSymbolRecords(pdb, reader);
	}

	// Could split this method up into separate methods: one for module symbols and the other for
	// Lines processing.  Note: would be processing streams more than once; lines would need to
	// skip over the symbols.
	private void processModuleSymbols()
			throws IOException, PdbException, CancelledException {
		// cvSignature:
		// >64K = C6
		// 1 = C7
		// 2 = C11 (vc5.x)
		// 3 = ??? (not specified, and not marked as reserved)
		// 4 = C13 (vc7.x)
		// 5-64K = RESERVED
		//
		// Both cvdump (1660 and 1668) and mod.cpp (575) seem to indicate that the first module
		// might have the cvSignature of C7 or C11 (when C7/C11), but modules thereafter will not
		// or may not have the value.  C13 would always have the C13 signature.
		boolean getSig = true;
		int cvSignature = 0;
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}

		for (ModuleInformation module : debugInfo.moduleInformationList) {
			pdb.checkCancelled();
			int streamNumber = module.getStreamNumberDebugInformation();
			if (streamNumber == 0xffff) {
				moduleSymbolsByOffset.add(new TreeMap<>());
				continue;
			}

			PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber);

			int sizeSymbolsSection = module.getSizeLocalSymbolsDebugInformation();
			PdbByteReader symbolsReader = reader.getSubPdbByteReader(sizeSymbolsSection);
			// See comment above regarding getSig boolean
			if (getSig) {
				cvSignature = symbolsReader.parseInt();
			}
			switch (cvSignature) {
				case 1:
				case 2:
					// We have no 1,2 examples to test this logic for cvSignature.  Confirming
					// or rejecting this logic is important for simplifying/refactoring this
					// method or writing new methods to allow for extraction of information from
					// individual modules.  The current implementation has cross-module logic
					// (setting state in the processing of the first and using this state in the
					// processing of follow-on modules).
					getSig = false;
					break;
				case 4:
					break;
				default:
					if (cvSignature < 0x10000) {
						throw new PdbException(
							"Invalid module CV signature in stream " + streamNumber);
					}
					break;
			}

			Map<Long, AbstractMsSymbol> oneModuleSymbolsByOffset =
				deserializeSymbolRecords(pdb, symbolsReader);
			moduleSymbolsByOffset.add(oneModuleSymbolsByOffset);
		}
	}

	/**
	 * Deserializes the {@link AbstractMsSymbol} symbols from the {@link PdbByteReader} and
	 * returns a {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols
	 * @param pdb {@link AbstractPdb} that owns the Symbols to be parsed
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize
	 * @return map of buffer offsets to {@link AbstractMsSymbol symbols}
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	public static Map<Long, AbstractMsSymbol> deserializeSymbolRecords(AbstractPdb pdb,
			PdbByteReader reader) throws PdbException, CancelledException {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		//System.out.println(reader.dump(0x400));
		Map<Long, AbstractMsSymbol> mySymbolsByOffset = new TreeMap<>();
		while (reader.hasMore()) {
			pdb.checkCancelled();

			// Including length in byte array for alignment purposes.
			int offset = reader.getIndex();
			AbstractMsSymbol symbol = SymbolParser.parseLengthAndSymbol(pdb, reader);
			mySymbolsByOffset.put((long) offset, symbol);
		}
		return mySymbolsByOffset;
	}

	/**
	 * Debug method for dumping information from this Symbol Records instance
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException upon issue writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 */
	protected void dump(Writer writer) throws IOException, CancelledException {
		writer.write("SymbolRecords-----------------------------------------------\n");
		dumpSymbolMap(symbolsByOffset, writer);
		for (int i = 0; i < moduleSymbolsByOffset.size(); i++) {
			pdb.checkCancelled();
			Map<Long, AbstractMsSymbol> map = moduleSymbolsByOffset.get(i);
			if (map != null) {
				writer.write("Module(" + i + ") List:\n");
				dumpSymbolMap(map, writer);
			}
		}
		writer.write("\nEnd SymbolRecords-------------------------------------------\n");
	}

	/**
	 * Debug method for dumping the symbols from a symbol map
	 * @param mySymbolsByOffset the {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; to dump
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException upon issue writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 */
	protected void dumpSymbolMap(Map<Long, AbstractMsSymbol> mySymbolsByOffset, Writer writer)
			throws IOException, CancelledException {
		writer.write("SymbolMap---------------------------------------------------");
		for (Map.Entry<Long, AbstractMsSymbol> entry : mySymbolsByOffset.entrySet()) {
			pdb.checkCancelled();
			StringBuilder builder = new StringBuilder();
			builder.append("\n------------------------------------------------------------\n");
			builder.append(String.format("Offset: 0X%08X\n", entry.getKey()));
			builder.append(entry.getValue());
			writer.write(builder.toString());
		}
		writer.write("\nEnd SymbolMap-----------------------------------------------\n");
	}

}
