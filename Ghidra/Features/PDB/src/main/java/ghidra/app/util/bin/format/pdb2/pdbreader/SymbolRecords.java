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
import ghidra.util.task.TaskMonitor;

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
	 * Constructor.
	 * @param pdb {@link AbstractPdb} to which the {@link SymbolRecords} belong.
	 */
	public SymbolRecords(AbstractPdb pdb) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
	}

	/**
	 * Returns the list of symbols.
	 * @return {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols.
	 */
	protected Map<Long, AbstractMsSymbol> getSymbolsByOffset() {
		return symbolsByOffset;
	}

	/**
	 * Returns the buffer-offset-to-symbol map for the module as specified by moduleNumber.
	 * @param moduleNumber The number ID of the module for which to return the list.
	 * @return {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols for the specified module.
	 */
	protected Map<Long, AbstractMsSymbol> getModuleSymbolsByOffset(int moduleNumber) {
		return moduleSymbolsByOffset.get(moduleNumber);
	}

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

		streamNumber = pdb.getDebugInfo().getSymbolRecordsStreamNumber();
		reader = pdb.getReaderForStreamNumber(streamNumber, monitor);
		symbolsByOffset = deserializeSymbolRecords(reader, monitor);

		for (AbstractModuleInformation module : pdb.getDebugInfo().moduleInformationList) {
			streamNumber = module.getStreamNumberDebugInformation();
			if (streamNumber != 0xffff) {
//				System.out.println("\n\nStreamNumber: " + streamNumber);
				reader = pdb.getReaderForStreamNumber(streamNumber, monitor);
				int x = reader.parseInt(); // TODO: do not know what this value is.
				int sizeDebug = module.getSizeLocalSymbolsDebugInformation();
				sizeDebug -= x; //TODO: seems right, but need to evaluate this
				PdbByteReader debugReader = reader.getSubPdbByteReader(sizeDebug);
				Map<Long, AbstractMsSymbol> oneModuleSymbolsByOffset =
					deserializeSymbolRecords(debugReader, monitor);
				moduleSymbolsByOffset.add(oneModuleSymbolsByOffset);
				// TODO: figure out the rest of the bytes in the stream
				// As of 20190618: feel that this is where we will find C11Lines or C13Lines
				// information.
//				PdbByteReader rest = reader.getSubPdbByteReader(reader.numRemaining());
//				System.out.println(rest.dump());
			}
			else {
				moduleSymbolsByOffset.add(new TreeMap<>());
			}
		}

	}

	/**
	 * Deserializes the {@link AbstractMsSymbol} symbols from the {@link PdbByteReader} and
	 * returns a {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols.
	 * @param reader {@link PdbByteReader} containing the symbol records to deserialize.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @return map of buffer offsets to {@link AbstractMsSymbol symbols}.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	public Map<Long, AbstractMsSymbol> deserializeSymbolRecords(PdbByteReader reader,
			TaskMonitor monitor) throws PdbException, CancelledException {
		//System.out.println(reader.dump(0x400));
		SymbolParser parser = pdb.getSymbolParser();
		Map<Long, AbstractMsSymbol> mySymbolsByOffset = new TreeMap<>();
		while (reader.hasMore()) {
			monitor.checkCanceled();

			// Including length in byte array for alignment purposes. 
			int offset = reader.getIndex();
			int recordLength = reader.parseUnsignedShortVal();

			PdbByteReader recordReader = reader.getSubPdbByteReader(recordLength);
			recordReader.markAlign(2);
			AbstractMsSymbol symbol = parser.parse(recordReader);
			mySymbolsByOffset.put((long) offset, symbol);
		}
		return mySymbolsByOffset;
	}

	/**
	 * Debug method for dumping information from this Symbol Records instance.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dump(Writer writer) throws IOException {
		writer.write("SymbolRecords-----------------------------------------------\n");
		dumpSymbolMap(symbolsByOffset, writer);
		for (int i = 0; i < moduleSymbolsByOffset.size(); i++) {
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
	 * @param mySymbolsByOffset the {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; to dump.
	 * @param writer {@link Writer} to which to dump the information.
	 * @throws IOException Upon IOException writing to the {@link Writer}.
	 */
	protected void dumpSymbolMap(Map<Long, AbstractMsSymbol> mySymbolsByOffset, Writer writer)
			throws IOException {
		writer.write("SymbolMap---------------------------------------------------");
		for (Map.Entry<Long, AbstractMsSymbol> entry : mySymbolsByOffset.entrySet()) {
			StringBuilder builder = new StringBuilder();
			builder.append("\n------------------------------------------------------------\n");
			builder.append(String.format("Offset: 0X%08X\n", entry.getKey()));
			builder.append(entry.getValue());
			writer.write(builder.toString());
		}
		writer.write("\nEnd SymbolMap-----------------------------------------------\n");
	}

}
