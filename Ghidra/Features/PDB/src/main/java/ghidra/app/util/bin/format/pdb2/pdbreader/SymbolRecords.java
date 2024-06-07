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

import ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfStream;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.datastruct.LRUMap;
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

	// Used for CvSig part of streams.  See methods below.
	private boolean getSig = true;
	private int cvSignature = -1;
	private int cvSignatureCase1and2Stream = MsfStream.NIL_STREAM_NUMBER;

	// Used for caching symbol records
	private double factor;
	private Map<Integer, LRUMap<Integer, SymLen>> symbolCache;

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
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	@Deprecated
	protected Map<Long, AbstractMsSymbol> getSymbolsByOffset()
			throws CancelledException, PdbException, IOException {
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return new TreeMap<>();
		}
		int streamNumber = debugInfo.getSymbolRecordsStreamNumber();
		if (streamNumber <= 0) {
			return new TreeMap<>();
		}
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber);
		return deserializeSymbolRecords(pdb, reader);
	}

	/**
	 * Returns the buffer-offset-to-symbol map for the module as specified by moduleNumber
	 * @param moduleNumber the number ID of the module for which to return the list
	 * @return {@link Map}&lt;{@link Long},{@link AbstractMsSymbol}&gt; of buffer offsets to
	 * symbols for the specified module
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	@Deprecated
	protected Map<Long, AbstractMsSymbol> getModuleSymbolsByOffset(int moduleNumber)
			throws CancelledException, IOException, PdbException {
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return new TreeMap<>();
		}
		ModuleInformation moduleInfo = debugInfo.moduleInformationList.get(moduleNumber);
		int streamNumber = moduleInfo.getStreamNumberDebugInformation();
		if (streamNumber == MsfStream.NIL_STREAM_NUMBER) {
			return new TreeMap<>();
		}
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber);
		int sizeSymbolsSection = moduleInfo.getSizeLocalSymbolsDebugInformation();
		PdbByteReader symbolsReader = reader.getSubPdbByteReader(sizeSymbolsSection);
		symbolsReader.skip(getCvSigLength(streamNumber));
		return deserializeSymbolRecords(pdb, symbolsReader);
	}

	/**
	 * Deserializes and initializes basic {@link SymbolRecords} information from the stream noted
	 * in the DBI header so that later symbol queries can be done
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 */
	void initialize() throws IOException, PdbException, CancelledException {
		initializeCache(0.001);
		determineCvSigValues(); // new method for random-access symbol work
	}

	// These methods are trying to adapt the logic of the previous method here (which attempted
	//  to capture the logic of the original MSFT design) to the new random access
	//  model.  However, the logic was never verified with other/older PDBs to know if the
	//  signature was only seen on the first module stream.  So, we really do not know if we
	//  should continue with this logic or not.
	//
	// Following is comment from the method that has been replaced, which might still be applicable:
	//
	// Could split this method up into separate methods: one for module symbols and the other for
	// Lines processing.  Note: would be processing streams more than once; lines would need to
	// skip over the symbols.
	private void determineCvSigValues() throws CancelledException, IOException, PdbException {
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}
		// We are assuming that first in the list is the one to look at for cases 1 and 2.
		//  If something else like lowest stream number, then need to change the logic.
		ModuleInformation moduleInfo = debugInfo.getModuleInformationList().get(0);
		int streamNumber = moduleInfo.getStreamNumberDebugInformation();
		if (streamNumber == MsfStream.NIL_STREAM_NUMBER) {
			return;
		}
		PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber);
		// Skipping pulling out of sub-reader for symbols, as symbols stuff is first.
		if (getSig) {
			cvSignature = reader.parseInt();
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
		cvSignatureCase1and2Stream = streamNumber;
	}

	/**
	 * Returns the space occupied by the cvSignature for the stream number
	 * @param streamNumber the stream number
	 * @return the space
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon processing error
	 */
	public int getCvSigLength(int streamNumber)
			throws CancelledException, PdbException {
		if (streamNumber == MsfStream.NIL_STREAM_NUMBER) {
			return 0; // returning inconsequential value; fact of NIL will be dealt with elsewhere
		}
		PdbByteReader reader;
		try {
			reader = pdb.getReaderForStreamNumber(streamNumber, 0, 4);
		}
		catch (IOException e) {
			throw new PdbException("PDB Error: Not enough data to read CvSigLength");
		}
		if (getSig) {
			cvSignature = reader.parseInt();
		}
		int size = 0;
		switch (cvSignature) {
			case 1:
			case 2:
				if (streamNumber == cvSignatureCase1and2Stream) {
					size = 4;
				}
				// else size remains 0
				break;
			case 4:
				size = 4;
				break;
			default:
				throw new PdbException("PDB Error: Bad CvSigLength state");
		}
		return size;
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

	public record SymLen(AbstractMsSymbol symbol, int length) {}

	/**
	 * Returns the symbol at the offset of the stream assigned to the module
	 * @param moduleNumber the module
	 * @param offset the stream offset
	 * @return the PDB symbol
	 * @throws PdbException upon moduleNumber out of range or no module information
	 * @throws CancelledException upon user cancellation
	 */
	public SymLen getRandomAccessRecordUsingModuleNumber(int moduleNumber, int offset)
			throws PdbException, CancelledException {
		ModuleInformation moduleInfo = pdb.getDebugInfo().getModuleInformation(moduleNumber);
		int streamNumber = moduleInfo.getStreamNumberDebugInformation();
		if (streamNumber == MsfStream.NIL_STREAM_NUMBER) {
			return null;
		}
		return getRandomAccessRecord(streamNumber, offset);
	}

	// TODO: consider pre-storing the lengths with one build stream read.  However, that would
	//  consume more memory, so only do this if willing to improve process performance at
	//  cost of memory.
	//Map<Long, Integer> recordLengths = new TreeMap<>();

	/**
	 * Returns the symbol at the offset of the stream
	 * @param streamNumber the stream
	 * @param offset the stream offset
	 * @return the PDB symbol
	 * @throws PdbException upon moduleNumber out of range or no module information
	 * @throws CancelledException upon user cancellation
	 */
	public SymLen getRandomAccessRecord(int streamNumber, int offset)
			throws CancelledException, PdbException {
		// TODO: Further investigate caching for larger PDBs with other coming changes
//		LRUMap<Integer, SymLen> streamSymbolCache = getSymbolCache(streamNumber);
//		SymLen symLen = streamSymbolCache.get(offset);
//		if (symLen == null) {
//			symLen = getRandomAccessRecordFromStream(streamNumber, offset);
//			streamSymbolCache.put(offset, symLen);
//		}
//		return symLen;
		return getRandomAccessRecordFromStream(streamNumber, offset);
	}

	/**
	 * Returns the symbol at the offset of the stream
	 * @param streamNumber the stream
	 * @param offset the stream offset
	 * @return the PDB symbol
	 * @throws PdbException upon moduleNumber out of range or no module information
	 * @throws CancelledException upon user cancellation
	 */
	private SymLen getRandomAccessRecordFromStream(int streamNumber, int offset)
			throws CancelledException, PdbException {
		try {
			PdbByteReader reader;
			reader = pdb.getReaderForStreamNumber(streamNumber, offset, 2);
			int recordLength = reader.parseUnsignedShortVal();
			// offset + 2 where 2 is sizeof(short)
			PdbByteReader recordReader =
				pdb.getReaderForStreamNumber(streamNumber, offset + 2, recordLength);
			AbstractMsSymbol symbol = SymbolParser.parse(pdb, recordReader);
			return new SymLen(symbol, recordLength + 2);
		}
		catch (IOException e) {
			return null;
		}
	}

	private void initializeCache(double factorArg) {
		// See notes about factor where the value is used.
		this.factor = factorArg;
		symbolCache = new HashMap<>();
	}

	private LRUMap<Integer, SymLen> getSymbolCache(int streamNumber) {
		LRUMap<Integer, SymLen> streamSymbolCache = symbolCache.get(streamNumber);
		if (streamSymbolCache == null) {
			MsfStream stream = pdb.getMsf().getStream(streamNumber);
			if (stream == null) {
				return null;
			}
			// Note that stream length is in bytes; factor needs to deal with both ratio of
			//  bytes to average symbol record size and the sizing of the cache as a percentage
			//  of total number of symbol records in the stream.  We are adding a fixed number
			//  for a minimum size.
			int size = (int) (factor * stream.getLength() + 256);
			streamSymbolCache = new LRUMap<>(size);
			symbolCache.put(streamNumber, streamSymbolCache);
		}
		return streamSymbolCache;
	}

	/**
	 * Debug method for dumping information from this Symbol Records instance
	 * @param writer {@link Writer} to which to dump the information
	 * @throws IOException upon issue writing to the {@link Writer}
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data to parse
	 */
	protected void dump(Writer writer) throws IOException, CancelledException, PdbException {
		writer.write("SymbolRecords-----------------------------------------------\n");
		Map<Long, AbstractMsSymbol> symbolsByOffset = getSymbolsByOffset();
		dumpSymbolMap(symbolsByOffset, writer);
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			return;
		}
		for (int i = 0; i < debugInfo.getNumModules(); i++) {
			pdb.checkCancelled();
			Map<Long, AbstractMsSymbol> map = getModuleSymbolsByOffset(i);
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
