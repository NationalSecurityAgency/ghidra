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
import ghidra.util.exception.CancelledException;

/**
 * <B> Note that this class is new, in-progress creation, being designed as a better interface for
 * getting information for any particular module (stream) in a more random-access manner.</B>
 * <P>
 * This class represents Module Stream data of a PDB file.  This is different from the
 * {@link ModuleInformation} and children classes that are parsed from the DBI stream,
 * which describes (or is control information for) what is the stream from which this
 * {@link Module} is parsed.  Note that we use the {@link ModuleInformation} as one of
 * the construction parameter to this class.
 * <P>
 * This class is only suitable for reading; not for writing or modifying a PDB.
 * <P>
 * We have intended to implement according to the Microsoft PDB API (source); see the API for
 * truth.
 */
public class Module {

	private AbstractPdb pdb;
	private ModuleInformation moduleInformation;

	private int streamNumber;
	private MsfStream stream = null;

	private int offsetSymbols;
	private int offsetLines;
	private int offsetC13Lines;
	private int offsetGlobalRefs;

	private int sizeSymbols;
	private int sizeLines;
	private int sizeC13Lines;
	private int sizeGlobalRefs;

	private boolean doDumpGlobalRefererenceInfo = false;

	//==============================================================================================
	public Module(AbstractPdb pdb, ModuleInformation moduleInformation) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		Objects.requireNonNull(moduleInformation, "moduleInformation cannot be null");
		this.pdb = pdb;
		this.moduleInformation = moduleInformation;
		precalculateStreamLocations();
	}

	public ModuleInformation getModuleInformation() {
		return moduleInformation;
	}

	private void precalculateStreamLocations() {
		streamNumber = moduleInformation.getStreamNumberDebugInformation();
		if (streamNumber == 0xffff) {
			return;
		}
		stream = pdb.getMsf().getStream(streamNumber);
		if (stream == null) {
			return;
		}
		int length = stream.getLength();

		sizeSymbols = moduleInformation.getSizeLocalSymbolsDebugInformation();
		sizeLines = moduleInformation.getSizeLineNumberDebugInformation();
		sizeC13Lines = moduleInformation.getSizeC13StyleLineNumberInformation();

		offsetSymbols = 0;
		offsetLines = sizeSymbols;
		offsetC13Lines = offsetLines + sizeLines;
		offsetGlobalRefs = offsetC13Lines + sizeC13Lines;
		// Note that sizeGlobalRefs includes the size field found within the stream and the field
		// should have a value that is 4 less than this size here.  Note that if additional
		// data is added to this stream by MSFT after these global at a future date, then this
		// calculation will not be correct.
		sizeGlobalRefs = length - offsetGlobalRefs;
	}

	//==============================================================================================
	/**
	 * Return the C11 Lines for this Module
	 * @return the C11 Lines
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon issue reading this Module's stream
	 */
	public C11Lines getLineInformation()
			throws CancelledException, PdbException {
		if (sizeLines == 0) {
			return null;
		}
		try {
			PdbByteReader reader =
				pdb.getReaderForStreamNumber(streamNumber, offsetLines, sizeLines);
			// This parser has not been tested with real data
			C11Lines c11Lines = C11Lines.parse(pdb, reader);
			return c11Lines;
		}
		catch (IOException e) {
			return null;
		}
	}

	//==============================================================================================
	/**
	 * Returns an MsSymbolIterator for the symbols of this module
	 * @return the iterator
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon invalid cvSignature
	 */
	public MsSymbolIterator getSymbolIterator() throws CancelledException, PdbException {
		PdbByteReader symbolsReader = getSymbolsReader();
		parseSignature(symbolsReader);
		MsSymbolIterator iterator = new MsSymbolIterator(pdb, symbolsReader);
		return iterator;
	}

	private void parseSignature(PdbByteReader symbolsReader) throws PdbException {
		if (symbolsReader == PdbByteReader.DUMMY) {
			return; // DUMMY is empty.
		}
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

		// NOTE: the following logic was originally intended for when processing multiple modules,
		// back-to-back.  It won't work here, as the getSig value is not retained.  Thing is, we
		// have no real data to test the questionable requirement (what we think was in MSFT
		// design) at this time.
		boolean getSig = true;
		int cvSignature = 0;
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
						"PDB Error: Invalid module CV signature in stream " + streamNumber);
				}
				break;
		}

	}

	//==============================================================================================
	/**
	 * Returns a C13SectionIterator that iterators over all C13Sections of this module
	 * @return the iterator
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	public C13SectionIterator<C13Section> getC13SectionIterator()
			throws CancelledException, PdbException {
		C13SectionIterator<C13Section> iterator = getC13SectionFilteredIterator(C13Section.class);
		return iterator;
	}

	/**
	 * Returns a C13SectionIterator that iterators over all filtered C13Sections of this module
	 * @param clazz The class of the filter type
	 * @return the iterator
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	public <T extends C13Section> C13SectionIterator<T> getC13SectionFilteredIterator(
			Class<T> clazz) throws CancelledException, PdbException {
		PdbByteReader c13SectionReader = getC13LinesReader();
		C13SectionIterator<T> iterator =
			new C13SectionIterator<>(c13SectionReader, clazz, true, pdb.getMonitor());
		return iterator;
	}

	//==============================================================================================
	/**
	 * Returns a GlobalReferenceOffsetIterator, but note that there is no determined end for
	 * iteration other than running out of data... it is very unlikely that it should be iterated
	 * until it is out of data.  Context should probably be used.  For instance, if the global
	 * symbol that is first in this iterator is a GPROC32, then it should probably be iterated over
	 * nested blocks until the closing END is found for the GPROC32
	 * @return the iterator
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	public GlobalReferenceOffsetIterator getGlobalReferenceOffsetIterator()
			throws CancelledException, PdbException {
		PdbByteReader globalRefsReader = getGlobalRefsReader();
		GlobalReferenceOffsetIterator iterator =
			new GlobalReferenceOffsetIterator(globalRefsReader);
		return iterator;
	}

	//==============================================================================================
	/**
	 * Returns a GlobalReferenceIterator.  Iterations of the GlobalReferenceIterator returns
	 * new MsSymbolIterators, but note that there is no determined end for each MsSymbolIterator
	 * other than running out of data... it is very unlikely that it should be iterated until
	 * it is out of data.  Context should probably be used.  For instance, if the global symbol
	 * that is first in this iterator is a GPROC32, then it should probably be iterated over
	 * nested blocks until the closing END is found for the GPROC32
	 * @return the iterator
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	public GlobalReferenceIterator getGlobalReferenceIterator()
			throws CancelledException, PdbException {
		PdbByteReader globalRefsReader = getGlobalRefsReader();
		GlobalReferenceIterator iterator =
			new GlobalReferenceIterator(pdb, globalRefsReader);
		return iterator;
	}

	//==============================================================================================
	private PdbByteReader getSymbolsReader() throws CancelledException {
		return getReader(offsetSymbols, sizeSymbols, "Symbols");
	}

	// Not yet used, but intended for when we change C11 Lines to the iterator model.
	@SuppressWarnings("unused")
	private PdbByteReader getLinesReader() throws CancelledException {
		return getReader(offsetLines, sizeLines, "Lines");
	}

	private PdbByteReader getC13LinesReader() throws CancelledException {
		return getReader(offsetC13Lines, sizeC13Lines,
			"C13Lines");
	}

	private PdbByteReader getGlobalRefsReader() throws CancelledException {
		return getReader(offsetGlobalRefs, sizeGlobalRefs, "GlobalRefs");
	}

	private PdbByteReader getReader(int offset, int size, String sectionName)
			throws CancelledException {
		if (streamNumber == 0xffff) {
			return PdbByteReader.DUMMY;
		}

		try {
			PdbByteReader reader = pdb.getReaderForStreamNumber(streamNumber);
			reader.skip(offset);
			try {
				if (size == -1) {
					size = reader.parseInt();
				}
				if (size == 0) {
					return PdbByteReader.DUMMY;
				}
				return reader.getSubPdbByteReader(size);
			}
			catch (PdbException e) {
				PdbLog.message("Exception retrieving PdbByteReader for stream " + streamNumber +
					" sectionName: " + e.getMessage());
				return PdbByteReader.DUMMY;
			}
		}
		catch (IOException e) {
			PdbLog.message("Exception sub-reader from reader for stream " + streamNumber +
				" sectionName: " + e.getMessage());
			return PdbByteReader.DUMMY;
		}

	}

	//==============================================================================================
	// Note that we are slowly changing the model to an iterator model so that not everything
	// is loaded into the class (note that as of this writing, the PdbByteReader still contains
	// full byte array of data, consuming memory at the time of use).
	/**
	 * Dumps this class to a Writer
	 * @param writer {@link Writer} to which to dump the information
	 * @throws PdbException upon not enough data left to parse
	 * @throws CancelledException upon user cancellation
	 * @throws IOException upon IOException writing to the {@link Writer}
	 */
	void dump(Writer writer)
			throws CancelledException, PdbException, IOException {

		writer.write("Module------------------------------------------------------\n");

		dumpSymbols(writer);
		dumpC11Lines(writer);
		dumpC13Sections(writer);

		// These can add tons of output, so have a flag to control whether they are output.
		if (doDumpGlobalRefererenceInfo) {
			dumpGlobalReferenceOffsets(writer);
			dumpGlobalReferences(writer);
		}

		writer.write("End Module--------------------------------------------------\n");
	}

	private void dumpSymbols(Writer writer)
			throws IOException, CancelledException, PdbException {
		writer.write("Symbols-----------------------------------------------------\n");
		MsSymbolIterator symbolIterator = getSymbolIterator();
		while (symbolIterator.hasNext()) {
			pdb.checkCancelled();
			AbstractMsSymbol symbol = symbolIterator.next();
			writer.append(symbol.toString());
			writer.append("\n");
		}
		writer.write("End Symbols-------------------------------------------------\n");
	}

	private void dumpC11Lines(Writer writer)
			throws IOException, CancelledException, PdbException {
		// Need to confirm C11 parsing and then convert it to an Iterator model; would be very
		// helpful to find some real data
		writer.write("C11Lines----------------------------------------------------\n");
		C11Lines c11lines = getLineInformation();
		if (c11lines != null) {
			writer.write(c11lines.dump());
		}
		writer.write("End C11Lines------------------------------------------------\n");
	}

	private void dumpC13Sections(Writer writer)
			throws IOException, CancelledException, PdbException {
		writer.write("C13Sections-------------------------------------------------\n");
		C13SectionIterator<C13Section> c13Iterator =
			getC13SectionFilteredIterator(C13Section.class);
		while (c13Iterator.hasNext()) {
			pdb.checkCancelled();
			C13Section c13Section = c13Iterator.next();
			c13Section.dump(writer);
		}
		writer.write("End C13Sections---------------------------------------------\n");

		// These are here as examples of what we might output in the future... the C13 types
		// in a type-by-type basis, including Dummy types.
//		C13SectionIterator<DummyC13Symbols> c13SymbolsIterator =
//			getC13SectionFilteredIterator(DummyC13Symbols.class);
//		while (c13SymbolsIterator.hasNext()) {
//			pdb.checkCancelled();
//			DummyC13Symbols dummyC13Symbols = c13SymbolsIterator.next();
//			dummyC13Symbols.dump(writer);
//		}
//
//		C13SectionIterator<C13Lines> c13LinesIterator =
//			getC13SectionFilteredIterator(C13Lines.class);
//		while (c13LinesIterator.hasNext()) {
//			pdb.checkCancelled();
//			C13Lines myC13Lines = c13LinesIterator.next();
//			myC13Lines.dump(writer);
//		}
	}

	// Need to confirm the global ref offsets and symbols by "study."
	private void dumpGlobalReferenceOffsets(Writer writer)
			throws IOException, CancelledException, PdbException {
		writer.write("GlobalReferenceSymbolOffsets--------------------------------\n");
		List<Long> tmp = new ArrayList<>();
		GlobalReferenceOffsetIterator globalRefsOffsetIterator =
			getGlobalReferenceOffsetIterator();
		while (globalRefsOffsetIterator.hasNext()) {
			pdb.checkCancelled();
			Long val = globalRefsOffsetIterator.next();
			writer.append(String.format("0x%08x\n", val));
			tmp.add(val);
		}
		int cnt = 0;
		GlobalReferenceOffsetIterator globalReferenceOffsetIterator =
			getGlobalReferenceOffsetIterator();
		while (globalReferenceOffsetIterator.hasNext()) {
			long val = globalReferenceOffsetIterator.next();
			long val2 = tmp.get(cnt++);
			if (val != val2) {
				int a = 1;
				a = a + 1;
			}
		}
		writer.write("End GlobalReferenceSymbolOffsets----------------------------\n");
	}

	// Need to confirm the global ref offsets and symbols by "study."
	private void dumpGlobalReferences(Writer writer)
			throws IOException, CancelledException, PdbException {
		writer.write("GlobalReferenceSymbols--------------------------------------\n");
		GlobalReferenceIterator globalReferenceIterator =
			getGlobalReferenceIterator();
		while (globalReferenceIterator.hasNext()) {
			pdb.checkCancelled();
			MsSymbolIterator symIter = globalReferenceIterator.next();
			if (symIter.hasNext()) {
				AbstractMsSymbol sym = symIter.next();
				writer.append(String.format("%s\n", sym.toString()));
			}
			else {
				writer.append("No sym in MsSymIterator returned by GlobalReferensIterator\n");
			}
		}
		writer.write("End GlobalReferenceSymbols----------------------------------\n");
	}

}
