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
import java.util.NoSuchElementException;

import ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfStream;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Iterator for Global Reference Offsets section of module stream.  This iterator returns
 * an {@link AbstractMsSymbol} iterator from the global symbols section that has been initialized
 * with the offset specified in this modules global reference offset section.
 */
class GlobalReferenceIterator implements ParsingIterator<MsSymbolIterator> {

	private AbstractPdb pdb;
	private int symbolsStreamNumber;

	private GlobalReferenceOffsetIterator offsetIterator = null;

	private MsSymbolIterator currentGlobalSymbolIterator = null;

	/**
	 * An Iterator of Global Reference Symbol Iterators (iterator of iterators)
	 * @param pdb {@link AbstractPdb} that owns the Symbols to be parsed
	 * @param reader PdbByteReader containing only Global Reference Offsets information and in
	 * newly constructed state
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon not enough data left to parse
	 */
	public GlobalReferenceIterator(AbstractPdb pdb, PdbByteReader reader)
			throws CancelledException, PdbException {
		this.pdb = pdb;
		PdbDebugInfo debugInfo = pdb.getDebugInfo();
		if (debugInfo == null) {
			throw new PdbException(
				"Cannot create " + getClass() + " because PDB Debug Info is null");
		}
		symbolsStreamNumber = debugInfo.getSymbolRecordsStreamNumber();
		if (symbolsStreamNumber == 0xffff) {
			throw new PdbException(
				"Cannot create " + getClass() + " because there is no symbol stream");
		}
		offsetIterator = new GlobalReferenceOffsetIterator(reader);
	}

	@Override
	public boolean hasNext() throws CancelledException {
		if (currentGlobalSymbolIterator == null) {
			find();
		}
		return (currentGlobalSymbolIterator != null);
	}

	@Override
	public MsSymbolIterator next() throws CancelledException, NoSuchElementException {
		if (hasNext()) {
			MsSymbolIterator returnGlobalSymbolIterator = currentGlobalSymbolIterator;
			currentGlobalSymbolIterator = null;
			return returnGlobalSymbolIterator;
		}
		throw new NoSuchElementException("next() called with no more elements");
	}

	@Override
	public MsSymbolIterator peek() throws CancelledException, NoSuchElementException {
		if (hasNext()) {
			return currentGlobalSymbolIterator;
		}
		throw new NoSuchElementException("peek() called with no more elements");
	}

	private void find() throws CancelledException {

		if (!offsetIterator.hasNext()) {
			currentGlobalSymbolIterator = null;
			return;
		}
		try {
			Long offset = offsetIterator.next();
			PdbByteReader reader =
				pdb.getReaderForStreamNumber(symbolsStreamNumber, offset.intValue(),
					MsfStream.MAX_STREAM_LENGTH);
			currentGlobalSymbolIterator = new MsSymbolIterator(pdb, reader);
		}
		catch (IOException e) {
			Msg.error(this, "Problem seen in find()", e);
			currentGlobalSymbolIterator = null;
		}
	}

}
