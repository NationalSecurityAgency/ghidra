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

import java.util.Iterator;
import java.util.NoSuchElementException;

import ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfStream;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup;
import ghidra.util.exception.CancelledException;

/**
 * Iterator for {@link SymbolGroup} that iterates through {@link AbstractMsSymbol
 * AbstractMsSymbols}
 */
public class MsSymbolIterator implements Iterator<AbstractMsSymbol> {

	private int streamNumber;
	private int startOffset;
	private SymbolRecords symbolRecords;
	private int lengthSymbols;
	private int nextRetrieveOffset;
	private int currentOffset;
	private SymbolRecords.SymLen symLen;

	public MsSymbolIterator(AbstractPdb pdb, int streamNumber, int startOffset, int lengthSymbols) {
		this.streamNumber = streamNumber;
		this.startOffset = startOffset;
		this.lengthSymbols = lengthSymbols;
		symbolRecords = pdb.getDebugInfo().getSymbolRecords();
		if (streamNumber == MsfStream.NIL_STREAM_NUMBER) {
			symLen = null;
			nextRetrieveOffset = 0;
			currentOffset = 0;
		}
		else {
			initGet();
		}
	}

	@Override
	public boolean hasNext() {
		return (symLen != null);
	}

	/**
	 * Peeks at and returns the next symbol without incrementing to the next.  If none are
	 * left, then throws NoSuchElementException and reinitializes the state for a new
	 * iteration.
	 * @see #initGet()
	 * @return the next symbol
	 * @throws NoSuchElementException if there are no more elements
	 */
	public AbstractMsSymbol peek() throws NoSuchElementException {
		if (symLen == null) {
			throw new NoSuchElementException();
		}
		return symLen.symbol();
	}

	@Override
	public AbstractMsSymbol next() {
		if (symLen == null) {
			throw new NoSuchElementException();
		}
		SymbolRecords.SymLen offer = symLen;
		currentOffset = nextRetrieveOffset;
		symLen = retrieveRecord();
		return offer.symbol();
	}

	private SymbolRecords.SymLen retrieveRecord() {
		if (streamNumber == MsfStream.NIL_STREAM_NUMBER) {
			return null;
		}
		if (nextRetrieveOffset >= lengthSymbols) {
			return null;
		}
		try {
			SymbolRecords.SymLen retrieved =
				symbolRecords.getRandomAccessRecord(streamNumber, nextRetrieveOffset);
			if (retrieved != null) {
				nextRetrieveOffset += retrieved.length();
			}
			return retrieved;
		}
		catch (PdbException | CancelledException e) {
			return null;
		}
	}

	/**
	 * Returns the next symbol.  If none are left, then throws NoSuchElementException and
	 * reinitializes the state for a new iteration.
	 * @see #initGet()
	 * @return the next symbol
	 * @throws NoSuchElementException if there are no more elements
	 */
	public long getCurrentOffset() {
		return currentOffset;
	}

	/**
	 * Initialized the mechanism for requesting the symbols in sequence.
	 * @see #hasNext()
	 */
	public void initGet() {
		if (streamNumber == MsfStream.NIL_STREAM_NUMBER) {
			return;
		}
		nextRetrieveOffset = startOffset;
		currentOffset = nextRetrieveOffset;
		symLen = retrieveRecord();
	}

	/**
	 * Initialized the mechanism for requesting the symbols in sequence.
	 * @param offset the offset to which to initialize the mechanism.
	 * @see #hasNext()
	 */
	public void initGetByOffset(long offset) {
		Long l = offset;
		nextRetrieveOffset = l.intValue();
		currentOffset = nextRetrieveOffset;
		symLen = retrieveRecord();
	}

	/**
	 * Returns the stream number
	 * @return the stream number
	 */
	public int getStreamNumber() {
		return streamNumber;
	}

}
