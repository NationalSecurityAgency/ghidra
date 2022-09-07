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

import java.util.NoSuchElementException;

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Iterator for {@link AbstractMsSymbol AbstractMsSymbols} being read from a stream.
 */
class MsSymbolIterator implements ParsingIterator<AbstractMsSymbol> {

	private AbstractPdb pdb;
	private PdbByteReader reader;

	private AbstractMsSymbol currentSymbol = null;

	/**
	 * Constructor.
	 * @param pdb {@link AbstractPdb} that owns the Symbols to be parsed
	 * @param reader for the stream section containing the symbol information
	 * @throws CancelledException upon user cancellation
	 */
	public MsSymbolIterator(AbstractPdb pdb, PdbByteReader reader) throws CancelledException {
		this.pdb = pdb;
		this.reader = reader;
	}

	@Override
	public boolean hasNext() throws CancelledException {
		if (currentSymbol == null) {
			find();
		}
		return (currentSymbol != null);
	}

	@Override
	public AbstractMsSymbol next() throws CancelledException, NoSuchElementException {
		if (hasNext()) {
			AbstractMsSymbol returnSymbol = currentSymbol;
			currentSymbol = null;
			return returnSymbol;
		}
		throw new NoSuchElementException("next() called with no more elements");
	}

	@Override
	public AbstractMsSymbol peek() throws CancelledException, NoSuchElementException {
		if (hasNext()) {
			return currentSymbol;
		}
		throw new NoSuchElementException("peek() called with no more elements");
	}

	private void find() throws CancelledException {
		if (!reader.hasMore()) {
			currentSymbol = null;
			return;
		}
		try {
			currentSymbol = SymbolParser.parseLengthAndSymbol(pdb, reader);
		}
		catch (PdbException e) {
			Msg.error(this, "Problem seen in find()", e);
			currentSymbol = null;
		}
	}

}
