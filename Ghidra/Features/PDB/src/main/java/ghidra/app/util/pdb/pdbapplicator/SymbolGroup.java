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

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;

/**
 * This class represents a particular group of Symbols that came from the same PDB stream.  This
 * wraps the internal structure and offers mechanisms for accessing records.  It does not map
 * directly to an MSFT structure.
 */
public class SymbolGroup {

	private Map<Long, AbstractMsSymbol> symbolsByOffset;
	private int moduleNumber;
	private List<Long> offsets;
	private Map<Long, Integer> indexByOffset;

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
	 * (0 for public/global Map).
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

	AbstractMsSymbolIterator iterator() {
		return new AbstractMsSymbolIterator();
	}

	//==============================================================================================
	/**
	 * Iterator for {@link SymbolGroup} that iterates through {@link AbstractMsSymbol
	 * AbstractMsSymbols}
	 */
	class AbstractMsSymbolIterator implements Iterator<AbstractMsSymbol> {

		private int nextIndex;
		private long currentOffset;

		public AbstractMsSymbolIterator() {
			nextIndex = 0;
			currentOffset = -1L;
		}

		@Override
		public boolean hasNext() {
			if (nextIndex == offsets.size()) {
				return false;
			}
			return true;
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
			if (nextIndex == offsets.size()) {
				throw new NoSuchElementException("none left");
			}
			long temporaryOffset = offsets.get(nextIndex);
			AbstractMsSymbol symbol = symbolsByOffset.get(temporaryOffset);
			if (symbol == null) {
				throw new NoSuchElementException("No symbol");
			}
			return symbol;
		}

		@Override
		public AbstractMsSymbol next() {
			if (nextIndex == offsets.size()) {
				throw new NoSuchElementException("none left");
			}
			currentOffset = offsets.get(nextIndex++);
			return symbolsByOffset.get(currentOffset);
		}

		/**
		 * Returns the next symbol.  If none are left, then throws NoSuchElementException and
		 * reinitializes the state for a new iteration.
		 * @see #initGet()
		 * @return the next symbol
		 * @throws NoSuchElementException if there are no more elements
		 */
		long getCurrentOffset() {
			return currentOffset;
		}

		/**
		 * Initialized the mechanism for requesting the symbols in sequence.
		 * @see #hasNext()
		 */
		void initGet() {
			nextIndex = 0;
		}

		/**
		 * Initialized the mechanism for requesting the symbols in sequence.
		 * @param offset the offset to which to initialize the mechanism.
		 * @see #hasNext()
		 */
		void initGetByOffset(long offset) {
			int index = indexByOffset.get(offset);
			if (index < 0) {
				index = 0;
			}
			nextIndex = index;
			currentOffset = offset;
		}

		// TODO: might not need this
		/**
		 * Returns the module number.
		 * @return the module number.
		 */
		int getModuleNumber() {
			return moduleNumber;
		}

	}
}
