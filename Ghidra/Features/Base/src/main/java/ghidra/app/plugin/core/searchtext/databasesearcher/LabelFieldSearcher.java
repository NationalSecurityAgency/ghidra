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
package ghidra.app.plugin.core.searchtext.databasesearcher;

import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.ProgramLocation;

public class LabelFieldSearcher extends ProgramDatabaseFieldSearcher {
	private AddressIterator iterator;
	private SymbolTable symbolTable;
	private Program program;

	public LabelFieldSearcher(Program program, ProgramLocation startLoc, AddressSetView set,
			boolean forward, Pattern pattern) {
		super(pattern, forward, startLoc, set);

		this.program = program;
		this.symbolTable = program.getSymbolTable();

		SymbolIterator symbolIterator;
		AddressIterator refIterator;
		if (set != null) {
			symbolIterator = program.getSymbolTable().getPrimarySymbolIterator(set, forward);
			refIterator =
				program.getReferenceManager().getReferenceDestinationIterator(set, forward);
		}
		else {
			symbolIterator =
				program.getSymbolTable().getPrimarySymbolIterator(startLoc.getAddress(), forward);
			refIterator = program.getReferenceManager().getReferenceDestinationIterator(
				startLoc.getAddress(), forward);
		}
		iterator = new SymbolAddressIterator(symbolIterator, refIterator, forward);

	}

	@Override
	protected Address advance(List<ProgramLocation> currentMatches) {
		Address nextAddress = iterator.next();
		if (nextAddress == null) {
			return null;
		}
		findMatchesForCurrentAddress(nextAddress, currentMatches);
		return nextAddress;
	}

	private void findMatchesForCurrentAddress(Address address,
			List<ProgramLocation> currentMatches) {
		Symbol[] symbols = symbolTable.getSymbols(address);
		makePrimaryLastItem(symbols);
		for (Symbol symbol : symbols) {
			Matcher matcher = pattern.matcher(symbol.getName());
			while (matcher.find()) {
				int charOffset = matcher.start();
				currentMatches.add(new LabelFieldLocation(symbol, 0, charOffset));
			}
		}
	}

	/**
	 * Move primary symbol to last element in array ...
	 */
	private void makePrimaryLastItem(Symbol[] symbols) {
		for (int i = 0; i < symbols.length - 1; ++i) {
			if (symbols[i].isPrimary()) {
				Symbol primary = symbols[i];
				System.arraycopy(symbols, i + 1, symbols, i, symbols.length - i - 1);
				symbols[symbols.length - 1] = primary;

				break;
			}
		}
	}

	private static class SymbolAddressIterator implements AddressIterator {
		private SymbolIterator symbolIterator;
		private AddressIterator refIterator;
		private Address nextAddress;
		private Address nextSymbolAddress;
		private Address nextRefAddress;
		private final boolean forward;

		SymbolAddressIterator(SymbolIterator symbolIterator, AddressIterator refIterator,
				boolean forward) {
			this.symbolIterator = symbolIterator;
			this.refIterator = refIterator;
			this.forward = forward;
			nextSymbolAddress = getNextSymbolAddress();
			nextRefAddress = getNextRefAddress();
		}

		/**
		 * @see java.util.Iterator#remove()
		 */
		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		private Address getNextRefAddress() {
			if (refIterator.hasNext()) {
				return refIterator.next();
			}
			return null;
		}

		private Address getNextSymbolAddress() {
			while (symbolIterator.hasNext()) {
				Symbol symbol = symbolIterator.next();
				if (symbol != null) {
					return symbol.getAddress();
				}
			}
			return null;
		}

		@Override
		public boolean hasNext() {
			if (nextAddress == null) {
				findNext();
			}
			return nextAddress != null;
		}

		private void findNext() {
			if (nextSymbolAddress == null) {
				nextSymbolAddress = getNextSymbolAddress();
			}
			if (nextRefAddress == null) {
				nextRefAddress = getNextRefAddress();
			}
			if (nextSymbolAddress == null) {
				nextAddress = nextRefAddress;
				nextRefAddress = null;
			}
			else if (nextRefAddress == null) {
				nextAddress = nextSymbolAddress;
				nextSymbolAddress = null;
			}
			else {
				int compareResult = nextSymbolAddress.compareTo(nextRefAddress);
				if (compareResult == 0) {
					nextAddress = nextSymbolAddress;
					nextSymbolAddress = null;
					nextRefAddress = null;
				}
				else if ((forward && compareResult < 0) || (!forward && compareResult > 0)) {
					nextAddress = nextSymbolAddress;
					nextSymbolAddress = null;
				}
				else {
					nextAddress = nextRefAddress;
					nextRefAddress = null;
				}
			}
		}

		@Override
		public Address next() {
			if (hasNext()) {
				Address ret = nextAddress;
				nextAddress = null;
				return ret;
			}
			return null;
		}

		@Override
		public Iterator<Address> iterator() {
			return this;
		}
	}
}
