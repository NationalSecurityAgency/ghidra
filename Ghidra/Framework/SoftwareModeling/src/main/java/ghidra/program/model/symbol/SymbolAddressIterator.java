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
package ghidra.program.model.symbol;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;

/**
 * Class to provide an address iterator over all symbols in memory. Addresses of symbols not in 
 * memory, such as external symbols, will not be returned.
 * <P>
 * This class should be used by clients that wish to process symbols while potentially changing 
 * which symbol is primary while processing the addresses. Using a symbol iterator while changing
 * the symbol's primary status will cause the symbol iterator to change as it is being used, which
 * may be inefficient. This class ensures that the same address will not be processed repeatedly by
 * working on chunks of address and tracking the next address to be processed.
 */
public class SymbolAddressIterator implements AddressIterator {
	private SymbolTable symbolTable;
	private int chunkSize;
	private AddressSet remainingSearchSet;
	private Iterator<Address> addressIterator;

	public SymbolAddressIterator(Program program, int chunkSize) {
		this(program, program.getMemory(), chunkSize);
	}

	public SymbolAddressIterator(Program program, AddressSetView set, int chunkSize) {
		this.symbolTable = program.getSymbolTable();
		this.chunkSize = chunkSize;
		this.remainingSearchSet = new AddressSet(set);
		this.addressIterator = getNextAddressChunkIterator();
	}

	@Override
	public boolean hasNext() {
		if (addressIterator.hasNext()) {
			return true;
		}
		addressIterator = getNextAddressChunkIterator();
		return addressIterator.hasNext();
	}

	@Override
	public Address next() {
		if (hasNext()) {
			return addressIterator.next();
		}
		return null;
	}

	private Iterator<Address> getNextAddressChunkIterator() {
		if (remainingSearchSet.isEmpty()) {
			return new EmptyAddressIterator();
		}

		List<Address> addresses = new ArrayList<>(chunkSize);
		SymbolIterator it = symbolTable.getPrimarySymbolIterator(remainingSearchSet, true);
		while (it.hasNext() && addresses.size() < chunkSize) {
			Symbol s = it.next();
			addresses.add(s.getAddress());
		}
		trimRemainingSearchSet(it, addresses);
		return addresses.iterator();
	}

	private void trimRemainingSearchSet(SymbolIterator it, List<Address> addresses) {
		if (addresses.isEmpty() || !it.hasNext()) {
			remainingSearchSet.clear();
		}
		else {
			Address lastAddress = addresses.getLast();
			remainingSearchSet.deleteFromMin(lastAddress);
		}
	}
}
