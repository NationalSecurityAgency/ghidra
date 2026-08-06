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
package ghidra.program.database.symbol;

import java.io.IOException;
import java.util.Set;

import db.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for all adapters before version 6. Since versions prior to version 6 do
 * not support read-only access, the only methods implemented are those required for the 
 * upgrade. This class stubs out all unnecessary methods so that subclasses just need to
 * implement the few required methods.  
 */
public abstract class PreV6SymbolDatabaseAdapter extends SymbolDatabaseAdapter {

	@Override
	final DBRecord createSymbolRecord(String name, long namespaceID, Address address,
			SymbolType symbolType, boolean isPrimary, SourceType source) {
		throw new UnsupportedOperationException();
	}

	@Override
	final DBRecord getSymbolRecord(long symbolID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final void removeSymbol(long symbolID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final boolean hasSymbol(Address addr) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final Field[] getSymbolIDs(Address addr) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getSymbolsByAddress(boolean forward) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getSymbolsByAddress(Address startAddr, boolean forward)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final void updateSymbolRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getSymbols(Address start, Address end, boolean forward)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getSymbols(AddressSetView set, boolean forward) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getPrimarySymbols(AddressSetView set, boolean forward) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final DBRecord getPrimarySymbol(Address address) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final void moveAddress(Address oldAddr, Address newAddr) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final Set<Address> deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException, IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getSymbolsByNamespace(long id) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getSymbolsByName(String name) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getSymbolsByLibrary(long libraryID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator scanSymbolsByName(String startName) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getExternalSymbolsByOriginalImportName(String extLabel)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getExternalSymbolsByMemoryAddress(Address extProgAddr) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final RecordIterator getSymbolsByNameAndNamespace(String name, long id) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final DBRecord getSymbolRecord(Address address, String name, long namespaceId)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final Address getMaxSymbolAddress(AddressSpace space) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	final Table getTable() {
		throw new UnsupportedOperationException();
	}

}
