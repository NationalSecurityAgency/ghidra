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
import java.util.*;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.AddressRangeMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Class to manage namespaces.
 */

public class NamespaceManager implements ManagerDB {
	private static final String NAMESPACE_MAP_NAME = "SCOPE ADDRESSES";
	private AddressRangeMapDB namespaceMap;
	private ErrorHandler errHandler;
	private AddressMap addrMap;
	private SymbolManager symbolMgr;
	private Namespace globalNamespace;
	private Lock lock;
	private Namespace lastBodyNamespace;
	private AddressSet lastBody;

	/**
	 * Construct a new namespace manager.
	 * @param handle the database handle.
	 * @param errHandler the error handler.
	 * @param addrMap the address map
	 * @param openMode the open mode
	 * @param lock the program synchronization lock
	 * @param monitor the task monitor.
	 * @throws VersionException if the table version is different from this adapter.
	 */
	public NamespaceManager(DBHandle handle, ErrorHandler errHandler, AddressMap addrMap,
			int openMode, Lock lock, TaskMonitor monitor) throws VersionException {

		this.errHandler = errHandler;
		this.addrMap = addrMap;
		this.lock = lock;

		if (handle.getTable("Scope") != null) {
			throw new VersionException("Program is transient development format, not supported");
		}

		namespaceMap = new AddressRangeMapDB(handle, addrMap, lock, NAMESPACE_MAP_NAME, errHandler,
			LongField.INSTANCE, true);

	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		lock.acquire();
		try {
			namespaceMap.clearRange(startAddr, endAddr);
		}
		finally {
			clearCache();
			lock.release();
		}
	}

	private void clearCache() {
		lastBodyNamespace = null;
		lastBody = null;
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		clearCache();
	}

	@Override
	public void setProgram(ProgramDB program) {
		this.symbolMgr = (SymbolManager) program.getSymbolTable();
		globalNamespace = program.getGlobalNamespace();
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// Nothing to do
	}

	void dbError(IOException e) {
		errHandler.dbError(e);

	}

	/**
	 * Get the global namespace.
	 */
	public Namespace getGlobalNamespace() {
		return globalNamespace;
	}

	/**
	 * Sets the body of a namespace.
	 * @param namespace the namespace whose body is to be modified.
	 * @param set the address set for the new body.
	 */
	public void setBody(Namespace namespace, AddressSetView set) throws OverlappingNamespaceException {
		if (set.getNumAddresses() > Integer.MAX_VALUE) {
			throw new IllegalArgumentException(
				"Namespace body size must be less than 0x7fffffff byte addresses");
		}
		lock.acquire();
		try {
			AddressSetView oldBody = removeBody(namespace);
			AddressRange range = overlapsNamespace(set);
			if (range != null) {
				doSetBody(namespace, oldBody);
				throw new OverlappingNamespaceException(range.getMinAddress(), range.getMaxAddress());
			}
			doSetBody(namespace, set);
		}
		finally {
			clearCache();
			lock.release();
		}
	}

	private void doSetBody(Namespace namespace, AddressSetView set) {
		Field field = new LongField(namespace.getID());
		AddressRangeIterator rangeIter = set.getAddressRanges();
		while (rangeIter.hasNext()) {
			AddressRange range = rangeIter.next();
			namespaceMap.paintRange(range.getMinAddress(), range.getMaxAddress(), field);
		}
	}

	/**
	 * Removes any associated body with the given namespace.
	 * @param namespace the namespace whose body is to be cleared.
	 */
	public AddressSetView removeBody(Namespace namespace) {
		lock.acquire();
		try {
			AddressSetView set = getAddressSet(namespace);
			AddressRangeIterator iter = set.getAddressRanges();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				namespaceMap.clearRange(range.getMinAddress(), range.getMaxAddress());
			}
			return set;
		}
		finally {
			clearCache();
			lock.release();
		}
	}

	/**
	 * Get the Namespace containing the given address. If the address is not
	 * in a defined namespace (e.g., Function), the global namespace is
	 * returned.
	 * @param addr the address for which to find a namespace.
	 */
	public Namespace getNamespaceContaining(Address addr) {
		Field field = namespaceMap.getValue(addr);
		if (field != null) {
			Symbol s = symbolMgr.getSymbol(field.getLongValue());
			if (s != null) {
				Object object = s.getObject();
				if (object instanceof Namespace) {
					return (Namespace) object;
				}
			}
		}
		return globalNamespace;
	}

	/**
	 * Checks if an existing namespace's address set intersects with
	 * the given set. If so, return the first overlapping range.
	 * @returns null if no overlaps, or an address range of the first overlap
	 */
	public AddressRange overlapsNamespace(AddressSetView set) {
		AddressRangeIterator addressRanges = set.getAddressRanges();
		for (AddressRange addressRange : addressRanges) {
			AddressRangeIterator namesSpaceRanges = namespaceMap.getAddressRanges(
				addressRange.getMinAddress(), addressRange.getMaxAddress());
			AddressRange existingRange = namesSpaceRanges.next();
			if (existingRange != null) {
				return existingRange;
			}
		}
		return null;
	}

	/**
	 * Get all Namespaces whose body overlaps the specified address set.
	 * @param set the address for which to find namespace's that intersect it.
	 * @return a LongField function key iterator.
	 */
	public Iterator<Namespace> getNamespacesOverlapping(AddressSetView set) {
		lock.acquire();
		try {
			LinkedHashSet<Long> idSet = new LinkedHashSet<Long>();
			AddressRangeIterator rangeIter = set.getAddressRanges();
			while (rangeIter.hasNext()) {
				AddressRange range = rangeIter.next();
				AddressRangeIterator namespaceRanges =
					namespaceMap.getAddressRanges(range.getMinAddress(), range.getMaxAddress());
				while (namespaceRanges.hasNext()) {
					AddressRange namespaceRange = namespaceRanges.next();
					Field field = namespaceMap.getValue(namespaceRange.getMinAddress());
					Long id = field.getLongValue();
					if (!idSet.contains(id)) {
						idSet.add(id);
					}
				}
			}

			List<Namespace> list = new ArrayList<Namespace>(idSet.size());
			for (long namespaceID : idSet) {
				Symbol s = symbolMgr.getSymbol(namespaceID);
				if (s != null) {
					Object obj = s.getObject();
					if (obj instanceof Namespace) {
						list.add((Namespace) s.getObject());
					}
				}
			}

			return list.iterator();

		}
		finally {
			clearCache();
			lock.release();
		}
	}

	/**
	 * Gets the body for the given namespace.
	 * @param namespace the namespace for which to get its body.
	 */
	public AddressSetView getAddressSet(Namespace namespace) {
		lock.acquire();
		try {
			if (namespace == lastBodyNamespace) {
				return lastBody;
			}
			AddressSetView mySet = getAddressSet(namespace.getID());
			AddressSet set = new AddressSet(mySet);
			SymbolIterator it = symbolMgr.getSymbols(namespace);
			while (it.hasNext()) {
				Symbol s = it.next();
				Object obj = s.getObject();
				if (obj instanceof Namespace) {
					set.add(((Namespace) obj).getBody());
				}
			}
			lastBodyNamespace = namespace;
			lastBody = set;
			return set;
		}
		finally {
			lock.release();
		}
	}

	private AddressSetView getAddressSet(long namespaceID) {
		lock.acquire();
		try {
			return namespaceMap.getAddressSet(new LongField(namespaceID));
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, CancelledException {
		lock.acquire();
		try {
			Address rangeEnd = fromAddr.addNoWrap(length - 1);

			AddressSet addrSet = new AddressSet(fromAddr, rangeEnd);
			ArrayList<NamespaceHolder> list = new ArrayList<NamespaceHolder>();

			AddressRangeIterator rangeIter = namespaceMap.getAddressRanges(fromAddr, rangeEnd);
			while (rangeIter.hasNext() && !addrSet.isEmpty()) {
				monitor.checkCanceled();
				AddressRange range = rangeIter.next();
				Field field = namespaceMap.getValue(range.getMinAddress());
				long namespaceID = field.getLongValue();
				AddressSet intersection = addrSet.intersect(getAddressSet(namespaceID));
				AddressRangeIterator namespaceRangeIter = intersection.getAddressRanges();
				while (namespaceRangeIter.hasNext() && !monitor.isCancelled()) {
					AddressRange namespaceRange = namespaceRangeIter.next();

					Address startAddr = namespaceRange.getMinAddress();
					Address endAddr = namespaceRange.getMaxAddress();

					long offset = startAddr.subtract(fromAddr);
					startAddr = toAddr.add(offset);
					offset = endAddr.subtract(fromAddr);
					endAddr = toAddr.add(offset);

					AddressRange newRange = new AddressRangeImpl(startAddr, endAddr);

					list.add(new NamespaceHolder(namespaceID, newRange));
				}
				addrSet = addrSet.subtract(intersection);
			}

			monitor.checkCanceled();
			namespaceMap.clearRange(fromAddr, rangeEnd);

			for (int i = 0; i < list.size(); i++) {
				monitor.checkCanceled();
				NamespaceHolder h = list.get(i);
				namespaceMap.paintRange(h.range.getMinAddress(), h.range.getMaxAddress(),
					new LongField(h.namespaceID));
			}
		}
		finally {
			clearCache();
			lock.release();
		}
	}

	private class NamespaceHolder {
		long namespaceID;
		AddressRange range;

		NamespaceHolder(long namespaceID, AddressRange range) {
			this.namespaceID = namespaceID;
			this.range = range;
		}
	}

}
