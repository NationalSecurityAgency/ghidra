/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.database.map;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.util.LanguageTranslator;

import java.io.IOException;
import java.util.*;

import db.DBHandle;

/**
 * Adapter for when no addr map database existed.
 */
class AddressMapDBAdapterNoTable extends AddressMapDBAdapter {

	private Address[] addresses;
	private AddressFactory factory;

	AddressMapDBAdapterNoTable(DBHandle handle, AddressFactory factory) {
		this.factory = factory;
		AddressSpace[] spaces = factory.getAddressSpaces();
		addresses = new Address[spaces.length];
		for (int i = 0; i < spaces.length; i++) {
			addresses[i] = spaces[i].getAddress(0);
		}
		Arrays.sort(addresses);
		oldAddrMap = new FactoryBasedAddressMap();
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#getBaseAddresses(boolean)
	 */
	@Override
	Address[] getBaseAddresses(boolean forceRead) {
		return addresses;
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#addBaseAddress(ghidra.program.model.address.Address)
	 */
	@Override
	Address[] addBaseAddress(Address addr, long normalizedOffset) {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#getEntries()
	 */
	@Override
	List<AddressMapEntry> getEntries() throws IOException {
		ArrayList<AddressMapEntry> list = new ArrayList<AddressMapEntry>();
		for (int i = 0; i < addresses.length; i++) {
			list.add(new AddressMapEntry(i, addresses[i].getAddressSpace().getName(), 0, false));
		}
		return list;
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#setEntries(java.util.List)
	 */
	@Override
	void setEntries(List<AddressMapEntry> entries) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.map.AddressMapDBAdapter#clearAll()
	 */
	@Override
	void clearAll() throws IOException {
		throw new UnsupportedOperationException();
	}

	private class FactoryBasedAddressMap implements AddressMap {

		/**
		 * Comparator used to identify if an addr occurs before or after the 
		 * start of a key range.
		 */
		private Comparator<Object> addressInsertionKeyRangeComparator = new Comparator<Object>() {
			@Override
			public int compare(Object keyRangeObj, Object addrObj) {
				KeyRange range = (KeyRange) keyRangeObj;
				Address addr = (Address) addrObj;

				Address min = decodeAddress(range.minKey);
				if (min.compareTo(addr) > 0) {
					return 1;
				}

				Address max = decodeAddress(range.maxKey);
				if (max.compareTo(addr) < 0) {
					return -1;
				}
				return 0;
			}
		};

		@Override
		public boolean hasSameKeyBase(long addrKey1, long addrKey2) {
			return (addrKey1 >> 32) == (addrKey2 >> 32);
		}

		@Override
		public boolean isKeyRangeMax(long addrKey) {
			return (addrKey & 0xffffffff) == 0xffffffff;
		}

		@Override
		public boolean isKeyRangeMin(long addrKey) {
			return (addrKey & 0xffffffff) == 0;
		}

		@Override
		public long getKey(Address addr, boolean create) {
			if (create) {
				throw new IllegalArgumentException("Old address map does not support key creation");
			}
			return factory.getIndex(addr);
		}

		@Override
		public long getAbsoluteEncoding(Address addr, boolean create) {
			if (create) {
				throw new IllegalArgumentException("Old address map does not support key creation");
			}
			return factory.getIndex(addr);
		}

		@Override
		public Address decodeAddress(long value) {
			return factory.oldGetAddressFromLong(value);
		}

		@Override
		public AddressFactory getAddressFactory() {
			return factory;
		}

		@Override
		public List<KeyRange> getKeyRanges(Address start, Address end, boolean create) {
			return getKeyRanges(start, end, false, create);
		}

		@Override
		public List<KeyRange> getKeyRanges(AddressSetView set, boolean create) {
			return getKeyRanges(set, false, create);
		}

		@Override
		public List<KeyRange> getKeyRanges(AddressSetView set, boolean absolute, boolean create) {
			ArrayList<KeyRange> keyRangeList = new ArrayList<KeyRange>();
			if (absolute) {
				return keyRangeList;
			}
			if (set == null) {
				keyRangeList.add(new KeyRange(Long.MIN_VALUE, Long.MAX_VALUE));
			}
			else {
				AddressRangeIterator it = set.getAddressRanges();
				while (it.hasNext()) {
					AddressRange range = it.next();
					Address start = range.getMinAddress();
					Address end = range.getMaxAddress();
					keyRangeList.add(new KeyRange(factory.getIndex(start), factory.getIndex(end)));
				}
			}
			return keyRangeList;
		}

		@Override
		public int findKeyRange(List<KeyRange> keyRangeList, Address addr) {
			if (addr == null) {
				return -1;
			}
			return Collections.binarySearch(keyRangeList, addr, addressInsertionKeyRangeComparator);
		}

		@Override
		public List<KeyRange> getKeyRanges(Address start, Address end, boolean absolute,
				boolean create) {
			return getKeyRanges(factory.getAddressSet(start, end), absolute, create);
		}

		@Override
		public Address getImageBase() {
			return factory.getDefaultAddressSpace().getAddress(0);
		}

		@Override
		public int getModCount() {
			return 0;
		}

		@Override
		public AddressMap getOldAddressMap() {
			return this;
		}

		@Override
		public void invalidateCache() {
		}

		@Override
		public boolean isUpgraded() {
			return false;
		}

		@Override
		public void deleteOverlaySpace(String name) {
		}

		@Override
		public void renameOverlaySpace(String oldName, String newName) {
		}

		@Override
		public void setImageBase(Address base) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setLanguage(Language newLanguage, AddressFactory addrFactory,
				LanguageTranslator translator) {
			throw new UnsupportedOperationException();
		}

	}

	@Override
	void setAddressFactory(AddressFactory addrFactory) {
		this.factory = addrFactory;
	}

	@Override
	void renameOverlaySpace(String oldName, String newName) {
		throw new UnsupportedOperationException();
	}

	@Override
	void deleteOverlaySpace(String name) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void deleteTable() {
		// don't have a table to delete
	}
}
