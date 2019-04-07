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
package ghidra.program.database.util;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.ProgramChangeSet;

import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of AddressSetCollection used by {@link ProgramChangeSet}.  It contains the
 * actual instances of the addressSets used by the {@link ProgramChangeSet} and protects access
 * to them by synchronizing on the ProgramChangeSet.
 * 
 * Because these objects use the actual addressSets within the programChangeSet for
 * efficiency reasons, any changes to those
 * underlying sets will be reflected in the set of addresses represented by this collection.  
 * But since it is synchronized, you will always get a stable set during any given call and
 * the AddressSetCollection interface is careful not to include iterator or other methods
 * that can't tolerate a underlying change.  This object is really only intended for use by
 * the GUI change bars and if it changes, it only results in possibly seeing the changes bars
 * a bit earlier than otherwise.  
 */
public class SynchronizedAddressSetCollection implements AddressSetCollection {
	private List<AddressSetView> addressSetList = new ArrayList<>();
	private Object sync;

	public SynchronizedAddressSetCollection(Object sync, AddressSetView... addressSetViews) {
		this.sync = sync;
		for (AddressSetView addressSetView : addressSetViews) {
			if (addressSetView != null && !addressSetView.isEmpty()) {
				addressSetList.add(addressSetView);
			}
		}
	}

	@Override
	public boolean intersects(AddressSetView addrSet) {
		synchronized (sync) {
			for (AddressSetView addressSet : addressSetList) {
				if (addressSet.intersects(addrSet)) {
					return true;
				}
			}
			return false;
		}
	}

	@Override
	public boolean intersects(Address start, Address end) {
		synchronized (sync) {
			for (AddressSetView addressSet : addressSetList) {
				if (addressSet.intersects(start, end)) {
					return true;
				}
			}
			return false;
		}
	}

	@Override
	public boolean contains(Address address) {
		synchronized (sync) {
			for (AddressSetView addressSet : addressSetList) {
				if (addressSet.contains(address)) {
					return true;
				}
			}
			return false;
		}
	}

	@Override
	public boolean hasFewerRangesThan(int rangeThreshold) {
		synchronized (sync) {
			int n = 0;
			for (AddressSetView addressSet : addressSetList) {
				n += addressSet.getNumAddressRanges();
				if (n >= rangeThreshold) {
					return false;
				}
			}
			return true;
		}
	}

	@Override
	public AddressSet getCombinedAddressSet() {
		synchronized (sync) {
			AddressSet set = new AddressSet();
			for (AddressSetView addressSet : addressSetList) {
				set.add(addressSet);
			}
			return set;
		}
	}

	@Override
	public Address findFirstAddressInCommon(AddressSetView set) {
		synchronized (sync) {
			Address firstCommonAddress = null;
			for (AddressSetView addressSet : addressSetList) {
				Address possibleFirst = addressSet.findFirstAddressInCommon(set);
				if (possibleFirst != null) {
					if (firstCommonAddress == null ||
						possibleFirst.compareTo(firstCommonAddress) < 0) {
						firstCommonAddress = possibleFirst;
					}
				}
			}
			return firstCommonAddress;
		}
	}

	@Override
	public boolean isEmpty() {
		synchronized (sync) {
			for (AddressSetView addressSet : addressSetList) {
				if (!addressSet.isEmpty()) {
					return false;
				}
			}
			return true;
		}
	}

	@Override
	public Address getMinAddress() {
		Address min = null;
		synchronized (sync) {
			for (AddressSetView addressSet : addressSetList) {
				Address setMin = addressSet.getMinAddress();
				if (setMin != null) {
					if (min == null || setMin.compareTo(min) < 0) {
						min = setMin;
					}
				}
			}
			return min;
		}
	}

	@Override
	public Address getMaxAddress() {
		Address max = null;
		synchronized (sync) {
			for (AddressSetView addressSet : addressSetList) {
				Address setMax = addressSet.getMaxAddress();
				if (setMax != null) {
					if (max == null || setMax.compareTo(max) > 0) {
						max = setMax;
					}
				}
			}
			return max;
		}
	}
}
