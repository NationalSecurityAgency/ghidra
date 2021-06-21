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
package ghidra.program.model.address;

import java.util.ArrayList;
import java.util.HashMap;

import ghidra.program.model.lang.BasicCompilerSpec;
import ghidra.util.datastruct.IntObjectHashtable;
import ghidra.util.exception.DuplicateNameException;

/**
 * Keeps track of all the Address spaces in the program and provides
 * methods for parsing address strings.
 */
public class DefaultAddressFactory implements AddressFactory {
	private AddressSpace defaultSpace;
	private AddressSpace constantSpace;
	private AddressSpace uniqueSpace;
	private IntObjectHashtable<AddressSpace> spaceLookup;
	private AddressSet memoryAddressSet;
	private AddressSpace registerSpace;

	private HashMap<String, AddressSpace> spaceNameTable;

	private ArrayList<AddressSpace> spaces;

	DefaultAddressFactory() {
		this(new AddressSpace[0], null);
	}

	/**
	 * Constructs a new DefaultAddressFactory.  The default space is assumed to be the first space
	 * in the array.
	 * @param addrSpaces array of address spaces for the Program
	 * 
	 */
	public DefaultAddressFactory(AddressSpace[] addrSpaces) {
		this(addrSpaces, null);
	}

	/**
	 * Constructs a new DefaultAddressFactory with the given spaces and default space.
	 * @param addrSpaces the set of addressSpaces to manage
	 * @param defaultSpace the space to use as the default space. The default space should
	 * be one of the spaces provided in the addrSpaces array. 
	 */
	public DefaultAddressFactory(AddressSpace[] addrSpaces, AddressSpace defaultSpace) {
		memoryAddressSet = new AddressSet();
		spaces = new ArrayList<>(addrSpaces.length);
		spaceLookup = new IntObjectHashtable<>();
		spaceNameTable = new HashMap<>();

		for (AddressSpace space : addrSpaces) {
			checkReservedSpace(space);
			spaces.add(space);

			if (space.equals(defaultSpace)) {
				this.defaultSpace = space;
			}
			spaceNameTable.put(space.getName(), space);
			spaceLookup.put(space.getSpaceID(), space);
			if (space.getType() == AddressSpace.TYPE_CONSTANT) {
				constantSpace = space;
			}
			else if (space.getType() == AddressSpace.TYPE_UNIQUE) {
				uniqueSpace = space;
			}
			else if (space.getType() == AddressSpace.TYPE_REGISTER) {
				if (registerSpace != null || !space.getName().equalsIgnoreCase("register")) {
					// Ghidra address encoding only handles a single register space
					throw new IllegalArgumentException(
						"Ghidra can only support a single Register space named 'register'");
				}
				registerSpace = space;
			}
			// build up an address set for all possible "real" addresses
			if (space.isMemorySpace()) {
				memoryAddressSet.addRange(space.getMinAddress(), space.getMaxAddress());
			}
		}

		if (hasMultipleMemorySpaces()) {
			AddressSpace[] physSpaces = this.getPhysicalSpaces();
			for (AddressSpace sp : physSpaces) {
				if (sp instanceof AbstractAddressSpace) {
					((AbstractAddressSpace) sp).setShowSpaceName(true);
				}
			}
		}
		if (this.defaultSpace == null) {
			if (defaultSpace != null) {
				throw new IllegalArgumentException("Specified default space not in array");
			}
			this.defaultSpace = spaces.get(0);
		}
		if (registerSpace == null) {
			registerSpace = AddressSpace.DEFAULT_REGISTER_SPACE;
		}
	}

	private void checkReservedSpace(AddressSpace space) {
		checkReservedVariable(space);
		checkReservedJoin(space);
		checkReservedExternal(space);
		checkReservedStack(space);
	}

	private void checkReservedVariable(AddressSpace space) {
		if (space.getType() == AddressSpace.TYPE_VARIABLE ||
			space.getName().equalsIgnoreCase(AddressSpace.VARIABLE_SPACE.getName())) {
			throw new IllegalArgumentException("Variable space should not be specified");
		}
	}

	private void checkReservedJoin(AddressSpace space) {
		if (space.getType() == AddressSpace.TYPE_JOIN ||
			space.getName().equals(BasicCompilerSpec.JOIN_SPACE_NAME)) {
			throw new IllegalArgumentException("Join space should not be specified");
		}
	}

	private void checkReservedExternal(AddressSpace space) {
		if (space.getType() == AddressSpace.TYPE_EXTERNAL ||
			space.getName().equalsIgnoreCase(AddressSpace.EXTERNAL_SPACE.getName())) {
			throw new IllegalArgumentException("External space should not be specified");
		}
	}

	private void checkReservedStack(AddressSpace space) {
		if (space.getType() == AddressSpace.TYPE_STACK ||
			space.getName().equalsIgnoreCase(BasicCompilerSpec.STACK_SPACE_NAME)) {
			throw new IllegalArgumentException("Stack space should not be specified");
		}
	}

	/**
	 * @see ghidra.program.model.address.AddressFactory#getAddress(java.lang.String)
	 */
	@Override
	public Address getAddress(String addrString) {
		try {
			Address addr = defaultSpace.getAddress(addrString);
			if (addr != null) {
				return addr;
			}
		}
		catch (AddressFormatException e) {
			// ignore
		}

		for (AddressSpace space : spaces) {
			//  default space already checked
			if (space == defaultSpace) {
				continue;
			}
			try {
				Address addr = space.getAddress(addrString);
				if (addr != null) {
					return addr;
				}
			}
			catch (AddressFormatException e) {
				// ignore
			}
		}
		return null;
	}

	@Override
	public Address[] getAllAddresses(String addrString) {
		return getAllAddresses(addrString, true);
	}

	@Override
	public Address[] getAllAddresses(String addrString, boolean caseSensitive) {
		ArrayList<Address> loadedMemoryList = new ArrayList<>();
		ArrayList<Address> otherList = new ArrayList<>();

		for (AddressSpace space : spaces) {
			// Only parse against true physical spaces first
			if (space.isMemorySpace()) {
				try {
					Address addr = space.getAddress(addrString, caseSensitive);
					if (addr == null) {
						continue;
					}
					if (space.isOverlaySpace() && addr.getAddressSpace() != space) {
						continue;
					}
					if (space.isNonLoadedMemorySpace()) {
						otherList.add(addr);
					}
					else if (space == defaultSpace) {
						loadedMemoryList.add(0, addr);
					}
					else {
						loadedMemoryList.add(addr);
					}
				}
				catch (AddressFormatException e) {
					//ignore
				}
			}
		}
		if (loadedMemoryList.isEmpty() && otherList.size() == 1) {
			return new Address[] { otherList.get(0) };
		}

		Address[] addrs = new Address[loadedMemoryList.size()];

		return loadedMemoryList.toArray(addrs);
	}

	@Override
	public AddressSpace getDefaultAddressSpace() {
		return defaultSpace;
	}

	@Override
	public AddressSpace[] getAddressSpaces() {
		return getPhysicalSpaces();// we avoid returning analysis spaces here
		//AddressSpace[] s  = new AddressSpace[spaces.length];
		//System.arraycopy(spaces,0,s,0,spaces.length);
		//return s;
	}

	@Override
	public AddressSpace[] getAllAddressSpaces() {
		AddressSpace[] allSpaces = new AddressSpace[spaces.size()];
		spaces.toArray(allSpaces);
		return allSpaces;
	}

	@Override
	public AddressSpace getAddressSpace(String name) {
		return spaceNameTable.get(name);
	}

	@Override
	public AddressSpace getAddressSpace(int spaceID) {
		return spaceLookup.get(spaceID);
	}

	@Override
	public int getNumAddressSpaces() {
		return getPhysicalSpaces().length;
	}

	@Override
	public boolean isValidAddress(Address addr) {
		return spaces.contains(addr.getAddressSpace());
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof DefaultAddressFactory)) {
			return false;
		}
		DefaultAddressFactory factory = (DefaultAddressFactory) o;

		if (spaces.size() != factory.spaces.size()) {
			return false;
		}
		for (AddressSpace space : spaces) {
			if (!factory.spaces.contains(space)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public long getIndex(Address addr) {
		AddressSpace space = addr.getAddressSpace();
		int id = space.getSpaceID();
		if (spaceLookup.get(id) == null) {
			spaceLookup.put(id, space);
		}
		long value = (long) id << 48;

		value += addr.getOffset();
		return value;
	}

	@Override
	public AddressSpace getPhysicalSpace(AddressSpace space) {
		return space.getPhysicalSpace();
	}

	@Override
	public AddressSpace[] getPhysicalSpaces() {
		ArrayList<AddressSpace> physicalSpaces = new ArrayList<>();
		for (AddressSpace space : spaces) {
			if (space.isMemorySpace()) {
				physicalSpaces.add(space);
			}
		}

		AddressSpace[] ret = new AddressSpace[physicalSpaces.size()];
		physicalSpaces.toArray(ret);
		return ret;
	}

	@Override
	public Address getAddress(int spaceID, long offset) {
		AddressSpace space = getAddressSpace(spaceID);
		if (space == null) {
			return null;
		}
		return space.getAddress(offset);
	}

	@Override
	public AddressSpace getConstantSpace() {
		return constantSpace;
	}

	@Override
	public AddressSpace getUniqueSpace() {
		return uniqueSpace;
	}

	@Override
	public AddressSpace getStackSpace() {
		throw new UnsupportedOperationException(
			"Use program's address factory to obtain compiler specified stack space");
	}

	@Override
	public AddressSpace getRegisterSpace() {
		return registerSpace;
	}

	@Override
	public Address getConstantAddress(long offset) {
		return constantSpace.getAddress(offset);
	}

	@Override
	public AddressSet getAddressSet(Address min, Address max) {
		if (min.getAddressSpace() == max.getAddressSpace()) {
			return new AddressSet(min, max);
		}
		AddressSet set = new AddressSet();
		AddressRangeIterator it = memoryAddressSet.getAddressRanges();
		while (it.hasNext()) {
			AddressRange r = it.next();
			AddressRange result = r.intersectRange(min, max);
			if (result != null) {
				set.add(result);
			}
		}
		return set;
	}

	@Override
	public AddressSet getAddressSet() {
		return new AddressSet(memoryAddressSet);
	}

	@Override
	public Address oldGetAddressFromLong(long value) {
		int spaceId = (int) (value >> 48);
		long offset = value & 0xFFFFFFFFL;

		AddressSpace space = spaceLookup.get(spaceId);
		if (space == null) {
			throw new AddressOutOfBoundsException(
				"Unable to decode old address - space not found (spaceId=" + spaceId + ")");
		}
		return space.getAddress(offset);
	}

	/**
	 * Adds an AddressSpace to this factory
	 * 
	 * @param space the address space being added.
	 * @throws DuplicateNameException if an address space with the given name already exists
	 */
	protected void addAddressSpace(AddressSpace space) throws DuplicateNameException {
		if (spaceNameTable.containsKey(space.getName())) {
			throw new DuplicateNameException("Space named " + space.getName() + " already exists!");
		}
		if (space.getType() == AddressSpace.TYPE_VARIABLE) {
			spaceNameTable.put("join", space);// Add VARIABLE space with name "join"
			return;// Don't put it in the spaces array or the id lookup table
		}
		spaces.add(space);
		spaceNameTable.put(space.getName(), space);
		spaceLookup.put(space.getSpaceID(), space);

		if (space.isMemorySpace()) {
			memoryAddressSet.addRange(space.getMinAddress(), space.getMaxAddress());
		}
	}

	/**
	 * Rename overlay with newName.
	 * @param oldOverlaySpaceName the existing overlay address space name
	 * @param newName the new name of the overlay address space.  
	 * @return new name applied to existing overlay space
	 * @throws DuplicateNameException if space with newName already exists
	 * @throws IllegalArgumentException if specified oldOverlaySpaceName was not found as
	 * an existing overlay space
	 */
	protected String renameOverlaySpace(String oldOverlaySpaceName, String newName)
			throws DuplicateNameException {
		if (getAddressSpace(newName) != null) {
			throw new DuplicateNameException("AddressSpace named " + newName + " already exists!");
		}
		AddressSpace space = getAddressSpace(oldOverlaySpaceName);
		if (space != null && space.isOverlaySpace()) {
			((OverlayAddressSpace) space).setName(newName);
			spaceNameTable.remove(oldOverlaySpaceName);
			spaceNameTable.put(space.getName(), space);
			return newName;
		}
		throw new IllegalArgumentException("No such overlay space: " + oldOverlaySpaceName);
	}

	/**
	 * Removes the AddressSpace from this factory
	 * 
	 * @param spaceName the name of the space to remove.
	 */
	protected void removeAddressSpace(String spaceName) {
		AddressSpace deletedSpace = spaceNameTable.get(spaceName);
		if (deletedSpace != null) {
			spaces.remove(deletedSpace);
			spaceNameTable.remove(deletedSpace.getName());
			spaceLookup.remove(deletedSpace.getSpaceID());
			if (deletedSpace.getType() == AddressSpace.TYPE_RAM ||
				deletedSpace.getType() == AddressSpace.TYPE_CODE) {
				memoryAddressSet.deleteRange(deletedSpace.getMinAddress(),
					deletedSpace.getMaxAddress());
			}
		}
	}

	@Override
	public boolean hasMultipleMemorySpaces() {
		return getPhysicalSpaces().length > 1;
	}
}
