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
package ghidra.app.util.viewer.util;

import java.math.BigInteger;

import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DiffUtility;
import ghidra.program.util.SimpleDiffUtility;

public class AddressIndexMapConverter extends AddressIndexMap {

	AddressIndexMap addressIndexMap;
	Program mapProgram;
	Program otherProgram;

	public AddressIndexMapConverter(AddressIndexMap addressIndexMap, Program mapProgram,
			Program otherProgram) {
		if (mapProgram == otherProgram) {
			throw new RuntimeException();
		}
		this.addressIndexMap = addressIndexMap;
		this.mapProgram = mapProgram;
		this.otherProgram = otherProgram;
	}

	@Override
	public Address getAddress(BigInteger index) {
		Address mapAddress = addressIndexMap.getAddress(index);
		return SimpleDiffUtility.getCompatibleAddress(mapProgram, mapAddress, otherProgram);
	}

	@Override
	public AddressSetView getOriginalAddressSet() {
		return DiffUtility.getCompatibleAddressSet(addressIndexMap.getOriginalAddressSet(),
			otherProgram);
	}

	@Override
	public AddressSetView getIndexedAddressSet() {
		return DiffUtility.getCompatibleAddressSet(addressIndexMap.getIndexedAddressSet(),
			otherProgram);
	}

	@Override
	public AddressSet getAddressSet(FieldSelection sel) {
		return DiffUtility.getCompatibleAddressSet(addressIndexMap.getAddressSet(sel),
			otherProgram);
	}

	@Override
	public FieldSelection getFieldSelection(AddressSetView set) {
		AddressSet mapSet = DiffUtility.getCompatibleAddressSet(set, mapProgram);
		return addressIndexMap.getFieldSelection(mapSet);
	}

	private Address getMapAddress(Address addr) {
		AddressSpace locAddressSpace = addr.getAddressSpace();
		AddressSpace programAddressSpace =
			mapProgram.getAddressFactory().getAddressSpace(locAddressSpace.getSpaceID());
		Address mapAddress = (programAddressSpace == locAddressSpace) ? addr
				: SimpleDiffUtility.getCompatibleAddress(otherProgram, addr, mapProgram);
		return mapAddress;
	}

	@Override
	public BigInteger getIndex(Address addr) {
		Address mapAddress = getMapAddress(addr);
		return addressIndexMap.getIndex(mapAddress);
	}

	@Override
	public BigInteger getMaxIndex(Address addr) {
		Address mapAddress = getMapAddress(addr);
		return addressIndexMap.getMaxIndex(mapAddress);
	}

	@Override
	public BigInteger getMinIndex(Address addr) {
		Address mapAddress = getMapAddress(addr);
		return addressIndexMap.getMinIndex(mapAddress);
	}

}
