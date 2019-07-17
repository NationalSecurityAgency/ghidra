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
package ghidra.feature.vt.db;

import static ghidra.feature.vt.db.VTTestUtils.addr;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.util.LanguageTranslator;

public class AddressMapTestDummy implements AddressMap {

	@Override
	public Address decodeAddress(long value) {
		return addr(value);
	}

	@Override
	public void deleteOverlaySpace(String name) throws IOException {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public int findKeyRange(List<KeyRange> keyRangeList, Address addr) {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public long getAbsoluteEncoding(Address addr, boolean create) {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public AddressFactory getAddressFactory() {
		return null;
	}

	@Override
	public Address getImageBase() {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public long getKey(Address addr, boolean create) {
		return addr.getOffset();
	}

	@Override
	public List<KeyRange> getKeyRanges(Address start, Address end, boolean create) {
		List<KeyRange> list = new ArrayList<>();
		list.add(new KeyRange(start.getOffset(), end.getOffset()));
		return list;
	}

	@Override
	public List<KeyRange> getKeyRanges(AddressSetView set, boolean create) {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public List<KeyRange> getKeyRanges(Address start, Address end, boolean absolute,
			boolean create) {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public List<KeyRange> getKeyRanges(AddressSetView set, boolean absolute, boolean create) {
		List<KeyRange> list = new ArrayList<>();
		AddressRangeIterator addressRanges = set.getAddressRanges();
		for (AddressRange addressRange : addressRanges) {
			list.add(new KeyRange(addressRange.getMinAddress().getOffset(),
				addressRange.getMaxAddress().getOffset()));
		}
		return list;
	}

	@Override
	public int getModCount() {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public AddressMap getOldAddressMap() {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public boolean hasSameKeyBase(long addrKey1, long addrKey2) {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public void invalidateCache() throws IOException {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public boolean isKeyRangeMax(long addrKey) {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public boolean isKeyRangeMin(long addrKey) {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public boolean isUpgraded() {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public void renameOverlaySpace(String oldName, String newName) throws IOException {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public void setImageBase(Address base) {
		throw new RuntimeException("Unimplmented!");
	}

	@Override
	public void setLanguage(Language newLanguage, AddressFactory addrFactory,
			LanguageTranslator translator) throws IOException {
		throw new RuntimeException("Unimplmented!");
	}

}
