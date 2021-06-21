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
package ghidra.trace.database.program;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.ProgramChangeSet;

public class DBTraceProgramViewChangeSet implements ProgramChangeSet {

	@Override
	public boolean hasChanges() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public AddressSetView getAddressSet() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void add(AddressSetView addrSet) {
		// TODO Auto-generated method stub

	}

	@Override
	public void addRange(Address addr1, Address addr2) {
		// TODO Auto-generated method stub

	}

	@Override
	public void addRegisterRange(Address addr1, Address addr2) {
		// TODO Auto-generated method stub

	}

	@Override
	public AddressSetView getRegisterAddressSet() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void dataTypeChanged(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dataTypeAdded(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public long[] getDataTypeChanges() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long[] getDataTypeAdditions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void categoryChanged(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public void categoryAdded(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public long[] getCategoryChanges() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long[] getCategoryAdditions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void sourceArchiveChanged(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public void sourceArchiveAdded(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public long[] getSourceArchiveChanges() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long[] getSourceArchiveAdditions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void programTreeChanged(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public void programTreeAdded(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public long[] getProgramTreeChanges() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long[] getProgramTreeAdditions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void symbolChanged(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public void symbolAdded(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public long[] getSymbolChanges() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long[] getSymbolAdditions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void tagChanged(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public void tagCreated(long id) {
		// TODO Auto-generated method stub

	}

	@Override
	public long[] getTagChanges() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public long[] getTagCreations() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AddressSetCollection getAddressSetCollectionSinceLastSave() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AddressSetCollection getAddressSetCollectionSinceCheckout() {
		// TODO Auto-generated method stub
		return null;
	}

}
