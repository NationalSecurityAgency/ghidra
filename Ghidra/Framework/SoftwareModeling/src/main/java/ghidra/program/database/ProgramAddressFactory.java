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
package ghidra.program.database;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.DuplicateNameException;

public class ProgramAddressFactory extends DefaultAddressFactory {

	private AddressFactory originalFactory;
	private AddressSpace stackSpace;

	public ProgramAddressFactory(Language language, CompilerSpec compilerSpec) {
		super(language.getAddressFactory().getAllAddressSpaces(),
			language.getAddressFactory().getDefaultAddressSpace());
		this.originalFactory = language.getAddressFactory();
		initOtherSpace(language);
		initExternalSpace(language);
		initStackSpace(language, compilerSpec);
		initHashSpace(language);
		initJoinSpace(language);
	}

	private void initOtherSpace(Language language) {
		try {
			addAddressSpace(AddressSpace.OTHER_SPACE);
		}
		catch (DuplicateNameException e) {
			throw new IllegalStateException("Language must not define 'OTHER' space: " +
				language.getLanguageID().getIdAsString());
		}
	}

	private void initExternalSpace(Language language) {
		try {
			addAddressSpace(AddressSpace.EXTERNAL_SPACE);
		}
		catch (DuplicateNameException e) {
			throw new IllegalStateException("Language must not define 'EXTERNAL' space: " +
				language.getLanguageID().getIdAsString());
		}
	}

	private void initStackSpace(Language language, CompilerSpec compilerSpec) {
		this.stackSpace = compilerSpec.getStackSpace();
		try {
			addAddressSpace(stackSpace);
		}
		catch (DuplicateNameException e) {
			throw new IllegalStateException("Language must not define 'STACK' space: " +
				language.getLanguageID().getIdAsString());
		}
	}

	private void initHashSpace(Language language) {
		try {
			addAddressSpace(AddressSpace.HASH_SPACE);
		}
		catch (DuplicateNameException e) {
			throw new IllegalStateException("Language must not define 'HASH' space: " +
				language.getLanguageID().getIdAsString());
		}
	}

	private void initJoinSpace(Language language) {
		try {
			addAddressSpace(AddressSpace.VARIABLE_SPACE);
		}
		catch (DuplicateNameException e) {
			throw new IllegalStateException("Language must not define 'JOIN' space: " +
				language.getLanguageID().getIdAsString());
		}
	}

	@Override
	public AddressSpace getStackSpace() {
		return stackSpace;
	}

	AddressFactory getOriginalAddressFactory() {
		return originalFactory;
	}

	public void addOverlayAddressSpace(OverlayAddressSpace ovSpace) throws DuplicateNameException {
		addAddressSpace(ovSpace);
	}

	public OverlayAddressSpace addOverlayAddressSpace(String name, AddressSpace originalSpace,
			long minOffset, long maxOffset) throws DuplicateNameException {
		int unique = 0;
		if (originalSpace.getType() == AddressSpace.TYPE_RAM ||
			originalSpace.getType() == AddressSpace.TYPE_OTHER) {
			unique = getNextUniqueID();
		}
		OverlayAddressSpace ovSpace =
			new OverlayAddressSpace(name, originalSpace, unique, minOffset, maxOffset);
		addAddressSpace(ovSpace);
		return ovSpace;
	}

	@Override
	public Address getAddress(int spaceID, long offset) {
		Address addr = super.getAddress(spaceID, offset);
		if (addr == null && spaceID == stackSpace.getSpaceID()) {
			return stackSpace.getAddress(offset);
		}
		return addr;
	}

	@Override
	public Address getAddress(String addrString) {
		Address addr = null;
		if (addrString.startsWith("Stack[") && addrString.endsWith("]")) {
			try {
				long stackOffset =
					NumericUtilities.parseHexLong(addrString.substring(6, addrString.length() - 1));
				addr = stackSpace.getAddress(stackOffset);
			}
			catch (NumberFormatException e) {
				// bad string
			}
		}
		else {
			addr = super.getAddress(addrString);
		}
		return addr;
	}

	void removeOverlaySpace(String name) {
		removeAddressSpace(name);
	}

	@Override
	protected void renameOverlaySpace(String oldName, String newName)
			throws DuplicateNameException {
		super.renameOverlaySpace(oldName, newName);
	}

	private int getNextUniqueID() {
		int maxID = 0;
		AddressSpace[] spaces = getAllAddressSpaces();
		for (AddressSpace space : spaces) {
			maxID = Math.max(maxID, space.getUnique());
		}
		return maxID + 1;
	}
}
