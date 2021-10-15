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

	protected void addOverlayAddressSpace(OverlayAddressSpace ovSpace)
			throws DuplicateNameException {
		addAddressSpace(ovSpace);
	}

	/**
	 * Create a new OverlayAddressSpace based upon the given overlay blockName and base AddressSpace
	 * 
	 * @param name the preferred name of the overlay address space to be created. This name may be
	 *            modified if preserveName is false to produce a valid overlay space name and avoid
	 *            duplication.
	 * @param preserveName if true specified name will be preserved, if false an unique acceptable
	 *            overlay space name will be generated from the specified name.
	 * @param originalSpace the base AddressSpace to overlay
	 * @param minOffset the min offset of the space
	 * @param maxOffset the max offset of the space
	 * @return the new overlay space
	 * @throws IllegalArgumentException if originalSpace is not permitted or preserveName is true
	 *             and a space with specified name already exists.
	 */
	protected OverlayAddressSpace addOverlayAddressSpace(String name, boolean preserveName,
			AddressSpace originalSpace, long minOffset, long maxOffset) {

		if (!originalSpace.isMemorySpace() || originalSpace.isOverlaySpace()) {
			throw new IllegalArgumentException(
				"Invalid address space for overlay: " + originalSpace.getName());
		}
		AddressSpace space = getAddressSpace(originalSpace.getName());
		if (space != originalSpace) {
			throw new IllegalArgumentException("Unknown memory address space instance");
		}

		String spaceName = name;
		if (!preserveName) {
			spaceName = fixupOverlaySpaceName(name);
			spaceName = getUniqueOverlayName(spaceName);
		}
		else if (getAddressSpace(name) != null) { // check before allocating unique ID
			throw new IllegalArgumentException("Space named " + name + " already exists!");
		}

		int unique = 0;
		if (originalSpace.getType() == AddressSpace.TYPE_RAM ||
			originalSpace.getType() == AddressSpace.TYPE_OTHER) {
			unique = getNextUniqueID();
		}

		OverlayAddressSpace ovSpace =
			new OverlayAddressSpace(spaceName, originalSpace, unique, minOffset, maxOffset);
		try {
			addAddressSpace(ovSpace);
		}
		catch (DuplicateNameException e) {
			throw new RuntimeException(e); // unexpected
		}
		return ovSpace;
	}

	/**
	 * Get a unique address space name based on the specified baseOverlayName
	 * 
	 * @param baseOverlayName base overlay address space name
	 * @return unique overlay space name
	 */
	private String getUniqueOverlayName(String baseOverlayName) {
		if (getAddressSpace(baseOverlayName) == null) {
			return baseOverlayName;
		}
		int index = 1;
		while (true) {
			String revisedName = baseOverlayName + "." + index++;
			if (getAddressSpace(revisedName) == null) {
				return revisedName;
			}
		}
	}

	/**
	 * Get base overlay name removing any numeric suffix which may have been added to avoid
	 * duplication. This method is intended to be used during rename only.
	 * 
	 * @param overlayName existing overlay space name
	 * @return base overlay name with any trailing index removed which may have been added to avoid
	 *         duplication.
	 */
	private String getBaseOverlayName(String overlayName) {
		int index = overlayName.lastIndexOf('.');
		if (index < 1) {
			return overlayName;
		}
		int value;
		try {
			value = Integer.parseInt(overlayName.substring(index + 1));
		}
		catch (NumberFormatException e) {
			return overlayName;
		}
		if (value < 1) {
			return overlayName;
		}
		String baseName = overlayName.substring(0, index);
		return overlayName.equals(baseName + '.' + value) ? baseName : overlayName;
	}

	/**
	 * Generate an allowed address space name from a block name. Use of unsupported characters will
	 * be converted to underscore (includes colon and all whitespace chars). double-underscore to
	 * ensure uniqueness.
	 * 
	 * @param blockName corresponding memory block name
	 * @return overlay space name
	 */
	private String fixupOverlaySpaceName(String blockName) {
		int len = blockName.length();
		StringBuffer buf = new StringBuffer(len);
		for (int i = 0; i < len; i++) {
			char c = blockName.charAt(i);
			if (c == ':' || c <= 0x20) {
				buf.append('_');
			}
			else {
				buf.append(c);
			}
		}
		return buf.toString();
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

	protected void removeOverlaySpace(String name) {
		removeAddressSpace(name);
	}

	/**
	 * Rename overlay with preferred newName. Actual name used will be returned and may differ from
	 * specified newName to ensure validity and avoid duplication.
	 * 
	 * @param oldOverlaySpaceName the existing overlay address space name
	 * @param newName the preferred new name of the overlay address space. This name may be modified
	 *            to produce a valid overlay space name to avoid duplication.
	 * @return new name applied to existing overlay space
	 */
	@Override
	protected String renameOverlaySpace(String oldOverlaySpaceName, String newName) {
		try {
			String revisedName = fixupOverlaySpaceName(newName);
			if (revisedName.equals(getBaseOverlayName(oldOverlaySpaceName))) {
				return oldOverlaySpaceName;
			}
			revisedName = getUniqueOverlayName(revisedName);
			return super.renameOverlaySpace(oldOverlaySpaceName, revisedName);
		}
		catch (DuplicateNameException e) {
			throw new RuntimeException(e); // unexpected
		}
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
