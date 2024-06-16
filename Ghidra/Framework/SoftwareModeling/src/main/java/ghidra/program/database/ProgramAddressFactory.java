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
import ghidra.util.InvalidNameException;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.DuplicateNameException;

public class ProgramAddressFactory extends DefaultAddressFactory {

	protected final OverlayRegionSupplier overlayRegionSupplier;

	private AddressFactory originalFactory;
	private AddressSpace stackSpace;
	private boolean hasStaleOverlays = false;
	private long nextTmpId = 1; // used for overlay naming

	/**
	 * Construct a Program address factory which augments the {@link DefaultAddressFactory} 
	 * supplied by a {@link Language}.  The following additional address spaces are added:
	 * <ul>
	 * <li>{@link AddressSpace#OTHER_SPACE}</li>
	 * <li>{@link AddressSpace#EXTERNAL_SPACE}</li>
	 * <li>A stack space (see {@link AddressSpace#TYPE_STACK})</li>
	 * <li>{@link AddressSpace#HASH_SPACE}</li>
	 * <li>A join space (see {@link AddressSpace#TYPE_JOIN})</li>
	 * </ol>
	 * In addition, support is provided for {@link ProgramOverlayAddressSpace}.
	 * @param language language specification
	 * @param compilerSpec compiler specification
	 * @param overlayRegionSupplier overlay space defined region supplier which will be invoked when 
	 * specific queries are performed on overlay address spaces.  If memory is not yet available 
	 * a null AddressSet may be returned by the supplier.
	 */
	public ProgramAddressFactory(Language language, CompilerSpec compilerSpec,
			OverlayRegionSupplier overlayRegionSupplier) {
		super(language.getAddressFactory().getAllAddressSpaces(),
			language.getAddressFactory().getDefaultAddressSpace());
		this.originalFactory = language.getAddressFactory();
		this.overlayRegionSupplier = overlayRegionSupplier;
		initOtherSpace(language);
		initExternalSpace(language);
		initStackSpace(language, compilerSpec);
		initHashSpace(language);
		initJoinSpace(language);
	}

	public void invalidateOverlayCache() {
		for (AddressSpace space : getAddressSpaces()) {
			if (space instanceof ProgramOverlayAddressSpace os) {
				os.invalidate();
			}
		}
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

	/**
	 * Determine whether the given space can have an overlay
	 * 
	 * @param baseSpace the overlay base address space
	 * @return true to allow, false to prohibit
	 */
	protected boolean isValidOverlayBaseSpace(AddressSpace baseSpace) {
		if (baseSpace != getAddressSpace(baseSpace.getName())) {
			return false;
		}
		return baseSpace.isMemorySpace() && !baseSpace.isOverlaySpace();
	}

	/**
	 * Add an overlay address space to this factory
	 * @param ovSpace overlay space
	 * @throws DuplicateNameException if name of overlay space already exists in this factory
	 */
	protected void addOverlaySpace(ProgramOverlayAddressSpace ovSpace)
			throws DuplicateNameException {
		if (!ovSpace.getOrderedKey().equals(ovSpace.getName())) {
			hasStaleOverlays = true;
		}
		addAddressSpace(ovSpace);
	}

	/**
	 * Create a new ProgramOverlayAddressSpace based upon the given overlay blockName and base AddressSpace
	 * @param key overlay record key
	 * @param overlayName overlay name
	 * @param baseSpace the base AddressSpace to overlay
	 * @return the new overlay space
	 * @throws DuplicateNameException if overlay name duplicates another address space name
	 * @throws IllegalArgumentException if baseSpace is not permitted or not found.
	 */
	protected ProgramOverlayAddressSpace addOverlaySpace(long key, String overlayName,
			AddressSpace baseSpace) throws DuplicateNameException {

		if (!isValidOverlayBaseSpace(baseSpace)) {
			throw new IllegalArgumentException(
				"Invalid base space for overlay: " + baseSpace.getName());
		}

		AddressSpace space = getAddressSpace(baseSpace.getName());
		if (space != baseSpace) {
			throw new IllegalArgumentException("Invalid memory address space instance");
		}

		return new ProgramOverlayAddressSpace(key, overlayName, baseSpace, getNextUniqueID(),
			overlayRegionSupplier, this);
	}

	public void checkValidOverlaySpaceName(String name)
			throws InvalidNameException, DuplicateNameException {

		if (!AddressSpace.isValidName(name)) {
			throw new InvalidNameException("Invalid overlay space name: " + name);
		}

		if (getAddressSpace(name) != null) {
			throw new DuplicateNameException("Duplicate address space name: " + name);
		}
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

	/**
	 * Remove an overlay space.
	 * It may be neccessary to invoke {@link #refreshStaleOverlayStatus()} when an overlay is
	 * removed.
	 * @param name overlay space name
	 */
	protected void removeOverlaySpace(String name) {
		AddressSpace space = getAddressSpace(name);
		if (!(space instanceof ProgramOverlayAddressSpace)) {
			throw new IllegalArgumentException("Overlay " + name + " not found");
		}
		removeAddressSpace(name);
	}

	protected void overlaySpaceRenamed(String oldOverlaySpaceName, String newName,
			boolean refreshStatusIfNeeded) {
		OverlayAddressSpace os = super.overlaySpaceRenamed(oldOverlaySpaceName, newName);
		if (!newName.equals(os.getOrderedKey())) {
			hasStaleOverlays = true;
		}
		else if (hasStaleOverlays && refreshStatusIfNeeded) {
			refreshStaleOverlayStatus(); // must check all overlays to determine status
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

	/**
	 * Examine all overlay spaces and update the stale status indicator
	 * (see {@link #hasStaleOverlays}).
	 */
	protected void refreshStaleOverlayStatus() {
		hasStaleOverlays = false;
		for (AddressSpace space : getAddressSpaces()) {
			if (space instanceof ProgramOverlayAddressSpace os) {
				if (!os.getName().equals(os.getOrderedKey())) {
					hasStaleOverlays = true;
					break;
				}
			}
		}
	}

	@Override
	public boolean hasStaleOverlayCondition() {
		return hasStaleOverlays;
	}

	/**
	 * Generate an ordered unique name-based key for use with overlay spaces.  
	 * This will generally be the overlay name unless that value has already been utilized by 
	 * another overlay.
	 * @param overlayName overlay name
	 * @return ordered key to be used
	 */
	synchronized String generateOrderedKey(String overlayName) {
		for (AddressSpace space : getAddressSpaces()) {
			if (space instanceof ProgramOverlayAddressSpace os) {
				if (overlayName.equals(os.getOrderedKey())) {
					return overlayName + Address.SEPARATOR + nextTmpId++;
				}
			}
		}
		return overlayName;
	}
}
