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
import ghidra.util.exception.DuplicateNameException;

public class ProgramOverlayAddressSpace extends OverlayAddressSpace {

	private final long key;
	private final OverlayRegionSupplier overlayRegionSupplier;

	private String overlayName;

	private AddressSetView overlaySet;

	/**
	 * 
	 * @param key DB record key
	 * @param overlayName current overlay name
	 * @param baseSpace base address space (type should be restricted as neccessary by caller)
	 * @param unique assigned unique ID
	 * @param overlayRegionSupplier callback handler which supplies the defined address set 
	 * for a specified overlay address space. 
	 * @param factory used to determine a suitable ordered overlay ordered-key used for
	 * {@link #equals(Object)} and {@link #compareTo(AddressSpace)}.
	 * @throws DuplicateNameException if specified name duplicates an existing address space name
	 */
	public ProgramOverlayAddressSpace(long key, String overlayName, AddressSpace baseSpace,
			int unique, OverlayRegionSupplier overlayRegionSupplier, ProgramAddressFactory factory)
			throws DuplicateNameException {
		super(baseSpace, unique, factory.generateOrderedKey(overlayName));
		this.key = key;
		this.overlayName = overlayName;
		this.overlayRegionSupplier = overlayRegionSupplier;
		factory.addOverlaySpace(this);
	}

	protected synchronized void invalidate() {
		overlaySet = null;
	}

	private void validate() {
		if (overlaySet == null) {
			overlaySet =
				overlayRegionSupplier != null ? overlayRegionSupplier.getOverlayAddressSet(this)
						: new AddressSet();
			if (overlaySet == null) {
				overlaySet = new AddressSet();
			}
		}
	}

	/**
	 * Get the DB record key used to store this overlay specification.
	 * This is intended to be used internally to reconcile address spaces only.
	 * @return DB record key
	 */
	public long getKey() {
		return key;
	}

	@Override
	public String getName() {
		return overlayName;
	}

	/**
	 * Method to support renaming an overlay address space instance.  Intended for internal use only.
	 * @param name new overlay space name
	 */
	public void setName(String name) {
		this.overlayName = name;
	}

	@Override
	public synchronized boolean contains(long offset) {
		try {
			Address addr = getAddressInThisSpaceOnly(makeValidOffset(offset));
			return getOverlayAddressSet().contains(addr);
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
	}

	@Override
	public synchronized AddressSetView getOverlayAddressSet() {
		validate();
		return overlaySet;
	}

}
