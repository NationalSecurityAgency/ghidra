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
package ghidra.program.model.pcode;

import ghidra.program.model.address.*;

/**
 * Alter address space decoding for a specific overlay space.
 * Any decoded space that matches the overlayed space is replaced with the overlay itself.
 * This causes addresses in the overlayed space to be converted into overlay addresses.
 */
public class PackedDecodeOverlay extends PackedDecode {

	private OverlayAddressSpace overlay = null;

	public PackedDecodeOverlay(AddressFactory addrFactory, OverlayAddressSpace spc)
			throws AddressFormatException {
		super(addrFactory);
		setOverlay(spc);
	}

	public void setOverlay(OverlayAddressSpace spc) throws AddressFormatException {
		AddressSpace underlie;
		if (overlay != null) {
			underlie = overlay.getOverlayedSpace();
			spaces[underlie.getUnique()] = underlie;
			overlay = null;
		}
		underlie = spc.getOverlayedSpace();
		if (underlie.getUnique() == 0 || underlie.getUnique() >= spaces.length) {
			throw new AddressFormatException("Cannot set overlay over " + underlie.getName());
		}
		spaces[underlie.getUnique()] = spc;
		overlay = spc;
	}
}
