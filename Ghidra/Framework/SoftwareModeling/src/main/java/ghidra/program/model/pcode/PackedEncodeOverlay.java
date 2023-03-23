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

import java.io.IOException;

import ghidra.program.model.address.*;

/**
 * Alter address space encoding for a specific overlay space.
 * Any space that matches the overlay space is encoded as the overlayed space.
 * This causes addresses in the overlay space to be converted into the underlying space.
 */
public class PackedEncodeOverlay extends PackedEncode {
	private OverlayAddressSpace overlay = null;
	private int overlayId;		// Id of the overlay space
	private int underlyingId;	// If of the space underlying the overlay

	public PackedEncodeOverlay(OverlayAddressSpace spc) throws AddressFormatException {
		super();
		setOverlay(spc);
	}

	public void setOverlay(OverlayAddressSpace spc) throws AddressFormatException {
		overlayId = spc.getUnique();
		AddressSpace underlie = spc.getOverlayedSpace();
		underlyingId = underlie.getUnique();
		if (underlyingId == 0) {
			throw new AddressFormatException("Cannot set overlay over " + underlie.getName());
		}
		overlay = spc;
	}

	@Override
	public void writeSpace(AttributeId attribId, AddressSpace spc) throws IOException {
		if (spc == overlay) {
			spc = overlay.getOverlayedSpace();
		}
		super.writeSpace(attribId, spc);
	}

	@Override
	public void writeSpaceId(AttributeId attribId, long spaceId) {
		if (spaceId == overlayId) {
			spaceId = underlyingId;
		}
		super.writeSpaceId(attribId, spaceId);
	}
}
