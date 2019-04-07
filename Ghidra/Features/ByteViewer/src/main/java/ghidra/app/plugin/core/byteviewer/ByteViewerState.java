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
package ghidra.app.plugin.core.byteviewer;

import java.math.BigInteger;

import docking.widgets.fieldpanel.support.ViewerPosition;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.format.*;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;

/**
 * Implementation for a snapshot of the the byte viewer's current view.
 */
class ByteViewerState {

	private ViewerPosition vp;
	private ByteBlock block;
	private BigInteger offset;
	private Address addr; // null if a program is not in view

	ByteViewerState(ByteBlockSet blockSet, ByteBlockInfo info, ViewerPosition vp) {
		block = info.getBlock();
		offset = info.getOffset();
		this.vp = vp;
		PluginEvent event = blockSet.getPluginEvent("", block, offset, info.getColumn());
		if (event != null) {
			if (event instanceof ProgramLocationPluginEvent) {
				ProgramLocation loc = ((ProgramLocationPluginEvent) event).getLocation();
				addr = loc.getAddress();
			}
		}
	}

	/**
	 * Returns the address that the current view is focused on.
	 *
	 * @return will return null if and only if the viewer does not currently
	 * have a program. In other words, if a viewer has a program then it must
	 * be able to associate a single "focus" address to any possible view it
	 * can be in. The choice of address to use is, of course, up to each
	 * implementing object.
	 */
	public Address getAddress() {
		return addr;
	}

	/**
	 * String representation for this object, used for debugging.
	 */
	@Override
	public String toString() {
		return "ByteViewerState: address=" + addr + ", view position index==> " +
			vp.getIndexAsInt() + ", view y offset==> " + vp.getYOffset();
	}

	/**
	 * Get the view position for the current component.
	 */
	ViewerPosition getViewerPosition() {
		return vp;
	}

	/**
	 * Get the block.
	 */
	ByteBlock getBlock() {
		return block;
	}

	/**
	 * Get the offset into the block.
	 */
	BigInteger getOffset() {
		return offset;
	}
}
