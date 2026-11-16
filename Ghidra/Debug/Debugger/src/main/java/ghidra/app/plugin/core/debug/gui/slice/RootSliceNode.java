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
package ghidra.app.plugin.core.debug.gui.slice;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;

class RootSliceNode extends AbstractSliceNode {
	private final Program image;
	private final Address staticPc;

	public RootSliceNode(Trace trace, Program image, Address staticPc) {
		this.image = image;
		this.staticPc = staticPc;
		super("<root>", trace);
	}

	@Override
	public String getLocation() {
		return "";
	}

	@Override
	public Address getAddress() {
		return null;
	}

	@Override
	public long getSnap() {
		return 0;
	}

	@Override
	public boolean displaySnap() {
		return false;
	}

	@Override
	public Program getImage() {
		return image;
	}

	@Override
	public Address getStaticPc() {
		return staticPc;
	}

	@Override
	public byte[] getBytes() {
		return null;
	}
}
