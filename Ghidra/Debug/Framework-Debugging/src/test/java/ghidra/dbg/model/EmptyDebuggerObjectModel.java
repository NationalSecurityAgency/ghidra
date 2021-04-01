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
package ghidra.dbg.model;

import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.agent.SpiTargetObject;
import ghidra.program.model.address.*;

public class EmptyDebuggerObjectModel extends AbstractDebuggerObjectModel {
	protected final AddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
	protected final AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] { ram });

	@Override
	public AddressFactory getAddressFactory() {
		return factory;
	}

	public Address addr(long off) {
		return ram.getAddress(off);
	}

	public AddressRange range(long min, long max) {
		return new AddressRangeImpl(addr(min), addr(max));
	}

	@Override
	public void addModelRoot(SpiTargetObject root) {
		super.addModelRoot(root);
	}
}
