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
package ghidra.dbg.sctl.client.depr;

import ghidra.program.model.address.*;

/**
 * A singleton default implementation of {@link DebuggerAddressMapper}
 * 
 * This implements the minimum required to provide an address factory, which simply maps the entire
 * offset space into single address space ("RAM") on the target.
 */
public class DefaultDebuggerAddressMapper implements DebuggerAddressMapper {
	/**
	 * The singleton instance
	 */
	public static final DefaultDebuggerAddressMapper INSTANCE = new DefaultDebuggerAddressMapper();

	protected final AddressSpace constant =
		new GenericAddressSpace("const", 64, AddressSpace.TYPE_CONSTANT, 0);
	protected final AddressSpace ram =
		new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 1);
	protected final AddressFactory factory =
		new DefaultAddressFactory(new AddressSpace[] { ram, constant });

	protected DefaultDebuggerAddressMapper() {
	}

	@Override
	public Address mapOffsetToAddress(long offset) {
		return ram.getAddress(offset);
	}

	@Override
	public long mapAddressToOffset(Address address) {
		return address.getOffset();
	}

	@Override
	public AddressFactory getAddressFactory() {
		return factory;
	}
}
