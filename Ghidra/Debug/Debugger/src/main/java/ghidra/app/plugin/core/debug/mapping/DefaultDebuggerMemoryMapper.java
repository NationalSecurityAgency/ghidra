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
package ghidra.app.plugin.core.debug.mapping;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;

public class DefaultDebuggerMemoryMapper implements DebuggerMemoryMapper {
	protected final AddressFactory traceAddressFactory;
	protected final AddressFactory targetAddressFactory;

	public DefaultDebuggerMemoryMapper(Language traceLanguage, DebuggerObjectModel targetModel) {
		this.traceAddressFactory = traceLanguage.getAddressFactory();
		this.targetAddressFactory = targetModel.getAddressFactory();
	}

	protected static boolean isInFactory(AddressSpace space, AddressFactory factory) {
		return factory.getAddressSpace(space.getName()) == space;
	}

	protected static boolean isInFactory(Address addr, AddressFactory factory) {
		return isInFactory(addr.getAddressSpace(), factory);
	}

	protected static Address toSameNamedSpace(Address addr, AddressFactory factory) {
		return factory.getAddressSpace(addr.getAddressSpace().getName())
				.getAddress(addr.getOffset());
	}

	@Override
	public Address traceToTarget(Address traceAddr) {
		assert isInFactory(traceAddr, traceAddressFactory);
		return toSameNamedSpace(traceAddr, targetAddressFactory);
	};

	@Override
	public AddressRange traceToTarget(AddressRange traceRange) {
		return new AddressRangeImpl(traceToTarget(traceRange.getMinAddress()),
			traceToTarget(traceRange.getMaxAddress()));
	}

	@Override
	public Address targetToTrace(Address targetAddr) {
		if (targetAddr == SpecialAddress.NO_ADDRESS) {
			/**
			 * TODO: Allow NO_ADDRESS into the database? There will be a bit of fallout as the UI
			 * will have to accommodate the same possibility, esp., for go-to.
			 */
			return null;
		}
		assert isInFactory(targetAddr, targetAddressFactory);
		return toSameNamedSpace(targetAddr, traceAddressFactory);
	}

	@Override
	public AddressRange targetToTrace(AddressRange targetRange) {
		return new AddressRangeImpl(targetToTrace(targetRange.getMinAddress()),
			targetToTrace(targetRange.getMaxAddress()));
	}
}
