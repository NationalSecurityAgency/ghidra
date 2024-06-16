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
package ghidra.pcode.exec.trace.data;

import ghidra.program.model.address.*;
import ghidra.trace.model.TraceTimeViewport;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryOperations;
import ghidra.trace.model.property.TracePropertyMapOperations;

/**
 * The default data-access shim for trace memory
 */
public class DefaultPcodeTraceMemoryAccess extends AbstractPcodeTraceDataAccess
		implements PcodeTraceMemoryAccess {

	/**
	 * Construct a shim
	 * 
	 * @param platform the associated platform
	 * @param snap the associated snap
	 * @param viewport the viewport, set to the same snapshot
	 */
	protected DefaultPcodeTraceMemoryAccess(TracePlatform platform, long snap,
			TraceTimeViewport viewport) {
		super(platform, snap, viewport);
	}

	@Override
	protected TraceMemoryOperations getMemoryOps(boolean createIfAbsent) {
		return mm;
	}

	@Override
	public <T> TracePropertyMapOperations<T> getPropertyOps(String name, Class<T> type,
			boolean createIfAbsent) {
		if (createIfAbsent) {
			return platform.getTrace()
					.getAddressPropertyManager()
					.getOrCreatePropertyMap(name, type);
		}
		return platform.getTrace().getAddressPropertyManager().getPropertyMap(name, type);
	}

	@Override
	protected Address toOverlay(Address address) {
		return address;
	}

	@Override
	protected AddressRange toOverlay(AddressRange range) {
		return range;
	}

	@Override
	protected AddressSetView toOverlay(AddressSetView set) {
		return set;
	}
}
