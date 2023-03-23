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

import java.util.HashMap;
import java.util.Map;

import db.Transaction;
import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.util.exception.DuplicateNameException;

public class ObjectBasedDebuggerMemoryMapper implements DebuggerMemoryMapper {
	protected final Trace trace;
	protected final AddressSpace base;

	protected final Map<Integer, AddressSpace> targetToTraceSpaces = new HashMap<>();
	protected final Map<Integer, AddressSpace> traceToTargetSpaces = new HashMap<>();

	public ObjectBasedDebuggerMemoryMapper(Trace trace) {
		this.trace = trace;
		this.base = trace.getBaseAddressFactory().getDefaultAddressSpace();
	}

	@Override
	public Address traceToTarget(Address traceAddr) {
		AddressSpace traceSpace = traceAddr.getAddressSpace();
		int traceIdHash = System.identityHashCode(traceSpace);
		AddressSpace targetSpace;
		synchronized (traceToTargetSpaces) {
			targetSpace = traceToTargetSpaces.get(traceIdHash);
		}
		/**
		 * Can only be null if space is the default space or some non-physical space. In that case,
		 * the target hasn't defined a space with that name, so no mapping.
		 */
		if (targetSpace == null) {
			return null;
		}
		return targetSpace.getAddress(traceAddr.getOffset());
	}

	@Override
	public Address targetToTrace(Address targetAddr) {
		AddressSpace targetSpace = targetAddr.getAddressSpace();
		int targetIdHash = System.identityHashCode(targetSpace);
		AddressSpace traceSpace;
		synchronized (traceToTargetSpaces) {
			traceSpace = targetToTraceSpaces.get(targetIdHash);
			if (traceSpace == null) {
				traceSpace = createSpace(targetSpace.getName());
				targetToTraceSpaces.put(targetIdHash, traceSpace);
				traceToTargetSpaces.put(System.identityHashCode(traceSpace),
					targetSpace);
			}
		}
		return traceSpace.getAddress(targetAddr.getOffset());
	}

	@Override
	public AddressRange targetToTraceTruncated(AddressRange targetRange) {
		// the DATA space can always accommodate all 64 bits
		return targetToTrace(targetRange);
	}

	protected AddressSpace createSpace(String name) {
		try (Transaction tx = trace.openTransaction("Create space for mapping")) {
			AddressFactory factory = trace.getBaseAddressFactory();
			AddressSpace space = factory.getAddressSpace(name);
			if (space == null) {
				return trace.getMemoryManager().createOverlayAddressSpace(name, base);
			}
			// Let the default space suffice for its own name
			// NB. if overlay already exists, we've already issued a warning
			if (space == base || space.isOverlaySpace()) {
				return space;
			}
			// Otherwise, do not allow non-physical spaces to be used by accident.
			return trace.getMemoryManager().createOverlayAddressSpace('_' + name, base);
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e);
		}
	}
}
