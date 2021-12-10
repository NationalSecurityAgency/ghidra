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
package ghidra.pcode.exec.trace;

import ghidra.pcode.exec.AccessPcodeExecutionException;
import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;

public class RequireIsKnownTraceCachedWriteBytesPcodeExecutorState
		extends AbstractCheckedTraceCachedWriteBytesPcodeExecutorState {

	public RequireIsKnownTraceCachedWriteBytesPcodeExecutorState(Trace trace, long snap,
			TraceThread thread, int frame) {
		super(trace, snap, thread, frame);
	}

	protected AddressSetView getKnown(TraceMemorySpace source) {
		return source.getAddressesWithState(snap, s -> s == TraceMemoryState.KNOWN);
	}

	protected AccessPcodeExecutionException excFor(AddressSetView unknown) {
		return new AccessPcodeExecutionException("Memory at " + unknown + " is unknown.");
	}

	@Override
	protected int checkUninitialized(TraceMemorySpace source, Address start, int size,
			AddressSet uninitialized) {
		if (source == null) {
			if (!uninitialized.contains(start)) {
				return (int) uninitialized.getMinAddress().subtract(start);
			}
			throw excFor(uninitialized);
		}
		// TODO: Could find first instead?
		AddressSetView unknown = uninitialized.subtract(getKnown(source));
		if (unknown.isEmpty()) {
			return size;
		}
		if (!unknown.contains(start)) {
			return (int) unknown.getMinAddress().subtract(start);
		}
		throw excFor(unknown);
	}
}
