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

import com.google.common.collect.Range;

import ghidra.pcode.exec.AccessPcodeExecutionException;
import ghidra.program.model.address.AddressSetView;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;

public class RequireHasKnownTraceCachedWriteBytesPcodeExecutorState
		extends RequireIsKnownTraceCachedWriteBytesPcodeExecutorState {

	public RequireHasKnownTraceCachedWriteBytesPcodeExecutorState(Trace trace, long snap,
			TraceThread thread, int frame) {
		super(trace, snap, thread, frame);
	}

	@Override
	protected AddressSetView getKnown(TraceMemorySpace source) {
		return source.getAddressesWithState(Range.closed(0L, snap),
			s -> s == TraceMemoryState.KNOWN);
	}

	@Override
	protected AccessPcodeExecutionException excFor(AddressSetView unknown) {
		throw new AccessPcodeExecutionException("Memory at " + unknown + " has never been known.");
	}
}
