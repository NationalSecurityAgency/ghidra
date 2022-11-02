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
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.program.model.address.AddressSetView;
import ghidra.trace.model.memory.TraceMemoryState;

/**
 * A relaxation of {@link RequireIsKnownTraceCachedWriteBytesPcodeExecutorStatePiece} that permits
 * reads of stale addresses
 * 
 * <p>
 * An address can be read so long as it is {@link TraceMemoryState#KNOWN} for any non-scratch snap
 * up to and including the given snap.
 */
public class RequireHasKnownTraceCachedWriteBytesPcodeExecutorStatePiece
		extends RequireIsKnownTraceCachedWriteBytesPcodeExecutorStatePiece {

	/**
	 * Construct a piece
	 * 
	 * @param data the trace-data access shim
	 */
	public RequireHasKnownTraceCachedWriteBytesPcodeExecutorStatePiece(PcodeTraceDataAccess data) {
		super(data);
	}

	@Override
	protected AddressSetView getKnown(PcodeTraceDataAccess backing) {
		return backing.getKnownBefore();
	}

	@Override
	protected AccessPcodeExecutionException excFor(AddressSetView unknown) {
		throw new AccessPcodeExecutionException("Memory at " + unknown + " has never been known.");
	}
}
