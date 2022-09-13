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
package ghidra.app.plugin.core.debug.service.emulation.data;

import java.util.concurrent.CompletableFuture;

import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.trace.data.PcodeTraceMemoryAccess;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

/**
 * A data-access shim for a trace's memory and the debugger
 */
public interface PcodeDebuggerMemoryAccess
		extends PcodeTraceMemoryAccess, PcodeDebuggerDataAccess {

	/**
	 * Instruct the associated recorder to read memory from the target
	 * 
	 * <p>
	 * The recorder may quantize the given address set to pages. It will include all the requested
	 * addresses, though. If this shim is not associated with a live session, the returned future
	 * completes immediately with false.
	 * 
	 * @param unknown the address set to read
	 * @return a future which completes when the read is complete and its results recorded to the
	 *         trace. It completes with true when any part of target memory was successfully read.
	 *         It completes with false if there is no target, or if the target was not read.
	 */
	CompletableFuture<Boolean> readFromTargetMemory(AddressSetView unknown);

	/**
	 * Use the Debugger's static mapping service to read bytes from relocated program images
	 * 
	 * <p>
	 * To be read, the program database for the static image must be open in the same tool as the
	 * trace being emulated. Depending on the use case, this may only be approximately correct. In
	 * particular, if the trace was from a live session that has since been terminated, and the
	 * image was relocated with fixups, reads at those fixups which fall through to static images
	 * will be incorrect, and may lead to undefined behavior in the emulated program.
	 * 
	 * @param bytes the destination byte store
	 * @param unknown the address set to read
	 * @return true if any bytes were read, false if there was no effect
	 */
	boolean readFromStaticImages(SemisparseByteArray bytes, AddressSetView unknown);

	/**
	 * Instruct the associated recorder to write target memory
	 * 
	 * <p>
	 * In normal operation, this will also cause the recorder, upon a successful write, to record
	 * the same bytes into the destination trace. If this shim is not associated with a live
	 * session, the returned future completes immediately with false.
	 * 
	 * @param address the address of the first byte to write
	 * @param data the bytes to write
	 * @return a future which completes when the write is complete and its results recorded to the
	 *         trace. It completes with true when the target was written. It completes with false if
	 *         there is no target, or if the target is not effected.
	 */
	CompletableFuture<Boolean> writeTargetMemory(Address address, byte[] data);
}
