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

import ghidra.pcode.exec.trace.data.PcodeTraceRegistersAccess;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

/**
 * A data-access shim for a trace's registers and the debugger
 */
public interface PcodeDebuggerRegistersAccess
		extends PcodeTraceRegistersAccess, PcodeDebuggerDataAccess {

	/**
	 * Instruct the associated recorder to read registers from the target
	 * 
	 * @param unknown the address set (in the platform's {@code register} space) of registers to
	 *            read
	 * @return a future which completes when the read is complete and its results recorded to the
	 *         trace. It completes with true when any part of target state was successfully read. It
	 *         completes with false if there is no target, or if the target was not read.
	 */
	CompletableFuture<Boolean> readFromTargetRegisters(AddressSetView unknown);

	/**
	 * Instruct the associated recorder to write target registers
	 * 
	 * <p>
	 * In normal operation, this will also cause the recorder, upon a successful write, to record
	 * the same values into the destination trace. If this shim is not associated with a live
	 * session, the returned future completes immediately with false.
	 * 
	 * @param address the address of the first byte to write (in the platform's {@code register}
	 *            space)
	 * @param data the bytes to write
	 * @return a future which completes when the write is complete and its results recorded to the
	 *         trace. It completes with true when the target was written. It completes with false if
	 *         there is no target, or if the target is not effected.
	 */
	CompletableFuture<Boolean> writeTargetRegister(Address address, byte[] data);
}
