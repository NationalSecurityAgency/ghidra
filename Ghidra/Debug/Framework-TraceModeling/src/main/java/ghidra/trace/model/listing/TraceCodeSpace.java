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
package ghidra.trace.model.listing;

import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.thread.TraceThread;

/**
 * A space within a {@link CodeManager} bound to a specific address space or thread and frame
 * 
 * <p>
 * Ordinarily, the manager can operate on all memory address spaces without the client needing to
 * bind to it specifically. However, there may be occasions where it's convenient (and more
 * efficient) to bind to the address space, anyway. Operating on register units requires binding to
 * the space.
 * 
 * @see TraceCodeManager#getCodeSpace(AddressSpace, boolean)}
 * @see TraceCodeManager#getCodeRegisterSpace(TraceThread, int, boolean)}
 */
public interface TraceCodeSpace extends TraceCodeOperations {

	/**
	 * Get the address space of this code space
	 * 
	 * @return the address space
	 */
	AddressSpace getAddressSpace();

	/**
	 * Get the associated thread, if applicable
	 * 
	 * @return the thread, or null
	 */
	TraceThread getThread();

	/**
	 * Get the associated frame level, if applicable
	 * 
	 * @return the frame level, or 0
	 */
	int getFrameLevel();

}
