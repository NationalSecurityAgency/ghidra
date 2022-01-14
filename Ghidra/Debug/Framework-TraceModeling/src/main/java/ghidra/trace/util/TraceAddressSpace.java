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
package ghidra.trace.util;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.thread.TraceThread;

/**
 * Identify the "full" address space in a trace.
 * 
 * <p>
 * Whenever the address space is {@code register}, then the thread and frame level become
 * necessarily to uniquely identify it. This will be deprecated when either, 1) unique register
 * overlay spaces are created for each thread/frame, or 2) register values are fully transitioned to
 * object model storage.
 */
public interface TraceAddressSpace {
	AddressSpace getAddressSpace();

	TraceThread getThread();

	int getFrameLevel();
}
