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
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

/**
 * Add conveniences for getting the thread and frame level, if applicable, from an object's address
 * space.
 */
public interface TraceSpaceMixin {
	/**
	 * Get the trace containing the object
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the object's address space
	 * 
	 * @return the address space
	 */
	AddressSpace getAddressSpace();

	/**
	 * Get the thread denoted by the object's address space
	 * 
	 * @return the thread
	 */
	default TraceThread getThread() {
		return TraceRegisterUtils.getThread(getTrace(), getAddressSpace());
	}

	/**
	 * Get the frame level denoted by the object's address space
	 * 
	 * <p>
	 * Note this will return 0 if the frame level is not applicable. This is the same as the
	 * innermost frame level when it is applicable. To distinguish whether or not a 0 return value
	 * is applicable, you must examine the path or schema.
	 * 
	 * @return the level or 0
	 */
	default int getFrameLevel() {
		return TraceRegisterUtils.getFrameLevel(getTrace(), getAddressSpace());
	}
}
