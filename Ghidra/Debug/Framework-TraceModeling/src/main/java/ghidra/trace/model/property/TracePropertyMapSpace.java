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
package ghidra.trace.model.property;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.Trace;

/**
 * A property map space for a memory space
 *
 * <p>
 * Note this interface is inherited by {@link TracePropertyMapRegisterSpace}, so "memory space" can
 * also mean the {@code register} space.
 *
 * @param <T> the type of values
 */
public interface TracePropertyMapSpace<T> extends TracePropertyMapOperations<T> {
	/**
	 * Get the trace
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the address space for this space
	 * 
	 * <p>
	 * If this is the {@code register} space, then {@link TracePropertyMapRegisterSpace#getThread()}
	 * and {@link TracePropertyMapRegisterSpace#getFrameLevel()} are necessary to uniquely identify
	 * this space.
	 * 
	 * @return the address space
	 */
	AddressSpace getAddressSpace();
}
