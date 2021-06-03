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

import com.google.common.collect.Range;

import ghidra.program.model.lang.Register;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link TraceBaseDefinedUnitsView} associated with a thread, restricted to register space, and
 * possibly restricted to a paritcular subset by type.
 * 
 * @param <T> the type of units in the view
 */
public interface TraceBaseDefinedRegisterView<T extends TraceCodeUnit>
		extends TraceBaseDefinedUnitsView<T>, TraceBaseCodeUnitsRegisterView<T> {

	/**
	 * Clear the units contained within the given span and register
	 * 
	 * Any units alive before the given span are truncated instead of deleted.
	 * 
	 * @param span the span to clear
	 * @param register the register
	 * @param monitor a monitor for progress and cancellation
	 * @throws CancelledException if the clear is cancelled
	 */
	default void clear(Range<Long> span, Register register, TaskMonitor monitor)
			throws CancelledException {
		clear(span, TraceRegisterUtils.rangeForRegister(register), true, monitor);
	}
}
