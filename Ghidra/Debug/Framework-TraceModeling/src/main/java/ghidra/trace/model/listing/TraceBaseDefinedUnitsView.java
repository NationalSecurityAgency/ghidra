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

import ghidra.program.model.address.AddressRange;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link TraceBaseCodeUnitsView} restricted (at least) to defined units
 *
 * @param <T> the type of units in the view
 */
public interface TraceBaseDefinedUnitsView<T extends TraceCodeUnit>
		extends TraceBaseCodeUnitsView<T> {

	/**
	 * Clear the units contained within the given span and address range.
	 * 
	 * Any units alive before the given span are truncated instead of deleted. That is, their end
	 * snaps are reduced such that they no longer intersect the given span. Note that the same is
	 * not true of a unit's start snap. If the start snap is contained in the span, the unit is
	 * deleted, even if its end snap is outside the span.
	 * 
	 * @param span the span to clear
	 * @param range the range to clear
	 * @param clearContext true to clear the register context as well
	 * @param monitor a monitor for progress and cancellation
	 * @throws CancelledException if the clear is cancelled
	 */
	void clear(Range<Long> span, AddressRange range, boolean clearContext, TaskMonitor monitor)
			throws CancelledException;
}
