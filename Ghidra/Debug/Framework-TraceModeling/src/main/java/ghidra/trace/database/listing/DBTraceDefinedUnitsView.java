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
package ghidra.trace.database.listing;

import java.util.*;

import com.google.common.collect.Range;

import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceDefinedUnitsView;
import ghidra.util.LockHold;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DBTraceDefinedUnitsView extends
		AbstractComposedDBTraceCodeUnitsView<AbstractDBTraceCodeUnit<?>, AbstractBaseDBTraceDefinedUnitsView<? extends AbstractDBTraceCodeUnit<?>>>
		implements TraceDefinedUnitsView {

	public DBTraceDefinedUnitsView(DBTraceCodeSpace space) {
		super(space, List.of(space.instructions, space.definedData));
	}

	@Override
	public boolean coversRange(Range<Long> span, AddressRange range) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			Set<TraceAddressSnapRange> set1 = new HashSet<>();
			Set<TraceAddressSnapRange> set2 = new HashSet<>();
			Set<TraceAddressSnapRange> cur = set1;
			cur.add(new ImmutableTraceAddressSnapRange(range, span));
			for (AbstractBaseDBTraceDefinedUnitsView<? extends AbstractDBTraceCodeUnit<?>> p : parts) {
				cur = p.subtractFrom(span, range, cur, set1, set2);
			}
			return cur.isEmpty();
		}
	}

	@Override
	public boolean intersectsRange(Range<Long> span, AddressRange range) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			for (AbstractBaseDBTraceDefinedUnitsView<? extends AbstractDBTraceCodeUnit<?>> p : parts) {
				if (p.intersectsRange(span, range)) {
					return true;
				}
			}
			return false;
		}
	}

	@Override
	public void clear(Range<Long> span, AddressRange range, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		for (AbstractBaseDBTraceDefinedUnitsView<? extends AbstractDBTraceCodeUnit<?>> view : parts) {
			view.clear(span, range, clearContext, monitor);
		}
	}
}
