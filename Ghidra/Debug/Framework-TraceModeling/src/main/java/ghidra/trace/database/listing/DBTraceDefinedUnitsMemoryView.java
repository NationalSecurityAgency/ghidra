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

import com.google.common.collect.Range;

import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.listing.TraceDefinedUnitsView;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DBTraceDefinedUnitsMemoryView extends
		AbstractBaseDBTraceCodeUnitsMemoryView<AbstractDBTraceCodeUnit<?>, DBTraceDefinedUnitsView>
		implements TraceDefinedUnitsView {
	public DBTraceDefinedUnitsMemoryView(DBTraceCodeManager manager) {
		super(manager);
	}

	@Override
	protected DBTraceDefinedUnitsView getView(DBTraceCodeSpace space) {
		return space.definedUnits;
	}

	@Override
	public void clear(Range<Long> span, AddressRange range, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		delegateDeleteV(range.getAddressSpace(), m -> m.clear(span, range, clearContext, monitor));
	}
}
