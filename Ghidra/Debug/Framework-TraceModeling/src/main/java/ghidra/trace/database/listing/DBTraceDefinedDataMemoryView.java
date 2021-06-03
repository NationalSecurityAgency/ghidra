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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.DataType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.listing.TraceDefinedDataView;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DBTraceDefinedDataMemoryView
		extends AbstractBaseDBTraceCodeUnitsMemoryView<DBTraceData, DBTraceDefinedDataView>
		implements TraceDefinedDataView {
	public DBTraceDefinedDataMemoryView(DBTraceCodeManager manager) {
		super(manager);
	}

	@Override
	protected DBTraceDefinedDataView getView(DBTraceCodeSpace space) {
		return space.definedData;
	}

	@Override
	public void clear(Range<Long> span, AddressRange range, boolean clearContext,
			TaskMonitor monitor) throws CancelledException {
		delegateDeleteV(range.getAddressSpace(), m -> m.clear(span, range, clearContext, monitor));
	}

	@Override
	public DBTraceDataAdapter create(Range<Long> lifespan, Address address, DataType dataType,
			int length) throws CodeUnitInsertionException {
		return delegateWrite(address.getAddressSpace(),
			m -> m.create(lifespan, address, dataType, length));
	}

	@Override
	public DBTraceDataAdapter create(Range<Long> lifespan, Address address, DataType dataType)
			throws CodeUnitInsertionException {
		return delegateWrite(address.getAddressSpace(), m -> m.create(lifespan, address, dataType));
	}
}
