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

import ghidra.lifecycle.Internal;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.listing.TraceDefinedDataView;
import ghidra.trace.util.TraceRegisterUtils;

@Internal
public interface InternalTraceDefinedDataView
		extends TraceDefinedDataView, InternalTraceBaseDefinedUnitsView<TraceData> {

	default TracePlatform getPlatformOf(DataType type) {
		if (type.getDataTypeManager() instanceof TraceBasedDataTypeManager dtm &&
			dtm.getTrace() == getTrace()) {
			return dtm.getPlatform();
		}
		/**
		 * TODO: Could we seek a nearest match in terms of data organization? Eh. Maybe not, because
		 * we'd also have to be concerned with whether there's a mapping at the desired address.
		 */
		return getTrace().getPlatformManager().getHostPlatform();
	}

	@Override
	DBTraceDataAdapter create(Lifespan lifespan, Address address, TracePlatform platform,
			DataType dataType) throws CodeUnitInsertionException;

	@Override
	DBTraceDataAdapter create(Lifespan lifespan, Address address, TracePlatform platform,
			DataType dataType, int length) throws CodeUnitInsertionException;

	@Override
	default DBTraceDataAdapter create(Lifespan lifespan, Address address, DataType dataType,
			int length) throws CodeUnitInsertionException {
		return create(lifespan, address, getPlatformOf(dataType), dataType, length);
	}

	@Override
	default DBTraceDataAdapter create(Lifespan lifespan, Address address, DataType dataType)
			throws CodeUnitInsertionException {
		return create(lifespan, address, getPlatformOf(dataType), dataType);
	}

	@Override
	default DBTraceDataAdapter create(TracePlatform platform, Lifespan lifespan, Register register,
			DataType dataType) throws CodeUnitInsertionException {
		TraceRegisterUtils.requireByteBound(register);
		AddressRange range = platform.getConventionalRegisterRange(getSpace(), register);
		return create(lifespan, range.getMinAddress(), platform, dataType, (int) range.getLength());
	}
}
