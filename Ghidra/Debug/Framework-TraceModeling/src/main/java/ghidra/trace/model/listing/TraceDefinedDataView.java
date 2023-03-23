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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.util.TraceRegisterUtils;

/**
 * A view of defined data units
 *
 * <p>
 * This view excludes instructions and default / undefined data units.
 */
public interface TraceDefinedDataView extends TraceBaseDefinedUnitsView<TraceData> {
	/**
	 * Create a data unit starting at the given address
	 * 
	 * @param lifespan the span for which the unit is effective
	 * @param address the starting address
	 * @param dataType the data type for the unit
	 * @param length the length of the unit, -1 for unspecified
	 * @return the new data unit
	 * @throws CodeUnitInsertionException if there's a conflict
	 */
	TraceData create(Lifespan lifespan, Address address, DataType dataType, int length)
			throws CodeUnitInsertionException;

	/**
	 * Create a data unit of unspecified length starting at the given address
	 * 
	 * <p>
	 * The length will be determined by the data type, possibly by examining the bytes, e.g., a
	 * null-terminated UTF-8 string.
	 * 
	 * @param lifespan the span for which the unit is effective
	 * @param address the starting address
	 * @param dataType the data type for the unit
	 * @return the new data unit
	 * @throws CodeUnitInsertionException if there's a conflict
	 */
	TraceData create(Lifespan lifespan, Address address, DataType dataType)
			throws CodeUnitInsertionException;

	/**
	 * Create a data unit on the given register
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space. In those
	 * cases, the assignment affects all threads.
	 * 
	 * @param lifespan the span for which the unit is effective
	 * @param register the register to assign a data type
	 * @param dataType the data type for the register
	 * @return the new data unit
	 * @throws CodeUnitInsertionException if there's a conflict
	 */
	default TraceData create(Lifespan lifespan, Register register, DataType dataType)
			throws CodeUnitInsertionException {
		TraceRegisterUtils.requireByteBound(register);
		return create(lifespan, register.getAddress(), dataType, register.getNumBytes());
	}

	/**
	 * Create a data unit on the given platform register
	 * 
	 * <p>
	 * If the register is memory mapped, this will delegate to the appropriate space. In those
	 * cases, the assignment affects all threads.
	 * 
	 * @param platform the platform whose language defines the register
	 * @param lifespan the span for which the unit is effective
	 * @param register the register to assign a data type
	 * @param dataType the data type for the register
	 * @return the new data unit
	 * @throws CodeUnitInsertionException if there's a conflict
	 */
	TraceData create(TracePlatform platform, Lifespan lifespan, Register register,
			DataType dataType) throws CodeUnitInsertionException;
}
