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

import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.Trace;
import ghidra.trace.util.TraceRegisterUtils;

public interface TraceDefinedDataRegisterView
		extends TraceDefinedDataView, TraceBaseDefinedRegisterView<TraceData> {

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
	default TraceData create(Range<Long> lifespan, Register register, DataType dataType)
			throws CodeUnitInsertionException {
		// TODO: A better way to handle memory-mapped registers?
		Trace trace = getThread().getTrace();
		if (register.getAddressSpace() != trace
				.getBaseLanguage()
				.getAddressFactory()
				.getRegisterSpace()) {
			return trace.getCodeManager()
					.definedData()
					.create(lifespan, register.getAddress(), dataType, register.getNumBytes());
		}
		TraceRegisterUtils.requireByteBound(register);
		return create(lifespan, register.getAddress(), dataType, register.getNumBytes());
	}
}
