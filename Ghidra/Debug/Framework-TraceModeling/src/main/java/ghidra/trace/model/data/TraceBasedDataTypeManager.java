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
package ghidra.trace.model.data;

import ghidra.program.model.data.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;

/**
 * A data type manager which is part of a {@link Trace}
 */
public interface TraceBasedDataTypeManager extends ProgramBasedDataTypeManager {

	@Override
	default TraceProgramView getProgram() {
		return getTrace().getProgramView();
	}

	/**
	 * Get the trace of which this data type manager is a part
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * TODO: Petition to have this replace
	 * {@link TraceBasedDataTypeManager#resolve(DataType, DataTypeConflictHandler)}
	 * 
	 * <p>
	 * TODO: What happens if handler keeps existing? Does it return existing or null? If it returns
	 * the existing, then can we still cast to T? If not, then we have to be careful with this
	 * method. We may need to keep {@code resolve}, and have this one return null when the handler
	 * keeps the existing one.
	 */
	@SuppressWarnings("unchecked")
	default <T extends DataType> T resolveType(T dataType, DataTypeConflictHandler handler) {
		/**
		 * 
		 */
		return (T) resolve(dataType, handler);
	}

	/**
	 * TODO: Petition to have this replace
	 * {@link TraceBasedDataTypeManager#addDataType(DataType, DataTypeConflictHandler)}
	 * 
	 * <p>
	 * TODO: What happens if handler keeps existing? Does it return existing or null? If it returns
	 * the existing, then can we still cast to T? If not, then we have to be careful with this
	 * method. We may need to keep {@code addDataType}, and have this one return null when the
	 * handler keeps the existing one.
	 */
	@SuppressWarnings("unchecked")
	default <T extends DataType> T addType(T dataType, DataTypeConflictHandler handler) {
		return (T) addDataType(dataType, handler);
	}

	/**
	 * TODO: Petition to have this replace
	 * {@link TraceBasedDataTypeManager#replaceDataType(DataType, DataType, boolean)}
	 */
	@SuppressWarnings("unchecked")
	default <T extends DataType> T replaceType(DataType existingDt, T replacementDt,
			boolean updateCategoryPath) throws DataTypeDependencyException {
		return (T) replaceDataType(existingDt, replacementDt, updateCategoryPath);
	}
}
