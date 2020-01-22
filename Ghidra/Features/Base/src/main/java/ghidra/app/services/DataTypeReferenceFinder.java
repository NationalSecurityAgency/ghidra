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
package ghidra.app.services;

import java.util.function.Consumer;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An interface for extension points to implement.  Implementations know how to find data type
 * references.
 * <p>
 * Implementation class names must end with DataTypeReferenceFinder
 */
public interface DataTypeReferenceFinder extends ExtensionPoint {

	/**
	 * Finds references in the current program in a manner appropriate with the given 
	 * implementation.
	 * <p>
	 * Note that this operation is multi-threaded and that results will be delivered as they 
	 * are found via the <code>callback</code>.
	 * 
	 * @param program the program to search
	 * @param dataType the type for which to search
	 * @param callback the callback to be called when a reference is found
	 * @param monitor the monitor that allows for progress and cancellation
	 * @throws CancelledException if the operation was cancelled
	 */
	public void findReferences(Program program, DataType dataType,
			Consumer<DataTypeReference> callback,
			TaskMonitor monitor) throws CancelledException;

	/**
	 * Finds references in the current program to specific field of the given {@link Composite} type
	 * in a manner appropriate with the given implementation.
	 * <p>
	 * Note that this operation is multi-threaded and that results will be delivered as they 
	 * are found via the <code>callback</code>.
	 * 
	 * @param program the program to search
	 * @param composite the type containing the field for which to search
	 * @param fieldName the name of the composite's field for which to search
	 * @param callback the callback to be called when a reference is found
	 * @param monitor the monitor that allows for progress and cancellation
	 * @throws CancelledException if the operation was cancelled
	 */
	public void findReferences(Program program, Composite composite, String fieldName,
			Consumer<DataTypeReference> callback, TaskMonitor monitor) throws CancelledException;
}
