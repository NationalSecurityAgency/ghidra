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
package ghidra.program.model.dtarchive;

import java.io.IOException;

import ghidra.program.model.data.ArchiveDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link PersistentDataTypeArchive} provides a collection of {@link DataType}s independent of any
 * Program and have their own storage mechanism to persist the collection.  The associated
 * {@link ArchiveDataTypeManager}  instance is provided to facilitate queries and management of 
 * the {@link DataType}s. 
 */
public interface PersistentDataTypeArchive extends DataTypeArchive {

	@Override
	public void release(Object consumer);

	@Override
	public boolean addConsumer(Object consumer);

	/**
	 * Save the category to source file.
	 * @param monitor the TaskMonitor to use to monitor/cancel the operation
	 * @throws IOException if IO error occurs
	 */
	@Override
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException;
}
