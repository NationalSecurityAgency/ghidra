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
package ghidra.app.plugin.core.decompile;

import java.util.function.Consumer;

import ghidra.app.services.DataTypeReference;
import ghidra.app.services.DataTypeReferenceFinder;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A simple spy to report when and how the finder service is called.
 */
public class StubDataTypeReferenceFinder implements DataTypeReferenceFinder {

	@Override
	public void findReferences(Program program, DataType dataType,
			Consumer<DataTypeReference> callback, TaskMonitor monitor) throws CancelledException {
		// stub
	}

	@Override
	public void findReferences(Program program, Composite composite, String fieldName,
			Consumer<DataTypeReference> callback, TaskMonitor monitor) throws CancelledException {
		// stub
	}
}
