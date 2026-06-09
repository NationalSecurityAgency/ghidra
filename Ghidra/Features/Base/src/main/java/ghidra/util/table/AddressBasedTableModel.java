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
package ghidra.util.table;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * This class is now just a shell left in place to not break external clients.
 *
 * @param <ROW_TYPE> the row type
 */
public abstract class AddressBasedTableModel<ROW_TYPE> extends GhidraProgramTableModel<ROW_TYPE> {

	public AddressBasedTableModel(String title, ServiceProvider serviceProvider, Program program,
			TaskMonitor monitor) {
		this(title, serviceProvider, program, monitor, false);
	}

	public AddressBasedTableModel(String title, ServiceProvider serviceProvider, Program program,
			TaskMonitor monitor, boolean loadIncrementally) {
		super(title, serviceProvider, program, monitor, loadIncrementally);
	}
}
