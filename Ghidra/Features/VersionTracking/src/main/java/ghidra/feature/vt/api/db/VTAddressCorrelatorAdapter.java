/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.api.db;

import static ghidra.feature.vt.api.db.VTAddressCorrelatorAdapter.AddressCorrelationTableDescriptor.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.util.List;

import db.*;
import db.util.TableColumn;

public abstract class VTAddressCorrelatorAdapter {

	public static class AddressCorrelationTableDescriptor extends db.util.TableDescriptor {

		public static TableColumn SOURCE_ENTRY_COL = new TableColumn(LongField.class, true);
		public static TableColumn SOURCE_ADDRESS_COL = new TableColumn(LongField.class);
		public static TableColumn DESTINATION_ADDRESS_COL = new TableColumn(LongField.class);
		
		public static AddressCorrelationTableDescriptor INSTANCE = new AddressCorrelationTableDescriptor();
	}
	
	static String TABLE_NAME = "AddressCorrelationTable";
	static Schema TABLE_SCHEMA = new Schema(0, "Key",
		INSTANCE.getColumnClasses(), INSTANCE.getColumnNames());
	static int[] TABLE_INDEXES = INSTANCE.getIndexedColumns();
	private DBHandle dbHandle;
	
	protected VTAddressCorrelatorAdapter(DBHandle dbHandle) {
		this.dbHandle = dbHandle;
	}
	
	public static VTAddressCorrelatorAdapter createAdapter(DBHandle dbHandle) throws IOException {
		return new VTAddressCorrelationAdapterV0(dbHandle);
	}

	public static VTAddressCorrelatorAdapter getAdapter(DBHandle dbHandle, TaskMonitor monitor) 
			throws VersionException {
		return new VTAddressCorrelationAdapterV0(dbHandle, monitor);
	}

	abstract void createAddressRecord(long sourceEntryLong, long sourceLong, long destinationLong) throws IOException;

	abstract List<Record> getAddressRecords(long sourceEntryLong) throws IOException;

	void close() {
		dbHandle.close();
	}

	void save(TaskMonitor monitor) throws CancelledException, IOException {
		dbHandle.save("", null, monitor);
	}
	void saveAs(File file, TaskMonitor monitor) throws CancelledException, IOException {
		dbHandle.saveAs(file, true, monitor);
	}
	
}
