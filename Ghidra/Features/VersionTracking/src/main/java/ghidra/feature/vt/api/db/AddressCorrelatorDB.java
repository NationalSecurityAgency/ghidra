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
package ghidra.feature.vt.api.db;

import static ghidra.feature.vt.api.db.VTAddressCorrelatorAdapter.AddressCorrelationTableDescriptor.DESTINATION_ADDRESS_COL;
import static ghidra.feature.vt.api.db.VTAddressCorrelatorAdapter.AddressCorrelationTableDescriptor.SOURCE_ADDRESS_COL;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import db.DBHandle;
import db.DBRecord;
import generic.stl.Pair;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;


public class AddressCorrelatorDB {
	
	private VTAddressCorrelatorAdapter adapter;
	private final Program sourceProgram;
	private final Program destinationProgram;


	public static AddressCorrelatorDB createAddressCorrelator(
			Program sourceProgram, Program destinationProgram) throws IOException {
	    
		DBHandle dbHandle = new DBHandle();
		AddressCorrelatorDB correlator = new AddressCorrelatorDB(
			sourceProgram, destinationProgram);
		
		long ID = dbHandle.startTransaction();
        try {
        	correlator.adapter = VTAddressCorrelatorAdapter.createAdapter( dbHandle );
     
        }
        finally {
        	dbHandle.endTransaction(ID, true);
        }
		
 		return correlator;
	}


	public static AddressCorrelatorDB getAddressCorrelator(DBHandle dbHandle, 
			Program sourceProgram, Program destinationProgram, TaskMonitor monitor)
			throws VersionException {
        
		AddressCorrelatorDB correlator = new AddressCorrelatorDB(
				sourceProgram, destinationProgram );
		correlator.adapter = VTAddressCorrelatorAdapter.getAdapter( dbHandle,  monitor );
        return correlator;
    }

	private AddressCorrelatorDB(Program sourceProgram, Program destinationProgram) {
		this.sourceProgram = sourceProgram;
		this.destinationProgram = destinationProgram;
	}
	
	public void addAddressCorrelation(Address sourceEntryPoint,
			Address sourceAddress, Address destinationAddress) throws IOException {
		long sourceEntryLong = getLongFromSourceAddress(sourceEntryPoint);
		long sourceLong = getLongFromSourceAddress(sourceAddress);
		long destinationLong = getLongFromDestinationAddress(destinationAddress);
		adapter.createAddressRecord(sourceEntryLong, sourceLong, destinationLong);
	}

	public List<Pair<Address, Address>> getAddressCorrelations(Address sourceEntryPoint) throws IOException {
		long sourceEntryLong = getLongFromSourceAddress(sourceEntryPoint);
		List<Pair<Address, Address>> addressList = new ArrayList<Pair<Address,Address>>();
		List<DBRecord> addressRecords = adapter.getAddressRecords(sourceEntryLong);
		for (DBRecord record : addressRecords) {
			long sourceLong = record.getLongValue(SOURCE_ADDRESS_COL.column());
			long destinationLong = record.getLongValue(DESTINATION_ADDRESS_COL.column());
			Address sourceAddress = getSourceAddressFromLong(sourceLong);
			Address destinationAddress = getDestinationAddressFromLong(destinationLong);
			addressList.add(new Pair<Address, Address>(sourceAddress, destinationAddress));
		}
		return addressList;
	}
	public void close() {
		adapter.close();
	}
	public void save(TaskMonitor monitor) throws CancelledException, IOException {
		adapter.save(monitor);
	}
	public void saveAs(File file, TaskMonitor monitor) throws CancelledException, IOException {
		adapter.saveAs(file, monitor);
	}
    private long getLongFromSourceAddress( Address address ) {
        AddressMap addressMap = sourceProgram.getAddressMap();
        return addressMap.getKey( address, false );
    }
    
    private long getLongFromDestinationAddress( Address address ) {
        AddressMap addressMap = destinationProgram.getAddressMap();
        return addressMap.getKey( address, false );
    }
    
    private Address getSourceAddressFromLong(long value) {
        AddressMap addressMap = sourceProgram.getAddressMap();
        return addressMap.decodeAddress( value );
    }
    
    private Address getDestinationAddressFromLong(long value) {
        AddressMap addressMap = destinationProgram.getAddressMap();
        return addressMap.decodeAddress( value );
    }
}
