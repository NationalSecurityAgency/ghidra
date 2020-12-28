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

import static ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor.*;

import db.DBRecord;
import ghidra.feature.vt.api.impl.MarkupItemStorage;
import ghidra.feature.vt.api.impl.MarkupItemStorageImpl;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTMarkupItemStatus;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.api.markuptype.VTMarkupTypeFactory;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class MarkupItemStorageDB extends DatabaseObject implements MarkupItemStorage {
	private final AssociationDatabaseManager associationManager;
	private final VTAssociation association;
	private final VTSessionDB session;

	private DBRecord record;

	MarkupItemStorageDB(DBRecord record, DBObjectCache<MarkupItemStorageDB> cache,
			AssociationDatabaseManager associationManager) {
		super(cache, record.getKey());
		this.record = record;
		this.associationManager = associationManager;
		this.session = associationManager.getSession();
		long associationKey = record.getLongValue(ASSOCIATION_KEY_COL.column());
		this.association = associationManager.getAssociation(associationKey);
	}

	@Override
	public VTMarkupType getMarkupType() {
		return VTMarkupTypeFactory.getMarkupType(record.getShortValue(MARKUP_TYPE_COL.column()));
	}

	@Override
	public VTAssociation getAssociation() {
		return association;
	}

	@Override
	public Address getSourceAddress() {
		long addressLong = record.getLongValue(SOURCE_ADDRESS_COL.column());
		Program program = session.getSourceProgram();
		AddressMap addressMap = program.getAddressMap();
		return addressMap.decodeAddress(addressLong);
	}

	@Override
	public Address getDestinationAddress() {
		long addressLong = record.getLongValue(DESTINATION_ADDRESS_COL.column());
		Program program = session.getDestinationProgram();
		AddressMap addressMap = program.getAddressMap();
		return addressMap.decodeAddress(addressLong);
	}

	@Override
	public String getDestinationAddressSource() {
		return record.getString(ADDRESS_SOURCE_COL.column());
	}

	@Override
	public VTMarkupItemStatus getStatus() {
		checkIsValid();
		byte ordinal = record.getByteValue(STATUS_COL.column());
		return VTMarkupItemStatus.values()[ordinal];
	}

	@Override
	public String getStatusDescription() {
		return record.getString(STATUS_DESCRIPTION_COL.column());
	}

	@Override
	public Stringable getSourceValue() {
		String string = record.getString(SOURCE_VALUE_COL.column());
		return Stringable.getStringable(string, session.getSourceProgram());
	}

	@Override
	public Stringable getDestinationValue() {
		String string = record.getString(ORIGINAL_DESTINATION_VALUE_COL.column());
		return Stringable.getStringable(string, session.getDestinationProgram());
	}

	@Override
	public void setSourceDestinationValues(Stringable sourceValue, Stringable destinationValue) {
		Program sourceProgram = session.getSourceProgram();
		String string = Stringable.getString(sourceValue, sourceProgram);
		record.setString(SOURCE_VALUE_COL.column(), string);

		Program destinationProgram = session.getDestinationProgram();
		string = Stringable.getString(destinationValue, destinationProgram);
		record.setString(ORIGINAL_DESTINATION_VALUE_COL.column(), string);
	}

	@Override
	public MarkupItemStorage setStatus(VTMarkupItemStatus status) {

		record.setByteValue(STATUS_COL.column(), (byte) status.ordinal());

		associationManager.updateMarkupRecord(record);
		return this;
	}

	@Override
	public MarkupItemStorage setApplyFailed(String message) {
		record.setString(STATUS_DESCRIPTION_COL.column(), message);
		return setStatus(VTMarkupItemStatus.FAILED_APPLY);
	}

	@Override
	public MarkupItemStorage reset() {
		associationManager.lock.acquire();
		try {
			MarkupItemStorage storage = new MarkupItemStorageImpl(getAssociation(), getMarkupType(),
				getSourceAddress(), getDestinationAddress(), getDestinationAddressSource());
			associationManager.removeMarkupRecord(record);
			return storage;
		}
		finally {
			associationManager.lock.release();
		}
	}

	@Override
	public MarkupItemStorage setDestinationAddress(Address destinationAddress, String addressSource) {
		if (destinationAddress == null) {
			destinationAddress = Address.NO_ADDRESS;
		}

		Program destinationProgram = session.getDestinationProgram();

		AddressMap addressMap = destinationProgram.getAddressMap();
		long addressID = addressMap.getKey(destinationAddress, false);
		record.setLongValue(DESTINATION_ADDRESS_COL.column(), addressID);

		record.setString(ADDRESS_SOURCE_COL.column(), addressSource);
		associationManager.updateMarkupRecord(record);
		return this;
	}

	@Override
	protected boolean refresh() {
		return refresh(null);
	}

	@Override
	protected boolean refresh(DBRecord matchRecord) {
		if (matchRecord == null) {
			matchRecord = associationManager.getMarkupItemRecord(key);
		}
		if (matchRecord == null) {
			return false;
		}
		record = matchRecord;
		return true;
	}

	@Override
	public String toString() {
		//@formatter:off
		StringBuffer buffy = new StringBuffer();
		buffy.append('\n').append(getClass().getSimpleName()).append('\n');
		buffy.append('\t').append("Source Address          = ").append(getSourceAddress()).append('\n');
		buffy.append('\t').append("Dest Address            = ").append(getDestinationAddress()).append('\n');
		buffy.append('\t').append("Markup Class            = ").append(getMarkupType()).append('\n');
		buffy.append('\t').append("Status                  = ").append(getStatus()).append('\n');
		buffy.append('\t').append("Source Value            = ").append(getSourceValue()).append('\n');
		buffy.append('\t').append("Dest Value              = ").append(getDestinationValue()).append('\n');
		buffy.append('\t').append("Association             = ").append(getAssociation()).append('\n');
		buffy.append('\t').append("Algorithm               = ").append(getDestinationAddressSource()).append('\n');
		//@formatter:on
		return buffy.toString();
	}

}
