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
package ghidra.program.database.data;

import java.io.IOException;
import java.util.*;

import db.DBRecord;
import db.Field;
import ghidra.docking.settings.Settings;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.UniversalID;

class AddressModelDB extends DataTypeDB {//implements AddressModel {

	private AddressModelDBAdapter addrModelAdapter;

	AddressModelDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
			AddressModelDBAdapter adapter, FunctionParameterAdapter paramAdapter,
			DBRecord record) {
		super(dataMgr, cache, record);
		this.addrModelAdapter = adapter;
	}

	@Override
	public boolean hasLanguageDependantLength() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getMnemonic(Settings settings) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getLength() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public String getDescription() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		// TODO Auto-generated method stub

	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// TODO Auto-generated method stub

	}

	@Override
	public long getLastChangeTime() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public UniversalID getUniversalID() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		// TODO Auto-generated method stub

	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		// TODO Auto-generated method stub

	}
//
//	@Override
//	public String name() {
//		// TODO Auto-generated method stub
//		return null;
//	}
//
//	@Override
//	public int ordinal() {
//		// TODO Auto-generated method stub
//		return 0;
//	}
//
//	@Override
//	public void setComment(String comment) {
//		// TODO Auto-generated method stub
//
//	}
//
//	@Override
//	public String getComment() {
//		// TODO Auto-generated method stub
//		return null;
//	}
//
	@Override
	protected String doGetName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected long doGetCategoryID() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	protected void doSetCategoryPathRecord(long categoryID) throws IOException {
		// TODO Auto-generated method stub

	}

	@Override
	protected void doSetNameRecord(String newName) throws IOException, InvalidNameException {
		// TODO Auto-generated method stub

	}

	@Override
	protected UniversalID getSourceArchiveID() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void setSourceArchiveID(UniversalID id) {
		// TODO Auto-generated method stub

	}

	@Override
	void setUniversalID(UniversalID oldUniversalID) {
		// TODO Auto-generated method stub

	}

	@Override
	public int getAlignedLength() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	protected boolean isEquivalent(DataType dataType, DataTypeConflictHandler handler) {
		return this.addressModel.equals(dataType.getAddressModel());
	}
}
