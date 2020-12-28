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
package ghidra.program.database.symbol;

import java.io.IOException;

import db.DBRecord;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.DynamicHash;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateReference;
import ghidra.util.Lock;
import ghidra.util.UniversalID;
import ghidra.util.exception.*;

/**
 * Database object for an Equate.
 * 
 * 
 */
public class EquateDB extends DatabaseObject implements Equate {

	private DBRecord record;
	private EquateManager equateMgr;

	/**
	 * Constructor
	 * @param equateMgr the equate manager
	 * @param cache EquateDB cache
	 * @param record the record for this equate.
	 */
	public EquateDB(EquateManager equateMgr, DBObjectCache<EquateDB> cache, DBRecord record) {
		super(cache, record.getKey());
		this.equateMgr = equateMgr;
		this.record = record;
	}

	@Override
	protected boolean refresh() {
		DBRecord rec = equateMgr.getEquateRecord(key);
		if (rec == null) {
			return false;
		}
		record = rec;
		return true;
	}

	/**
	 * @see ghidra.program.model.symbol.Equate#addReference(ghidra.program.model.address.Address, int)
	 */
	@Override
	public void addReference(Address refAddr, int opIndex) {
		checkDeleted();
		try {
			Instruction instr = equateMgr.getProgram().getCodeManager().getInstructionAt(refAddr);
			long dynamicHash;
			if (instr == null)
				dynamicHash = 0;
			else {
				long value = record.getLongValue(EquateDBAdapter.VALUE_COL);
			    long hashArray[] = DynamicHash.calcConstantHash(instr, value);
			    if (hashArray.length != 1)
			    	dynamicHash = 0;
			    else
			    	dynamicHash = hashArray[0];
			}
			equateMgr.addReference(key, refAddr, (short) opIndex, dynamicHash);
		}
		catch (IOException e) {
			equateMgr.dbError(e);
		}
	}

	/**
	 * @see ghidra.program.model.symbol.Equate#addReference(long, ghidra.program.model.address.Address)
	 */
	@Override
	public void addReference(long dynamicHash, Address refAddr) {
		checkDeleted();
		try {
			short opIndex = findOpIndex(refAddr, dynamicHash);
			equateMgr.addReference(key, refAddr, opIndex, dynamicHash);
		}
		catch (IOException e) {
			equateMgr.dbError(e);
		}
	}

	private short findOpIndex(Address refAddr, long dynamicHash) {
		Instruction instr = equateMgr.getProgram().getCodeManager().getInstructionAt(refAddr);
		if (instr == null) {
			return -1;
		}
		long value = record.getLongValue(EquateDBAdapter.VALUE_COL);
		long checkHash[] = DynamicHash.calcConstantHash(instr, value);
		for (long element : checkHash)
			if (element == dynamicHash)
				return findScalarOpIndex(instr);
		return -1;
	}

	private short findScalarOpIndex(Instruction instr) {
		short opIndex = -1;
		long value = record.getLongValue(EquateDBAdapter.VALUE_COL);
		int numOperands = instr.getNumOperands();
		for (short i = 0; i < numOperands; i++) {
			for (Object obj : instr.getOpObjects(i)) {
				if (obj instanceof Scalar) {
					if (((Scalar) obj).getValue() != value) {
						continue;
					}
					if (opIndex >= 0) {
						return -1; // non-unique scalar operand value - can't identify operand
					}
					opIndex = i;
				}
			}
		}
		return opIndex;
	}

	/**
	 * @see ghidra.program.model.symbol.Equate#getName()
	 */
	@Override
	public String getName() {
		checkIsValid();
		return record.getString(EquateDBAdapter.NAME_COL);
	}

	@Override
	public String getDisplayName() {
		String equateName = getName();
		if (isEnumBased()) {
			DataTypeManager dtm = equateMgr.getProgram().getDataTypeManager();
			UniversalID id = EquateManager.getDataTypeUUID(equateName);
			Enum enoom = (Enum) dtm.findDataTypeForID(id);
			if (enoom == null || enoom.getName(getValue()) == null) {
				return EquateManager.formatNameForEquateError(getValue());
			}
			return enoom.getName(getValue()); // has the tag and found the matching enum
		}
		return equateName; // has no tag, which is ok; just return the name
	}

	@Override
	public UniversalID getEnumUUID() {
		String equateName = getName();
		if (isValidUUID()) {
			return EquateManager.getDataTypeUUID(equateName);
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.symbol.Equate#getReferenceCount()
	 */
	@Override
	public int getReferenceCount() {
		checkIsValid();
		try {
			return equateMgr.getReferenceCount(key);
		}
		catch (IOException e) {
			equateMgr.dbError(e);
		}
		return 0;
	}

	/**
	 * @see ghidra.program.model.symbol.Equate#getReferences()
	 */
	@Override
	public EquateReference[] getReferences() {
		checkIsValid();
		try {
			return equateMgr.getReferences(key);
		}
		catch (IOException e) {
			equateMgr.dbError(e);
		}
		return new EquateReference[0];
	}

	/**
	 * @see ghidra.program.model.symbol.Equate#getValue()
	 */
	@Override
	public long getValue() {
		checkIsValid();
		return record.getLongValue(EquateDBAdapter.VALUE_COL);
	}

	/**
	 * @see ghidra.program.model.symbol.Equate#getDisplayValue()
	 */
	@Override
	public String getDisplayValue() {
		long val = getValue();
		return ((val < 0) ? "-" : "") + "0x" + Long.toHexString(Math.abs(val));
	}

	/**
	 * @see ghidra.program.model.symbol.Equate#removeReference(ghidra.program.model.address.Address, int)
	 */
	@Override
	public void removeReference(Address refAddr, int opIndex) {
		checkDeleted();
		try {
			equateMgr.removeReference(this, refAddr, (short) opIndex);
		}
		catch (IOException e) {
			equateMgr.dbError(e);
		}
	}

	/**
	 * @see ghidra.program.model.symbol.Equate#removeReference(long, ghidra.program.model.address.Address)
	 */
	@Override
	public void removeReference(long dynamicHash, Address refAddr) {
		checkDeleted();
		try {
			equateMgr.removeReference(this, dynamicHash, refAddr);
		}
		catch (IOException e) {
			equateMgr.dbError(e);
		}
	}

	/**
	 * @see ghidra.program.model.symbol.Equate#renameEquate(java.lang.String)
	 */
	@Override
	public void renameEquate(String newName) throws DuplicateNameException, InvalidInputException {
		Lock lock = equateMgr.getLock();
		lock.acquire();
		try {
			checkDeleted();

			String oldName = getName();
			if (oldName.equals(newName)) {
				return;
			}
			try {
				equateMgr.getEquateDatabaseAdapter().getRecordKey(newName);
				throw new DuplicateNameException("Equate named " + newName + " already exists");
			}
			catch (NotFoundException e) {
			}
			catch (IOException e) {
				equateMgr.dbError(e);
				return;
			}
			equateMgr.validateName(newName);

			record.setString(EquateDBAdapter.NAME_COL, newName);
			updateRecord();
			equateMgr.equateNameChanged(oldName, newName);
		}
		finally {
			lock.release();
		}
	}

	private void updateRecord() {
		try {
			equateMgr.getEquateDatabaseAdapter().updateRecord(record);
		}
		catch (IOException e) {
			equateMgr.dbError(e);
		}
	}

	@Override
	public boolean isValidUUID() {
		String equateName = getDisplayName();
		if (equateName == null || equateName.contains(EquateManager.ERROR_TAG)) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isEnumBased() {
		return getName().startsWith(EquateManager.DATATYPE_TAG);
	}

	/**
	 * 
	 * @see java.lang.Object#equals(Object)
	 */
	@Override
	public boolean equals(Object obj) {

		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}
		Equate eq = (Equate) obj;

		if (getValue() != eq.getValue()) {
			return false;
		}
		return getName().equals(eq.getName());
	}

	/**
	 * 
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return getName().hashCode();
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return getDisplayName();
	}
}
