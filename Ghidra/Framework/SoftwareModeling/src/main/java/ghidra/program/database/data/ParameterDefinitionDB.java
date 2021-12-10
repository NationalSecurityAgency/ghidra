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

import db.DBRecord;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SymbolUtilities;

/**
 * Database implementation for a Parameter.
 */
final class ParameterDefinitionDB implements ParameterDefinition {

	private DataTypeManagerDB dataMgr;
	private DBRecord record;
	private FunctionDefinitionDB parent;
	private FunctionParameterAdapter adapter;

	ParameterDefinitionDB(DataTypeManagerDB dataMgr, FunctionParameterAdapter adapter,
			FunctionDefinitionDB parent, DBRecord record) {
		this.dataMgr = dataMgr;
		this.parent = parent;
		this.adapter = adapter;
		this.record = record;
	}

	DBRecord getRecord() {
		return record;
	}

	long getKey() {
		return record.getKey();
	}

	@Override
	public final DataType getDataType() {
		DataType dt =
			dataMgr.getDataType(record.getLongValue(FunctionParameterAdapter.PARAMETER_DT_ID_COL));
		if (dt == null) {
			dt = DataType.DEFAULT;
		}
		return dt;
	}

	@Override
	public void setDataType(DataType type) {
		type = ParameterDefinitionImpl.validateDataType(type, dataMgr, false);

		getDataType().removeParent(parent);

		type = dataMgr.resolve(type, null);
		type.addParent(parent);

		record.setLongValue(FunctionParameterAdapter.PARAMETER_DT_ID_COL,
			dataMgr.getResolvedID(type));
		record.setIntValue(FunctionParameterAdapter.PARAMETER_DT_LENGTH_COL, type.getLength());
		try {
			adapter.updateRecord(record);
			dataMgr.dataTypeChanged(parent, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public String getName() {
		String name = record.getString(FunctionParameterAdapter.PARAMETER_NAME_COL);
		if (name == null) {
			name = SymbolUtilities.getDefaultParamName(getOrdinal());
		}
		return name;
	}

	@Override
	public int getLength() {
		DataType dt = getDataType();
		if (dt != null && dt.getLength() > -1) {
			return dt.getLength();
		}
		return record.getIntValue(FunctionParameterAdapter.PARAMETER_DT_LENGTH_COL);
	}

	@Override
	public void setName(String name) {
		if (SymbolUtilities.isDefaultParameterName(name)) {
			name = null;
		}
		record.setString(FunctionParameterAdapter.PARAMETER_NAME_COL, name);
		try {
			adapter.updateRecord(record);
			dataMgr.dataTypeChanged(parent, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public String getComment() {
		return record.getString(FunctionParameterAdapter.PARAMETER_COMMENT_COL);
	}

	@Override
	public void setComment(String comment) {
		record.setString(FunctionParameterAdapter.PARAMETER_COMMENT_COL, comment);
		try {
			adapter.updateRecord(record);
			dataMgr.dataTypeChanged(parent, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	public FunctionDefinition getParent() {
		return parent;
	}

	@Override
	public int getOrdinal() {
		return record.getIntValue(FunctionParameterAdapter.PARAMETER_ORDINAL_COL);
	}

	@Override
	public boolean isEquivalent(Variable otherVar) {
		if (otherVar == null) {
			return false;
		}
		if (!(otherVar instanceof Parameter)) {
			return false;
		}
		if (getOrdinal() != ((Parameter) otherVar).getOrdinal()) {
			return false;
		}
		if (!DataTypeUtilities.isSameOrEquivalentDataType(getDataType(), otherVar.getDataType())) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isEquivalent(ParameterDefinition parm) {
		if (parm == null) {
			return false;
		}
		if (getOrdinal() != parm.getOrdinal()) {
			return false;
		}
		if (!DataTypeUtilities.isSameOrEquivalentDataType(getDataType(), parm.getDataType())) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(ParameterDefinition p) {
		return getOrdinal() - p.getOrdinal();
	}

	@Override
	public String toString() {
		return getDataType().getName() + " " + getName();
	}

}
