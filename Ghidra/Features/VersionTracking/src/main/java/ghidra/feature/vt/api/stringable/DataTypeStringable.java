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
package ghidra.feature.vt.api.stringable;

import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;
import ghidra.util.UniversalID;
import ghidra.util.exception.AssertException;

import java.util.StringTokenizer;

public class DataTypeStringable extends Stringable {

	public static final String SHORT_NAME = "DT";

	private long managerUniversalID;
	private long dataTypeID;
	private String dataTypeName;
	private int length;

	public DataTypeStringable() {
		super(SHORT_NAME);
	}

	public DataTypeStringable(DataType dataType, DataTypeManager dataTypeManager, int length) {
		super(SHORT_NAME);
		UniversalID universalID = dataTypeManager.getUniversalID();
		this.managerUniversalID = universalID.getValue();
		this.dataTypeID = dataTypeManager.getID(dataType);
		this.dataTypeName = dataType.getName();
		this.length = length;
	}

	@Override
	public String getDisplayString() {
		return dataTypeName + " (size=" + length + ")";
	}

	@Override
	protected String doConvertToString(Program program) {
		return Long.toString(managerUniversalID) + DELIMITER + Long.toString(dataTypeID) +
			DELIMITER + dataTypeName + DELIMITER + Integer.toString(length);
	}

	@Override
	protected void doRestoreFromString(String string, Program program) {
		StringTokenizer tokenizzy = new StringTokenizer(string, DELIMITER);
		managerUniversalID = Long.parseLong(tokenizzy.nextToken());
		dataTypeID = Long.parseLong(tokenizzy.nextToken());
		dataTypeName = tokenizzy.nextToken();
		length = Integer.parseInt(tokenizzy.nextToken());
	}

	public long getDataTypeManagerID() {
		return managerUniversalID;
	}

	public long getDataTypeID() {
		return dataTypeID;
	}

	public String getDataTypeName() {
		return dataTypeName;
	}

	public DataType getDataType(DataTypeManager dataTypeManager) {
		long actualUniversalID = dataTypeManager.getUniversalID().getValue();
		if (actualUniversalID != managerUniversalID) {
			throw new AssertException("Provided data type manager ID of " + actualUniversalID +
				" doesn't matched saved ID of " + managerUniversalID + ".");
		}
		return dataTypeManager.getDataType(dataTypeID);
	}

	public int getLength() {
		return length;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || (getClass() != obj.getClass())) {
			return false;
		}
		DataTypeStringable other = (DataTypeStringable) obj;

		return managerUniversalID == other.managerUniversalID && dataTypeID == other.dataTypeID &&
			SystemUtilities.isEqual(dataTypeName, other.dataTypeName) && length == other.length;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (dataTypeID ^ (dataTypeID >>> 32));
		result = prime * result + ((dataTypeName == null) ? 0 : dataTypeName.hashCode());
		result = prime * result + (int) (managerUniversalID ^ (managerUniversalID >>> 32));
		result = prime * result + (length);
		return result;
	}
}
