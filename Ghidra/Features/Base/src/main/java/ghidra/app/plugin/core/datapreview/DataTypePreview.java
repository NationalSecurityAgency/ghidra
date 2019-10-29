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
/*
 * Created on May 22, 2006
 */
package ghidra.app.plugin.core.datapreview;

import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeInstance;
import ghidra.program.model.mem.*;

class DataTypePreview implements Preview {
	private static final int MAX_PREVIEW_LENGTH = 150;

	protected DataType dt;

	DataTypePreview(DataType dt) {
		this.dt = dt;
	}

	@Override
	public String getName() {
		return dt.getName();
	}

	@Override
	public String getPreview(Memory memory, Address addr) {
		try {
			MemBuffer mb = new DumbMemBufferImpl(memory, addr);
			DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(dt, mb, MAX_PREVIEW_LENGTH);
			if (dti == null) {
				return "";
			}

			int length = Math.min(dti.getLength(), MAX_PREVIEW_LENGTH);
			return dt.getRepresentation(mb, new SettingsImpl(), length);
		}
		catch (Exception e) {

			return "ERROR: unable to create preview";
		}
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public int compareTo(Preview p) {
		if (p instanceof DataTypePreview) {
			DataTypePreview dtp = (DataTypePreview) p;
			return getName().compareToIgnoreCase(dtp.getName());
		}
		return toString().compareToIgnoreCase(p.toString());
	}
}
