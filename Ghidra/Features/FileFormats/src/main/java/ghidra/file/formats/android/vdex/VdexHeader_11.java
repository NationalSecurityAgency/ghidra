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
package ghidra.file.formats.android.vdex;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

public class VdexHeader_11 extends VdexHeader_10 {

	public VdexHeader_11(BinaryReader reader) throws IOException, UnsupportedVdexVersionException {
		super(reader);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = super.toDataType();
		try {
			String className = StructConverterUtil.parseName(VdexHeader_11.class);
			dataType.setName(className);
		}
		catch (Exception e) {
			//ignore...
		}
		return dataType;
	}
}
