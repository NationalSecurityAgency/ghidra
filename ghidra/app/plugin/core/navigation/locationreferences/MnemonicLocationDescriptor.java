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
package ghidra.app.plugin.core.navigation.locationreferences;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.MnemonicFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.AssertException;

public class MnemonicLocationDescriptor extends DataTypeLocationDescriptor {

	MnemonicLocationDescriptor(ProgramLocation location, Program program) {
		super(location, program);

		if (!(location instanceof MnemonicFieldLocation)) {
			throw new AssertException("Unexpected ProgramLocation type - Cannot create a " +
				"LocationDescriptor for type: " + location);
		}
	}

	@Override
	protected String generateLabel() {
		MnemonicFieldLocation mnemonicLocation = (MnemonicFieldLocation) getLocation();
		String mnemonicString = mnemonicLocation.getMnemonic();
		if (getSourceDataType().equals(getBaseDataType())) {
			return mnemonicString;
		}
		String name = baseDataType.getName();
		return mnemonicString + " (" + name + ")";
	}

	@Override
	protected String getDataTypeName() {
		return baseDataType.getName();
	}

	@Override
	protected DataType getSourceDataType() {
		Data data = getData(getLocation());
		return data.getDataType();
	}

	@Override
	protected DataType getBaseDataType() {
		Data data = getData(getLocation());
		if (data != null) {
			return ReferenceUtils.getBaseDataType(data.getDataType());
		}
		return null;
	}
}
