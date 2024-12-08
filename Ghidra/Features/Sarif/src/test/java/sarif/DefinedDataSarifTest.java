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
package sarif;

import org.junit.Test;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.util.ProgramDiff;

public class DefinedDataSarifTest extends AbstractSarifTest {

	public DefinedDataSarifTest() {
		super();
	}

	@Test
	public void testDefinedData() throws Exception {
		ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
		Structure sdt = DataTypesSarifTest.createComplexStructureDataType(dtm);
		Structure struct = (Structure) dtm.resolve(sdt, null);

		program.getListing().createData(addr(0x100), struct);

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

}
