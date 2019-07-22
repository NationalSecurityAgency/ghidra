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
 *
 */
package ghidra.program.database.data;

import ghidra.program.model.data.*;

public class StructureDBBigEndianBitFieldTest extends StructureImplBigEndianBitFieldTest {

	private static DataTypeManager dataMgr;

	@Override
	public void setUp() throws Exception {
		getDataTypeManager().startTransaction("Test");
		super.setUp();
	}

	@Override
	protected DataTypeManager getDataTypeManager() {
		synchronized (MSVCStructureDBBitFieldTest.class) {
			if (dataMgr == null) {
				dataMgr = new StandAloneDataTypeManager("Test");
				DataOrganizationImpl dataOrg = (DataOrganizationImpl) dataMgr.getDataOrganization();
				DataOrganizationTestUtils.initDataOrganization32BitMips(dataOrg);
			}
			return dataMgr;
		}
	}

}
