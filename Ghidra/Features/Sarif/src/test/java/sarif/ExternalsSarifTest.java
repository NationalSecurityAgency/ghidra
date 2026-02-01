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

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramDiff;
import ghidra.util.exception.InvalidInputException;

public class ExternalsSarifTest extends AbstractSarifTest {

	public ExternalsSarifTest() {
		super();
	}

	@Test
	public void testExtLocation() throws Exception {
		ExternalManager extMgr = program.getExternalManager();
		ExternalLocation loc1 = extMgr.addExtLocation("ext1", "label0", null, SourceType.USER_DEFINED);
		assertEquals("ext1", loc1.getLibraryName());
		assertEquals("label0", loc1.getLabel());

		ExternalLocation loc2 = extMgr.addExtLocation("ext1", "label1", addr(1000), SourceType.USER_DEFINED);
		assertEquals("ext1", loc2.getLibraryName());
		assertEquals("label1", loc2.getLabel());

		ExternalLocation loc3 = extMgr.addExtLocation("ext2", "label1", null, SourceType.USER_DEFINED);
		assertEquals("ext2", loc3.getLibraryName());
		assertEquals("label1", loc3.getLabel());

		extMgr.addExtLocation("ext2", "label2", null, SourceType.USER_DEFINED);

		extMgr.addExtLocation("ext2", null, addr(2000), SourceType.USER_DEFINED);

		try {
			extMgr.addExtLocation("ext2", null, null, SourceType.USER_DEFINED);
			Assert.fail();
		} catch (InvalidInputException e) {
			// expected
		}

		extMgr.addExtLocation("ext1", "label1", addr(1500), SourceType.USER_DEFINED);

		ProgramDiff programDiff = readWriteCompare();

		AddressSetView differences = programDiff.getDifferences(monitor);
		assert (differences.isEmpty());
	}

}
