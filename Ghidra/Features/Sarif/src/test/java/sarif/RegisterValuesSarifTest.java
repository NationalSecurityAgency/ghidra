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

import java.math.BigInteger;

import org.junit.Test;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.util.ProgramDiff;

public class RegisterValuesSarifTest extends AbstractSarifTest {

	public RegisterValuesSarifTest() {
		super();
	}

	@Test
	public void testRegisterValues() throws Exception {
		ProgramContext programContext = program.getProgramContext();
		programContext.setValue(programContext.getBaseContextRegister(), addr(0x1f00), addr(0x1fff),
			BigInteger.ONE);

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

}
