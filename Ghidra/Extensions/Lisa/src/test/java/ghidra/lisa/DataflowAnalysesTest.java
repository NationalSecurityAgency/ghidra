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
package ghidra.lisa;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import ghidra.lisa.gui.LisaOptions.InterproceduralOption;
import ghidra.lisa.gui.LisaOptions.ValueDomainOption;

public class DataflowAnalysesTest extends AbstractLisaTest {

	@Category(AbstractLisaTest.class)
	@Test
	public void testAvailable() {
		lisaOptions.setValueDomain(ValueDomainOption.DDATA_AVAILABLE);
		runTest();
		equalsAssert(valueOf("0040000b:1:register:00000000"), "register:00000000 < 5");   				 //SUB AX, 0x5
		equalsAssert(valueOf("0040000b:5:register:00000000"),
			"[register:00000000 == 0, register:00000000 INT_SLESS 0]");   								 //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"),
			"[register:00000000 == 0, register:00000000 INT_AND 255, register:00000000 INT_SLESS 0]");   //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), null);  									 //RET
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testConstantPropagation() {
		lisaOptions.setValueDomain(ValueDomainOption.DDATA_CONSTPROP);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "4");      //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"), "ffff");   //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "ffff");   //RET
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testLiveness() {
		lisaOptions.setValueDomain(ValueDomainOption.PDATA_LIVENESS);
		lisaOptions.setInterproceduralOption(InterproceduralOption.BACKWARDS);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), null);  				 //SUB AX, 0x5
		equalsAssert(valueOf("0040000b:1:register:00000000"), "register:00000000");  //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"), "register:00000000");  //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), null);  				 //RET
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testReaching() {
		lisaOptions.setValueDomain(ValueDomainOption.PDATA_REACHING);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "register:00000000 = 4");  //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"),
			"register:00000000 = INT_SUB(register:00000000, 5)");  						 //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"),
			"register:00000010 = register:00000000"); 			   						 //RET
	}
}
