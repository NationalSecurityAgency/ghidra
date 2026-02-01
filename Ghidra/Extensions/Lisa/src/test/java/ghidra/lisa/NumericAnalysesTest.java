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

import ghidra.lisa.gui.LisaOptions.DescendingPhaseOption;
import ghidra.lisa.gui.LisaOptions.ValueDomainOption;

public class NumericAnalysesTest extends AbstractLisaTest {

	@Category(AbstractLisaTest.class)
	@Test
	public void testConstantPropagation() {
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_CONSTPROP);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "4");    	 //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"), "ffff");   //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "ffff");   //RET
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testInterval() {
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_INTERVAL);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "[4, 4]");     //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"), "[-1, -1]");   //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "[-1, -1]");   //RET
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testNonRedundantSetOfInterval() {
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_POWERSET);
		lisaOptions.setDescendingPhaseOption(DescendingPhaseOption.GLB);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "[-Inf, +Inf]");   //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"), "[-Inf, +Inf]");   //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "[-Inf, +Inf]");   //RET
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testParity() {
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_PARITY);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "Even");  //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"), "Odd");   //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "Odd");   //RET
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testPentagons() {
		init();
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_PENTAGON);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "[4, 4]");     //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"), "[-1, -1]");   //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "[-1, -1]");   //RET
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testSign() {
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_SIGN);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "+");   	 //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"), "#TOP#");  //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "#TOP#");  //RET
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testUpperBounds() {
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_UPPERBOUND);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "{}");  //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"), "{}");  //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "{}");  //RET
	}
}
