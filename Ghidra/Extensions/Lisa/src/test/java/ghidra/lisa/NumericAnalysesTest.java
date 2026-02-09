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
		equalsAssert(valueOf("0040000f:0:register:00000000"), "-1");     //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "-1");     //RET
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
	
	@Category(AbstractLisaTest.class)
	@Test
	public void testIntervalHighPcodePreState() {
		init(1);
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_INTERVAL);
		lisaOptions.setPostState(false);
		lisaOptions.setHighPcode(true);
		runTest();
		equalsAssert(valueOf("0040000e:37:register:00000000"), null);
		equalsAssert(valueOf("00400010:13:register:00000000"), "[-Inf, +Inf]");
		equalsAssert(valueOf("00400018:47:register:00000000"), "[0, +Inf]");  // [3, +Inf] optimized out
		equalsAssert(valueOf("00400012:46:register:00000000"), "[-Inf, 2]");
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testIntervalHighPcodePostState() {
		init(2);
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_INTERVAL);
		lisaOptions.setPostState(true);
		lisaOptions.setHighPcode(true);
		runTest();
		equalsAssert(valueOf("0040000e:76:register:00000000"), "[-Inf, +Inf]");
		equalsAssert(valueOf("00400012:18:register:00000000"), "[-Inf, 2]");
		equalsAssert(valueOf("00400018:78:register:00000000"), "[0, +Inf]");  // [3, +Inf] optimized out
		equalsAssert(valueOf("0040001c:45:register:00000000"), "[0, 9]");
		equalsAssert(valueOf("00400026:67:register:00000000"), "[1, +Inf]");
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testIntervalHighPcodePhi() {
		init(3);
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_INTERVAL);
		lisaOptions.setPostState(true);
		lisaOptions.setHighPcode(true);
		runTest();
		equalsAssert(valueOf("0040000a:2:register:00000000"), null);
		equalsAssert(valueOf("00400011:142:register:00000000"), "[-Inf, +Inf]");
		equalsAssert(valueOf("0040001c:26:register:00000000"), "[-Inf, -3]");
		equalsAssert(valueOf("00400011:142:register:00000000"), "[-Inf, +Inf]");
		equalsAssert(valueOf("00400020:111:register:00000000"), "[3, +Inf]");
		equalsAssert(valueOf("00400022:115:register:00000000"), "[3, 8]");
		equalsAssert(valueOf("00400026:29:register:00000000"), "[-Inf, 39]");
		equalsAssert(valueOf("0040002a:38:register:00000000"), "[-Inf, +Inf]");
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testIntervalLowPcodePhiJLE() {
		init(3);
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_INTERVAL_LX86);
		lisaOptions.setPostState(true);
		lisaOptions.setHighPcode(false);
		runTest();
		equalsAssert(valueOf("00400011:0:register:00000000"), "[-Inf, +Inf]");
		equalsAssert(valueOf("0040001c:0:register:00000000"), "[-Inf, -3]");
		equalsAssert(valueOf("0040001e:0:register:00000000"), "[3, +Inf]");
		equalsAssert(valueOf("00400022:0:register:00000000"), "[3, 8]");
		equalsAssert(valueOf("00400026:0:register:00000000"), "[-Inf, 8]");
		equalsAssert(valueOf("00400026:3:register:00000000"), "[-Inf, 39]");
		equalsAssert(valueOf("0040002a:0:register:00000000"), "[-Inf, +Inf]");
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testIntervalLowPcodePhiJL() {
		init(4);
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_INTERVAL_LX86);
		lisaOptions.setPostState(true);
		lisaOptions.setHighPcode(false);
		runTest();
		equalsAssert(valueOf("00400011:0:register:00000000"), "[-Inf, +Inf]");
		equalsAssert(valueOf("0040001c:0:register:00000000"), "[-Inf, -3]");
		equalsAssert(valueOf("0040001e:0:register:00000000"), "[3, +Inf]");
		equalsAssert(valueOf("00400022:0:register:00000000"), "[3, 8]");
		equalsAssert(valueOf("00400026:0:register:00000000"), "[-Inf, 8]");
		equalsAssert(valueOf("00400026:3:register:00000000"), "[-Inf, 39]");
		equalsAssert(valueOf("0040002a:0:register:00000000"), "[-Inf, +Inf]");
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testIntervalLowPcodePhiJBE() {
		init(5);
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_INTERVAL_LX86);
		lisaOptions.setPostState(true);
		lisaOptions.setHighPcode(false);
		runTest();
		equalsAssert(valueOf("00400011:0:register:00000000"), "[-Inf, +Inf]");
		equalsAssert(valueOf("0040001c:0:register:00000000"), "[-Inf, -3]");
		equalsAssert(valueOf("0040001e:0:register:00000000"), "[3, +Inf]");
		equalsAssert(valueOf("00400022:0:register:00000000"), "[3, 8]");
		equalsAssert(valueOf("00400026:0:register:00000000"), "[-Inf, 8]");
		equalsAssert(valueOf("00400026:3:register:00000000"), "[-Inf, 39]");
		equalsAssert(valueOf("0040002a:0:register:00000000"), "[-Inf, +Inf]");
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testIntervalLowAll() {
		init(6);
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_INTERVAL_LX86);
		lisaOptions.setPostState(true);
		lisaOptions.setHighPcode(false);
		runTest();
		equalsAssert(valueOf("00400011:0:register:00000000"), "[-Inf, +Inf]");
		equalsAssert(valueOf("0040001c:0:register:00000000"), "[4, +Inf]");
		equalsAssert(valueOf("00400021:0:register:00000000"), "[4, 8]");
		equalsAssert(valueOf("00400026:0:register:00000000"), "[4, 5]");
		equalsAssert(valueOf("0040002e:0:register:00000000"), "[4, 4]");
		equalsAssert(valueOf("00400031:0:register:00000000"), "[5, 5]");
		equalsAssert(valueOf("00400034:0:register:00000000"), "[6, 8]");
		equalsAssert(valueOf("00400037:0:register:00000000"), "[9, +Inf]");
		equalsAssert(valueOf("0040003a:0:register:00000000"), "[-Inf, 3]");
		equalsAssert(valueOf("00400042:0:register:00000000"), "[0, 3]");
		equalsAssert(valueOf("00400045:0:register:00000000"), "[-Inf, -1]");
		equalsAssert(valueOf("0040004a:0:register:00000000"), "[-Inf, -1]");  // Should be _|_
		equalsAssert(valueOf("0040004d:0:register:00000000"), "[-Inf, -1]");
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testIntervalLowAllRev() {
		init(7);
		lisaOptions.setValueDomain(ValueDomainOption.VALUE_INTERVAL_LX86);
		lisaOptions.setPostState(true);
		lisaOptions.setHighPcode(false);
		runTest();
		equalsAssert(valueOf("00400011:0:register:00000000"), "[-Inf, +Inf]");
		equalsAssert(valueOf("0040001c:0:register:00000000"), "[-Inf, -4]");
		equalsAssert(valueOf("00400021:0:register:00000000"), "[-8, -4]");
		equalsAssert(valueOf("00400026:0:register:00000000"), "[-5, -4]");
		equalsAssert(valueOf("0040002e:0:register:00000000"), "[-4, -4]");
		equalsAssert(valueOf("00400031:0:register:00000000"), "[-5, -5]");
		equalsAssert(valueOf("00400034:0:register:00000000"), "[-8, -6]");
		equalsAssert(valueOf("00400037:0:register:00000000"), "[-Inf, -9]");
		equalsAssert(valueOf("0040003a:0:register:00000000"), "[-3, +Inf]");
		equalsAssert(valueOf("00400042:0:register:00000000"), "[-3, 0]");
		equalsAssert(valueOf("00400045:0:register:00000000"), "[1, +Inf]");
		equalsAssert(valueOf("0040004a:0:register:00000000"), "_|_");
		equalsAssert(valueOf("0040004d:0:register:00000000"), "[1, +Inf]");
	}

}
