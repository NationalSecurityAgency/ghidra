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

public class MiscAnalysesTest extends AbstractLisaTest {

	@Category(AbstractLisaTest.class)
	@Test
	public void testStability() {
		lisaOptions.setValueDomain(ValueDomainOption.STABILITY);
		lisaOptions.setInterproceduralOption(InterproceduralOption.CONTEXT);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "=");    //SUB AX, 0x5
		equalsAssert(valueOf("0040000b:3:register:00000000"), "≠");    //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000000"), "=");    //MOV RDX, RAX
		equalsAssert(valueOf("0040000f:0:register:00000010"), null);   //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "=");    //RET
	}

	@Category(AbstractLisaTest.class)
	@Test
	public void testNoninterference() {
		lisaOptions.setValueDomain(ValueDomainOption.NONINTERFERENCE);
		lisaOptions.setInterproceduralOption(InterproceduralOption.CONTEXT);
		runTest();
		equalsAssert(valueOf("0040000b:0:register:00000000"), "HL");    //SUB AX, 0x5
		equalsAssert(valueOf("0040000f:0:register:00000010"), null);    //MOV RDX, RAX
		equalsAssert(valueOf("00400012:0:register:00000010"), "HL");    //RET
	}

//	@Category(AbstractLisaTest.class)
//	@Test
//	public void testTrend() {
//		lisaOptions.setValueDomain(ValueDomainOption.VALUE_TREND);
//		lisaOptions.setInterproceduralOption(InterproceduralOption.CONTEXT);
//		runTest();
//		equalsAssert(valueOf("0040000b:0:register:00000000"), "#TOP#");    //SUB AX, 0x5
//		equalsAssert(valueOf("0040000f:0:register:00000000"), "#TOP#");    //MOV RDX, RAX
//		equalsAssert(valueOf("0040000f:0:register:00000010"), null);   	   //MOV RDX, RAX
//		equalsAssert(valueOf("00400012:0:register:00000010"), "#TOP#");    //RET
//	}

}
