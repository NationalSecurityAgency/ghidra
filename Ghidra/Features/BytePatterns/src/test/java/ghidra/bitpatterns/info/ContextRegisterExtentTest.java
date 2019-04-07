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
package ghidra.bitpatterns.info;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.bitpatterns.info.ContextRegisterExtent;
import ghidra.bitpatterns.info.ContextRegisterInfo;

public class ContextRegisterExtentTest extends AbstractGenericTest {

	@Test
	public void testEmptyExtent() {
		ContextRegisterExtent crExtent = new ContextRegisterExtent();
		assertTrue(crExtent.getContextRegisters().isEmpty());
		assertTrue(crExtent.getValuesForRegister("testRegister").isEmpty());
		assertEquals("", crExtent.toString());
	}

	@Test
	public void testNullInputs() {
		ContextRegisterExtent crExtent = new ContextRegisterExtent();
		crExtent.addContextInfo(null);
		assertTrue(crExtent.getContextRegisters().isEmpty());
		crExtent.addContextInfo(new ArrayList<ContextRegisterInfo>());
		assertTrue(crExtent.getContextRegisters().isEmpty());
	}

	@Test
	public void testRegistersAndValues() {
		BigInteger one = new BigInteger("1");
		BigInteger two = new BigInteger("2");
		String contextRegister1 = "A";
		String contextRegister2 = "B";
		ContextRegisterExtent crExtent = new ContextRegisterExtent();

		ContextRegisterInfo cInfo1 = new ContextRegisterInfo(contextRegister1);
		cInfo1.setValue(one);

		ContextRegisterInfo cInfo2 = new ContextRegisterInfo(contextRegister1);
		cInfo2.setValue(two);

		ContextRegisterInfo cInfo3 = new ContextRegisterInfo(contextRegister2);
		cInfo3.setValue(one);

		List<ContextRegisterInfo> info = new ArrayList<ContextRegisterInfo>();
		info.add(cInfo3);
		info.add(cInfo2);
		info.add(cInfo1);
		crExtent.addContextInfo(info);

		List<String> regs = crExtent.getContextRegisters();
		assertEquals(2, regs.size());
		assertEquals(contextRegister1, regs.get(0));
		assertEquals(contextRegister2, regs.get(1));

		List<BigInteger> values = crExtent.getValuesForRegister(contextRegister1);
		assertEquals(2, values.size());
		assertEquals(one, values.get(0));
		assertEquals(two, values.get(1));

	}

}
