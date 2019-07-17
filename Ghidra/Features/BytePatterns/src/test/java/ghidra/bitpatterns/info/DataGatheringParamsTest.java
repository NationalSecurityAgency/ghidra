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

import java.util.*;

import org.junit.Test;

import ghidra.bitpatterns.info.DataGatheringParams;

public class DataGatheringParamsTest extends generic.test.AbstractGenericTest {

	@Test
	public void testNullString() {
		List<String> contextRegs = DataGatheringParams.getContextRegisterList(null);
		assertTrue(contextRegs.isEmpty());
	}

	@Test
	public void testEmptyString() {
		List<String> contextRegs = DataGatheringParams.getContextRegisterList("");
		assertTrue(contextRegs.isEmpty());
	}

	@Test
	public void testLiteralNull() {
		List<String> contextRegs = DataGatheringParams.getContextRegisterList("null");
		assertTrue(contextRegs.isEmpty());
	}

	public void basicTest() {
		List<String> contextRegs = DataGatheringParams.getContextRegisterList("reg1,reg2,reg3");
		Set<String> regSet = new HashSet<String>(contextRegs);
		assertEquals(regSet.size(), 3);
		assertTrue(regSet.contains("reg1"));
		assertTrue(regSet.contains("reg2"));
		assertTrue(regSet.contains("reg3"));
	}

	@Test
	public void testEmptyRegName() {
		List<String> contextRegs = DataGatheringParams.getContextRegisterList("reg1, ,reg2");
		Set<String> regSet = new HashSet<String>(contextRegs);
		assertEquals(regSet.size(), 2);
		assertTrue(regSet.contains("reg1"));
		assertTrue(regSet.contains("reg2"));
	}

	@Test
	public void testNameTrimming() {
		List<String> contextRegs = DataGatheringParams.getContextRegisterList(" reg1, reg2 ,reg3 ");
		Set<String> regSet = new HashSet<String>(contextRegs);
		assertEquals(regSet.size(), 3);
		assertTrue(regSet.contains("reg1"));
		assertTrue(regSet.contains("reg2"));
		assertTrue(regSet.contains("reg3"));
	}

}
