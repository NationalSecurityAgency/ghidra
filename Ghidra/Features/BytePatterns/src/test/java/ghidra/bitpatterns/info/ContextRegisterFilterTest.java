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

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class ContextRegisterFilterTest extends AbstractGenericTest {

	private ContextRegisterFilter filter;

	private String cReg1;
	private String cReg2;
	private String cReg3;

	private BigInteger one;
	private BigInteger two;
	private BigInteger three;

	private ContextRegisterInfo info1;
	private ContextRegisterInfo info2;
	private ContextRegisterInfo info3;

	private List<ContextRegisterInfo> listToFilter1;
	private List<ContextRegisterInfo> listToFilter2;
	private List<ContextRegisterInfo> listToFilter3;

	@Before
	public void setUp() throws Exception {
		cReg1 = "cReg1";
		cReg2 = "cReg2";
		cReg3 = "cReg3";
		one = new BigInteger("1");
		two = new BigInteger("2");
		three = new BigInteger("3");
		info1 = new ContextRegisterInfo(cReg1);
		info2 = new ContextRegisterInfo(cReg2);
		info3 = new ContextRegisterInfo(cReg3);
		listToFilter1 = new ArrayList<ContextRegisterInfo>();
		listToFilter2 = new ArrayList<ContextRegisterInfo>();
		listToFilter3 = new ArrayList<ContextRegisterInfo>();

		filter = new ContextRegisterFilter();
		filter.addRegAndValueToFilter(cReg1, one);
		filter.addRegAndValueToFilter(cReg2, two);
	}

	@Test
	public void testEmptyFilter() {
		ContextRegisterFilter emptyFilter = new ContextRegisterFilter();
		assertTrue(emptyFilter.allows(listToFilter1));
	}

	@Test
	public void testFilteringEmptyList() {
		assertTrue(filter.allows(new ArrayList<ContextRegisterInfo>()));
	}

	@Test
	public void basicPassTest() {
		info1.setValue(one);
		listToFilter1.add(info1);
		assertTrue(filter.allows(listToFilter1));

		info3.setValue(three);
		listToFilter3.add(info3);
		assertTrue(filter.allows(listToFilter3));
	}

	@Test
	public void basicFailTest() {
		info1.setValue(two);
		listToFilter1.add(info1);
		assertFalse(filter.allows(listToFilter1));

		info2.setValue(two);
		listToFilter2.add(info2);
		assertTrue(filter.allows(listToFilter2));

		listToFilter1.add(info2);
		assertFalse(filter.allows(listToFilter1));

	}

}
