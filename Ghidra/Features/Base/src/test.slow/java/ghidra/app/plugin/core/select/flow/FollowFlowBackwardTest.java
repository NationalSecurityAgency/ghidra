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
package ghidra.app.plugin.core.select.flow;

import static org.junit.Assert.assertEquals;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;

import org.junit.Test;

public class FollowFlowBackwardTest extends AbstractFollowFlowTest {

	@Test
	public void testFollowAllFlowsBackFrom0x2f() {

		AddressSetView flowAddresses = getFlowsTo(0x2f, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x2f));
		expectedAddresses.add(addr(0x30), addr(0x5e));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x5f() {

		AddressSetView flowAddresses = getFlowsTo(0x5f, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x15));
		expectedAddresses.add(addr(0x30), addr(0x5f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x8f() {

		AddressSetView flowAddresses = getFlowsTo(0x8f, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x20));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x60), addr(0x8f));
		expectedAddresses.add(addr(0x5000), addr(0x5003));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0xbf() {

		AddressSetView flowAddresses = getFlowsTo(0xbf, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x2e));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x90), addr(0xbf));
		expectedAddresses.add(addr(0x5024), addr(0x5027));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x131() {

		AddressSetView flowAddresses = getFlowsTo(0x131, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x15));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x130), addr(0x131));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x161() {

		AddressSetView flowAddresses = getFlowsTo(0x161, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x15));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x160), addr(0x161));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x191() {

		AddressSetView flowAddresses = getFlowsTo(0x191, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x15));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x5004), addr(0x5007));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x231() {

		AddressSetView flowAddresses = getFlowsTo(0x231, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x20));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x60), addr(0x75));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x5000), addr(0x5003));
		expectedAddresses.add(addr(0x5048), addr(0x504b));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x261() {

		AddressSetView flowAddresses = getFlowsTo(0x261, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x20));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x60), addr(0x80));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x5000), addr(0x5003));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x291() {

		AddressSetView flowAddresses = getFlowsTo(0x291, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x20));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x60), addr(0x8e));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x5000), addr(0x5003));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x331() {

		AddressSetView flowAddresses = getFlowsTo(0x331, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x2e));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x90), addr(0xa5));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x5008), addr(0x500b));
		expectedAddresses.add(addr(0x5024), addr(0x5027));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x361() {

		AddressSetView flowAddresses = getFlowsTo(0x361, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x2e));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x90), addr(0xb0));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x5024), addr(0x5027));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x391() {

		AddressSetView flowAddresses = getFlowsTo(0x391, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x2e));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x90), addr(0xbe));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5024), addr(0x5027));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x5000() {

		AddressSetView flowAddresses = getFlowsTo(0x5000, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5000), addr(0x5003));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x5004() {

		AddressSetView flowAddresses = getFlowsTo(0x5004, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5004), addr(0x5007));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x5008() {

		AddressSetView flowAddresses = getFlowsTo(0x5008, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5008), addr(0x500b));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x5020() {

		AddressSetView flowAddresses = getFlowsTo(0x5020, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5020), addr(0x5020));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x5020And0x5021() {

		AddressSetView flowAddresses =
			getFlowsTo(new AddressSet(addr(0x5020), addr(0x5021)), followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5020), addr(0x5021));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x502b() {

		AddressSetView flowAddresses = getFlowsTo(0x502b, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x502b), addr(0x502b));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x5030() {

		AddressSetView flowAddresses = getFlowsTo(0x5030, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5030), addr(0x5030));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x5034() {

		AddressSetView flowAddresses = getFlowsTo(0x5034, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x20));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x60), addr(0x8e));
		expectedAddresses.add(addr(0x290), addr(0x290));
		expectedAddresses.add(addr(0x5000), addr(0x5003));
		expectedAddresses.add(addr(0x5034), addr(0x5037));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x5040() {

		AddressSetView flowAddresses = getFlowsTo(0x5040, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x2e));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x90), addr(0xbe));
		expectedAddresses.add(addr(0x390), addr(0x390));
		expectedAddresses.add(addr(0x5024), addr(0x5027));
		expectedAddresses.add(addr(0x5040), addr(0x5040));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x5048() {

		AddressSetView flowAddresses = getFlowsTo(0x5048, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5048), addr(0x504b));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalCallsBackFrom0x2f() {

		AddressSetView flowAddresses = getFlowsTo(0x2f, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x25), addr(0x2f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalCallsBackFrom0x23() {

		AddressSetView flowAddresses = getFlowsTo(0x23, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0e), addr(0x24));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalCallsBackFrom0x8() {

		AddressSetView flowAddresses = getFlowsTo(0x8, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x9));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalCallsBackFrom0x5f() {

		AddressSetView flowAddresses = getFlowsTo(0x5f, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x53), addr(0x5f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalCallsBackFrom0x38() {

		AddressSetView flowAddresses = getFlowsTo(0x38, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0e), addr(0x15));
		expectedAddresses.add(addr(0x30), addr(0x39));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalCallsBackFrom0x31() {

		AddressSetView flowAddresses = getFlowsTo(0x31, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0e), addr(0x15));
		expectedAddresses.add(addr(0x30), addr(0x31));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalCallsBackFrom0x8f() {

		AddressSetView flowAddresses = getFlowsTo(0x8f, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x85), addr(0x8f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalCallsBackFrom0x61() {

		AddressSetView flowAddresses = getFlowsTo(0x61, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x60), addr(0x61));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalCallsBackFrom0xbf() {

		AddressSetView flowAddresses = getFlowsTo(0xbf, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0xb5), addr(0xbf));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalCallsBackFrom0x91() {

		AddressSetView flowAddresses = getFlowsTo(0x91, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x90), addr(0x91));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testConditionalCallsBackFrom0x2f() {

		AddressSetView flowAddresses = getFlowsTo(0x2f, followOnlyConditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x25), addr(0x2f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testConditionalCallsBackFrom0x6() {

		AddressSetView flowAddresses = getFlowsTo(0x6, followOnlyConditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x7));
		expectedAddresses.add(addr(0x53), addr(0x5e));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testConditionalCallsBackFrom0x161() {

		AddressSetView flowAddresses = getFlowsTo(0x161, followOnlyConditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x3e), addr(0x50));
		expectedAddresses.add(addr(0x160), addr(0x161));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testConditionalCallsBackFrom0x261() {

		AddressSetView flowAddresses = getFlowsTo(0x261, followOnlyConditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x6e), addr(0x80));
		expectedAddresses.add(addr(0x260), addr(0x261));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testComputedCallsBackFrom0x96() {

		AddressSetView flowAddresses = getFlowsTo(0x96, followOnlyComputedCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x25), addr(0x2c));
		expectedAddresses.add(addr(0x90), addr(0x97));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testComputedCallsBackFrom0x5f() {

		AddressSetView flowAddresses = getFlowsTo(0x5f, followOnlyComputedCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x53), addr(0x5f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testComputedCallsBackFrom0x391() {

		AddressSetView flowAddresses = getFlowsTo(0x391, followOnlyComputedCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0xb5), addr(0xbe));
		expectedAddresses.add(addr(0x390), addr(0x391));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testAllCallsBackFrom0x8f() {

		AddressSetView flowAddresses = getFlowsTo(0x8f, followAllCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x85), addr(0x8f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testAllCallsBackFrom0x331() {

		AddressSetView flowAddresses = getFlowsTo(0x331, followAllCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x9e), addr(0xa5));
		expectedAddresses.add(addr(0x330), addr(0x331));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testAllCallsBackFrom0x361() {

		AddressSetView flowAddresses = getFlowsTo(0x361, followAllCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x9e), addr(0xb0));
		expectedAddresses.add(addr(0x360), addr(0x361));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testAllCallsBackFrom0x391() {

		AddressSetView flowAddresses = getFlowsTo(0x391, followAllCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0xb5), addr(0xbe));
		expectedAddresses.add(addr(0x390), addr(0x391));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalJumpsBackFrom0x2f() {

		AddressSetView flowAddresses = getFlowsTo(0x2f, followOnlyUnconditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x25), addr(0x2f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalJumpsBackFrom0x23() {

		AddressSetView flowAddresses = getFlowsTo(0x23, followOnlyUnconditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x24));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testUnconditionalJumpsBackFrom0x391() {

		AddressSetView flowAddresses = getFlowsTo(0x391, followOnlyUnconditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x390), addr(0x391));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testConditionalJumpsBackFrom0x5f() {

		AddressSetView flowAddresses = getFlowsTo(0x5f, followOnlyConditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x53), addr(0x5f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testConditionalJumpsBackFrom0x3c() {

		AddressSetView flowAddresses = getFlowsTo(0x3c, followOnlyConditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x30), addr(0x37));
		expectedAddresses.add(addr(0x3a), addr(0x3d));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testConditionalJumpsBackFrom0x291() {

		AddressSetView flowAddresses = getFlowsTo(0x291, followOnlyConditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x290), addr(0x291));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testComputedJumpsBackFrom0x5f() {

		AddressSetView flowAddresses = getFlowsTo(0x5f, followOnlyComputedJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x3e), addr(0x5f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testComputedJumpsBackFrom0x191() {

		AddressSetView flowAddresses = getFlowsTo(0x191, followOnlyComputedJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x190), addr(0x191));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testComputedJumpsBackFrom0x230() {

		AddressSetView flowAddresses = getFlowsTo(0x230, followOnlyComputedJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x230), addr(0x230));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testPointersBackFrom0x230() {

		AddressSetView flowAddresses = getFlowsTo(0x230, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x230), addr(0x230));
		expectedAddresses.add(addr(0x5048), addr(0x504b));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testPointersBackFrom0x331() {

		AddressSetView flowAddresses = getFlowsTo(0x331, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x5008), addr(0x500b));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testPointersBackFrom0x5040() {

		AddressSetView flowAddresses = getFlowsTo(0x5040, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x390), addr(0x390));
		expectedAddresses.add(addr(0x5040), addr(0x5040));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testPointersBackFrom0x60() {

		AddressSetView flowAddresses = getFlowsTo(0x60, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x60), addr(0x60));
		expectedAddresses.add(addr(0x5000), addr(0x5003));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testPointersBackFrom0x5004() {

		AddressSetView flowAddresses = getFlowsTo(0x5004, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5004), addr(0x5007));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testAllJumpsBackFrom0x8f() {

		AddressSetView flowAddresses = getFlowsTo(0x8f, followAllJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x60), addr(0x8f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testAllJumpsBackFrom0x191() {

		AddressSetView flowAddresses = getFlowsTo(0x191, followAllJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x190), addr(0x191));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testAllLimitedFlowsBackFromEnd() {

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x131), addr(0x131));
		selectionSet.add(addr(0x161), addr(0x161));
		selectionSet.add(addr(0x191), addr(0x191));
		selectionSet.add(addr(0x231), addr(0x231));
		selectionSet.add(addr(0x261), addr(0x261));
		selectionSet.add(addr(0x291), addr(0x291));
		selectionSet.add(addr(0x331), addr(0x331));
		selectionSet.add(addr(0x361), addr(0x361));
		selectionSet.add(addr(0x391), addr(0x391));

		AddressSetView flowAddresses = getFlowsTo(selectionSet, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x2e));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x60), addr(0x8e));
		expectedAddresses.add(addr(0x90), addr(0xbe));
		expectedAddresses.add(addr(0x130), addr(0x131));
		expectedAddresses.add(addr(0x160), addr(0x161));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5000), addr(0x5003));
		expectedAddresses.add(addr(0x5004), addr(0x5007));
		expectedAddresses.add(addr(0x5008), addr(0x500b));
		expectedAddresses.add(addr(0x5024), addr(0x5027));
		expectedAddresses.add(addr(0x5048), addr(0x504b));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}
}
