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

public class FollowFlowForwardTest extends AbstractFollowFlowTest {

	@Test
	public void testFollowAllFlowsFrom0x0() {

		AddressSetView flowAddresses = getFlowsFrom(0x0, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));
		expectedAddresses.add(addr(0x30), addr(0x52));
		expectedAddresses.add(addr(0x54), addr(0x5f));
		expectedAddresses.add(addr(0x60), addr(0x84));
		expectedAddresses.add(addr(0x86), addr(0x8f));
		expectedAddresses.add(addr(0x90), addr(0xb4));
		expectedAddresses.add(addr(0xb6), addr(0xbf));
		expectedAddresses.add(addr(0x130), addr(0x131));
		expectedAddresses.add(addr(0x160), addr(0x161));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5034), addr(0x5037));
		expectedAddresses.add(addr(0x5040), addr(0x5043));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x10() {

		AddressSetView flowAddresses = getFlowsFrom(0x10, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));
		expectedAddresses.add(addr(0x30), addr(0x52));
		expectedAddresses.add(addr(0x54), addr(0x5f));
		expectedAddresses.add(addr(0x60), addr(0x84));
		expectedAddresses.add(addr(0x86), addr(0x8f));
		expectedAddresses.add(addr(0x90), addr(0xb4));
		expectedAddresses.add(addr(0xb6), addr(0xbf));
		expectedAddresses.add(addr(0x130), addr(0x131));
		expectedAddresses.add(addr(0x160), addr(0x161));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5034), addr(0x5037));
		expectedAddresses.add(addr(0x5040), addr(0x5043));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x17() {

		AddressSetView flowAddresses = getFlowsFrom(0x17, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x17), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));
		expectedAddresses.add(addr(0x60), addr(0x84));
		expectedAddresses.add(addr(0x86), addr(0x8f));
		expectedAddresses.add(addr(0x90), addr(0xb4));
		expectedAddresses.add(addr(0xb6), addr(0xbf));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5034), addr(0x5037));
		expectedAddresses.add(addr(0x5040), addr(0x5043));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x2f() {

		AddressSetView flowAddresses = getFlowsFrom(0x2f, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x2f), addr(0x2f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x47() {

		AddressSetView flowAddresses = getFlowsFrom(0x47, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));
		expectedAddresses.add(addr(0x30), addr(0x52));
		expectedAddresses.add(addr(0x54), addr(0x5f));
		expectedAddresses.add(addr(0x60), addr(0x84));
		expectedAddresses.add(addr(0x86), addr(0x8f));
		expectedAddresses.add(addr(0x90), addr(0xb4));
		expectedAddresses.add(addr(0xb6), addr(0xbf));
		expectedAddresses.add(addr(0x130), addr(0x131));
		expectedAddresses.add(addr(0x160), addr(0x161));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5034), addr(0x5037));
		expectedAddresses.add(addr(0x5040), addr(0x5043));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x77() {

		AddressSetView flowAddresses = getFlowsFrom(0x77, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x77), addr(0x84));
		expectedAddresses.add(addr(0x86), addr(0x8f));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x5034), addr(0x5037));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x5000() {

		AddressSetView flowAddresses = getFlowsFrom(0x5000, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x60), addr(0x84));
		expectedAddresses.add(addr(0x86), addr(0x8f));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x5000), addr(0x5003));
		expectedAddresses.add(addr(0x5034), addr(0x5037));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x5020() {

		AddressSetView flowAddresses = getFlowsFrom(0x5020, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5020), addr(0x5023));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x5020struct() {

		AddressSetView flowAddresses =
			getFlowsFrom(new AddressSet(addr(0x5020), addr(0x5029)), followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x90), addr(0xb4));
		expectedAddresses.add(addr(0xb6), addr(0xbf));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5020), addr(0x5029));
		expectedAddresses.add(addr(0x5040), addr(0x5043));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x5024() {

		AddressSetView flowAddresses = getFlowsFrom(0x5024, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x90), addr(0xb4));
		expectedAddresses.add(addr(0xb6), addr(0xbf));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5024), addr(0x5027));
		expectedAddresses.add(addr(0x5040), addr(0x5043));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x5034() {

		AddressSetView flowAddresses = getFlowsFrom(0x5034, followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5034), addr(0x5037));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllFlowsFrom0x5030struct() {

		AddressSetView flowAddresses =
			getFlowsFrom(new AddressSet(addr(0x5030), addr(0x5039)), followAllFlows());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5030), addr(0x5039));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowUnconditionalCall0x0() {

		AddressSetView flowAddresses = getFlowsFrom(0x0, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x9));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowUnconditionalCall0xb() {

		AddressSetView flowAddresses = getFlowsFrom(0xb, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0xb), addr(0xd));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowUnconditionalCall0xf() {

		AddressSetView flowAddresses = getFlowsFrom(0xf, followOnlyUnconditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0xf), addr(0x24));
		expectedAddresses.add(addr(0x30), addr(0x39));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowConditionalCall0x0() {

		AddressSetView flowAddresses = getFlowsFrom(0x0, followOnlyConditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x9));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowConditionalCall0xe() {

		AddressSetView flowAddresses = getFlowsFrom(0xe, followOnlyConditionalCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0xe), addr(0x24));
		expectedAddresses.add(addr(0x60), addr(0x69));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowComputedCall0x0() {

		AddressSetView flowAddresses = getFlowsFrom(0x0, followOnlyComputedCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x9));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowComputedCall0x25() {

		AddressSetView flowAddresses = getFlowsFrom(0x25, followOnlyComputedCalls());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x25), addr(0x2f));
		expectedAddresses.add(addr(0x90), addr(0x99));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowUnconditionalJump0x0() {

		AddressSetView flowAddresses = getFlowsFrom(0x0, followOnlyUnconditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x9));
		expectedAddresses.add(addr(0xe), addr(0x24));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowUnconditionalJump0xb() {

		AddressSetView flowAddresses = getFlowsFrom(0xb, followOnlyUnconditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0xb), addr(0xd));
		expectedAddresses.add(addr(0xf), addr(0x24));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowUnconditionalJump0x3b() {

		AddressSetView flowAddresses = getFlowsFrom(0x3b, followOnlyUnconditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x3b), addr(0x3d));
		expectedAddresses.add(addr(0x3f), addr(0x52));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowConditionalJump0x0() {

		AddressSetView flowAddresses = getFlowsFrom(0x0, followOnlyConditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0xd));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowConditionalJump0xb() {

		AddressSetView flowAddresses = getFlowsFrom(0xb, followOnlyConditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0xb), addr(0xd));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowConditionalJump0x21() {

		AddressSetView flowAddresses = getFlowsFrom(0x21, followOnlyConditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x21), addr(0x24));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowComputedJump0x0() {

		AddressSetView flowAddresses = getFlowsFrom(0x0, followOnlyComputedJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x9));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowComputedJump0x21() {

		AddressSetView flowAddresses = getFlowsFrom(0x21, followOnlyComputedJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x21), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowPointers0x0() {

		AddressSetView flowAddresses = getFlowsFrom(0x0, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x9));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowPointers0x5048() {

		AddressSetView flowAddresses = getFlowsFrom(0x5048, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x5048), addr(0x504b));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowPointers0x290() {

		AddressSetView flowAddresses = getFlowsFrom(0x290, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x5034), addr(0x5037));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowPointers0x390() {

		AddressSetView flowAddresses = getFlowsFrom(0x390, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5040), addr(0x5043));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowPointers0x5000() {

		AddressSetView flowAddresses = getFlowsFrom(0x5000, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x60), addr(0x69));
		expectedAddresses.add(addr(0x5000), addr(0x5003));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowPointers0x5034() {

		AddressSetView flowAddresses = getFlowsFrom(0x5034, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x5034), addr(0x5037));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowPointers0x500c() {

		AddressSetView flowAddresses = getFlowsFrom(0x500c, followOnlyPointers());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x500c), addr(0x500f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowConditionalAndUnconditionalJumps0x0() {

		AddressSetView flowAddresses = getFlowsFrom(0x0, followConditionalAndUnconditionalJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x24));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}

	@Test
	public void testFollowAllJumps0x0() {

		AddressSetView flowAddresses = getFlowsFrom(0x0, followAllJumps());

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));

		assertEquals(new MySelection(expectedAddresses), new MySelection(flowAddresses));
	}
}
