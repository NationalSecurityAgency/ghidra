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
package ghidra.program.model.pcode;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;

public class VarnodeTest extends AbstractGenericTest {

	private static AddressSpace ramSpace = new GenericAddressSpace("ram", 64,
		AddressSpace.TYPE_RAM, 0);

	private static AddressSpace stackSpace = new GenericAddressSpace("stack", ramSpace.getSize(),
		ramSpace.getAddressableUnitSize(), AddressSpace.TYPE_STACK, 0);

	// @formatter:off
	
	private static Varnode[] STACK_NODES = new Varnode[] {
		stackNode(0, 4),
		stackNode(0, 4),
		stackNode(0, 4),
		stackNode(-4, 4),
		stackNode(-4, 4),
		stackNode(-4, 4),
		stackNode(4, 4),
		stackNode(4, 4),
		stackNode(4, 4)
	};
	
	private static Varnode[] INTERSECTING_STACK_NODES = new Varnode[] {
		stackNode(0, 4),
		stackNode(-2, 4),
		stackNode(2, 4),
		stackNode(-4, 4),
		stackNode(-6, 4),
		stackNode(-2, 4),
		stackNode(4, 4),
		stackNode(2, 4),
		stackNode(6, 4)
	};
	
	private static Varnode[] NON_INTERSECTING_STACK_NODES = new Varnode[] {
		stackNode(-4, 4),
		stackNode(4, 4),
		stackNode(10, 4),
		stackNode(0, 4),
		stackNode(-8, 4),
		stackNode(4, 4),
		stackNode(0, 4),
		stackNode(-4, 4),
		stackNode(8, 4)
	};
	
	private static Varnode[] RAM_NODES = new Varnode[] { 
		ramNode(0, 10), 
		ramNode(0, 10),
		ramNode(0, 10), 
		ramNode(10, 10), 
		ramNode(10, 10), 
		ramNode(10, 10),
		ramNode(Long.MAX_VALUE - 5, 10), 
		ramNode(Long.MAX_VALUE - 5, 10),
		ramNode(Long.MAX_VALUE - 5, 10), 
		ramNode(-20L, 10), 
		ramNode(-20L, 10), 
		ramNode(-20L, 10),
		ramNode(-20L, 40), 
		ramNode(-20L, 40), 
		ramNode(-20L, 40), 
		ramNode(-20L, 40),
		ramNode(-20L, 40), 
	};

	// Intersecting cases
	private static Varnode[] INTERSECTING_RAM_NODES = new Varnode[] { 
		ramNode(-5L, 10), 
		ramNode(5, 10),
		ramNode(-5L, 20), 
		ramNode(5, 10), 
		ramNode(15, 10), 
		ramNode(5, 20),
		ramNode(Long.MAX_VALUE - 10, 10), 
		ramNode(Long.MAX_VALUE, 10),
		ramNode(Long.MAX_VALUE - 10, 20), 
		ramNode(-25L, 10), 
		ramNode(-15L, 10), 
		ramNode(-25L, 20),
		ramNode(-25L, 20), 
		ramNode(-25L, 50), 
		ramNode(-15L, 10), 
		ramNode(5, 10), 
		ramNode(5, 20) 
	};

	// Non-Intersecting cases
	private static Varnode[] NON_INTERSECTING_RAM_NODES = new Varnode[] { 
		ramNode(-20L, 10),
		ramNode(-5L, 5), 
		ramNode(Long.MAX_VALUE - 5, 10), 
		ramNode(20, 10), 
		ramNode(0, 10),
		ramNode(Long.MAX_VALUE - 5, 10), 
		ramNode(-5L, 10), 
		ramNode(Long.MAX_VALUE - 20, 10),
		ramNode(-10L, 10), 
		ramNode(0, 10), 
		ramNode(-40L, 10), 
		ramNode(0, 10), 
		ramNode(20, 10), 
		ramNode(60, 40), 
		ramNode(-40L, 20), 
		ramNode(-60L, 20),
		ramNode(Long.MAX_VALUE - 5, 10),
	}; 
	
	// @formatter:on

	private static Varnode ramNode(long offset, int size) {
		return new Varnode(ramSpace.getAddress(offset), size);
	}

	private static Varnode stackNode(long offset, int size) {
		return new Varnode(stackSpace.getAddress(offset), size);
	}

	public VarnodeTest() {
		super();
	}

@Test
    public void testRamIntersects() {
		for (int i = 0; i < RAM_NODES.length; i++) {
			assertTrue("Varnodes expected to intersect [" + i + "]",
				RAM_NODES[i].intersects(INTERSECTING_RAM_NODES[i]));
		}
		for (int i = 0; i < RAM_NODES.length; i++) {
			assertTrue("Varnodes expected to not intersect [" + i + "]",
				!RAM_NODES[i].intersects(NON_INTERSECTING_RAM_NODES[i]));
		}
	}

@Test
    public void testStackIntersects() {
		for (int i = 0; i < STACK_NODES.length; i++) {
			assertTrue("Varnodes expected to intersect [" + i + "]",
				STACK_NODES[i].intersects(INTERSECTING_STACK_NODES[i]));
		}
		for (int i = 0; i < STACK_NODES.length; i++) {
			assertTrue("Varnodes expected to not intersect [" + i + "]",
				!STACK_NODES[i].intersects(NON_INTERSECTING_STACK_NODES[i]));
		}
	}

}
