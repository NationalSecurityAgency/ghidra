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
package ghidra.program.database;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.AddressSpace;

public class ProgramAddressFactoryOverlayTest extends AbstractGenericTest {

	private ProgramDB p;
	ProgramAddressFactory factory;
	private AddressSpace defaultSpace;

	public ProgramAddressFactoryOverlayTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		p = builder.getProgram();
		factory = p.getAddressFactory();
		defaultSpace = p.getAddressFactory().getDefaultAddressSpace();
		p.addConsumer(this);
		builder.dispose();

		p.withTransaction("Add Overlays", () -> {
			p.createOverlaySpace("A", defaultSpace);
			p.createOverlaySpace("B", defaultSpace);
			p.createOverlaySpace("C", defaultSpace);
		});
	}

	@After
	public void tearDown() throws Exception {
		p.release(this);
	}

	private int getSpaceId(String spaceName) {
		AddressSpace space = factory.getAddressSpace(spaceName);
		assertNotNull("Space " + spaceName + " not found", space);
		return System.identityHashCode(space);
	}

	@Test
	public void testOverlayRename() throws Exception {

		AddressSpace aSpace = factory.getAddressSpace("A");
		int aId = System.identityHashCode(aSpace);
		AddressSpace bSpace = factory.getAddressSpace("B");
		int bId = System.identityHashCode(bSpace);
		AddressSpace cSpace = factory.getAddressSpace("C");
		int cId = System.identityHashCode(cSpace);

		// Perform extensive renames within single transaction
		p.withTransaction("Add Overlays", () -> {
			p.renameOverlaySpace("C", "Ctmp");
			p.renameOverlaySpace("A", "C");
			p.renameOverlaySpace("B", "A");
			p.renameOverlaySpace("Ctmp", "B");

			p.createOverlaySpace("D", defaultSpace);
		});

		assertEquals(aId, getSpaceId("C"));
		assertEquals(bId, getSpaceId("A"));
		assertEquals(cId, getSpaceId("B"));

		assertEquals("C", aSpace.getName());
		assertEquals("A", bSpace.getName());
		assertEquals("B", cSpace.getName());

		assertNotNull(factory.getAddressSpace("D"));

		p.undo();

		assertEquals(aId, getSpaceId("A"));
		assertEquals(bId, getSpaceId("B"));
		assertEquals(cId, getSpaceId("C"));

		assertEquals("A", aSpace.getName());
		assertEquals("B", bSpace.getName());
		assertEquals("C", cSpace.getName());

		assertNull(factory.getAddressSpace("D"));

		p.redo();

		assertEquals(aId, getSpaceId("C"));
		assertEquals(bId, getSpaceId("A"));
		assertEquals(cId, getSpaceId("B"));

		assertEquals("C", aSpace.getName());
		assertEquals("A", bSpace.getName());
		assertEquals("B", cSpace.getName());

		assertNotNull(factory.getAddressSpace("D"));

	}
}
