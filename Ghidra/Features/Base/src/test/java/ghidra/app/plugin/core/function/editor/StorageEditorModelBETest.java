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
package ghidra.app.plugin.core.function.editor;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.lang.Register;
import ghidra.util.exception.InvalidInputException;

public class StorageEditorModelBETest extends StorageEditorModelTest {

	public StorageEditorModelBETest() {
		super(ProgramBuilder._SPARC64, "g0");
	}

	@Override
	@Test
	public void testDuplicateStorageAddress() {
		VarnodeInfo varnode = model.getVarnodes().get(0);
		model.setVarnodeType(varnode, VarnodeType.Register);
		model.setVarnode(varnode, program.getRegister(testRegName).getAddress().add(4), 4);

		model.addVarnode();
		varnode = model.getVarnodes().get(1);
		model.setVarnode(varnode, program.getRegister(testRegName).getAddress().add(6), 2);
		assertTrue(!model.isValid());
		assertEquals("Row 1: Overlapping storage address used.", model.getStatusText());
	}

	@Test
	public void testChangingSizeAffectsAddress() throws InvalidInputException {

		Register register = model.getProgram().getRegister("g1");
		assertNotNull(register);

		// test constrained
		createStorageModel(4, 4, false);
		VarnodeInfo varnode = model.getVarnodes().get(0);
		model.setVarnodeType(varnode, VarnodeType.Register);
		assertEquals(4, varnode.getSize().intValue());
		assertEquals(64, register.getBitLength());
		model.setVarnode(varnode, register);
		assertEquals(register.getAddress().getOffset() + 4,
			model.getVarnodes().get(0).getAddress().getOffset());
		assertEquals(4, varnode.getSize().intValue());

		// test unconstrained
		createStorageModel(4, 4, true);
		varnode = model.getVarnodes().get(0);
		model.setVarnodeType(varnode, VarnodeType.Register);
		assertEquals(4, varnode.getSize().intValue());
		assertEquals(64, register.getBitLength());
		model.setVarnode(varnode, register);
		assertEquals(register.getAddress().getOffset(),
			model.getVarnodes().get(0).getAddress().getOffset());
		assertEquals(8, varnode.getSize().intValue());
	}
}
