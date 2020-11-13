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
package ghidra.app.util.viewer.field;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.junit.*;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.util.RegisterFieldLocation;
import ghidra.test.*;

public class RegisterFieldFactoryTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private Program program;

	public RegisterFieldFactoryTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		program = buildProgram();

		env = new TestEnv();
		tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	private ProgramDB buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);
		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createEmptyFunction(null, "1001000", 40, null);
		builder.createReturnInstruction("1001000");

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testRegisterField() throws ContextChangeException {

		FunctionIterator iter =
			program.getFunctionManager().getFunctions(program.getMinAddress(), true);
		Function function = iter.next();
		Address entry = function.getEntryPoint();
		Address end = function.getBody().getMaxAddress();

		ProgramContext pc = program.getProgramContext();
		List<Register> nonContextRegs = getNonContextLeafRegisters(pc);

		int transactionID = program.startTransaction("test");
		int subRegCount = 0;
		int flagRegCount = 0;
		try {
			for (Register register : nonContextRegs) {
				pc.setValue(register, entry, end, BigInteger.valueOf(5));
				if (register.getParentRegister() == null) {
					++flagRegCount; // e.g., C
				}
				else {
					++subRegCount; // e.g., r0l,r0h (consolidate into r0)
				}
			}
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForPostedSwingRunnables();
		cb.updateNow();

		assertTrue(cb.goToField(entry, RegisterFieldFactory.FIELD_NAME, 0, 0, 0));

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(flagRegCount + (subRegCount / 2), tf.getNumRows());
	}

	private List<Register> getNonContextLeafRegisters(ProgramContext pc) {
		List<Register> nonContextRegs = new ArrayList<Register>();
		for (Register reg : pc.getRegisters()) {
			if (reg.isProcessorContext() || reg.hasChildren()) {
				continue;
			}
				nonContextRegs.add(reg);
		}
		return nonContextRegs;
	}

	@Test
	public void testSubsetRegisterField() throws ContextChangeException {
		FunctionIterator iter =
			program.getFunctionManager().getFunctions(program.getMinAddress(), true);
		Function function = iter.next();
		Address entry = function.getEntryPoint();

		ProgramContext pc = program.getProgramContext();
		List<Register> regs = getNonContextLeafRegisters(pc);

		int count = 0;
		int transactionID = program.startTransaction("test");
		try {
			for (int i = 0; i < regs.size(); i++) {
				if (i % 2 == 0) {
					pc.setValue(regs.get(i), entry, entry, BigInteger.valueOf(i));
				}
			}
			for (Register reg : regs) {
				RegisterValue value = pc.getNonDefaultValue(reg, entry);
				Register parent = reg.getParentRegister();
				if (value != null && value.getSignedValue() != null &&
					(parent == null || !pc.getNonDefaultValue(parent, entry).hasValue())) {
					++count;
				}
			}
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForPostedSwingRunnables();
		cb.updateNow();

		assertTrue(cb.goToField(entry, RegisterFieldFactory.FIELD_NAME, 0, 0, 0));

		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		assertEquals(count, tf.getNumRows());

	}

	@Test
	public void testProgramLocation() throws ContextChangeException {
		FunctionIterator iter =
			program.getFunctionManager().getFunctions(program.getMinAddress(), true);
		Function function = iter.next();
		Address entry = function.getEntryPoint();

		ProgramContext pc = program.getProgramContext();
		int transactionID = program.startTransaction("test");
		try {
			pc.setValue(program.getRegister("C"), entry, entry, BigInteger.valueOf(1));
			pc.setValue(program.getRegister("lrh"), entry, entry, BigInteger.valueOf(2));
			pc.setValue(program.getRegister("lrl"), entry, entry, BigInteger.valueOf(3));
			pc.setValue(program.getRegister("r0"), entry, entry, BigInteger.valueOf(4));
			pc.setValue(program.getRegister("r1l"), entry, entry, BigInteger.valueOf(5));
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		program.flushEvents();
		waitForPostedSwingRunnables();
		cb.updateNow();

		assertTrue(cb.goToField(entry, RegisterFieldFactory.FIELD_NAME, 0, 0, 0));

		assertTrue(cb.getCurrentLocation() instanceof RegisterFieldLocation);

		RegisterFieldLocation loc = (RegisterFieldLocation) cb.getCurrentLocation();
		String[] regAssumes = loc.getRegisterStrings();
		assertEquals(4, regAssumes.length);
		assertEquals("assume C = 0x1", regAssumes[0]);
		assertEquals("assume lr = 0x20003", regAssumes[1]);
		assertEquals("assume r0 = 0x4", regAssumes[2]);
		assertEquals("assume r1l = 0x5", regAssumes[3]);
	}

}
