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
import java.util.*;

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
		List<Register> nonContextRegs = getNonContextRegisters(pc);

		int transactionID = program.startTransaction("test");
		int count = 0;
		try {
			for (Register register : nonContextRegs) {
				pc.setValue(register, entry, end, BigInteger.valueOf(5));
				if (register.getParentRegister() == null) {
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

	private List<Register> getNonContextRegisters(ProgramContext pc) {
		List<Register> nonContextRegs = new ArrayList<Register>();
		for (Register reg : pc.getRegisters()) {
			if (!reg.isProcessorContext()) {
				nonContextRegs.add(reg);
			}
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
		List<Register> regs = getNonContextRegisters(pc);

		int count = 0;
		int transactionID = program.startTransaction("test");
		try {
			for (int i = 0; i < regs.size(); i++) {
				if (i % 2 == 0) {
					pc.setValue(regs.get(i), entry, entry, BigInteger.valueOf(i));
				}
			}
			for (int i = 0; i < regs.size(); i++) {
				Register reg = regs.get(i);
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
		List<Register> regs = getNonContextRegisters(pc);
		Collections.sort(regs, new RegComparator());
		int transactionID = program.startTransaction("test");
		try {
			for (int i = 0; i < 3; i++) {
				pc.setValue(regs.get(i), entry, entry, BigInteger.valueOf(i));
			}
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
		assertTrue(loc.getRegisterStrings()[0].indexOf(regs.get(0).getName()) > 0);
		assertTrue(loc.getRegisterStrings()[1].indexOf(regs.get(1).getName()) > 0);
		assertTrue(loc.getRegisterStrings()[2].indexOf(regs.get(2).getName()) > 0);
	}

	private class RegComparator implements Comparator<Register> {
		@Override
		public int compare(Register r1, Register r2) {
			return r1.getName().compareToIgnoreCase(r2.getName());
		}

	}

}
