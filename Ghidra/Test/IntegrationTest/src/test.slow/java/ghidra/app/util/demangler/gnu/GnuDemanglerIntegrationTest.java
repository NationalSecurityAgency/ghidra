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
package ghidra.app.util.demangler.gnu;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;

public class GnuDemanglerIntegrationTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("test", true);
		builder.createMemory(".text", "0x01001000", 0x100);
		program = builder.getProgram();
	}

	@Test
	public void testExceptionOnFailToDemangle() throws Exception {

		String mangled = "?InvokeHelper@CWnd@@QAAXJGGPAXPBEZZ_00912eaf";

		DemanglerCmd cmd = new DemanglerCmd(addr("01001000"), mangled);

		// this used to trigger an exception
		cmd.applyTo(program);
	}

	@Test
	public void testDemangler_Format_EDG_DemangleOnlyKnownPatterns_False_DollarInNamespace()
			throws DemangledException {

		String mangled = "MyFunction__11MyNamespacePQ215$ParamNamespace9paramName";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this performs initialization

		GnuDemanglerOptions options = new GnuDemanglerOptions();
		options.setDemangleOnlyKnownPatterns(false);
		options = options.withDeprecatedDemangler();
		DemangledObject result = demangler.demangle(mangled, options);
		assertNotNull(result);
		assertEquals("undefined MyNamespace::MyFunction($ParamNamespace::paramName *)",
			result.getSignature(false));

		DemanglerCmd cmd = new DemanglerCmd(addr("01001000"), mangled, options);

		// this used to trigger an exception
		boolean success = applyCmd(program, cmd);
		assertTrue("Demangler command failed: " + cmd.getStatusMsg(), success);

		assertNotNull(cmd.getDemangledObject());
	}

	@Test
	public void testParsingReturnType_UnnamedType() throws Exception {

		String mangled = "_ZN13SoloGimbalEKFUt_C2Ev";

		GnuDemangler demangler = new GnuDemangler();
		demangler.canDemangle(program);// this performs initialization

		GnuDemanglerOptions options = new GnuDemanglerOptions();
		options.setDemangleOnlyKnownPatterns(false);
		options = options.withDeprecatedDemangler();
		DemangledObject result = demangler.demangle(mangled, options);
		assertNotNull(result);
		assertEquals("undefined SoloGimbalEKF::{unnamed_type#1}::SoloGimbalEKF(void)",
			result.getSignature(false));

		DemanglerCmd cmd = new DemanglerCmd(addr("01001000"), mangled, options);

		// this used to trigger an exception
		boolean success = applyCmd(program, cmd);
		assertTrue("Demangler command failed: " + cmd.getStatusMsg(), success);

		assertNotNull(cmd.getDemangledObject());
	}

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

}
