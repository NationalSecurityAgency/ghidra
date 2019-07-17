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
/*
 * Created on Aug 27, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package ghidra.app.plugin.core.select.reference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.*;

import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.test.*;

public class SelectRefereceActionsTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private AddressFactory addrFactory;
	private CodeBrowserPlugin cb;
	private SelectForwardRefsAction forwardAction;
	private SelectBackRefsAction backwardAction;

	@Before
	public void setUp() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("test", false);
		builder.createMemory("mem", "0000", 0x100);
		builder.addBytesBranchConditional("0x20", "0x10");
		builder.addBytesBranchConditional("0x30", "0x20");
		builder.addBytesBranchConditional("0x40", "0x20");
		builder.addBytesBranchConditional("0x44", "0x14");
		builder.disassemble("0x00", 0x100);

		program = builder.getProgram();
		program.addConsumer(this);
		builder.dispose();

		addrFactory = program.getAddressFactory();

		env = new TestEnv();
		PluginTool tool = env.showTool(program);
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(SelectRefsPlugin.class.getName());

		cb = env.getPlugin(CodeBrowserPlugin.class);
		SelectRefsPlugin plugin = env.getPlugin(SelectRefsPlugin.class);
		forwardAction = (SelectForwardRefsAction) getInstanceField("forwardAction", plugin);
		backwardAction = (SelectBackRefsAction) getInstanceField("backwardAction", plugin);

	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private ProgramSelection getCurrentSelection() {
		ListingActionContext context =
			(ListingActionContext) cb.getProvider().getActionContext(null);
		return context.getSelection();
	}

	@Test
	public void testForwardLocation() {
		String start = "0020";

		// Selection of address 01001144 gets expanded within code viewer provider
		// to full code unit
		CodeUnit cu = program.getListing().getCodeUnitContaining(addr("0010"));

		ProgramLocation location = new AddressFieldLocation(program, addr(start));
		cb.goTo(location);

		ProgramSelection selection = getCurrentSelection();
		assertTrue(selection.isEmpty());
		performAction(forwardAction, cb.getProvider().getActionContext(null), true);
		selection = getCurrentSelection();
		assertEquals(selection.getNumAddresses(), cu.getLength());

		for (Address addr = cu.getMinAddress(); addr.compareTo(cu.getMaxAddress()) <= 0; addr =
			addr.add(1)) {
			assertTrue(selection.contains(addr));
		}
	}

	@Test
	public void testBackwardLocation() {
		String start = "0020";

		// Selection of address 010064c0 and 010064fb gets expanded within code viewer provider
		// to full code unit
		AddressSet set = new AddressSet();
		CodeUnit cu = program.getListing().getCodeUnitContaining(addr("0030"));
		set.addRange(cu.getMinAddress(), cu.getMaxAddress());
		cu = program.getListing().getCodeUnitContaining(addr("0040"));
		set.addRange(cu.getMinAddress(), cu.getMaxAddress());

		ProgramLocation location = new AddressFieldLocation(program, addr(start));
		cb.goTo(location);

		ProgramSelection selection = getCurrentSelection();
		assertTrue(selection.isEmpty());
		performAction(backwardAction, cb.getProvider().getActionContext(null), true);
		selection = getCurrentSelection();
		assertEquals(new AddressSet(selection), set);
	}

	@Test
	public void testSelectionWithNoReferences() {

		ProgramSelection selection = new ProgramSelection(addr("0050"), addr("0060"));
		CodeViewerProvider provider = cb.getProvider();
		provider.setSelection(selection);

		performAction(forwardAction, provider.getActionContext(null), true);

		selection = getCurrentSelection();
		assertEquals(selection.isEmpty(), true);

		selection = new ProgramSelection(addr("010049d0"), addr("010049dd"));
		provider.setSelection(selection);

		performAction(backwardAction, provider.getActionContext(null), true);
		selection = getCurrentSelection();
		assertEquals(selection.isEmpty(), true);
	}

	@Test
	public void testSelectionForwardReferencesOnly() {
		String[] start = { "0030", "0050" };
		ProgramSelection selection = new ProgramSelection(addr(start[0]), addr(start[1]));

		// Selection of address 01005a3c and 01005bff gets expanded within code viewer provider
		// to full code unit
		AddressSet set = new AddressSet();
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(addr("0014"));
		set.addRange(cu.getMinAddress(), cu.getMaxAddress());
		cu = listing.getCodeUnitContaining(addr("0020"));
		set.addRange(cu.getMinAddress(), cu.getMaxAddress());

		CodeViewerProvider provider = cb.getProvider();
		provider.setSelection(selection);

		performAction(backwardAction, provider.getActionContext(null), true);
		selection = getCurrentSelection();
		assertTrue(selection.isEmpty());

		selection = new ProgramSelection(addr(start[0]), addr(start[1]));
		provider.setSelection(selection);
		performAction(forwardAction, provider.getActionContext(null), true);
		selection = getCurrentSelection();
		assertEquals(new AddressSet(selection), set);
	}

	@Test
	public void testSelectionBackwardReferencesOnly() {
		String[] start = { "0000", "0014" };
		ProgramSelection selection = new ProgramSelection(addr(start[0]), addr(start[1]));

		// Selection of address 01006580, 01006511 and 010065cc gets expanded within code viewer provider
		// to full code unit
		AddressSet set = new AddressSet();
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(addr("0020"));
		set.addRange(cu.getMinAddress(), cu.getMaxAddress());
		cu = listing.getCodeUnitContaining(addr("0044"));
		set.addRange(cu.getMinAddress(), cu.getMaxAddress());

		CodeViewerProvider provider = cb.getProvider();
		provider.setSelection(selection);

		performAction(forwardAction, provider.getActionContext(null), true);
		selection = getCurrentSelection();
		assertTrue(selection.isEmpty());

		selection = new ProgramSelection(addr(start[0]), addr(start[1]));
		provider.setSelection(selection);
		performAction(backwardAction, provider.getActionContext(null), true);
		selection = getCurrentSelection();
		assertEquals(new AddressSet(selection), set);
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}
}
