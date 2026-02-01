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

import static org.junit.Assert.*;

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
		ProgramLocation location = new AddressFieldLocation(program, addr(start));
		cb.goTo(location);

		ProgramSelection currentSelection = getCurrentSelection();
		assertTrue(currentSelection.isEmpty());
		performAction(forwardAction, cb.getProvider(), true);
		currentSelection = getCurrentSelection();
		CodeUnit cu = program.getListing().getCodeUnitContaining(addr("0010"));
		assertEquals(currentSelection.getNumAddresses(), cu.getLength());

		for (Address addr = cu.getMinAddress(); addr.compareTo(cu.getMaxAddress()) <= 0; addr =
			addr.add(1)) {
			assertTrue(currentSelection.contains(addr));
		}
	}

	@Test
	public void testBackwardLocation() {
		String start = "0020";

		ProgramLocation location = new AddressFieldLocation(program, addr(start));
		cb.goTo(location);

		ProgramSelection currentSelection = getCurrentSelection();
		assertTrue(currentSelection.isEmpty());
		performAction(backwardAction, cb.getProvider(), true);

		AddressSet referenceAddrs = getCodeUnitAddrs("0030", "0040");
		currentSelection = getCurrentSelection();
		assertEquals(new AddressSet(currentSelection), referenceAddrs);
	}

	@Test
	public void testSelectionWithNoReferences() {

		AddressSetView addrs = toAddressSet(program, "0050", "0060");

		CodeViewerProvider provider = cb.getProvider();

		makeSelection(env.getTool(), program, addrs);
		performAction(forwardAction, provider, true);

		ProgramSelection currentSelection = getCurrentSelection();
		assertEquals(currentSelection.isEmpty(), true);

		currentSelection = new ProgramSelection(addr("010049d0"), addr("010049dd"));
		addrs = toAddressSet(program, "010049d0", "010049dd");
		makeSelection(env.getTool(), program, addrs);
		performAction(backwardAction, provider, true);
		currentSelection = getCurrentSelection();
		assertEquals(currentSelection.isEmpty(), true);
	}

	@Test
	public void testSelectionForwardReferencesOnly() {

		AddressSetView addrs = toAddressSet(program, "0030", "0050");
		AddressSet referenceAddrs = getCodeUnitAddrs("0014", "0020");

		CodeViewerProvider provider = cb.getProvider();

		makeSelection(env.getTool(), program, addrs);
		performAction(backwardAction, provider, true);
		ProgramSelection selection = getCurrentSelection();
		assertTrue(selection.isEmpty());

		makeSelection(env.getTool(), program, addrs);
		performAction(forwardAction, provider, true);
		selection = getCurrentSelection();
		assertEquals(new AddressSet(selection), referenceAddrs);
	}

	@Test
	public void testSelectionBackwardReferencesOnly() {

		AddressSetView addrs = toAddressSet(program, "0000", "0014");
		AddressSet referenceAddrs = getCodeUnitAddrs("0020", "0044");

		CodeViewerProvider provider = cb.getProvider();

		makeSelection(env.getTool(), program, addrs);
		performAction(forwardAction, provider, true);

		ProgramSelection curentSelection = getCurrentSelection();
		assertTrue(curentSelection.isEmpty());

		makeSelection(env.getTool(), program, addrs);
		performAction(backwardAction, provider, true);
		curentSelection = getCurrentSelection();
		assertEquals(new AddressSet(curentSelection), referenceAddrs);
	}

	private AddressSet getCodeUnitAddrs(String... addrs) {

		// Selection of addresses gets expanded within code viewer provider to full code unit
		AddressSet set = new AddressSet();
		Listing listing = program.getListing();
		for (String addr : addrs) {
			CodeUnit cu = listing.getCodeUnitContaining(addr(addr));
			set.addRange(cu.getMinAddress(), cu.getMaxAddress());
		}
		return set;
	}

	private Address addr(String address) {
		return addrFactory.getAddress(address);
	}
}
