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
package ghidra.feature.vt.gui.provider;

import static org.junit.Assert.*;
import ghidra.feature.vt.api.correlator.program.SymbolNameProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

import java.util.List;

import javax.swing.JFrame;

import org.junit.*;

public class VTExactSymbolMatch1Test extends AbstractGhidraHeadedIntegrationTest {
	private VTTestEnv env;
	private VTSession session;
	private Program srcProg;
	private Program destProg;

	public VTExactSymbolMatch1Test() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		env = new VTTestEnv();
		PluginTool tool = env.showTool();
		session =
			env.createSession("VersionTracking/WallaceSrc.strDiffAddrTest.gzf",
				"VersionTracking/WallaceVersion2", new SymbolNameProgramCorrelatorFactory());
		assertNotNull(session);

		srcProg = env.getSourceProgram();
		destProg = env.getDestinationProgram();
		JFrame toolFrame = tool.getToolFrame();
		toolFrame.setSize(800, 800);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testExactSymbolCorrelator() {

		//Make sure this is being found - example of unique symbol match - different address endings 
		//(testing that the addr is stripped off correctly or they wouldn't match

		//s_%s_%s_deployed_on_%s__004166a0	004166a0	s_%s_%s_deployed_on_%s__00416830	00416830
		assertTrue(isMatch(addr(srcProg, "004166a0"), addr(destProg, "00416830")));

		//Make sure these are being found by exact symbol correlator
		//they were erroneously being found by duplicate symbol correlator because
		//the old way of removing the address tail removed the _e from these so they 
		//appeared to match each other and themselves both	

		//_initterm_e	EXTERNAL:00000009	_initterm_e	EXTERNAL:00000009
		//add check for name is at right addr because external functions addresses can change if the program is re-analyzed
		//this should stay the same unless someone changes the .gzf files
		assertTrue(verifyExternalAddressesName(srcProg, addr(srcProg, "EXTERNAL:00000009"),
			"_initterm_e"));
		assertTrue(verifyExternalAddressesName(destProg, addr(destProg, "EXTERNAL:00000009"),
			"_initterm_e"));
		assertTrue(isMatch(addr(srcProg, "EXTERNAL:00000009"), addr(destProg, "EXTERNAL:00000009")));

		//_initterm	EXTERNAL:0000000a	_initterm	EXTERNAL:0000000a
		assertTrue(verifyExternalAddressesName(srcProg, addr(srcProg, "EXTERNAL:0000000a"),
			"_initterm"));
		assertTrue(verifyExternalAddressesName(destProg, addr(destProg, "EXTERNAL:0000000a"),
			"_initterm"));
		assertTrue(isMatch(addr(srcProg, "EXTERNAL:0000000a"), addr(destProg, "EXTERNAL:0000000a")));

		//Make sure these are not in the unique symbol match list - they should be in duplicate one 

		//s_Stack_area_around__alloca_memory_00417060	00417060	s_Stack_area_around__alloca_memory_00417060	00417060
		assertFalse(isMatch(addr(srcProg, "00417060"), addr(destProg, "00417060")));

		//s_Stack_area_around__alloca_memory_00417060	00417060	s_Stack_area_around__alloca_memory_00416fd8	00416fd8
		assertFalse(isMatch(addr(srcProg, "00417060"), addr(destProg, "00416fd8")));

		//s_Stack_area_around__alloca_memory_00416fd8	00416fd8	s_Stack_area_around__alloca_memory_00417060	00417060
		assertFalse(isMatch(addr(srcProg, "00416fd8"), addr(destProg, "00417060")));

		//s_Stack_area_around__alloca_memory_00416fd8	00416fd8	s_Stack_area_around__alloca_memory_00416fd8	00416fd8
		assertFalse(isMatch(addr(srcProg, "00416fd8"), addr(destProg, "00416fd8")));

		//Make sure thunks are not being found - only external functions and normal functions - not the thunks
		//thunk__initterm	004110b4	thunk__initterm	004110b4
		assertFalse(isMatch(addr(srcProg, "004110b4"), addr(destProg, "004110b4")));
		//thunk__initterm_e	0041120d	thunk__initterm_e	00411208
		assertFalse(isMatch(addr(srcProg, "0041120d"), addr(destProg, "00411208")));

	}

	public boolean verifyExternalAddressesName(Program prog, Address extAddr, String name) {
		SymbolIterator symbols = prog.getSymbolTable().getSymbols(name);
		while (symbols.hasNext()) {
			Symbol nextSym = symbols.next();
			if (nextSym.getAddress().equals(extAddr)) {
				return true;
			}
		}
		return false;
	}

	public boolean isMatch(Address srcAddr, Address destAddr) {
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (int i = 0; i < matchSets.size(); i++) {
			VTMatchSet matchSet = matchSets.get(i);

			if (matchSet.getMatches(srcAddr, destAddr).size() > 0) {
				return true;
			}
		}
		return false;
	}

	private Address addr(Program program, String address) {
		AddressFactory addrFactory = program.getAddressFactory();
		return addrFactory.getAddress(address);
	}
}
