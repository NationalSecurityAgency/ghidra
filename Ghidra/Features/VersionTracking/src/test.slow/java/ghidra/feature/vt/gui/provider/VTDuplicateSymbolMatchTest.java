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
import ghidra.feature.vt.api.correlator.program.DuplicateSymbolNameProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

import java.util.List;

import javax.swing.JFrame;

import org.junit.*;

public class VTDuplicateSymbolMatchTest extends AbstractGhidraHeadedIntegrationTest {
	private VTTestEnv env;
	private VTSession session;
	private Program srcProg;
	private Program destProg;

	public VTDuplicateSymbolMatchTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		env = new VTTestEnv();
		PluginTool tool = env.showTool();
		session =
			env.createSession("VersionTracking/WallaceSrc.dupeStringTest.gzf",
				"VersionTracking/WallaceVersion2",
				new DuplicateSymbolNameProgramCorrelatorFactory());
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
	public void testDuplicateSymbolCorrelator() {

		List<VTMatchSet> matchSets = session.getMatchSets();
		assertEquals(3, matchSets.size());

		//make sure these are found by the duplicate symbol matcher:
		//s_Stack_area_around__alloca_memory_00417060	00417060	s_Stack_area_around__alloca_memory_00417060	00417060
		assertTrue(isMatch(addr(srcProg, "00417060"), addr(destProg, "00417060")));

		//s_Stack_area_around__alloca_memory_00417060	00417060	s_Stack_area_around__alloca_memory_00416fd8	00416fd8
		assertTrue(isMatch(addr(srcProg, "00417060"), addr(destProg, "00416fd8")));

		//s_Stack_area_around__alloca_memory_00416fd8	00416fd8	s_Stack_area_around__alloca_memory_00417060	00417060
		assertTrue(isMatch(addr(srcProg, "00416fd8"), addr(destProg, "00417060")));

		//s_Stack_area_around__alloca_memory_00416fd8	00416fd8	s_Stack_area_around__alloca_memory_00416fd8	00416fd8
		assertTrue(isMatch(addr(srcProg, "00416fd8"), addr(destProg, "00416fd8")));

		//s_%s_%s_deployed_on_%s__004166a0	004166a0	s_%s_%s_deployed_on_%s__00416830	00416830
		assertTrue(isMatch(addr(srcProg, "004166a0"), addr(destProg, "00416830")));

		//s_%s_%s_deployed_on_%s__00416830	00416830	s_%s_%s_deployed_on_%s__00416830	00416830
		assertTrue(isMatch(addr(srcProg, "00416830"), addr(destProg, "00416830")));

		//Make sure these are not found by the duplicate matcher (should be found by unique matcher)
		//they were erroneously being found because the old way of removing the address tail removed 
		//the _e from these so they all appeared to match each other		

		//_initterm_e	00419284	_initterm_e	00419280
		assertFalse(isMatch(addr(srcProg, "00419284"), addr(destProg, "00419280")));

		//_initterm	00419288	_initterm_e	00419280
		assertFalse(isMatch(addr(srcProg, "00419288"), addr(destProg, "00419280")));

		//_initterm_e	00419284	_initterm	00419284
		assertFalse(isMatch(addr(srcProg, "00419284"), addr(destProg, "00419284")));

		//_initterm	00419288	_initterm	00419284
		assertFalse(isMatch(addr(srcProg, "00419288"), addr(destProg, "00419284")));

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
