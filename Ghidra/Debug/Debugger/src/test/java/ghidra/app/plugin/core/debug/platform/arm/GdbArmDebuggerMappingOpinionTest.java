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
package ghidra.app.plugin.core.debug.platform.arm;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.*;
import java.util.stream.Collectors;

import org.junit.Test;

import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOffer;
import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOpinion;
import ghidra.app.plugin.core.debug.platform.arm.GdbArmDebuggerMappingOpinion.GdbAArch64Offer;
import ghidra.app.plugin.core.debug.platform.arm.GdbArmDebuggerMappingOpinion.GdbArmOffer;
import ghidra.dbg.model.TestDebuggerObjectModel;
import ghidra.dbg.model.TestTargetProcess;
import ghidra.program.model.lang.LanguageID;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class GdbArmDebuggerMappingOpinionTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void testQueryOpinionsIncludesArmLdefsBased() {
		TestDebuggerObjectModel model = new TestDebuggerObjectModel();

		model.session.environment.changeAttributes(List.of(), Map.ofEntries(
			Map.entry("_debugger", "gdb"),
			Map.entry("_arch", "armv7"),
			Map.entry("_endian", "little")),
			"Testing");

		TestTargetProcess process = model.addProcess(1234);

		List<DebuggerMappingOffer> offers = DebuggerMappingOpinion.queryOpinions(process, false);
		assertFalse(offers.isEmpty());
		Set<DebuggerMappingOffer> ldefsOnes = offers.stream()
				.filter(o -> o.getClass().equals(GdbArmOffer.class))
				.collect(Collectors.toSet());
		assertFalse(ldefsOnes.isEmpty());
		Set<LanguageID> ids =
			ldefsOnes.stream().map(o -> o.getTraceLanguageID()).collect(Collectors.toSet());
		assertTrue(ids.contains(new LanguageID("ARM:LE:32:v7")));
	}

	@Test
	public void testQueryOpinionsExcludesArmLdefsBased() {
		TestDebuggerObjectModel model = new TestDebuggerObjectModel();

		model.session.environment.changeAttributes(List.of(), Map.ofEntries(
			Map.entry("_debugger", "gdb"),
			Map.entry("_arch", "i386:x86-64:intel"),
			Map.entry("_endian", "little")),
			"Testing");

		TestTargetProcess process = model.addProcess(1234);

		List<DebuggerMappingOffer> offers = DebuggerMappingOpinion.queryOpinions(process, false);
		assertFalse(offers.isEmpty());
		Set<DebuggerMappingOffer> ldefsOnes = offers.stream()
				.filter(o -> o.getClass().equals(GdbArmOffer.class))
				.collect(Collectors.toSet());
		assertTrue(ldefsOnes.isEmpty());
	}

	@Test
	public void testQueryOpinionsIncludesAArch64LdefsBased() {
		TestDebuggerObjectModel model = new TestDebuggerObjectModel();

		model.session.environment.changeAttributes(List.of(), Map.ofEntries(
			Map.entry("_debugger", "gdb"),
			Map.entry("_arch", "aarch64"),
			Map.entry("_endian", "little")),
			"Testing");

		TestTargetProcess process = model.addProcess(1234);

		List<DebuggerMappingOffer> offers = DebuggerMappingOpinion.queryOpinions(process, false);
		assertFalse(offers.isEmpty());
		Set<DebuggerMappingOffer> ldefsOnes = offers.stream()
				.filter(o -> o.getClass().equals(GdbAArch64Offer.class))
				.collect(Collectors.toSet());
		assertFalse(ldefsOnes.isEmpty());
		Set<LanguageID> ids =
			ldefsOnes.stream().map(o -> o.getTraceLanguageID()).collect(Collectors.toSet());
		assertTrue(ids.contains(new LanguageID("AARCH64:LE:64:v8A")));
	}

}
