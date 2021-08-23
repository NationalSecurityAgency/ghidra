package ghidra.app.plugin.core.debug.platform.gdb;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.*;
import java.util.stream.Collectors;

import org.junit.Test;

import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOffer;
import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOpinion;
import ghidra.app.plugin.core.debug.platform.gdb.DefaultGdbDebuggerMappingOpinion.GdbDefaultOffer;
import ghidra.dbg.model.TestDebuggerObjectModel;
import ghidra.dbg.model.TestTargetProcess;
import ghidra.program.model.lang.LanguageID;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class DefaultGdbDebuggerMappingOpinionTest extends AbstractGhidraHeadlessIntegrationTest {
	@Test
	public void testQueryOpinionsIncludesLdefsBased() {
		TestDebuggerObjectModel model = new TestDebuggerObjectModel();

		// TODO: A good number of names are definitely missing from ldefs :(
		model.session.environment.changeAttributes(List.of(), Map.ofEntries(
			Map.entry("_debugger", "gdb"),
			Map.entry("_arch", "armv5t"),
			Map.entry("_endian", "little")),
			"Testing");

		TestTargetProcess process = model.addProcess(1234);

		List<DebuggerMappingOffer> offers = DebuggerMappingOpinion.queryOpinions(process);
		assertFalse(offers.isEmpty());
		Set<DebuggerMappingOffer> ldefsOnes = offers.stream()
				.filter(o -> o.getClass().equals(GdbDefaultOffer.class))
				.collect(Collectors.toSet());
		assertFalse(ldefsOnes.isEmpty());
		Set<LanguageID> ids =
			ldefsOnes.stream().map(o -> o.getTraceLanguageID()).collect(Collectors.toSet());
		assertTrue(ids.contains(new LanguageID("ARM:LE:32:v5t")));
	}
}
