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
package ghidra.app.plugin.core.debug.service.modules;

import static org.junit.Assert.*;

import java.io.File;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProviderTest;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.trace.model.target.schema.XmlSchemaContext;
import ghidra.util.Msg;

// Not technically a GUI test, but must be carried out in the context of a plugin tool
public class DebuggerStaticMappingServiceTest extends AbstractGhidraHeadedDebuggerTest {
	// TODO: Make change listener more detailed, and test it, too!

	protected DebuggerStaticMappingService mappingService;

	protected TraceStaticMappingManager mappingManager;

	protected AddressSpace dynSpace;
	protected AddressSpace stSpace;

	@Before
	public void setUpStaticMappingService() throws Exception {
		addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		mappingService = tool.getService(DebuggerStaticMappingService.class);

		createTrace();
		intoProject(tb.trace);
		traceManager.openTrace(tb.trace);
		mappingManager = tb.trace.getStaticMappingManager();
		waitForDomainObject(tb.trace);

		createProgram();
		intoProject(program);
		programManager.openProgram(program);
		waitForProgram(program);

		dynSpace = tb.trace.getBaseAddressFactory().getDefaultAddressSpace();
		stSpace = program.getAddressFactory().getDefaultAddressSpace();
	}

	protected void addMapping() throws Exception {
		TraceLocation from =
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00100000));
		ProgramLocation to = new ProgramLocation(program, stSpace.getAddress(0x00200000));
		try (Transaction tx = tb.startTransaction()) {
			DebuggerStaticMappingUtils.addMapping(from, to, 0x1000, false);
		}
		waitForDomainObject(tb.trace);
	}

	protected void addConflictedMapping(boolean truncateExisting) throws Exception {
		TraceLocation from = new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(10),
			dynSpace.getAddress(0x00100800));
		ProgramLocation to = new ProgramLocation(program, stSpace.getAddress(0x00300000));
		try (Transaction tx = tb.startTransaction()) {
			DebuggerStaticMappingUtils.addMapping(from, to, 0x1000, truncateExisting);
		}
	}

	protected Trace copyTrace() throws Exception {
		File saved = tb.save();
		try (ToyDBTraceBuilder r = new ToyDBTraceBuilder(saved)) {
			assertNotSame(tb.trace, r.trace);
			traceManager.openTrace(r.trace);
			waitForDomainObject(r.trace);
			return r.trace;
		}
	}

	protected void add2ndMapping() throws Exception {
		TraceLocation from =
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00102000));
		ProgramLocation to = new ProgramLocation(program, stSpace.getAddress(0x00200000));
		try (Transaction tx = tb.startTransaction()) {
			DebuggerStaticMappingUtils.addMapping(from, to, 0x800, false);
		}
		waitForDomainObject(tb.trace);
	}

	@Test
	public void testAddMappingAddsToManager() throws Exception {
		addMapping();

		assertEquals(1, mappingManager.getAllEntries().size());
		TraceStaticMapping m = mappingManager.findContaining(dynSpace.getAddress(0x00100000), 0);
		assertTrue(m.getStaticProgramURL().toString().endsWith(getProgramName()));
		assertEquals("ram:00200000", m.getStaticAddress());
		assertEquals(0x1000, m.getLength());
	}

	@Test
	public void testAddMappingSecondLanguage() throws Exception {
		programManager.closeProgram(program, true);
		DomainFile df = program.getDomainFile();
		program.release(this);
		df.delete();

		createProgram(getSLEIGH_X86_LANGUAGE());
		intoProject(program);
		programManager.openProgram(program);
		waitForProgram(program);

		stSpace = program.getAddressFactory().getDefaultAddressSpace();

		addMapping();

		assertEquals(1, mappingManager.getAllEntries().size());
		TraceStaticMapping m = mappingManager.findContaining(dynSpace.getAddress(0x00100000), 0);
		assertTrue(m.getStaticProgramURL().toString().endsWith(getProgramName()));
		assertEquals("ram:00200000", m.getStaticAddress());
		assertEquals(0x1000, m.getLength());
	}

	@Test
	public void testAddMappingTruncateExisting() throws Exception {
		addMapping();
		try {
			addConflictedMapping(false);
		}
		catch (TraceConflictedMappingException e) {
			// pass
		}

		addConflictedMapping(true);

		assertEquals(2, mappingManager.getAllEntries().size());

		TraceStaticMapping at5 = mappingManager.findContaining(dynSpace.getAddress(0x00100800), 5);
		assertEquals(new AddressRangeImpl(dynSpace.getAddress(0x00100000), 0x1000),
			at5.getTraceAddressRange());
		assertEquals(Lifespan.span(0, 9), at5.getLifespan());

		TraceStaticMapping at10 =
			mappingManager.findContaining(dynSpace.getAddress(0x00100800), 10);
		assertEquals(new AddressRangeImpl(dynSpace.getAddress(0x00100800), 0x1000),
			at10.getTraceAddressRange());
		assertEquals(Lifespan.nowOn(10), at10.getLifespan());
	}

	@Test
	public void testAddMappingThenTranslateTraceToStaticMissWayBefore() throws Exception {
		addMapping();

		assertNull(mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00000bad))));
	}

	@Test
	public void testAddMappingThenTranslateTraceToStaticMissJustBefore() throws Exception {
		addMapping();

		assertNull(mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x000fffff))));
	}

	@Test
	public void testAddMappingThenTranslateTraceToStaticHitAtStart() throws Exception {
		addMapping();

		ProgramLocation loc = mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00100000)));
		assertEquals(program, loc.getProgram());
		assertEquals(stSpace.getAddress(0x00200000), loc.getAddress());
	}

	@Test
	public void testAddMappingThenTranslateTraceToStaticHitInMiddle() throws Exception {
		addMapping();

		ProgramLocation loc = mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00100c0d)));
		assertEquals(program, loc.getProgram());
		assertEquals(stSpace.getAddress(0x00200c0d), loc.getAddress());
	}

	@Test
	public void testAddMappingThenTranslateTraceToStaticHitAtEnd() throws Exception {
		addMapping();

		ProgramLocation loc = mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00100fff)));
		assertEquals(program, loc.getProgram());
		assertEquals(stSpace.getAddress(0x00200fff), loc.getAddress());
	}

	@Test
	public void testAddMappingThenTranslateTraceToStaticMissJustAfter() throws Exception {
		addMapping();

		assertNull(mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00101000))));
	}

	@Test
	public void testAddMappingThenTranslateTraceToStaticMissWayAfter() throws Exception {
		addMapping();

		assertNull(mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0xbadbadbadL))));
	}

	@Test
	public void testAddMappingThenCopyAndTranslateStaticToTraceMissWayBefore() throws Throwable {
		addMapping();
		copyTrace();
		add2ndMapping();
		waitOn(mappingService.changesSettled());

		Set<TraceLocation> locations = mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0x00000bad)));
		assertTrue(locations.isEmpty());
	}

	@Test
	public void testAddMappingThenCopyAndTranslateStaticToTraceMissJustBefore() throws Throwable {
		addMapping();
		copyTrace();
		add2ndMapping();
		waitOn(mappingService.changesSettled());

		Set<TraceLocation> locations = mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0x001fffff)));
		assertTrue(locations.isEmpty());
	}

	@Test
	public void testAddMappingThenCopyAndTranslateStaticToTraceHitAtStart() throws Throwable {
		addMapping();
		Trace copy = copyTrace();
		add2ndMapping();
		waitOn(mappingService.changesSettled());

		Set<TraceLocation> locations = mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0x00200000)));
		assertEquals(3, locations.size()); // Assert the size to ensure locations are distinct
		Set<TraceLocation> expected = new HashSet<>();
		expected.add(new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
			dynSpace.getAddress(0x00100000)));
		expected.add(new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
			dynSpace.getAddress(0x00102000)));
		expected.add(new DefaultTraceLocation(copy, null, Lifespan.nowOn(0),
			dynSpace.getAddress(0x00100000)));
		assertEquals(expected, locations);
	}

	@Test
	public void testAddMappingThenCopyAndTranslateStaticToTraceHitInMiddle() throws Throwable {
		addMapping();
		Trace copy = copyTrace();
		add2ndMapping();
		waitOn(mappingService.changesSettled());

		Set<TraceLocation> locations = mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0x00200833)));
		assertEquals(2, locations.size());
		Set<TraceLocation> expected = new HashSet<>();
		expected.add(new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
			dynSpace.getAddress(0x00100833)));
		expected.add(new DefaultTraceLocation(copy, null, Lifespan.nowOn(0),
			dynSpace.getAddress(0x00100833)));
		assertEquals(expected, locations);
	}

	@Test
	public void testAddMappingThenCopyAndTranslateStaticToTraceHitAtEnd() throws Throwable {
		addMapping();
		Trace copy = copyTrace();
		add2ndMapping();
		waitOn(mappingService.changesSettled());

		Set<TraceLocation> locations = mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0x00200fff)));
		assertEquals(2, locations.size());
		Set<TraceLocation> expected = new HashSet<>();
		expected.add(new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
			dynSpace.getAddress(0x00100fff)));
		expected.add(new DefaultTraceLocation(copy, null, Lifespan.nowOn(0),
			dynSpace.getAddress(0x00100fff)));
		assertEquals(expected, locations);
	}

	@Test
	public void testAddMappingThenCopyAndTranslateStaticToTraceMissJustAfter() throws Throwable {
		addMapping();
		copyTrace();
		add2ndMapping();
		waitOn(mappingService.changesSettled());

		Set<TraceLocation> locations = mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0x00201000)));
		assertTrue(locations.isEmpty());
	}

	@Test
	public void testAddMappingThenCopyAndTranslateStaticToTraceMissWayAfter() throws Throwable {
		addMapping();
		copyTrace();
		add2ndMapping();
		waitOn(mappingService.changesSettled());

		Set<TraceLocation> locations = mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0xbadbadbadL)));
		assertTrue(locations.isEmpty());
	}

	@Test
	public void testAddMappingThenTranslateTraceViewToStaticEmpty() throws Exception {
		addMapping();

		Map<Program, Collection<MappedAddressRange>> views =
			mappingService.getOpenMappedViews(tb.trace, new AddressSet(), 0);
		assertTrue(views.isEmpty());
	}

	@Test
	public void testAddMappingThenTranslateTraceViewToStaticReplete() throws Exception {
		addMapping();

		AddressSet set = new AddressSet();
		// Before
		set.add(dynSpace.getAddress(0x00000bad), dynSpace.getAddress(0x00000bad + 0xff));
		// Over start boundary
		set.add(dynSpace.getAddress(0x00100000 - 0x100), dynSpace.getAddress(0x00100000 + 0xff));
		// Within
		set.add(dynSpace.getAddress(0x00100c0d), dynSpace.getAddress(0x00100ccc));
		// Over end boundary
		set.add(dynSpace.getAddress(0x00101000 - 0x100), dynSpace.getAddress(0x00101000 + 0xff));
		// After
		set.add(dynSpace.getAddress(0xbadbadbadL), dynSpace.getAddress(0xbadbadbadL + 0xff));

		Map<Program, Collection<MappedAddressRange>> views =
			mappingService.getOpenMappedViews(tb.trace, set, 0);
		assertEquals(1, views.size());
		Collection<MappedAddressRange> mappedSet = views.get(program);

		assertEquals(Set.of(
			new MappedAddressRange(tb.range(0x00100000, 0x001000ff),
				tb.range(stSpace, 0x00200000, 0x002000ff)),
			new MappedAddressRange(tb.range(0x00100c0d, 0x00100ccc),
				tb.range(stSpace, 0x00200c0d, 0x00200ccc)),
			new MappedAddressRange(tb.range(0x00100f00, 0x00100fff),
				tb.range(stSpace, 0x00200f00, 0x00200fff))),
			mappedSet);
	}

	@Test
	public void testAddMappingThenTranslateStaticViewToTraceEmpty() throws Throwable {
		addMapping();
		copyTrace();
		add2ndMapping();
		waitOn(mappingService.changesSettled());

		Map<TraceSpan, Collection<MappedAddressRange>> views =
			mappingService.getOpenMappedViews(program, new AddressSet());
		assertTrue(views.isEmpty());
	}

	@Test
	public void testAddMappingThenTranslateStaticViewToTraceReplete() throws Throwable {
		addMapping();
		Trace copy = copyTrace();
		add2ndMapping();
		waitOn(mappingService.changesSettled());

		AddressSet set = new AddressSet();
		// Before
		set.add(stSpace.getAddress(0x00000bad), stSpace.getAddress(0x00000bad + 0xff));
		// Over start boundary
		set.add(stSpace.getAddress(0x00200000 - 0x100), stSpace.getAddress(0x00200000 + 0xff));
		// Within, over middle boundary
		set.add(stSpace.getAddress(0x00200800 - 0x10), stSpace.getAddress(0x00200800 + 0xf));
		// Over end boundary
		set.add(stSpace.getAddress(0x00201000 - 0x100), stSpace.getAddress(0x00201000 + 0xff));
		// After
		set.add(stSpace.getAddress(0xbadbadbadL), stSpace.getAddress(0xbadbadbadL + 0xff));

		Map<TraceSpan, Collection<MappedAddressRange>> views =
			mappingService.getOpenMappedViews(program, set);
		Msg.info(this, views);
		assertEquals(2, views.size());
		Collection<MappedAddressRange> mappedSet1 =
			views.get(new DefaultTraceSpan(tb.trace, Lifespan.nowOn(0)));
		Collection<MappedAddressRange> mappedSet2 =
			views.get(new DefaultTraceSpan(copy, Lifespan.nowOn(0)));

		assertEquals(Set.of(
			new MappedAddressRange(tb.range(stSpace, 0x00200000, 0x002000ff),
				tb.range(0x00100000, 0x001000ff)),
			new MappedAddressRange(tb.range(stSpace, 0x002007f0, 0x0020080f),
				tb.range(0x001007f0, 0x0010080f)),
			new MappedAddressRange(tb.range(stSpace, 0x00200f00, 0x00200fff),
				tb.range(0x00100f00, 0x00100fff)),
			new MappedAddressRange(tb.range(stSpace, 0x00200000, 0x002000ff),
				tb.range(0x00102000, 0x001020ff)),
			new MappedAddressRange(tb.range(stSpace, 0x002007f0, 0x002007ff),
				tb.range(0x001027f0, 0x001027ff))),
			mappedSet1);

		assertEquals(Set.of(
			new MappedAddressRange(tb.range(stSpace, 0x00200000, 0x002000ff),
				tb.range(0x00100000, 0x001000ff)),
			new MappedAddressRange(tb.range(stSpace, 0x002007f0, 0x0020080f),
				tb.range(0x001007f0, 0x0010080f)),
			new MappedAddressRange(tb.range(stSpace, 0x00200f00, 0x00200fff),
				tb.range(0x00100f00, 0x00100fff))),
			mappedSet2);
	}

	@Test
	public void testAddMappingThenCloseStaticAndOpenMappedMissWayBefore() throws Throwable {
		// NOTE: Does not make sense to test program->trace, as program has no mapping records
		addMapping();
		programManager.closeProgram(program, true);
		waitForSwing();
		waitOn(mappingService.changesSettled());

		AddressSet addrSet = new AddressSet(dynSpace.getAddress(0x00000bad));
		Set<Program> programSet =
			mappingService.openMappedProgramsInView(tb.trace, addrSet, 0, null);

		assertTrue(programSet.isEmpty());
	}

	@Test
	public void testAddMappingThenCloseStaticAndOpenMappedHitInMiddle() throws Throwable {
		addMapping();
		programManager.closeProgram(program, true);
		waitForSwing();
		waitOn(mappingService.changesSettled());

		AddressSet addrSet = new AddressSet(dynSpace.getAddress(0x00100c0d));
		Set<Program> programSet =
			mappingService.openMappedProgramsInView(tb.trace, addrSet, 0, null);

		assertEquals(1, programSet.size());
		Program reopened = programSet.iterator().next();
		assertEquals(getProgramName(), reopened.getName());
	}

	@Test
	public void testAddMappingThenCloseStaticAndOpenMappedMissWayAfter() throws Throwable {
		addMapping();
		programManager.closeProgram(program, true);
		waitForSwing();
		waitOn(mappingService.changesSettled());

		AddressSet addrSet = new AddressSet(dynSpace.getAddress(0xbadbadbadL));
		Set<Program> programSet =
			mappingService.openMappedProgramsInView(tb.trace, addrSet, 0, null);

		assertTrue(programSet.isEmpty());
	}

	@Test
	public void testAddMappingThenCloseStaticAndTranslateTraceToStaticHitInMiddle()
			throws Throwable {
		addMapping();
		waitOn(mappingService.changesSettled());
		// pre-check
		assertNotNull(mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00100c0d))));

		programManager.closeProgram(program, true);
		waitForSwing();
		waitOn(mappingService.changesSettled());

		assertNull(mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00100c0d))));
	}

	@Test
	public void testAddMappingThenCloseTraceAndTranslateStaticToTraceHitInMiddle()
			throws Throwable {
		addMapping();
		waitOn(mappingService.changesSettled());
		// pre-check
		assertEquals(1, mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0x00200c0d))).size());

		traceManager.closeTrace(tb.trace);
		waitForSwing();
		waitOn(mappingService.changesSettled());

		assertTrue(mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0x00200c0d))).isEmpty());
	}

	@Test
	public void testAddMappingThenCloseAndReopenStaticAndTranslateTraceToStaticHitInMiddle()
			throws Throwable {
		addMapping();
		programManager.closeProgram(program, true);
		waitForSwing();
		waitOn(mappingService.changesSettled());
		// pre-check
		assertNull(mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00100c0d))));

		programManager.openProgram(program);
		waitForProgram(program);
		waitOn(mappingService.changesSettled());

		assertNotNull(mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00100c0d))));
	}

	@Test
	public void testAddMappingThenCloseAndReopenTraceAndTranslateStaticToTraceHitInMiddle()
			throws Throwable {
		addMapping();
		traceManager.closeTrace(tb.trace);
		waitForSwing();
		waitOn(mappingService.changesSettled());

		// pre-check
		assertTrue(mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0x00200c0d))).isEmpty());

		traceManager.openTrace(tb.trace);
		waitForDomainObject(tb.trace);
		waitOn(mappingService.changesSettled());

		assertEquals(1, mappingService.getOpenMappedLocations(
			new ProgramLocation(program, stSpace.getAddress(0x00200c0d))).size());
	}

	@Test
	public void testAddMappingThenRemoveButAbortThenTranslateTraceToStaticHitInMiddle()
			throws Throwable {
		addMapping();
		TraceLocation goodLoc =
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00100c0d));
		try (Transaction tx = tb.startTransaction()) {
			mappingManager.findContaining(dynSpace.getAddress(0x00100000), 0).delete();
			waitForDomainObject(tb.trace);
			waitOn(mappingService.changesSettled());
			// pre-check
			assertNull(mappingService.getOpenMappedLocation(goodLoc));
			tx.abort();
		}
		waitForDomainObject(tb.trace);
		waitOn(mappingService.changesSettled());

		assertNotNull(mappingService.getOpenMappedLocation(goodLoc));
	}

	@Test
	public void testAddCorrelationRemoveButUndoThenRequestMappingDynamicToStaticWithin()
			throws Throwable {
		addMapping();
		waitOn(mappingService.changesSettled());

		TraceLocation goodLoc =
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				dynSpace.getAddress(0x00100c0d));

		// pre-pre-check
		assertNotNull(mappingService.getOpenMappedLocation(goodLoc));

		try (Transaction tx = tb.startTransaction()) {
			mappingManager.findContaining(dynSpace.getAddress(0x00100000), 0).delete();
		}
		waitForDomainObject(tb.trace);
		waitOn(mappingService.changesSettled());

		// pre-check
		assertNull(mappingService.getOpenMappedLocation(goodLoc));

		undo(tb.trace, true);
		waitOn(mappingService.changesSettled());

		assertNotNull(mappingService.getOpenMappedLocation(goodLoc));
	}

	// TODO: open trace, add mapping to closed program, then open that program

	// TODO: The various mapping proposals

	@Test
	public void testGroupRegionsByLikelyModule() throws Exception {
		TraceMemoryRegion echoText, echoData, libText, libData;
		DBTraceMemoryManager mm = tb.trace.getMemoryManager();
		try (Transaction tx = tb.startTransaction()) {
			tb.createRootObject("Target");
			echoText = mm.createRegion("Memory[/bin/echo (0x00400000)]",
				0, tb.range(0x00400000, 0x0040ffff), TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			echoData = mm.createRegion("Memory[/bin/echo (0x00600000)]",
				0, tb.range(0x00600000, 0x00600fff), TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
			libText = mm.createRegion("Memory[/lib/libc.so (0x7ff00000)]",
				0, tb.range(0x7ff00000, 0x7ff0ffff), TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			libData = mm.createRegion("Memory[/lib/libc.so (0x7ff20000)]",
				0, tb.range(0x7ff20000, 0x7ff20fff), TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
		}

		Set<Set<TraceMemoryRegion>> actual =
			DebuggerStaticMappingProposals.groupRegionsByLikelyModule(mm.getAllRegions());
		assertEquals(Set.of(Set.of(echoText, echoData), Set.of(libText, libData)), actual);
	}

	protected void assertMapsTwoWay(long stOff, long dynOff) {
		TraceLocation dynLoc =
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(dynOff));
		ProgramLocation stLoc = new ProgramLocation(program, stSpace.getAddress(stOff));
		assertEquals(stLoc, mappingService.getOpenMappedLocation(dynLoc));
		assertEquals(dynLoc, mappingService.getOpenMappedLocation(tb.trace, stLoc, 0));
	}

	@Test
	public void testMapFullSpace() throws Throwable {
		try (Transaction tx = tb.startTransaction()) {
			TraceLocation traceLoc =
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0));
			ProgramLocation progLoc = new ProgramLocation(program, stSpace.getAddress(0));
			// NB. 0 indicates 1 << 64
			mappingService.addMapping(traceLoc, progLoc, 0, true);
		}
		waitForSwing();
		waitOn(mappingService.changesSettled());

		assertMapsTwoWay(0L, 0L);
		assertMapsTwoWay(-1L, -1L);
		assertMapsTwoWay(Long.MAX_VALUE, Long.MAX_VALUE);
		assertMapsTwoWay(Long.MIN_VALUE, Long.MIN_VALUE);
	}

	@Test
	public void testProposeModuleMappingNullBase() throws Throwable {
		DBTraceObject objModBash;
		try (Transaction tx = tb.startTransaction()) {
			SchemaContext ctx = XmlSchemaContext.deserialize(DebuggerModulesProviderTest.CTX_XML);
			DBTraceObjectManager objects = tb.trace.getObjectManager();
			objects.createRootObject(ctx.getSchema(new SchemaName("Session")));
			objModBash =
				objects.createObject(KeyPath.parse("Processes[1].Modules[/bin/bash]"));
			objModBash.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
		}

		TraceModule modBash = objModBash.queryInterface(TraceModule.class);
		assertEquals(Map.of(),
			mappingService.proposeModuleMaps(List.of(modBash), 0, List.of(program)));
	}
}
