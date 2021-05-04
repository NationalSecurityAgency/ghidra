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
package ghidra.dbg.test;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.junit.Test;

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.DebuggerCallbackReorderer;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.util.Msg;

/**
 * Tests the functionality of breakpoints
 * 
 * <p>
 * Note that this test does not check for nuances regarding specification vs. location, as it is
 * meant to generalize across models for interests of the UI only. As such, we only test that we can
 * set breakpoints at given addresses and that a location manifests there, regardless of the
 * intervening mechanisms. We also test some basic operations on the breakpoint (location) itself.
 * Models which have separate specifications from locations, or for which you want to test
 * non-address specifications will need to add their own tests, tailored to the semantics of that
 * model's breakpoint specifications.
 * 
 * <p>
 * TODO: Enable, disable (if supported), delete (if supported), manipulation via CLI is synced
 */
public abstract class AbstractDebuggerModelBreakpointsTest extends AbstractDebuggerModelTest
		implements RequiresTarget {

	/**
	 * Get the expected (absolute) path of the target's breakpoint container
	 * 
	 * @param targetPath the path of the target
	 * @return the expected path, or {@code null} for no assertion
	 */
	public List<String> getExpectedBreakpointContainerPath(List<String> targetPath) {
		return null;
	}

	public abstract TargetBreakpointKindSet getExpectedSupportedKinds();

	public abstract AddressRange getSuitableRangeForBreakpoint(TargetObject target,
			TargetBreakpointKind kind) throws Throwable;

	public boolean isSupportsTogglableLocations() {
		return false;
	}

	public boolean isSupportsDeletableLocations() {
		return false;
	}

	@Test
	public void testBreakpointContainerIsWhereExpected() throws Throwable {
		m.build();

		TargetObject target = obtainTarget();
		List<String> expectedBreakpointContainerPath =
			getExpectedBreakpointContainerPath(target.getPath());
		assumeNotNull(expectedBreakpointContainerPath);
		TargetBreakpointSpecContainer container =
			m.suitable(TargetBreakpointSpecContainer.class, target.getPath());
		assertEquals(expectedBreakpointContainerPath, container.getPath());
	}

	@Test
	public void testBreakpointContainerSupportsExpectedKinds() throws Throwable {
		m.build();

		TargetObject target = obtainTarget();
		TargetBreakpointSpecContainer container =
			m.suitable(TargetBreakpointSpecContainer.class, target.getPath());
		waitOn(container.fetchAttributes());
		assertEquals(getExpectedSupportedKinds(), container.getSupportedBreakpointKinds());
	}

	@Test
	public void testBreakpointsSupportTogglableAsExpected() throws Throwable {
		m.build();

		for (TargetObjectSchema schema : m.getModel()
				.getRootSchema()
				.getContext()
				.getAllSchemas()) {
			Set<Class<? extends TargetObject>> ifs = schema.getInterfaces();
			if (ifs.contains(TargetBreakpointLocation.class)) {
				boolean supportsTogglableLocations = ifs.contains(TargetTogglable.class) &&
					!ifs.contains(TargetBreakpointSpec.class);
				assertEquals(isSupportsTogglableLocations(), supportsTogglableLocations);
			}
		}
	}

	@Test
	public void testBreakpointLocationsSupportDeletableAsExpected() throws Throwable {
		m.build();

		for (TargetObjectSchema schema : m.getModel()
				.getRootSchema()
				.getContext()
				.getAllSchemas()) {
			Set<Class<? extends TargetObject>> ifs = schema.getInterfaces();
			if (ifs.contains(TargetBreakpointLocation.class)) {
				boolean supportsDeletableLocations = ifs.contains(TargetDeletable.class) &&
					!ifs.contains(TargetBreakpointSpec.class);
				assertEquals(isSupportsDeletableLocations(), supportsDeletableLocations);
			}
		}
	}

	protected TargetBreakpointLocation assertAtLeastOneLocCovers(
			Collection<? extends TargetBreakpointLocation> locs, AddressRange range,
			TargetBreakpointKind kind) throws Throwable {
		for (TargetBreakpointLocation l : locs) {
			TargetBreakpointSpec spec = l.getSpecification();
			if (spec == null) { // Mid construction?
				continue;
			}
			if (l.getAddress() == null || l.getLength() == null) {
				continue;
			}
			AddressRange actualRange = new AddressRangeImpl(l.getAddress(), l.getLength());
			if (!actualRange.contains(range.getMinAddress()) ||
				!actualRange.contains(range.getMaxAddress())) {
				continue;
			}
			if (spec.getKinds() == null) {
				continue;
			}
			if (!spec.getKinds().contains(kind)) {
				continue;
			}
			return l;
		}
		fail("No location covers expected breakpoint");
		return null;
	}

	/**
	 * Verify that the given breakpoint location covers the required range and kind, using the
	 * interpreter
	 * 
	 * @param range the requested range of the breakpoint
	 * @param kind the requested kind of the breakpoint
	 * @param loc the location object
	 * @param interpreter the interpreter
	 * @throws Throwable if anything goes wrong
	 */
	protected void assertLocCoversViaInterpreter(AddressRange range,
			TargetBreakpointKind kind, TargetBreakpointLocation loc,
			TargetInterpreter interpreter) throws Throwable {
		fail("Unless hasInterpreter is false, the test must implement this method");
	}

	/**
	 * Verify that the given spec and/or location is in the given state, using the interpreter
	 * 
	 * @param t the spec or location
	 * @param enabled the expected state: true for enabled, false for disabled
	 * @param interpreter the interpreter
	 * @throws Throwable if anything goes wrong
	 */
	protected void assertEnabledViaInterpreter(TargetTogglable t, boolean enabled,
			TargetInterpreter interpreter) throws Throwable {
		fail("Unless hasInterpreter is false, the test must implement this method");
	}

	/**
	 * Verify that the given spec and/or location no longer exists, using the interpreter
	 * 
	 * @param d the spec or location
	 * @param interpreter the interpreter
	 * @throws Throwable if anything goes wrong
	 */
	protected void assertDeletedViaInterpreter(TargetDeletable d, TargetInterpreter interpreter)
			throws Throwable {
		fail("Unless hasInterpreter is false, the test must implement this method");
	}

	/**
	 * Place the given breakpoint using the interpreter
	 * 
	 * @param range the requested range
	 * @param kind the requested kind
	 * @param interpreter the interpreter
	 * @throws Throwable if anything goes wrong
	 */
	protected void placeBreakpointViaInterpreter(AddressRange range, TargetBreakpointKind kind,
			TargetInterpreter interpreter) throws Throwable {
		fail("Unless hasInterpreter is false, the test must implement this method");
	}

	/**
	 * Disable the given spec and/or location using the interpreter
	 * 
	 * @param t the spec and/or location
	 * @param interpreter the interpreter
	 * @throws Throwable if anything goes wrong
	 */
	protected void disableViaInterpreter(TargetTogglable t, TargetInterpreter interpreter)
			throws Throwable {
		fail("Unless hasInterpreter is false, the test must implement this method");
	}

	/**
	 * Enable the given spec and/or location using the interpreter
	 * 
	 * @param t the spec and/or location
	 * @param interpreter the interpreter
	 * @throws Throwable if anything goes wrong
	 */
	protected void enableViaInterpreter(TargetTogglable t, TargetInterpreter interpreter)
			throws Throwable {
		fail("Unless hasInterpreter is false, the test must implement this method");
	}

	/**
	 * Delete the given spec and/or location using the interpreter
	 * 
	 * @param d the spec and/or location
	 * @param interpreter the interpreter
	 * @throws Throwable if anything goes wrong
	 */
	protected void deleteViaInterpreter(TargetDeletable d, TargetInterpreter interpreter)
			throws Throwable {
		fail("Unless hasInterpreter is false, the test must implement this method");
	}

	protected void addMonitor() {
		var monitor = new DebuggerModelListener() {
			DebuggerCallbackReorderer reorderer = new DebuggerCallbackReorderer(this);

			@Override
			public void created(TargetObject object) {
				if (!object.getJoinedPath(".").contains("reak")) {
					return;
				}
				Msg.debug(this, "CREATED " + object.getJoinedPath("."));
			}

			protected String logDisp(Object val) {
				if (val == null) {
					return "<null>"; // Should never happen
				}
				if (val instanceof TargetObject) {
					TargetObject obj = (TargetObject) val;
					return "obj-" + obj.getJoinedPath(".");
				}
				return val.toString();
			}

			@Override
			public void attributesChanged(TargetObject object, Collection<String> removed,
					Map<String, ?> added) {
				if (!object.getJoinedPath(".").contains("reak")) {
					return;
				}
				Msg.debug(this,
					"ATTRIBUTES: object=" + object.getJoinedPath(".") + ",removed=" + removed);
				for (Entry<String, ?> ent : added.entrySet()) {
					Msg.debug(this,
						"  ATTR_added: " + ent.getKey() + "=" + logDisp(ent.getValue()));
				}
			}

			@Override
			public void elementsChanged(TargetObject object, Collection<String> removed,
					Map<String, ? extends TargetObject> added) {
				if (!object.getJoinedPath(".").contains("reak")) {
					return;
				}
				Msg.debug(this,
					"ELEMENTS: object=" + object.getJoinedPath(".") + ",removed=" + removed);
				for (Entry<String, ?> ent : added.entrySet()) {
					Msg.debug(this,
						"  ELEM_added: " + ent.getKey() + "=" + logDisp(ent.getValue()));
				}
			}
		};
		m.getModel().addModelListener(monitor.reorderer, true);
	}

	protected void runTestPlaceBreakpoint(TargetBreakpointKind kind) throws Throwable {
		assumeTrue(getExpectedSupportedKinds().contains(kind));
		m.build();

		addMonitor();

		TargetObject target = obtainTarget();
		TargetBreakpointSpecContainer container = findBreakpointSpecContainer(target.getPath());
		AddressRange range = getSuitableRangeForBreakpoint(target, kind);
		waitOn(container.placeBreakpoint(range, Set.of(kind)));
		TargetBreakpointLocation loc = retry(() -> {
			Collection<? extends TargetBreakpointLocation> found =
				m.findAll(TargetBreakpointLocation.class, target.getPath(), true).values();
			return assertAtLeastOneLocCovers(found, range, kind);
		}, List.of(AssertionError.class));
		if (m.hasInterpreter()) {
			TargetInterpreter interpreter = findInterpreter();
			assertLocCoversViaInterpreter(range, kind, loc, interpreter);
		}
	}

	protected void runTestPlaceBreakpointViaInterpreter(TargetBreakpointKind kind)
			throws Throwable {
		assumeTrue(getExpectedSupportedKinds().contains(kind));
		assumeTrue(m.hasInterpreter());
		m.build();

		addMonitor();

		TargetObject target = obtainTarget();
		TargetInterpreter interpreter = findInterpreter();
		AddressRange range = getSuitableRangeForBreakpoint(target, kind);
		placeBreakpointViaInterpreter(range, kind, interpreter);
		TargetBreakpointLocation loc = retry(() -> {
			Collection<? extends TargetBreakpointLocation> found =
				m.findAll(TargetBreakpointLocation.class, target.getPath(), true).values();
			return assertAtLeastOneLocCovers(found, range, kind);
		}, List.of(AssertionError.class));
		assertLocCoversViaInterpreter(range, kind, loc, interpreter);
	}

	@Test
	public void testPlaceSoftwareExecuteBreakpoint() throws Throwable {
		runTestPlaceBreakpoint(TargetBreakpointKind.SW_EXECUTE);
	}

	@Test
	public void testPlaceHardwareExecuteBreakpoint() throws Throwable {
		runTestPlaceBreakpoint(TargetBreakpointKind.HW_EXECUTE);
	}

	@Test
	public void testPlaceReadBreakpoint() throws Throwable {
		runTestPlaceBreakpoint(TargetBreakpointKind.READ);
	}

	@Test
	public void testPlaceWriteBreakpoint() throws Throwable {
		runTestPlaceBreakpoint(TargetBreakpointKind.WRITE);
	}

	@Test
	public void testPlaceSoftwareExecuteBreakpointViaInterpreter() throws Throwable {
		runTestPlaceBreakpointViaInterpreter(TargetBreakpointKind.SW_EXECUTE);
	}

	@Test
	public void testPlaceHardwareExecuteBreakpointViaInterpreter() throws Throwable {
		runTestPlaceBreakpointViaInterpreter(TargetBreakpointKind.HW_EXECUTE);
	}

	@Test
	public void testPlaceReadBreakpointViaInterpreter() throws Throwable {
		runTestPlaceBreakpointViaInterpreter(TargetBreakpointKind.READ);
	}

	@Test
	public void testPlaceWriteBreakpointViaInterpreter() throws Throwable {
		runTestPlaceBreakpointViaInterpreter(TargetBreakpointKind.WRITE);
	}

	protected Set<TargetBreakpointLocation> createLocations() throws Throwable {
		// TODO: Test with multiple targets?
		TargetObject target = obtainTarget();
		TargetBreakpointSpecContainer container = findBreakpointSpecContainer(target.getPath());
		assertNotNull("No breakpoint spec container", container);
		Set<TargetBreakpointLocation> locs = new HashSet<>();
		for (TargetBreakpointKind kind : getExpectedSupportedKinds()) {
			AddressRange range = getSuitableRangeForBreakpoint(target, kind);
			waitOn(container.placeBreakpoint(range, Set.of(kind)));
			locs.add(retry(() -> {
				Collection<? extends TargetBreakpointLocation> found =
					m.findAll(TargetBreakpointLocation.class, target.getPath(), true).values();
				return assertAtLeastOneLocCovers(found, range, kind);
			}, List.of(AssertionError.class)));
		}
		Msg.debug(this, "Have locations: " +
			locs.stream().map(l -> l.getJoinedPath(".")).collect(Collectors.toSet()));
		return locs;
	}

	protected void runToggleTest(Set<TargetTogglable> set) throws Throwable {
		List<TargetTogglable> order = new ArrayList<>(set);
		Collections.shuffle(order);
		// Disable each
		for (TargetTogglable t : order) {
			waitOn(t.disable());
			retryVoid(() -> {
				assertFalse(t.isEnabled());
			}, List.of(AssertionError.class));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertEnabledViaInterpreter(t, false, interpreter);
			}
		}
		// Repeat it for fun. Should have no effect
		for (TargetTogglable t : order) {
			waitOn(t.disable());
			retryVoid(() -> {
				assertFalse(t.isEnabled());
			}, List.of(AssertionError.class));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertEnabledViaInterpreter(t, false, interpreter);
			}
		}

		// Enable each
		for (TargetTogglable t : order) {
			waitOn(t.enable());
			retryVoid(() -> {
				assertTrue(t.isEnabled());
			}, List.of(AssertionError.class));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertEnabledViaInterpreter(t, true, interpreter);
			}
		}
		// Repeat it for fun. Should have no effect
		for (TargetTogglable t : order) {
			waitOn(t.enable());
			retryVoid(() -> {
				assertTrue(t.isEnabled());
			}, List.of(AssertionError.class));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertEnabledViaInterpreter(t, true, interpreter);
			}
		}
	}

	protected void runToggleTestViaInterpreter(Set<TargetTogglable> set,
			TargetInterpreter interpreter) throws Throwable {
		List<TargetTogglable> order = new ArrayList<>(set);
		Collections.shuffle(order);
		// Disable each
		for (TargetTogglable t : order) {
			disableViaInterpreter(t, interpreter);
			retryVoid(() -> {
				assertFalse(t.isEnabled());
			}, List.of(AssertionError.class));
			assertEnabledViaInterpreter(t, false, interpreter);
		}
		// Repeat it for fun. Should have no effect
		for (TargetTogglable t : order) {
			disableViaInterpreter(t, interpreter);
			retryVoid(() -> {
				assertFalse(t.isEnabled());
			}, List.of(AssertionError.class));
			assertEnabledViaInterpreter(t, false, interpreter);
		}

		// Enable each
		for (TargetTogglable t : order) {
			enableViaInterpreter(t, interpreter);
			retryVoid(() -> {
				assertTrue(t.isEnabled());
			}, List.of(AssertionError.class));
			assertEnabledViaInterpreter(t, true, interpreter);
		}
		// Repeat it for fun. Should have no effect
		for (TargetTogglable t : order) {
			enableViaInterpreter(t, interpreter);
			retryVoid(() -> {
				assertTrue(t.isEnabled());
			}, List.of(AssertionError.class));
			assertEnabledViaInterpreter(t, true, interpreter);
		}
	}

	@Test
	public void testToggleBreakpoints() throws Throwable {
		m.build();

		Set<TargetBreakpointLocation> locs = createLocations();
		runToggleTest(locs.stream()
				.map(l -> l.getSpecification().as(TargetTogglable.class))
				.collect(Collectors.toSet()));
	}

	@Test
	public void testToggleBreakpointsViaInterpreter() throws Throwable {
		assumeTrue(m.hasInterpreter());
		m.build();

		Set<TargetBreakpointLocation> locs = createLocations();
		TargetInterpreter interpreter = findInterpreter();
		runToggleTestViaInterpreter(locs.stream()
				.map(l -> l.getSpecification().as(TargetTogglable.class))
				.collect(Collectors.toSet()),
			interpreter);
	}

	@Test
	public void testToggleBreakpointLocations() throws Throwable {
		assumeTrue(isSupportsTogglableLocations());
		m.build();

		Set<TargetBreakpointLocation> locs = createLocations();
		runToggleTest(
			locs.stream().map(l -> l.as(TargetTogglable.class)).collect(Collectors.toSet()));
	}

	@Test
	public void testToggleBreakpointLocationsViaInterpreter() throws Throwable {
		assumeTrue(isSupportsTogglableLocations());
		assumeTrue(m.hasInterpreter());
		m.build();

		Set<TargetBreakpointLocation> locs = createLocations();
		TargetInterpreter interpreter = findInterpreter();
		runToggleTestViaInterpreter(
			locs.stream().map(l -> l.as(TargetTogglable.class)).collect(Collectors.toSet()),
			interpreter);
	}

	protected void runDeleteTest(Set<TargetDeletable> set) throws Throwable {
		List<TargetDeletable> order = new ArrayList<>(set);
		Collections.shuffle(order);
		// Delete each
		for (TargetDeletable d : order) {
			waitOn(d.delete());
			retryVoid(() -> {
				assertFalse(d.isValid());
			}, List.of(AssertionError.class));
			if (m.hasInterpreter()) {
				TargetInterpreter interpreter = findInterpreter();
				assertDeletedViaInterpreter(d, interpreter);
			}
		}
	}

	protected void runDeleteTestViaInterpreter(Set<TargetDeletable> set,
			TargetInterpreter interpreter) throws Throwable {
		List<TargetDeletable> order = new ArrayList<>(set);
		Collections.shuffle(order);
		// Delete each
		for (TargetDeletable d : order) {
			deleteViaInterpreter(d, interpreter);
			retryVoid(() -> {
				assertFalse(d.isValid());
			}, List.of(AssertionError.class));
			assertDeletedViaInterpreter(d, interpreter);
		}
	}

	@Test
	public void testDeleteBreakpoints() throws Throwable {
		m.build();

		Set<TargetBreakpointLocation> locs = createLocations();
		runDeleteTest(locs.stream()
				.map(l -> l.getSpecification().as(TargetDeletable.class))
				.collect(Collectors.toSet()));
	}

	@Test
	public void testDeleteBreakpointsViaInterpreter() throws Throwable {
		assumeTrue(m.hasInterpreter());
		m.build();

		Set<TargetBreakpointLocation> locs = createLocations();
		TargetInterpreter interpreter = findInterpreter();
		runDeleteTestViaInterpreter(locs.stream()
				.map(l -> l.getSpecification().as(TargetDeletable.class))
				.collect(Collectors.toSet()),
			interpreter);
	}

	@Test
	public void testDeleteBreakpointLocations() throws Throwable {
		assumeTrue(isSupportsDeletableLocations());
		m.build();

		Set<TargetBreakpointLocation> locs = createLocations();
		runDeleteTest(
			locs.stream().map(l -> l.as(TargetDeletable.class)).collect(Collectors.toSet()));
	}

	@Test
	public void testDeleteBreakpointLocationsViaInterpreter() throws Throwable {
		assumeTrue(isSupportsDeletableLocations());
		assumeTrue(m.hasInterpreter());
		m.build();

		TargetInterpreter interpreter = findInterpreter();
		Set<TargetBreakpointLocation> locs = createLocations();
		runDeleteTestViaInterpreter(
			locs.stream().map(l -> l.as(TargetDeletable.class)).collect(Collectors.toSet()),
			interpreter);
	}
}
