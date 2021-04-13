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
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

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

	protected void runTestPlaceBreakpoint(TargetBreakpointKind kind) throws Throwable {
		assumeTrue(getExpectedSupportedKinds().contains(kind));
		m.build();

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

		TargetObject target = obtainTarget();
		TargetBreakpointSpecContainer container = findBreakpointSpecContainer(target.getPath());
		AddressRange range = getSuitableRangeForBreakpoint(target, kind);
		waitOn(container.placeBreakpoint(range, Set.of(kind)));
		retryVoid(() -> {
			Collection<? extends TargetBreakpointLocation> found =
				m.findAll(TargetBreakpointLocation.class, target.getPath(), true).values();
			assertAtLeastOneLocCovers(found, range, kind);
		}, List.of(AssertionError.class));
	}

	@Test
	public void testPlaceSoftwareBreakpoint() throws Throwable {
		runTestPlaceBreakpoint(TargetBreakpointKind.SW_EXECUTE);
	}

	@Test
	public void testPlaceHardwareBreakpoint() throws Throwable {
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
		}
		// Repeat it for fun. Should have no effect
		for (TargetTogglable t : order) {
			waitOn(t.disable());
			retryVoid(() -> {
				assertFalse(t.isEnabled());
			}, List.of(AssertionError.class));
		}

		// Enable each
		for (TargetTogglable t : order) {
			waitOn(t.enable());
			retryVoid(() -> {
				assertTrue(t.isEnabled());
			}, List.of(AssertionError.class));
		}
		// Repeat it for fun. Should have no effect
		for (TargetTogglable t : order) {
			waitOn(t.enable());
			retryVoid(() -> {
				assertTrue(t.isEnabled());
			}, List.of(AssertionError.class));
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
	public void testToggleBreakpointLocations() throws Throwable {
		assumeTrue(isSupportsTogglableLocations());
		m.build();

		Set<TargetBreakpointLocation> locs = createLocations();
		runToggleTest(
			locs.stream().map(l -> l.as(TargetTogglable.class)).collect(Collectors.toSet()));
	}

	protected void runDeleteTest(Set<TargetDeletable> set) throws Throwable {
		List<TargetDeletable> order = new ArrayList<>(set);
		Collections.shuffle(order);
		// Disable each
		for (TargetDeletable d : order) {
			waitOn(d.delete());
			retryVoid(() -> {
				assertFalse(d.isValid());
			}, List.of(AssertionError.class));
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
	public void testDeleteBreakpointLocations() throws Throwable {
		assumeTrue(isSupportsDeletableLocations());
		m.build();

		Set<TargetBreakpointLocation> locs = createLocations();
		runDeleteTest(
			locs.stream().map(l -> l.as(TargetDeletable.class)).collect(Collectors.toSet()));
	}
}
