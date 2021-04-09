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
package ghidra.dbg.agent;

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Test;

import generic.Unique;
import ghidra.async.AsyncTestUtils;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.testutil.*;
import ghidra.dbg.testutil.AttributesChangedListener.AttributesChangedInvocation;
import ghidra.dbg.testutil.ElementsChangedListener.ElementsChangedInvocation;
import ghidra.dbg.testutil.InvalidatedListener.InvalidatedInvocation;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;

public class DefaultDebuggerObjectModelTest implements AsyncTestUtils {

	public static class FakeTargetObject extends DefaultTargetObject<TargetObject, TargetObject> {
		public FakeTargetObject(AbstractDebuggerObjectModel model, TargetObject parent,
				String name) {
			super(model, parent, name, "Fake");
		}
	}

	public static class FakeTargetRegisterBank extends FakeTargetObject
			implements TargetRegisterBank {

		public FakeTargetRegisterBank(AbstractDebuggerObjectModel model, TargetObject parent,
				String name) {
			super(model, parent, name);
		}

		@Override
		public CompletableFuture<? extends Map<String, byte[]>> readRegistersNamed(
				Collection<String> names) {
			throw new UnsupportedOperationException();
		}

		@Override
		public CompletableFuture<Void> writeRegistersNamed(Map<String, byte[]> values) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * Functionally identical to a Fake, but intrinsically different
	 */
	public static class PhonyTargetObject extends DefaultTargetObject<TargetObject, TargetObject> {
		public PhonyTargetObject(AbstractDebuggerObjectModel model, TargetObject parent,
				String name) {
			super(model, parent, name, "Phony");
		}
	}

	public static class FakeDebuggerObjectModel extends AbstractDebuggerObjectModel {
		DefaultTargetModelRoot root = new DefaultTargetModelRoot(this, "Root");

		public FakeDebuggerObjectModel() {
			addModelRoot(root);
		}

		@Override
		public CompletableFuture<? extends TargetObject> fetchModelRoot() {
			return CompletableFuture.completedFuture(root);
		}

		@Override
		public AddressFactory getAddressFactory() {
			return TODO();
		}

		@Override
		public AddressSpace getAddressSpace(String name) {
			return TODO();
		}
	}

	static class OffThreadTargetObject extends DefaultTargetObject<TargetObject, TargetObject> {
		public OffThreadTargetObject(AbstractDebuggerObjectModel model, TargetObject parent,
				String name, String typeHint) {
			super(model, parent, name, typeHint);
		}

		@Override
		public CompletableFuture<TargetObject> fetchElement(String name) {
			return CompletableFuture.supplyAsync(() -> null)
					.thenCompose(v -> super.fetchElement(name));
		}
	}

	FakeDebuggerObjectModel model = new FakeDebuggerObjectModel();

	@Test
	public void testGetModelObjectLen0() throws Throwable {
		assertEquals(model.root, waitOn(model.fetchModelValue()));
	}

	@Test
	public void testGetModelObjectLen1() throws Throwable {
		FakeTargetObject a = new FakeTargetObject(model, model.root, "A");
		model.root.changeAttributes(List.of(), Map.of("A", a), "Test");

		assertEquals(a, waitOn(model.fetchModelValue("A")));
	}

	@Test
	public void testGetModelObjectLen1NoExist() throws Throwable {
		FakeTargetObject a = new FakeTargetObject(model, model.root, "A");
		model.root.changeAttributes(List.of(), Map.of("A", a), "Test");

		assertEquals(null, waitOn(model.fetchModelValue("NoA")));
	}

	@Test
	public void testGetModelObjectLen2() throws Throwable {
		FakeTargetObject a = new FakeTargetObject(model, model.root, "A");
		model.root.changeAttributes(List.of(), Map.of("A", a), "Test");

		FakeTargetObject b = new FakeTargetObject(model, a, "[B]");
		a.changeElements(List.of(), List.of(b), "Test");

		assertEquals(b, waitOn(model.fetchModelValue("A", "[B]")));
	}

	@Test
	public void testGetModelObjectLen2NoExist() throws Throwable {
		FakeTargetObject a = new FakeTargetObject(model, model.root, "A");
		model.root.changeAttributes(List.of(), Map.of("A", a), "Test");

		FakeTargetObject b = new FakeTargetObject(model, a, "[B]");
		a.changeElements(List.of(), List.of(b), "Test");

		assertEquals(null, waitOn(model.fetchModelValue("NoA", "[B]")));
		assertEquals(null, waitOn(model.fetchModelValue("NoA", "[NoB]")));
		assertEquals(null, waitOn(model.fetchModelValue("A", "[NoB]")));
	}

	@Test
	public void testElementReplacement() throws Throwable {
		ElementsChangedListener elemL = new ElementsChangedListener();
		InvalidatedListener invL = new InvalidatedListener();
		model.addModelListener(elemL);
		model.addModelListener(invL);
		TargetObjectAddedWaiter waiter = new TargetObjectAddedWaiter(model);

		FakeTargetObject fakeA = new FakeTargetObject(model, model.root, "[A]");
		model.root.setElements(List.of(fakeA), "Init");
		assertEquals(fakeA, waitOn(waiter.wait(PathUtils.parse("[A]"))));
		waitOn(model.flushEvents());
		elemL.clear();
		invL.clear();

		PhonyTargetObject phonyA = new PhonyTargetObject(model, model.root, "[A]");

		// mere creation causes removal of old
		waitOn(elemL.count.waitUntil(c -> c >= 1));
		ElementsChangedInvocation changed1 = Unique.assertOne(elemL.invocations);
		assertSame(model.root, changed1.parent);
		assertEquals(Set.of("A"), changed1.removed);
		assertTrue(changed1.added.isEmpty());

		waitOn(invL.count.waitUntil(c -> c >= 1));
		InvalidatedInvocation invalidated = Unique.assertOne(invL.invocations);
		assertSame(fakeA, invalidated.object);

		elemL.clear();
		invL.clear();
		model.root.setElements(List.of(phonyA), "Replace");

		assertSame(phonyA, waitOn(model.fetchModelValue("[A]")));
		assertFalse(fakeA.isValid());

		waitOn(elemL.count.waitUntil(c -> c >= 1));
		ElementsChangedInvocation changed2 = Unique.assertOne(elemL.invocations);
		assertSame(model.root, changed2.parent);
		assertSame(phonyA, Unique.assertOne(changed2.added.values()));
		assertTrue(changed2.removed.isEmpty());
		waiter.close();
	}

	@Test
	public void testAttributeReplacement() throws Throwable {
		AttributesChangedListener attrL = new AttributesChangedListener();
		model.addModelListener(attrL);

		String str1 = new String("EqualStrings");
		String str2 = new String("EqualStrings");
		model.root.setAttributes(Map.of("a", str1), "Init");
		waitOn(model.flushEvents());

		/**
		 * Note: mere object creation will cause "prior removal," so we'll do this test just with
		 * primitives. Should not cause replacement, since str1 and str2 are equal.
		 */
		attrL.clear();
		model.root.setAttributes(Map.of("a", str2), "Replace");
		waitOn(model.flushEvents());

		// Verify str1 was not replaced with str2
		assertSame(str1, waitOn(model.fetchModelValue("a")));
		assertEquals(0, attrL.invocations.size());

		// Now, with prior removal
		// TODO: Should I permit custom equality check?
		attrL.clear();
		model.root.setAttributes(Map.of(), "Clear");
		model.root.setAttributes(Map.of("a", str2), "Replace");
		waitOn(model.flushEvents());

		assertEquals(2, attrL.invocations.size());
		AttributesChangedInvocation changed = attrL.invocations.get(0);
		assertEquals(model.root, changed.parent);
		assertEquals("a", Unique.assertOne(changed.removed));
		assertEquals(0, changed.added.size());
		changed = attrL.invocations.get(1);
		assertEquals(model.root, changed.parent);
		assertSame(str2, Unique.assertOne(changed.added.values()));
		assertEquals(0, changed.removed.size());
	}

	@Test
	public void testInvalidation() throws Throwable {
		InvalidatedListener invL = new InvalidatedListener();
		model.addModelListener(invL);

		FakeTargetObject fakeA = new FakeTargetObject(model, model.root, "A");
		model.root.setAttributes(Map.of("A", fakeA), "Init");

		FakeTargetObject fakeA1 = new FakeTargetObject(model, fakeA, "[1]");
		FakeTargetObject fakeA2 = new FakeTargetObject(model, fakeA, "[2]");
		fakeA.setElements(List.of(fakeA1, fakeA2), "Init");
		waitOn(model.flushEvents());
		invL.clear();

		model.root.setAttributes(Map.of(), "Clear");

		waitOn(invL.count.waitValue(3));
	}

	public static class EventRecordingListener implements DebuggerModelListener {
		List<Pair<String, TargetObject>> record = new ArrayList<>();

		@Override
		public void created(TargetObject object) {
			record.add(new ImmutablePair<>("created", object));
		}

		@Override
		public void elementsChanged(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObject> added) {
			for (TargetObject elem : added.values()) {
				record.add(new ImmutablePair<>("addedElem", elem));
			}
		}

		@Override
		public void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			for (Object attr : added.values()) {
				if (attr instanceof TargetObject) {
					record.add(new ImmutablePair<>("addedAttr", (TargetObject) attr));
				}
			}
		}

		@Override
		public void rootAdded(TargetObject root) {
			record.add(new ImmutablePair<>("rootAdded", root));
		}

		@Override
		public void registersUpdated(TargetObject bank, Map<String, byte[]> updates) {
			record.add(new ImmutablePair<>("registersUpdated", bank));
		}
	}

	@Test
	public void testCreationAndModelListenerWithoutReplay() throws Throwable {
		EventRecordingListener listener = new EventRecordingListener();
		model.addModelListener(listener, false);
		waitOn(model.flushEvents());
		waitOn(model.fetchModelRoot());
		listener.record.clear();

		FakeTargetObject fakeA = new FakeTargetObject(model, model.root, "A");
		FakeTargetRegisterBank fakeA1rb = new FakeTargetRegisterBank(model, fakeA, "[1]");
		fakeA1rb.listeners.fire.registersUpdated(fakeA1rb, Map.of());
		fakeA.setElements(List.of(fakeA1rb), "Init");
		model.root.setAttributes(List.of(fakeA), Map.of(), "Init");

		waitOn(model.flushEvents());

		assertEquals(List.of(
			new ImmutablePair<>("created", fakeA),
			new ImmutablePair<>("created", fakeA1rb),
			new ImmutablePair<>("registersUpdated", fakeA1rb),
			new ImmutablePair<>("addedElem", fakeA1rb),
			new ImmutablePair<>("addedAttr", fakeA)),
			listener.record);
	}

	@Test
	public void testAddListenerWithReplay() throws Throwable {

		FakeTargetObject fakeA = new FakeTargetObject(model, model.root, "A");
		FakeTargetRegisterBank fakeA1rb = new FakeTargetRegisterBank(model, fakeA, "[1]");
		fakeA1rb.listeners.fire.registersUpdated(fakeA1rb, Map.of());
		fakeA.setElements(List.of(fakeA1rb), "Init");
		model.root.setAttributes(List.of(fakeA), Map.of(), "Init");
		EventRecordingListener listener = new EventRecordingListener();
		model.addModelListener(listener, true);

		waitOn(model.flushEvents());

		assertEquals(List.of(
			new ImmutablePair<>("created", model.root),
			new ImmutablePair<>("created", fakeA),
			new ImmutablePair<>("created", fakeA1rb),
			new ImmutablePair<>("addedElem", fakeA1rb),
			new ImmutablePair<>("addedAttr", fakeA),
			new ImmutablePair<>("rootAdded", model.root)),
			listener.record);
	}
}
