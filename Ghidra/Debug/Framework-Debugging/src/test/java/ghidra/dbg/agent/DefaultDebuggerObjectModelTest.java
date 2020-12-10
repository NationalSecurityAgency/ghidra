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

import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

import org.junit.Test;

import generic.Unique;
import ghidra.async.AsyncUtils;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.*;
import ghidra.dbg.util.AttributesChangedListener.AttributesChangedInvocation;
import ghidra.dbg.util.ElementsChangedListener.ElementsChangedInvocation;
import ghidra.dbg.util.InvalidatedListener.InvalidatedInvocation;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.SystemUtilities;

public class DefaultDebuggerObjectModelTest {
	static final long TIMEOUT_MILLISECONDS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	public static class FakeTargetObject extends DefaultTargetObject<TargetObject, TargetObject> {
		public FakeTargetObject(DebuggerObjectModel model, TargetObject parent, String name) {
			super(model, parent, name, "Fake");
		}
	}

	/**
	 * Functionally identical to a Fake, but intrinsically different
	 */
	public static class PhonyTargetObject extends DefaultTargetObject<TargetObject, TargetObject> {
		public PhonyTargetObject(DebuggerObjectModel model, TargetObject parent, String name) {
			super(model, parent, name, "Phony");
		}
	}

	public static class FakeDebuggerObjectModel extends AbstractDebuggerObjectModel {
		DefaultTargetModelRoot root = new DefaultTargetModelRoot(this, "Root");

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

		@Override
		public CompletableFuture<Void> close() {
			return AsyncUtils.NIL;
		}
	}

	static class OffThreadTargetObject extends DefaultTargetObject<TargetObject, TargetObject> {
		public OffThreadTargetObject(DebuggerObjectModel model, TargetObject parent, String name,
				String typeHint) {
			super(model, parent, name, typeHint);
		}

		@Override
		public CompletableFuture<TargetObject> fetchElement(String name) {
			return CompletableFuture.supplyAsync(() -> null)
					.thenCompose(v -> super.fetchElement(name));
		}
	}

	protected static <T> T waitOn(CompletableFuture<T> future) throws Throwable {
		try {
			return future.get(TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
		}
		catch (ExecutionException e) {
			throw e.getCause();
		}
	}

	FakeDebuggerObjectModel model = new FakeDebuggerObjectModel();

	@Test
	public void testGetModelObjectLen0() throws Throwable {
		assertEquals(model.root, waitOn(model.fetchModelObject()));
	}

	@Test
	public void testGetModelObjectLen1() throws Throwable {
		FakeTargetObject a = new FakeTargetObject(model, model.root, "A");
		model.root.changeAttributes(List.of(), Map.of("A", a), "Test");

		assertEquals(a, waitOn(model.fetchModelObject("A")));
	}

	@Test
	public void testGetModelObjectLen1NoExist() throws Throwable {
		FakeTargetObject a = new FakeTargetObject(model, model.root, "A");
		model.root.changeAttributes(List.of(), Map.of("A", a), "Test");

		assertEquals(null, waitOn(model.fetchModelObject("NoA")));
	}

	@Test
	public void testGetModelObjectLen2() throws Throwable {
		FakeTargetObject a = new FakeTargetObject(model, model.root, "A");
		model.root.changeAttributes(List.of(), Map.of("A", a), "Test");

		FakeTargetObject b = new FakeTargetObject(model, a, "[B]");
		a.changeElements(List.of(), List.of(b), "Test");

		assertEquals(b, waitOn(model.fetchModelObject("A", "[B]")));
	}

	@Test
	public void testGetModelObjectLen2NoExist() throws Throwable {
		FakeTargetObject a = new FakeTargetObject(model, model.root, "A");
		model.root.changeAttributes(List.of(), Map.of("A", a), "Test");

		FakeTargetObject b = new FakeTargetObject(model, a, "[B]");
		a.changeElements(List.of(), List.of(b), "Test");

		assertEquals(null, waitOn(model.fetchModelObject("NoA", "[B]")));
		assertEquals(null, waitOn(model.fetchModelObject("NoA", "[NoB]")));
		assertEquals(null, waitOn(model.fetchModelObject("A", "[NoB]")));
	}

	@Test
	public void testElementReplacement() throws Throwable {
		ElementsChangedListener elemL = new ElementsChangedListener();
		InvalidatedListener invL = new InvalidatedListener();

		FakeTargetObject fakeA = new FakeTargetObject(model, model.root, "[A]");
		model.root.setElements(List.of(fakeA), "Init");

		model.root.addListener(elemL);
		fakeA.addListener(invL);

		PhonyTargetObject phonyA = new PhonyTargetObject(model, model.root, "[A]");
		model.root.setElements(List.of(phonyA), "Replace");

		assertSame(phonyA, waitOn(model.fetchModelObject("[A]")));
		assertFalse(fakeA.isValid());

		ElementsChangedInvocation changed = Unique.assertOne(elemL.invocations);
		assertSame(model.root, changed.parent);
		assertSame(phonyA, Unique.assertOne(changed.added.values()));

		InvalidatedInvocation invalidated = Unique.assertOne(invL.invocations);
		assertSame(fakeA, invalidated.object);
		assertEquals("Replace", invalidated.reason);
	}

	@Test
	public void testAttributeReplacement() throws Throwable {
		AttributesChangedListener attrL = new AttributesChangedListener();
		InvalidatedListener invL = new InvalidatedListener();

		FakeTargetObject fakeA = new FakeTargetObject(model, model.root, "A");
		model.root.setAttributes(Map.of("A", fakeA), "Init");

		model.root.addListener(attrL);
		fakeA.addListener(invL);

		PhonyTargetObject phonyA = new PhonyTargetObject(model, model.root, "A");
		model.root.setAttributes(Map.of("A", phonyA), "Replace");

		// Object-valued attribute replacement requires prior removal 
		assertSame(fakeA, waitOn(model.fetchModelObject("A")));
		assertEquals(0, attrL.invocations.size());
		assertEquals(0, invL.invocations.size());

		// Now, with prior removal
		// TODO: Should I permit custom equality check?
		model.root.setAttributes(Map.of(), "Clear");
		model.root.setAttributes(Map.of("A", phonyA), "Replace");

		assertEquals(2, attrL.invocations.size());
		AttributesChangedInvocation changed = attrL.invocations.get(0);
		assertEquals(model.root, changed.parent);
		assertSame("A", Unique.assertOne(changed.removed));
		assertEquals(0, changed.added.size());
		changed = attrL.invocations.get(1);
		assertEquals(model.root, changed.parent);
		assertSame(phonyA, Unique.assertOne(changed.added.values()));
		assertEquals(0, changed.removed.size());

		InvalidatedInvocation invalidated = Unique.assertOne(invL.invocations);
		assertSame(fakeA, invalidated.object);
		assertEquals("Clear", invalidated.reason);
	}

	@Test
	public void testInvalidation() throws Throwable {
		InvalidatedListener invL = new InvalidatedListener();

		FakeTargetObject fakeA = new FakeTargetObject(model, model.root, "A");
		model.root.setAttributes(Map.of("A", fakeA), "Init");

		FakeTargetObject fakeA1 = new FakeTargetObject(model, fakeA, "[1]");
		FakeTargetObject fakeA2 = new FakeTargetObject(model, fakeA, "[2]");
		fakeA.setElements(List.of(fakeA1, fakeA2), "Init");

		fakeA.addListener(invL);
		fakeA1.addListener(invL);
		fakeA2.addListener(invL);

		model.root.setAttributes(Map.of(), "Clear");

		waitOn(invL.count.waitValue(3));
	}
}
