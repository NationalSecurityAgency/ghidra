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
package ghidra.dbg.testutil;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import ghidra.async.*;
import ghidra.dbg.*;
import ghidra.dbg.DebugModelConventions.AsyncAccess;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.test.AbstractDebuggerModelTest;
import ghidra.dbg.test.AbstractDebuggerModelTest.DebuggerTestSpecimen;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.util.NumericUtilities;

public interface DebuggerModelTestUtils extends AsyncTestUtils {

	default byte[] arr(String hex) {
		return NumericUtilities.convertStringToBytes(hex);
	}

	/**
	 * Performs the cast, after verifying the schema, too
	 * 
	 * @param <T> the type of the object
	 * @param type the class of the object
	 * @param obj the object to cast
	 * @return the same object
	 */
	default <T extends TargetObject> T cast(Class<T> type, TargetObject obj) {
		assertTrue(obj.getSchema().getInterfaces().contains(type));
		return type.cast(obj);
	}

	default <T extends TargetObject> T ancestor(Class<T> type, TargetObject seed) throws Throwable {
		return DebugModelConventions.ancestor(type, seed);
	}

	default AsyncAccess access(TargetObject obj) throws Throwable {
		return new AsyncAccess(
			ancestor(TargetAccessConditioned.class, Objects.requireNonNull(obj)));
	}

	default void waitAcc(TargetObject obj) throws Throwable {
		AsyncAccess acc = access(obj);
		waitAcc(acc);
		acc.dispose();
	}

	default void waitAcc(AsyncReference<Boolean, ?> access) throws Throwable {
		waitOn(access.waitValue(true));
	}

	default void cli(TargetObject interpreter, String cmd) throws Throwable {
		TargetInterpreter as = interpreter.as(TargetInterpreter.class);
		waitOn(as.execute(cmd));
	}

	default String captureCli(TargetObject interpreter, String cmd) throws Throwable {
		TargetInterpreter as = interpreter.as(TargetInterpreter.class);
		return waitOn(as.executeCapture(cmd));
	}

	default void launch(TargetObject launcher, Map<String, ?> args) throws Throwable {
		TargetLauncher as = launcher.as(TargetLauncher.class);
		waitOn(as.launch(args));
	}

	default void resume(TargetObject resumable) throws Throwable {
		TargetResumable as = resumable.as(TargetResumable.class);
		waitOn(as.resume());
	}

	default void step(TargetObject steppable, TargetStepKind kind) throws Throwable {
		TargetSteppable as = steppable.as(TargetSteppable.class);
		waitOn(as.step(kind));
	}

	default TargetObject getFocus(TargetObject scope) {
		TargetFocusScope as = scope.as(TargetFocusScope.class);
		return as.getFocus();
	}

	default void focus(TargetObject scope, TargetObject focus) throws Throwable {
		TargetFocusScope as = scope.as(TargetFocusScope.class);
		waitOn(as.requestFocus(focus));
	}

	static Map<String, String> hexlify(Map<String, byte[]> map) {
		return map.entrySet()
				.stream()
				.collect(Collectors.toMap(Entry::getKey,
					e -> NumericUtilities.convertBytesToString(e.getValue())));
	}

	/**
	 * Assert that there is a single reference with shortest path, and get it
	 * 
	 * @param <T> the type of object reference
	 * @param refs the map of paths to references, <em>sorted shortest-key-first</em>
	 * @return the value of the entry with shortest key
	 */
	default <T> T assertUniqueShortest(NavigableMap<List<String>, T> refs) {
		assertTrue(refs.size() >= 1);
		Iterator<Entry<List<String>, T>> rit = refs.entrySet().iterator();
		Entry<List<String>, T> shortest = rit.next();
		if (!rit.hasNext()) {
			return shortest.getValue();
		}
		Entry<List<String>, T> next = rit.next();
		assertTrue("Shortest is not unique: " + refs,
			next.getKey().size() > shortest.getKey().size());

		return shortest.getValue();
	}

	default TargetAttachable getAttachable(Collection<? extends TargetAttachable> attachables,
			DebuggerTestSpecimen specimen, DummyProc dummy, AbstractDebuggerModelTest test) {
		return attachables.stream().filter(a -> {
			try {
				return specimen.isAttachable(dummy, a, test);
			}
			catch (Throwable e) {
				throw new AssertionError(e);
			}
		}).findFirst().orElse(null);
	}

	default TargetProcess getProcessRunning(Collection<? extends TargetProcess> processes,
			DebuggerTestSpecimen specimen, AbstractDebuggerModelTest test) {
		return getProcessRunning(processes, specimen, test, p -> true);
	}

	default TargetProcess getProcessRunning(Collection<? extends TargetProcess> processes,
			DebuggerTestSpecimen specimen, AbstractDebuggerModelTest test,
			Predicate<TargetProcess> predicate) {
		return processes.stream().filter(p -> {
			try {
				return predicate.test(p) && specimen.isRunningIn(p, test);
			}
			catch (Throwable e) {
				throw new AssertionError(e);
			}
		}).findFirst().orElse(null);
	}

	default Collection<TargetProcess> fetchProcesses(AbstractDebuggerModelTest test)
			throws Throwable {
		return test.m.findAll(TargetProcess.class, PathUtils.parse(""), false).values();
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	default Collection<TargetAttachable> fetchAttachables(TargetObject container)
			throws Throwable {
		return (Collection) waitOn(container.fetchElements(true)).values();
	}

	default TargetProcess getProcessRunning(DebuggerTestSpecimen specimen,
			AbstractDebuggerModelTest test) throws Throwable {
		return getProcessRunning(specimen, test, p -> true);
	}

	default TargetProcess getProcessRunning(DebuggerTestSpecimen specimen,
			AbstractDebuggerModelTest test, Predicate<TargetProcess> predicate) throws Throwable {
		return getProcessRunning(fetchProcesses(test), specimen, test, predicate);
	}

	default TargetProcess retryForProcessRunning(
			DebuggerTestSpecimen specimen, AbstractDebuggerModelTest test) throws Throwable {
		return retry(() -> {
			TargetProcess process = getProcessRunning(specimen, test);
			assertNotNull(process);
			return process;
		}, List.of(AssertionError.class));
	}

	default TargetProcess retryForOtherProcessRunning(DebuggerTestSpecimen specimen,
			AbstractDebuggerModelTest test, Predicate<TargetProcess> predicate, long timeoutMs)
			throws Throwable {
		return retry(timeoutMs, () -> {
			TargetProcess process = getProcessRunning(specimen, test, predicate);
			assertNotNull(process);
			return process;
		}, List.of(AssertionError.class));
	}

	default void waitSettled(DebuggerObjectModel model, int ms) throws Throwable {
		AsyncDebouncer<Void> debouncer = new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, ms);
		var listener = new DebuggerModelListener() {
			@Override
			public void attributesChanged(TargetObject object, Collection<String> removed,
					Map<String, ?> added) {
				debouncer.contact(null);
			}

			@Override
			public void breakpointHit(TargetObject container, TargetObject trapped,
					TargetStackFrame frame, TargetBreakpointSpec spec,
					TargetBreakpointLocation breakpoint) {
				debouncer.contact(null);
			}

			@Override
			public void consoleOutput(TargetObject console, Channel channel, byte[] data) {
				debouncer.contact(null);
			}

			@Override
			public void created(TargetObject object) {
				debouncer.contact(null);
			}

			@Override
			public void elementsChanged(TargetObject object, Collection<String> removed,
					Map<String, ? extends TargetObject> added) {
				debouncer.contact(null);
			}

			@Override
			public void event(TargetObject object, TargetThread eventThread, TargetEventType type,
					String description, List<Object> parameters) {
				debouncer.contact(null);
			}

			@Override
			public void invalidateCacheRequested(TargetObject object) {
				debouncer.contact(null);
			}

			@Override
			public void invalidated(TargetObject object, TargetObject branch, String reason) {
				debouncer.contact(null);
			}

			@Override
			public void memoryReadError(TargetObject memory, AddressRange range,
					DebuggerMemoryAccessException e) {
				debouncer.contact(null);
			}

			@Override
			public void memoryUpdated(TargetObject memory, Address address, byte[] data) {
				debouncer.contact(null);
			}

			@Override
			public void registersUpdated(TargetObject bank, Map<String, byte[]> updates) {
				debouncer.contact(null);
			}

			@Override
			public void rootAdded(TargetObject root) {
				debouncer.contact(null);
			}
		};
		model.addModelListener(listener);
		debouncer.contact(null);
		waitOnNoValidate(debouncer.settled());
	}
}
