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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeNotNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.junit.Test;

import ghidra.async.AsyncDebouncer;
import ghidra.async.AsyncTimer;
import ghidra.dbg.DebugModelConventions.AsyncState;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMemory;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.TargetSteppable;
import ghidra.dbg.target.TargetThread;
import ghidra.util.Msg;

/**
 * Tests the functionality of a single-stepping a target
 * 
 * <p>
 * Note that multiple sub-cases of this test can be generated in order to test each steppable object
 * in the model. Take care when selecting which object (usually a thread) to put under test. If, for
 * example, the selected thread is performing a blocking system call, then the tests will almost
 * certainly time out.
 */
public abstract class AbstractDebuggerModelSteppableTest extends AbstractDebuggerModelTest
		implements RequiresTarget {

	/**
	 * Get the expected (absolute) path of the steppable under test
	 * 
	 * @param threadPath the path of the target (usually a thread)
	 * @return the expected path, or {@code null} for no assertion
	 */
	public List<String> getExpectedSteppablePath(List<String> threadPath) {
		return null;
	}

	@Test
	public void testSteppableIsWhereExpected() throws Throwable {
		m.build();

		TargetObject target = maybeSubstituteThread(obtainTarget());
		List<String> expectedSteppablePath = getExpectedSteppablePath(target.getPath());
		assumeNotNull(expectedSteppablePath);

		TargetSteppable steppable = findSteppable(target.getPath());
		assertEquals(expectedSteppablePath, steppable.getPath());
	}

	/**
	 * An arbitrary number
	 * 
	 * <p>
	 * Should be enough to prove that stepping works consistently, but not so high that the test
	 * drags on. Definitely 2 or greater :)
	 * 
	 * @return the number of steps in the test
	 */
	protected int getStepCount() {
		return 5;
	}

	/**
	 * This just steps the target some number of times and verifies the execution state between
	 * 
	 * @throws Throwable if anything goes wrong
	 */
	@Test
	public void testStep() throws Throwable {
		m.build();

		TargetObject target = maybeSubstituteThread(obtainTarget());
		AsyncState state =
			new AsyncState(m.suitable(TargetExecutionStateful.class, target.getPath()));
		TargetSteppable steppable = findSteppable(target.getPath());
		for (int i = 0; i < getStepCount(); i++) {
			waitOn(steppable.step());
			TargetExecutionState st =
				waitOn(state.waitUntil(s -> s != TargetExecutionState.RUNNING));
			assertTrue("Target terminated while stepping", st.isAlive());
		}
	}

	// TODO: Test other kinds of steps
	// TODO: Test expected step kinds (or expected parameters)
	// TODO: Once there, use the generic method invocation style

	/**
	 * The window of silence necessary to assume no more callbacks will occur
	 * 
	 * @return the window in milliseconds
	 */
	protected long getDebounceWindowMs() {
		return 5000;
	}

	enum CallbackType {
		EVENT_RUNNING,
		EVENT_STOPPED,
		REGS_UPDATED,
		REGS_CACHE_INVALIDATED,
		MEM_CACHE_INVALIDATED;
	}

	/**
	 * Test event order for single stepping
	 * 
	 * <p>
	 * This tests that the {@link DebuggerModelListener#registersUpdated(TargetObject, Map)}
	 * callback occurs "last" following a step. While other callbacks may intervene, the order ought
	 * to be {@code event(RUNNING)}, {@code event(STOPPED)}, {@code registersUpdated()}. An
	 * {@code event()} cannot follow, as that would cause the snap to advance, making registers
	 * appear stale . Worse, if {@code registersUpdated} precedes {@code STOPPED}, the recorder will
	 * write values into the snap previous to the one it ought. This principle applies to all
	 * {@code event()}s, but is easiest to test for single-stepping. We also check that the
	 * registers (cached) are not invalidated after they are updated for the step. Note that
	 * {@code STOPPED} can be substituted for any event which implies the target is stopped.
	 * 
	 * @throws Throwable if anything goes wrong
	 */
	@Test
	public void testStepEventOrder() throws Throwable {
		m.build();

		var listener = new DebuggerModelListener() {
			List<CallbackType> callbacks = new ArrayList<>();
			List<String> log = new ArrayList<>();
			AsyncDebouncer<Void> debouncer =
				new AsyncDebouncer<Void>(AsyncTimer.DEFAULT_TIMER, getDebounceWindowMs());

			@Override
			public void event(TargetObject object, TargetThread eventThread, TargetEventType type,
					String description, List<Object> parameters) {
				synchronized (callbacks) {
					if (type == TargetEventType.RUNNING) {
						callbacks.add(CallbackType.EVENT_RUNNING);
					}
					else if (type.impliesStop) {
						callbacks.add(CallbackType.EVENT_STOPPED);
					}
					log.add("event(" + type + "): " + description);
				}
				debouncer.contact(null);
			}

			@Override
			public void registersUpdated(TargetObject bank, Map<String, byte[]> updates) {
				synchronized (callbacks) {
					callbacks.add(CallbackType.REGS_UPDATED);
					log.add("registersUpdated()");
				}
				debouncer.contact(null);
			}

			@Override
			public void invalidateCacheRequested(TargetObject object) {
				synchronized (callbacks) {
					if (object instanceof TargetRegisterBank) {
						callbacks.add(CallbackType.REGS_CACHE_INVALIDATED);
						log.add("invalidateCacheRequested(TargetRegisterBank)");
					}
					else if (object instanceof TargetMemory) {
						callbacks.add(CallbackType.MEM_CACHE_INVALIDATED);
						log.add("invalidateCacheRequested(TargetMemory)");
					}
				}
				debouncer.contact(null);
			}

			@Override
			public void attributesChanged(TargetObject object, Collection<String> removed,
					Map<String, ?> added) {
				debouncer.contact(null);
			}

			@Override
			public void elementsChanged(TargetObject object, Collection<String> removed,
					Map<String, ? extends TargetObject> added) {
				debouncer.contact(null);
			}
		};
		m.getModel().addModelListener(listener);

		CompletableFuture<Void> settledBefore = listener.debouncer.settled();
		TargetObject target = maybeSubstituteThread(obtainTarget());
		AsyncState state =
			new AsyncState(m.suitable(TargetExecutionStateful.class, target.getPath()));
		TargetSteppable steppable = findSteppable(target.getPath());
		waitOnNoValidate(settledBefore);
		synchronized (listener.callbacks) {
			listener.callbacks.clear();
			listener.log.add("CLEARED callbacks");
		}

		CompletableFuture<Void> settledAfter = listener.debouncer.settled();
		waitOn(steppable.step());
		TargetExecutionState st =
			waitOn(state.waitUntil(s -> s != TargetExecutionState.RUNNING));
		assertTrue("Target terminated while stepping", st.isAlive());
		waitOnNoValidate(settledAfter);

		List<CallbackType> callbacks;
		synchronized (listener.callbacks) {
			callbacks = List.copyOf(listener.callbacks);
		}

		Msg.info(this, "Observations: " + callbacks);
		
		boolean observedRunning = false;
		boolean observedStopped = false;
		boolean observedRegsUpdated = false;
		boolean observedInvalidateRegs = false;
		boolean observedInvalidateMem = false;
		for (CallbackType cb : callbacks) {
			switch (cb) {
				case EVENT_RUNNING:
					if (observedRunning) {
						fail("Observed a second event(RUNNING).");
					}
					observedRunning = true;
					break;
				case EVENT_STOPPED:
					if (observedStopped) {
						fail("Observed a second event(STOPPED).");
					}
					observedStopped = true;
					break;
				case REGS_UPDATED:
					if (!observedStopped) {
						fail("Observed registersUpdated() before event(STOPPED).");
					}
					observedRegsUpdated = true;
					break;
				case REGS_CACHE_INVALIDATED:
					if (!observedStopped) {
						if (observedRunning) {
							// Recorder will ignore, but it still counts for flushing model
							break;
						}
						/**
						 * Spurious cache invalidations are not permitted before the recorder would
						 * create a new snap. It knows to ignore invalidations that occur between
						 * event(RUNNING) and event(STOPPED).
						 */
						fail("Observed a spurious invalidateCacheRequested(Regs).");
					}
					else if (observedInvalidateRegs) {
						Msg.warn(this, 
							"Observed an extra invalidateCacheRequested(Regs) after event(STOPPED).");
					}
					else if (observedRegsUpdated) {
						// The invalidate would effectively undo the update
						fail("Observed invalidateCacheRequested(Regs) after registersUpdated().");
					}
					else {
						observedInvalidateRegs = true;
					}
					break;
				case MEM_CACHE_INVALIDATED:
					if (!observedStopped) {
						if (observedRunning) {
							// Recorder will ignore, but it still counts for flushing model
							observedInvalidateMem = true;
							break;
						}
						/**
						 * Spurious cache invalidations are not permitted before the recorder would
						 * create a new snap. It knows to ignore invalidations that occur between
						 * event(RUNNING) and event(STOPPED).
						 */
						fail("Observed a spurious invalidateCacheRequested(Mem).");
					}
					else if (observedInvalidateMem) {
						Msg.warn(this, 
							"Observed an extra invalidateCacheRequested(Mem) after event(STOPPED).");
					}
					else {
						observedInvalidateMem = true;
					}
					break;
				default:
					throw new AssertionError();
			}
		}

		if (!observedStopped) {
			fail("Never observed event(STOPPED).");
		}
		if (!observedRegsUpdated && !observedInvalidateRegs) {
			fail("Observed neither invalidateCacheRequested(Regs) nor registersUpdated().");
		}
		if (!observedInvalidateMem) {
			/**
			 * NOTE: even though STOPPED advances the snapshot, we still require
			 * invalidateCacheRequested(Mem) to ensure the model's memory cache is not stale.
			 * Whether or not your model employs an internal cache, this is required, because your
			 * model may be accessed via a proxy model (e.g., GADP) that uses a cache.
			 */
			fail("Never observed invalidateCacheRequested(Mem).");
		}
	}
}
