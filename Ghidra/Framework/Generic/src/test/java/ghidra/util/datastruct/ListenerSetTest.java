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
package ghidra.util.datastruct;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import generic.json.Json;
import generic.test.AbstractGTest;
import ghidra.util.*;
import ghidra.util.exception.AssertException;

public class ListenerSetTest {

	@Test
	public void testListenerNotification() {

		ListenerSet<DummyListener> listeners = new ListenerSet<>(DummyListener.class, true);

		SpyDummyListener spy = new SpyDummyListener();
		listeners.add(spy);

		String event = "Event";
		listeners.invoke().workDone(event);

		assertEquals(1, spy.getEvents().size());
		assertEquals(event, spy.getEvents().get(0));
	}

	@Test
	public void testBehavesLikeSet() {
		ListenerSet<DummyListener> listeners = new ListenerSet<>(DummyListener.class, true);

		SpyDummyListener l1 = new SpyDummyListener();
		SpyDummyListener l2 = new SpyDummyListener();

		listeners.add(l1);
		listeners.add(l2);

		listeners.invoke().workDone("EventA");
		assertEquals(1, l1.getEvents().size());
		assertEquals(1, l2.getEvents().size());

		listeners.add(l1); // This had better not double fire

		listeners.invoke().workDone("EventB");
		assertEquals(2, l1.getEvents().size());
		assertEquals(2, l2.getEvents().size());
	}

	@Test
	public void testContinuesOnError() {

		// disable the default error reporting to avoid polluting the console
		Msg.setErrorLogger(new SpyErrorLogger());
		Msg.setErrorDisplay(new SpyErrorDisplay());

		ListenerSet<DummyListener> listeners = new ListenerSet<>(DummyListener.class, true);

		SpyDummyListener l1 = new SpyDummyListener() {
			@Override
			public void workDone(String e) {
				super.workDone(e);
				throw new RuntimeException("It had better continue (1)");
			}
		};

		listeners.add(l1);

		SpyDummyListener l2 = new SpyDummyListener() {
			@Override
			public void workDone(String e) {
				super.workDone(e);
				throw new RuntimeException("It had better continue (2)");
			}
		};

		listeners.add(l2);

		listeners.invoke().workDone("Should see on both");
		assertEquals("Should see on both", l1.getEvents().get(0));
		assertEquals("Should see on both", l2.getEvents().get(0));
	}

	@Test
	public void testWeaklyReferencesListeners() {
		ListenerSet<DummyListener> listeners = new ListenerSet<>(DummyListener.class, true);

		SpyDummyListener l1 = new SpyDummyListener();
		listeners.add(l1);

		listeners.invoke().workDone("EventA");
		assertEquals("EventA", l1.get());

		l1 = null; // Trash the only strong reference

		AbstractGTest.waitForCondition(() -> {
			System.gc();
			return listeners.size() == 0;
		});
	}

	@Test
	public void testAddWhileNotifying() throws Exception {

		//
		// Test that any listeners added while notifying will not be notified and will not cause
		// exceptions.
		//

		ListenerSet<DummyListener> listeners = new ListenerSet<>(DummyListener.class, true);
		SpyErrorHandler spyErrorHandler = new SpyErrorHandler();
		listeners.setErrorHandler(spyErrorHandler);

		int n = 5;
		List<SpyDummyListener> originalListeners = createLatchedListeners(n);
		for (SpyDummyListener l : originalListeners) {
			listeners.add(l);
		}

		// notify in another thread to not block the test thread
		String event = "Event";
		Thread notifyThread = new Thread(() -> {
			listeners.invoke().workDone(event);
		});
		notifyThread.start();

		List<SpyDummyListener> newListeners = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			LatchedSpyListener blockedListener = AbstractGTest.waitFor(() -> activeListener);
			activeListener = null;

			// wait to ensure the listeners are being notified; mutate the listener list; tell the
			// listener being notified to continue;
			blockedListener.waitForStart();
			SpyDummyListener l = new SpyDummyListener();
			newListeners.add(l);
			listeners.add(l);
			blockedListener.proceed();
		}

		notifyThread.join(2000);

		for (SpyDummyListener l : originalListeners) {
			assertEquals(event, l.get());
		}

		for (SpyDummyListener newListener : newListeners) {
			assertTrue(newListener.getEvents().isEmpty());
		}
		assertNull(spyErrorHandler.getException());
	}

	@Test
	public void testRemoveWhileNotifying() throws Exception {

		//
		// Test that any listeners removed while notifying will are still notified and will not
		// cause exceptions.
		//

		ListenerSet<DummyListener> listeners = new ListenerSet<>(DummyListener.class, true);
		SpyErrorHandler spyErrorHandler = new SpyErrorHandler();
		listeners.setErrorHandler(spyErrorHandler);

		int n = 5;
		List<SpyDummyListener> originalListeners = createLatchedListeners(n);
		for (SpyDummyListener l : originalListeners) {
			listeners.add(l);
		}

		// notify in another thread to not block the test thread
		String event = "Event";
		Thread notifyThread = new Thread(() -> {
			listeners.invoke().workDone(event);
		});
		notifyThread.start();

		for (int i = 0; i < n; i++) {
			LatchedSpyListener blockedListener = AbstractGTest.waitFor(() -> activeListener);
			activeListener = null;

			// wait to ensure the listeners are being notified; mutate the listener list; tell the
			// listener being notified to continue;
			blockedListener.waitForStart();
			listeners.remove(blockedListener);
			blockedListener.proceed();
		}

		notifyThread.join(2000);

		for (SpyDummyListener l : originalListeners) {
			assertEquals(event, l.get());
		}
		assertNull(spyErrorHandler.getException());
	}

	@Test
	public void testErrorReporting() {

		ListenerSet<DummyListener> listeners = new ListenerSet<>(DummyListener.class, true);
		SpyErrorHandler spyErrorHandler = new SpyErrorHandler();
		listeners.setErrorHandler(spyErrorHandler);

		listeners.add(new ExceptionalDummyListener());

		String event = "Event";
		listeners.invoke().workDone(event);

		assertNotNull(spyErrorHandler.getException());
	}

//=================================================================================================
// Thread-based Test Code
//=================================================================================================

	// variables only used by the thread-based tests
	private Throwable notificationException;
	private LatchedSpyListener activeListener;

	private List<SpyDummyListener> createLatchedListeners(int n) {
		List<SpyDummyListener> list = new ArrayList<>();
		for (int i = 0; i < n; i++) {
			list.add(new LatchedSpyListener());
		}
		return list;
	}

	private class LatchedSpyListener extends SpyDummyListener {

		private CountDownLatch startedLatch = new CountDownLatch(1);
		private CountDownLatch proceedLatch = new CountDownLatch(1);

		void proceed() {
			proceedLatch.countDown();
		}

		void waitForStart() throws InterruptedException {
			assertTrue("Timed-out waiting for event notification",
				startedLatch.await(2, TimeUnit.SECONDS));
		}

		@Override
		public void workDone(String e) {

			activeListener = this;

			if (notificationException != null) {
				return; // stop processing if the test fails
			}

			startedLatch.countDown();
			super.workDone(e);
			try {
				if (!proceedLatch.await(2, TimeUnit.SECONDS)) {
					notificationException =
						new AssertException("Failed waiting to proceed in listener notificaiton");
				}
			}
			catch (InterruptedException e1) {
				notificationException =
					new AssertException("Interrupted waiting to proceed in listener notification");
			}
		}
	}

//=================================================================================================
// Dummy Listener
//=================================================================================================

	public interface DummyListener {
		void workDone(String e);
	}

	private int id = 0;

	private class SpyDummyListener implements DummyListener {

		private List<String> events = new ArrayList<>();
		@SuppressWarnings("unused") // used by toString()
		private String name;

		SpyDummyListener() {
			name = "Spy " + ++id;
		}

		@Override
		public void workDone(String e) {
			events.add(e);
		}

		String get() {
			if (events.isEmpty()) {
				return null;
			}
			return events.get(0);
		}

		List<String> getEvents() {
			return events;
		}

		@Override
		public String toString() {
			return Json.toString(this);
		}
	}

//=================================================================================================
// Inner Classes
//=================================================================================================

	private class ExceptionalDummyListener implements DummyListener {
		@Override
		public void workDone(String e) {
			throw new RuntimeException("Fail!");
		}
	}

	private class SpyErrorHandler implements ListenerErrorHandler {

		private Throwable exception;

		@Override
		public void handleError(Object listener, Throwable t) {
			if (exception == null) {
				exception = t;
			}
		}

		Throwable getException() {
			return exception;
		}
	}

}
