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
package ghidra.util.task;

import static org.junit.Assert.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.SystemUtilities;

public class SwingUpdateManagerTest extends AbstractGenericTest {
	private static final int MIN_DELAY = 500;
	private static final int MAX_DELAY = 1000;
	private volatile int runnableCalled;
	private SwingUpdateManager manager;

	@Before
	public void setUp() throws Exception {
		manager = createUpdateManager(MIN_DELAY, MAX_DELAY);

		// must turn this on to get the expected results, as in headless mode the update manager
		// will run it's Swing work immediately on the test thread, which is not true to the
		// default behavior
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, Boolean.FALSE.toString());
	}

	@Test
	public void testOneCallForOneUpdate() {
		manager.update();
		waitForManager();
		assertEquals("Expected only 1 callback", 1, runnableCalled);
	}

	@Test
	public void testOneCallFromUpdateNow() {
		manager.updateNow();
		waitForManager();
		assertEquals("Expected only 1 callback", 1, runnableCalled);
	}

	@Test
	public void testOneCallForUpdateLater() {
		manager.updateLater();
		waitForManager();
		assertEquals("Expected only 1 callback", 1, runnableCalled);
	}

	@Test
	public void testTwoCallForMultipleFastUpdateCalls() {
		for (int i = 0; i < 10; i++) {
			manager.update();
			sleep(10);
		}
		waitForManager();
		assertEquals("Expected 2 callbacks", 2, runnableCalled);
	}

	@Test
	public void testMaxTimeout() {

		//
		// Hard Test!: Many timing-sensitive factors are at play here: this thread and it's
		//             run and sleep scheduling; the Swing thread and its scheduling and the
		//             Swing timer's scheduling.  Thus, making a simple AND reliable test is
		//             nearly impossible.  So, we test here the basic max timeout mechanism.
		//
		//             The loop below calls update many times.  The first call to update always
		//             triggers an immediate update.  Each successive call, as long as it is
		//             faster than *min delay* will trigger an update to be buffered, to be
		//             delayed.  This delay gets reset upon each update call until the *max delay*
		//             time has been passed.
		//

		int sleepyTime = 5;
		int maxDelay = 600;
		manager = createUpdateManager(200, maxDelay);

		for (int i = 0; i < 4; i++) {
			manager.update();
			sleep(sleepyTime);
		}

		assertEquals("Expected 1 max delay callback", 1, runnableCalled);

		waitForManager();
		assertEquals("Expected one immediate callback and one max delay callback (2 total)", 2,
			runnableCalled);
	}

	@Test
	public void testFlush() {
		manager.flush();
		waitForSwing();
		assertFalse(manager.isBusy());
		assertEquals("Did not expect the callback after stop()", 0, runnableCalled);

		manager.updateLater();
		manager.flush();
		waitForManager();
		assertEquals("Expected only 1 callback", 1, runnableCalled);
	}

	@Test
	public void testStop() {
		manager.updateLater();
		manager.stop();
		waitForSwing();
		assertTrue(!manager.isBusy());
		assertEquals("Did not expect the callback after stop()", 0, runnableCalled);

		//
		// Make sure we can use again
		//
		runnableCalled = 0;
		manager.update();
		waitForManager();
		assertEquals("Expected only 1 callback", 1, runnableCalled);
	}

	@Test
	public void testHasPendingUpdates() {
		manager.updateLater();
		assertTrue("Should have pending updates after calling update, but before the work" +
			"has been done", manager.hasPendingUpdates());
		waitForManager();
		assertEquals("Expected only 1 callback", 1, runnableCalled);
		assertFalse("Still have pending updates after performing work",
			manager.hasPendingUpdates());
	}

	@Test
	public void testDispose() {
		for (int i = 0; i < 10; i++) {
			manager.update();
			sleep(1);
		}
		assertTrue(manager.hasPendingUpdates());
		manager.dispose();
		assertFalse(manager.hasPendingUpdates());
		int called = runnableCalled;
		//
		// Cannot use again
		//
		manager.update();
		waitForManager();
		// make sure the callback did not occur.
		assertEquals(called, runnableCalled);
	}

	@Test
	public void testIsBusy() throws Exception {
		//
		// Another complicated test: we want to make sure that if we try to trigger an update
		// that isBusy() will return true, even if the update runnable has not yet been posted
		// to the Swing thread.
		//
		// To do this, we will need to block the Swing thread so that we know the request happens
		// before the update runnable is called.
		//

		CountDownLatch startLatch = new CountDownLatch(1);
		CountDownLatch endLatch = new CountDownLatch(1);
		AtomicBoolean exception = new AtomicBoolean();

		runSwing(new Runnable() {
			@Override
			public void run() {
				startLatch.countDown();
				try {
					endLatch.await(10, TimeUnit.SECONDS);
				}
				catch (InterruptedException e) {
					exception.set(true);
				}
			}
		}, false);

		// This will cause the swing thread to block until we countdown the end latch
		startLatch.await(10, TimeUnit.SECONDS);

		manager.update();
		assertTrue("Manager not busy after requesting an update", manager.isBusy());

		endLatch.countDown();

		waitForManager();
		assertTrue("Manager still busy after waiting for update", !manager.isBusy());

		assertFalse("Interrupted waiting for CountDowLatch", exception.get());
	}

	@Test
	public void testCallToUpdateWhileAnUpdateIsWorking() throws Exception {

		//
		// Test that an update call from a non-swing thread will still get processed if the
		// manager is actively processing an update on the swing thread.
		//

		CountDownLatch startLatch = new CountDownLatch(1);
		CountDownLatch endLatch = new CountDownLatch(1);
		AtomicBoolean exception = new AtomicBoolean();

		Runnable r = () -> {
			runnableCalled++;

			startLatch.countDown();
			try {
				endLatch.await(10, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				exception.set(true);
			}
		};

		// start the update manager and have it wait for us
		manager = new SwingUpdateManager(MIN_DELAY, MAX_DELAY, r);
		manager.update();

		// have the swing thread block until we countdown the end latch
		startLatch.await(10, TimeUnit.SECONDS);

		// post the second update request now that the manager is actively processing
		manager.update();

		// let the update manager finish; verify 2 work items total
		endLatch.countDown();
		waitForManager();
		assertEquals("Expected exactly 2 callbacks", 2, runnableCalled);
	}

	@Test
	public void testNotFiringTooOften() throws InterruptedException {
		Thread t = new Thread(() -> {
			for (int i = 0; i < 50; i++) {
				manager.update();
				manager.update();
				manager.update();
				manager.update();
				sleep(10);
			}
		});
		t.start();
		t.join();
		waitForManager();
		assertEquals(2, runnableCalled);
	}

//==================================================================================================
// Private Methods
//==================================================================================================
	private void waitForManager() {

		// let all swing updates finish, which may trigger the update manager
		waitForSwing();

		while (manager.isBusy()) {
			sleep(DEFAULT_WAIT_DELAY);
		}

		// let any resulting swing events finish
		waitForSwing();
	}

	private SwingUpdateManager createUpdateManager(int min, int max) {
		return new SwingUpdateManager(min, max, new Runnable() {

			@Override
			public void run() {
				runnableCalled++;
			}
		});
	}
}
