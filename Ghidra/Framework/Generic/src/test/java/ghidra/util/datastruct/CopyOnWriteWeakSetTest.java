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

import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.exception.AssertException;

public class CopyOnWriteWeakSetTest extends AbstractGenericTest {

	private List<Listener> listeners = new ArrayList<Listener>();

	public CopyOnWriteWeakSetTest() {
		super();
	}

@Test
    public void testIterationWithModification_Add() throws InterruptedException {

		final CountDownLatch finishedLatch = new CountDownLatch(1);
		final CopyOnWriteWeakSet<Listener> set = new CopyOnWriteWeakSet<Listener>();

		LatchListener latchListener = new LatchListener();

		for (int i = 0; i < 5; i++) {
			Listener listener = new Listener();
			listeners.add(listener); // non-weak storage
			set.add(listener);
		}

		listeners.add(latchListener);
		set.add(latchListener);

		for (int i = 0; i < 5; i++) {
			Listener listener = new Listener();
			listeners.add(listener); // non-weak storage
			set.add(listener);
		}

		final AtomicReference<Throwable> exception = new AtomicReference<Throwable>();
		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					for (Listener listener : set) {
						listener.doIt();
					}
				}
				catch (Throwable t) {
					exception.set(t);
				}
				finishedLatch.countDown();
			}
		}).start();

		latchListener.waitForStart();

		// now modify the set and make sure we don't ever explode
		Listener listener = new Listener();
		set.add(listener);

		latchListener.release();

		finishedLatch.await(5, TimeUnit.SECONDS);

		assertNull("Found exception while processing set: " + exception.get(), exception.get());
	}

@Test
    public void testIterationWithModification_Remove() throws InterruptedException {

		final CountDownLatch finishedLatch = new CountDownLatch(1);
		final CopyOnWriteWeakSet<Listener> set = new CopyOnWriteWeakSet<Listener>();

		Listener listener = null;
		LatchListener latchListener = new LatchListener();

		for (int i = 0; i < 5; i++) {
			listener = new Listener();
			listeners.add(listener); // non-weak storage
			set.add(listener);
		}

		listeners.add(latchListener);
		set.add(latchListener);

		for (int i = 0; i < 5; i++) {
			listener = new Listener();
			listeners.add(listener); // non-weak storage
			set.add(listener);
		}

		final AtomicReference<Throwable> exception = new AtomicReference<Throwable>();
		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					for (Listener l : set) {
						l.doIt();
					}
				}
				catch (Throwable t) {
					exception.set(t);
				}
				finishedLatch.countDown();
			}
		}).start();

		latchListener.waitForStart();

		// now modify the set and make sure we don't ever explode
		set.remove(listener);

		latchListener.release();

		finishedLatch.await(5, TimeUnit.SECONDS);

		assertNull("Found exception while processing set", exception.get());
	}

@Test
    public void testIterationWithModification_Clear() throws InterruptedException {

		final CountDownLatch finishedLatch = new CountDownLatch(1);
		final CopyOnWriteWeakSet<Listener> set = new CopyOnWriteWeakSet<Listener>();

		LatchListener latchListener = new LatchListener();

		for (int i = 0; i < 5; i++) {
			Listener listener = new Listener();
			listeners.add(listener); // non-weak storage
			set.add(listener);
		}

		listeners.add(latchListener);
		set.add(latchListener);

		for (int i = 0; i < 5; i++) {
			Listener listener = new Listener();
			listeners.add(listener); // non-weak storage
			set.add(listener);
		}

		final AtomicReference<Throwable> exception = new AtomicReference<Throwable>();
		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					for (Listener listener : set) {
						listener.doIt();
					}
				}
				catch (Throwable t) {
					exception.set(t);
				}
				finishedLatch.countDown();
			}
		}).start();

		latchListener.waitForStart();

		// now modify the set and make sure we don't ever explode
		set.clear();

		latchListener.release();

		finishedLatch.await(5, TimeUnit.SECONDS);

		assertNull("Found exception while processing set", exception.get());
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class Listener {
//		private int ID = instanceCount++;

		void doIt() {
//			if (!done) {
////				Msg.info(this, "Listener.sleep(): " + ID);
//				sleep(10);
//			}
		}
	}

	private class LatchListener extends Listener {

		private CountDownLatch startedLatch = new CountDownLatch(1);
		private CountDownLatch pauseLatch = new CountDownLatch(1);

		@Override
		void doIt() {

			startedLatch.countDown();

			try {
				pauseLatch.await(5, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				throw new AssertException(e);
			}
		}

		void waitForStart() {
			try {
				startedLatch.await(5, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				throw new AssertException(e);
			}
		}

		void release() {
			pauseLatch.countDown();
		}
	}
}
