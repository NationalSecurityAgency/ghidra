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
package ghidra.util;

import static org.junit.Assert.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class CountLatchTest extends AbstractGenericTest {

	public CountLatchTest() {
		super();
	}

	@Test
	public void testNoWaitInitially() throws InterruptedException {
		CountLatch countLatch = new CountLatch();
		assertTrue(countLatch.await(10, TimeUnit.MILLISECONDS));
	}

	@Test
	public void testWaitsWhenCountNotZero() throws InterruptedException {
		CountLatch countLatch = new CountLatch();
		countLatch.increment();
		assertFalse(countLatch.await(10, TimeUnit.MILLISECONDS));
	}

	@Test
	public void testNoWaitWhenCountIncrementedThenDecremented() throws InterruptedException {
		CountLatch countLatch = new CountLatch();
		countLatch.increment();
		countLatch.decrement();
		assertTrue(countLatch.await(10, TimeUnit.MILLISECONDS));
	}

	@Test
	public void testWaitsThenReturnsWhenCountDecremented() throws InterruptedException {
		final CountDownLatch startLatch = new CountDownLatch(1);
		final CountDownLatch doneLatch = new CountDownLatch(1);
		final CountLatch countLatch = new CountLatch();
		final AtomicBoolean b = new AtomicBoolean(false);
		countLatch.increment();
		Thread t = new Thread() {
			@Override
			public void run() {
				try {
					startLatch.await();
					if (countLatch.await(1000, TimeUnit.MILLISECONDS)) {
						b.set(true);
					}
				}
				catch (InterruptedException e) {
					e.printStackTrace();
				}
				finally {
					doneLatch.countDown();
				}
			}
		};
		t.start();
		startLatch.countDown();
		assertFalse(b.get());
		countLatch.decrement();
		doneLatch.await();
		assertTrue(b.get());
	}

}
