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
package ghidra.async;

import static org.junit.Assert.*;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;

import ghidra.util.Msg;

public class AsyncReferenceTest {
	@Test
	public void testListener() {
		AsyncReference<String, Integer> str = new AsyncReference<>();
		AtomicReference<String> got = new AtomicReference<>();
		AtomicInteger gotCause = new AtomicInteger();
		str.addChangeListener((old, val, cause) -> {
			got.set(val);
			gotCause.set(cause);
		});
		str.set("Hello", 1);
		assertEquals("Hello", got.get());
		assertEquals(1, gotCause.get());
		str.set("World", 2);
		assertEquals("World", got.get());
		assertEquals(2, gotCause.get());
	}

	@Test
	public void testWaitChanged() throws InterruptedException, ExecutionException {
		AsyncReference<String, Void> str = new AsyncReference<>();
		CompletableFuture<String> chg1 = str.waitChanged();
		CompletableFuture<String> chg2 = str.waitChanged();
		assertFalse(chg1.isDone());
		assertFalse(chg2.isDone());
		str.set("Hello", null);
		assertTrue(chg1.isDone());
		assertTrue(chg2.isDone());
		assertEquals("Hello", chg1.get());
		assertEquals("Hello", chg2.get());

		CompletableFuture<String> chg3 = str.waitChanged();
		assertFalse(chg3.isDone());
		str.set("World", null);
		assertTrue(chg3.isDone());
		assertEquals("World", chg3.get());
	}

	@Test
	public void testWaitValue() {
		AsyncReference<String, Void> str = new AsyncReference<>();
		CompletableFuture<Void> matchHello = str.waitValue("Hello");
		CompletableFuture<Void> matchWorld = str.waitValue("World");
		assertFalse(matchHello.isDone());
		assertFalse(matchWorld.isDone());
		assertEquals(matchHello, str.waitValue("Hello"));

		str.set("Hello", null);
		assertTrue(matchHello.isDone());
		assertFalse(matchWorld.isDone());
		assertTrue(str.waitValue("Hello").isDone());

		str.set("World", null);
		assertFalse(str.waitValue("Hello").isDone());
		assertTrue(matchWorld.isDone());
	}

	@Test
	public void testDebouncer() throws InterruptedException, ExecutionException, TimeoutException {
		AsyncDebouncer<Void> debouncer = new AsyncDebouncer<>(new AsyncTimer(), 100);
		long startTime = System.currentTimeMillis();
		CompletableFuture<Void> settled = debouncer.settled();
		debouncer.contact(null);
		settled.get(300, TimeUnit.MILLISECONDS);
		long endTime = System.currentTimeMillis();
		long duration = endTime - startTime;
		Msg.info(this, "duration: " + duration);
		assertTrue(duration >= 100);
	}

	@Test
	public void testDebouncedUnchanged() throws InterruptedException {
		AsyncReference<Integer, Void> orig = new AsyncReference<>(1);
		AsyncReference<Integer, Void> db = orig.debounced(new AsyncTimer(), 100);
		CompletableFuture<Integer> settled = db.waitChanged();
		orig.set(1, null);
		Thread.sleep(200);
		assertFalse(settled.isDone());
	}

	@Test
	public void testDebouncedSingleChange()
			throws InterruptedException, ExecutionException, TimeoutException {
		AsyncReference<Integer, Void> orig = new AsyncReference<>(1);
		AsyncReference<Integer, Void> db = orig.debounced(new AsyncTimer(), 100);
		CompletableFuture<Integer> settled = db.waitChanged();
		long startTime = System.currentTimeMillis();
		orig.set(2, null);
		int s = settled.get(300, TimeUnit.MILLISECONDS);
		long endTime = System.currentTimeMillis();
		assertEquals(2, s);
		long duration = endTime - startTime;
		Msg.info(this, "duration: " + duration);
		assertTrue(duration >= 100);
	}

	@Test
	public void testDebouncedChangedBack() throws InterruptedException {
		AsyncReference<Integer, Void> orig = new AsyncReference<>(1);
		AsyncReference<Integer, Void> db = orig.debounced(new AsyncTimer(), 100);
		CompletableFuture<Integer> settled = db.waitChanged();
		orig.set(2, null);
		orig.set(1, null);
		Thread.sleep(200);
		assertFalse(settled.isDone());
	}

	@Test
	public void testManyChanges()
			throws InterruptedException, ExecutionException, TimeoutException {
		AsyncReference<Integer, String> orig = new AsyncReference<>(1);
		AsyncReference<Integer, String> db = orig.debounced(new AsyncTimer(), 100);
		CompletableFuture<Integer> settledVal = new CompletableFuture<>();
		CompletableFuture<String> settledCause = new CompletableFuture<>();
		db.addChangeListener((old, val, cause) -> {
			assertTrue(settledVal.complete(val));
			assertTrue(settledCause.complete(cause));
		});
		long startTime = System.currentTimeMillis();
		orig.set(2, "First");
		Thread.sleep(50);
		orig.set(4, "Second");
		Thread.sleep(50);
		orig.set(3, "Third");
		Thread.sleep(50);
		orig.set(4, "Fourth");
		int s = settledVal.get(300, TimeUnit.MILLISECONDS);
		long endTime = System.currentTimeMillis();
		assertEquals(4, s);
		long duration = endTime - startTime;
		Msg.info(this, "duration: " + duration);
		assertTrue(duration >= 250);
		assertEquals("Fourth", settledCause.get());
	}
}
