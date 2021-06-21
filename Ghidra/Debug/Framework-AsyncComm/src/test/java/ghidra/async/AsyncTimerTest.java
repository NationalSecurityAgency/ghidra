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

import static org.junit.Assert.assertTrue;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import ghidra.async.AsyncTimer;

public class AsyncTimerTest {
	@Test
	public void testMarkWait1000ms() throws Exception {
		AsyncTimer timer = new AsyncTimer();

		long start = System.currentTimeMillis();
		timer.mark().after(1000).get(5000, TimeUnit.MILLISECONDS);
		long diff = System.currentTimeMillis() - start;
		assertTrue(diff >= 1000);
		assertTrue(diff < 5000);
	}

	@Test
	public void testMarkWait1000Then2000ms() throws Exception {
		AsyncTimer timer = new AsyncTimer();

		long start = System.currentTimeMillis();
		long diff;
		AsyncTimer.Mark mark = timer.mark();
		mark.after(1000).get(5000, TimeUnit.MILLISECONDS);
		diff = System.currentTimeMillis() - start;
		assertTrue(diff >= 1000);
		assertTrue(diff < 2000);

		mark.after(2000).get(5000, TimeUnit.MILLISECONDS);
		diff = System.currentTimeMillis() - start;
		assertTrue(diff >= 2000);
		assertTrue(diff < 3000);
	}

	@Test
	public void testMarkWait1000ThenMarkWait1000ms() throws Exception {
		AsyncTimer timer = new AsyncTimer();

		long start = System.currentTimeMillis();
		long diff;
		timer.mark().after(1000).get(5000, TimeUnit.MILLISECONDS);
		diff = System.currentTimeMillis() - start;
		assertTrue(diff >= 1000);
		assertTrue(diff < 2000);

		timer.mark().after(1000).get(5000, TimeUnit.MILLISECONDS);
		diff = System.currentTimeMillis() - start;
		assertTrue(diff >= 2000);
		assertTrue(diff < 3000);
	}

	@Test
	public void testMarkWait1000And2000ms() throws Exception {
		AsyncTimer.Mark mark = new AsyncTimer().mark();
		long start = System.currentTimeMillis();

		CompletableFuture<Long> first = new CompletableFuture<>();
		CompletableFuture<Long> second = new CompletableFuture<>();
		mark.after(1000).thenAccept((v) -> first.complete(System.currentTimeMillis()));
		mark.after(2000).thenAccept((v) -> second.complete(System.currentTimeMillis()));
		first.get();
		second.get();
		long diff1 = first.get() - start;
		long diff2 = second.get() - start;

		assertTrue(diff1 >= 1000);
		assertTrue(diff1 < 2000);

		assertTrue(diff2 >= 2000);
		assertTrue(diff2 < 3000);
	}

	@Test
	public void testMarkWait2000And1000ms() throws Exception {
		AsyncTimer.Mark mark = new AsyncTimer().mark();
		long start = System.currentTimeMillis();

		CompletableFuture<Long> first = new CompletableFuture<>();
		CompletableFuture<Long> second = new CompletableFuture<>();
		mark.after(2000).thenAccept((v) -> first.complete(System.currentTimeMillis()));
		mark.after(1000).thenAccept((v) -> second.complete(System.currentTimeMillis()));
		first.get();
		second.get();
		long diff1 = first.get() - start;
		long diff2 = second.get() - start;

		assertTrue(diff1 >= 2000);
		assertTrue(diff1 < 3000);

		assertTrue(diff2 >= 1000);
		assertTrue(diff2 < 2000);
	}

	@Test
	public void testMarkWait2000And1000ThenCancel1000ms() throws Exception {
		AsyncTimer.Mark mark = new AsyncTimer().mark();
		long start = System.currentTimeMillis();

		CompletableFuture<Long> first = new CompletableFuture<>();
		mark.after(2000).thenAccept((v) -> first.complete(System.currentTimeMillis()));
		mark.after(1000).cancel(true);
		first.get();
		long diff = first.get() - start;

		assertTrue(diff >= 2000);
		assertTrue(diff < 3000);
	}

	@Test
	public void testMarkWait2000And2000ThenCancel2000ms() throws Exception {
		// The two timed futures should be treated separately, so the first must still complete
		AsyncTimer.Mark mark = new AsyncTimer().mark();
		long start = System.currentTimeMillis();

		CompletableFuture<Long> first = new CompletableFuture<>();
		mark.after(2000).thenAccept((v) -> first.complete(System.currentTimeMillis()));
		mark.after(2000).cancel(true);
		first.get();
		long diff = first.get() - start;

		assertTrue(diff >= 2000);
		assertTrue(diff < 3000);
	}

	@Test
	public void testScheduleInPast() throws Exception {
		AsyncTimer timer = new AsyncTimer();
		long start = System.currentTimeMillis();
		timer.atSystemTime(0).get(5000, TimeUnit.MILLISECONDS);
		long diff = System.currentTimeMillis() - start;
		assertTrue(diff < 100);
	}
}
