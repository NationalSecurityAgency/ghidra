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
package ghidra.dbg.memory;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import org.junit.Test;

import mockit.Expectations;
import mockit.Mocked;

public class CachedMemoryTest {

	class ReadRecord extends CompletableFuture<byte[]> {
		final long address;
		final int length;

		public ReadRecord(long address, int length) {
			this.address = address;
			this.length = length;
		}
	}

	class WriteRecord extends CompletableFuture<Void> {
		final long address;
		final byte[] data;

		public WriteRecord(long address, byte[] data) {
			this.address = address;
			this.data = data;
		}
	}

	class DummyMemory implements MemoryReader, MemoryWriter {
		final List<CompletableFuture<?>> record = new ArrayList<>();

		@Override
		public CompletableFuture<Void> writeMemory(long address, byte[] data) {
			return null;
		}

		@Override
		public CompletableFuture<byte[]> readMemory(long address, int length) {
			return new ReadRecord(address, length);
		}
	}

	interface MemoryReaderWriter extends MemoryReader, MemoryWriter {
		// Nothing new, just combined interfaces
	}

	@Mocked
	protected MemoryReaderWriter memory;

	byte[] inc(int len) {
		byte[] result = new byte[len];
		inc(result, 0, len, 0);
		return result;
	}

	void inc(byte[] arr, int off, int len, int start) {
		for (int i = 0; i < len; i++) {
			arr[off + i] = (byte) (i + start);
		}
	}

	@Test
	public void testSingleRead() throws Exception {
		final CompletableFuture<byte[]> raw = new CompletableFuture<>();
		new Expectations() {
			{
				memory.readMemory(1234, 90);
				result = raw;
			}
		};

		CachedMemory cache = new CachedMemory(memory, memory);
		CompletableFuture<byte[]> future = cache.readMemory(1234, 90);
		raw.complete(inc(90));
		byte[] arr = future.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(90), arr);
	}

	@Test
	public void testSingleReadCompletedEarly() throws Exception {
		new Expectations() {
			{
				memory.readMemory(1234, 90);
				result = CompletableFuture.completedFuture(inc(90));
			}
		};

		CachedMemory cache = new CachedMemory(memory, memory);
		CompletableFuture<byte[]> future = cache.readMemory(1234, 90);
		byte[] arr = future.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(90), arr);
	}

	@Test
	public void testOverlappingSequentialReads() throws Exception {
		final CompletableFuture<byte[]> firstRaw = new CompletableFuture<>();
		final CompletableFuture<byte[]> secondRaw = new CompletableFuture<>();
		new Expectations() {
			{
				memory.readMemory(1234, 100);
				result = firstRaw;
				memory.readMemory(1334, 50);
				result = secondRaw;
			}
		};

		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(1234, 100);
		firstRaw.complete(inc(100));
		byte[] firstArr = first.get(1000, TimeUnit.MILLISECONDS);

		CompletableFuture<byte[]> second = cache.readMemory(1284, 100);
		secondRaw.complete(inc(50));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(100), firstArr);

		byte[] dinc = new byte[100];
		inc(dinc, 0, 50, 50);
		inc(dinc, 50, 50, 0);
		assertArrayEquals(dinc, secondArr);
	}

	@Test
	public void testOverlappingParallelReads() throws Exception {
		final CompletableFuture<byte[]> firstRaw = new CompletableFuture<>();
		final CompletableFuture<byte[]> secondRaw = new CompletableFuture<>();
		new Expectations() {
			{
				memory.readMemory(1234, 100);
				result = firstRaw;
				memory.readMemory(1334, 50);
				result = secondRaw;
			}
		};

		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(1234, 100);
		CompletableFuture<byte[]> second = cache.readMemory(1284, 100);
		firstRaw.complete(inc(100));
		secondRaw.complete(inc(50));
		byte[] firstArr = first.get(1000, TimeUnit.MILLISECONDS);
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(100), firstArr);

		byte[] dinc = new byte[100];
		inc(dinc, 0, 50, 50);
		inc(dinc, 50, 50, 0);
		assertArrayEquals(dinc, secondArr);
	}

	@Test
	public void testSameStartsGrowingParallelReads() throws Exception {
		final CompletableFuture<byte[]> firstRaw = new CompletableFuture<>();
		final CompletableFuture<byte[]> secondRaw = new CompletableFuture<>();
		new Expectations() {
			{
				memory.readMemory(1234, 50);
				result = firstRaw;
				memory.readMemory(1284, 50);
				result = secondRaw;
			}
		};

		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(1234, 50);
		CompletableFuture<byte[]> second = cache.readMemory(1234, 100);

		assertFalse(first.isDone());
		firstRaw.complete(inc(50));
		byte[] firstArr = first.get(1000, TimeUnit.MILLISECONDS);

		assertFalse(second.isDone());
		secondRaw.complete(inc(50));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(50), firstArr);

		byte[] dinc = new byte[100];
		inc(dinc, 0, 50, 0);
		inc(dinc, 50, 50, 0);
		assertArrayEquals(dinc, secondArr);
	}

	@Test
	public void testLargeOffsetsParallelReads() throws Exception {
		final CompletableFuture<byte[]> firstRaw = new CompletableFuture<>();
		final CompletableFuture<byte[]> secondRaw = new CompletableFuture<>();
		new Expectations() {
			{
				memory.readMemory(0x8000000000000000L, 100);
				result = firstRaw;
				memory.readMemory(0x8000000000000000L + 100, 50);
				result = secondRaw;
			}
		};

		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(0x8000000000000000L, 100);
		CompletableFuture<byte[]> second = cache.readMemory(0x8000000000000000L + 50, 100);
		firstRaw.complete(inc(100));
		secondRaw.complete(inc(50));
		byte[] firstArr = first.get(1000, TimeUnit.MILLISECONDS);
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(100), firstArr);

		byte[] dinc = new byte[100];
		inc(dinc, 0, 50, 50);
		inc(dinc, 50, 50, 0);
		assertArrayEquals(dinc, secondArr);
	}

	@Test
	public void testErroneousRead() throws Exception {
		final CompletableFuture<byte[]> firstErr = new CompletableFuture<>();
		final CompletableFuture<byte[]> secondRaw = new CompletableFuture<>();
		new Expectations() {
			{
				memory.readMemory(0, 100);
				result = firstErr;
				memory.readMemory(50, 100);
				result = secondRaw;
			}
		};

		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(0, 100);
		Throwable sentinel = new AssertionError("Sentinel");
		firstErr.completeExceptionally(sentinel);
		try {
			first.get(1000, TimeUnit.MILLISECONDS);
			fail();
		}
		catch (ExecutionException e) {
			assertEquals(sentinel, e.getCause());
		}

		CompletableFuture<byte[]> second = cache.readMemory(50, 100);
		secondRaw.complete(inc(100));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(100), secondArr);
	}

	@Test
	public void testPartialResult() throws Exception {
		final CompletableFuture<byte[]> firstPartial = new CompletableFuture<>();
		final CompletableFuture<byte[]> secondRaw = new CompletableFuture<>();
		new Expectations() {
			{
				memory.readMemory(0, 100);
				result = firstPartial;
				memory.readMemory(50, 50);
				result = secondRaw;
			}
		};

		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(0, 100);
		firstPartial.complete(inc(50)); // request was for 100!
		byte[] firstArr = first.get(1000, TimeUnit.MILLISECONDS);
		assertArrayEquals(inc(50), firstArr);

		CompletableFuture<byte[]> second = cache.readMemory(25, 75);
		secondRaw.complete(inc(50));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);

		byte[] dinc = new byte[75];
		inc(dinc, 0, 25, 25);
		inc(dinc, 25, 50, 0);
		assertArrayEquals(dinc, secondArr);
	}

	@Test
	public void testDisjointParallellFirstErrs() throws Exception {
		final CompletableFuture<byte[]> firstErr = new CompletableFuture<>();
		final CompletableFuture<byte[]> secondRaw = new CompletableFuture<>();
		new Expectations() {
			{
				memory.readMemory(0, 25);
				result = firstErr;
				memory.readMemory(50, 25);
				result = secondRaw;
			}
		};

		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(0, 25);
		CompletableFuture<byte[]> second = cache.readMemory(50, 25);

		Throwable sentinel = new AssertionError("Sentinel");
		firstErr.completeExceptionally(sentinel);
		try {
			first.get(0, TimeUnit.MILLISECONDS);
			fail();
		}
		catch (ExecutionException e) {
			assertEquals(sentinel, e.getCause());
		}

		secondRaw.complete(inc(25));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);
		assertArrayEquals(inc(25), secondArr);
	}

	@Test
	public void testPartialFromErr() throws Exception {
		final CompletableFuture<byte[]> firstErr = new CompletableFuture<>();
		final CompletableFuture<byte[]> secondRaw = new CompletableFuture<>();
		new Expectations() {
			{
				memory.readMemory(50, 50);
				result = firstErr;
				memory.readMemory(0, 50);
				result = secondRaw;
			}
		};

		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(50, 50);
		CompletableFuture<byte[]> second = cache.readMemory(0, 100);

		Throwable sentinel = new AssertionError("Sentinel");
		firstErr.completeExceptionally(sentinel);
		try {
			first.get(0, TimeUnit.MILLISECONDS);
			fail();
		}
		catch (ExecutionException e) {
			assertEquals(sentinel, e.getCause());
		}
		// First should still succeed partially
		secondRaw.complete(inc(50));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);
		assertArrayEquals(inc(50), secondArr);
	}
}
