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

import java.util.Deque;
import java.util.LinkedList;
import java.util.concurrent.*;

import org.junit.Test;

public class CachedMemoryTest {

	static class RequestRecord<T> {
		final CompletableFuture<T> future = new CompletableFuture<>();
		final long address;

		public RequestRecord(long address) {
			this.address = address;
		}
	}

	static class ReadRequestRecord extends RequestRecord<byte[]> {
		final int length;

		public ReadRequestRecord(long address, int length) {
			super(address);
			this.length = length;
		}
	}

	static class WriteRequestRecord extends RequestRecord<Void> {
		final byte[] data;

		public WriteRequestRecord(long address, byte[] data) {
			super(address);
			this.data = data;
		}
	}

	static class TestMemoryReaderWriter implements MemoryReader, MemoryWriter {
		Deque<RequestRecord<?>> earlies = new LinkedList<>();
		Deque<RequestRecord<?>> requests = new LinkedList<>();

		@Override
		public CompletableFuture<byte[]> readMemory(long address, int length) {
			RequestRecord<?> early = earlies.poll();
			if (early != null) {
				ReadRequestRecord req = (ReadRequestRecord) early;
				assertEquals(req.address, address);
				assertEquals(req.length, length);
				return req.future;
			}
			ReadRequestRecord req = new ReadRequestRecord(address, length);
			requests.add(req);
			return req.future;
		}

		@Override
		public CompletableFuture<Void> writeMemory(long address, byte[] data) {
			WriteRequestRecord req = new WriteRequestRecord(address, data);
			requests.add(req);
			return req.future;
		}

		public void expectEarlyRead(long address, byte[] data) {
			ReadRequestRecord req = new ReadRequestRecord(address, data.length);
			req.future.complete(data);
			earlies.add(req);
		}

		public ReadRequestRecord assertPollRead() {
			return (ReadRequestRecord) requests.remove();
		}

		public WriteRequestRecord assertPollWrite() {
			return (WriteRequestRecord) requests.remove();
		}
	}

	protected TestMemoryReaderWriter memory = new TestMemoryReaderWriter();

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
		CachedMemory cache = new CachedMemory(memory, memory);
		CompletableFuture<byte[]> future = cache.readMemory(1234, 90);

		ReadRequestRecord rec = memory.assertPollRead();
		assertEquals(1234, rec.address);
		assertEquals(90, rec.length);

		rec.future.complete(inc(90));
		byte[] arr = future.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(90), arr);
	}

	@Test
	public void testSingleReadIncludesMax() throws Exception {
		CachedMemory cache = new CachedMemory(memory, memory);
		CompletableFuture<byte[]> future = cache.readMemory(-4, 4);

		ReadRequestRecord rec = memory.assertPollRead();
		assertEquals(-4, rec.address);
		assertEquals(4, rec.length);

		rec.future.complete(new byte[] { 1, 2, 3, 4 });
		byte[] arr = future.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(new byte[] { 1, 2, 3, 4 }, arr);
	}

	@Test
	public void testSingleReadCompletedEarly() throws Exception {
		memory.expectEarlyRead(1234, inc(90));

		CachedMemory cache = new CachedMemory(memory, memory);
		CompletableFuture<byte[]> future = cache.readMemory(1234, 90);
		byte[] arr = future.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(90), arr);
	}

	@Test
	public void testOverlappingSequentialReads() throws Exception {
		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(1234, 100);
		ReadRequestRecord req1 = memory.assertPollRead();
		assertEquals(1234, req1.address);
		assertEquals(100, req1.length);
		req1.future.complete(inc(100));
		byte[] firstArr = first.get(1000, TimeUnit.MILLISECONDS);

		CompletableFuture<byte[]> second = cache.readMemory(1284, 100);
		ReadRequestRecord req2 = memory.assertPollRead();
		assertEquals(1334, req2.address);
		assertEquals(50, req2.length);
		req2.future.complete(inc(50));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(100), firstArr);

		byte[] dinc = new byte[100];
		inc(dinc, 0, 50, 50);
		inc(dinc, 50, 50, 0);
		assertArrayEquals(dinc, secondArr);
	}

	@Test
	public void testOverlappingParallelReads() throws Exception {
		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(1234, 100);
		ReadRequestRecord req1 = memory.assertPollRead();
		assertEquals(1234, req1.address);
		assertEquals(100, req1.length);

		CompletableFuture<byte[]> second = cache.readMemory(1284, 100);
		ReadRequestRecord req2 = memory.assertPollRead();
		assertEquals(1334, req2.address);
		assertEquals(50, req2.length);

		req1.future.complete(inc(100));
		req2.future.complete(inc(50));
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
		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(1234, 50);
		ReadRequestRecord req1 = memory.assertPollRead();
		assertEquals(1234, req1.address);
		assertEquals(50, req1.length);

		CompletableFuture<byte[]> second = cache.readMemory(1234, 100);
		ReadRequestRecord req2 = memory.assertPollRead();
		assertEquals(1284, req2.address);
		assertEquals(50, req2.length);

		assertFalse(first.isDone());
		req1.future.complete(inc(50));
		byte[] firstArr = first.get(1000, TimeUnit.MILLISECONDS);

		assertFalse(second.isDone());
		req2.future.complete(inc(50));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(50), firstArr);

		byte[] dinc = new byte[100];
		inc(dinc, 0, 50, 0);
		inc(dinc, 50, 50, 0);
		assertArrayEquals(dinc, secondArr);
	}

	@Test
	public void testLargeOffsetsParallelReads() throws Exception {
		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(0x8000_0000_0000_0000L, 100);
		ReadRequestRecord req1 = memory.assertPollRead();
		assertEquals(0x8000_0000_0000_0000L, req1.address);
		assertEquals(100, req1.length);

		CompletableFuture<byte[]> second = cache.readMemory(0x8000_0000_0000_0000L + 50, 100);
		ReadRequestRecord req2 = memory.assertPollRead();
		assertEquals(0x8000_0000_0000_0000L + 100, req2.address);
		assertEquals(50, req2.length);

		req1.future.complete(inc(100));
		req2.future.complete(inc(50));
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
		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(0, 100);
		ReadRequestRecord req1 = memory.assertPollRead();
		assertEquals(0, req1.address);
		assertEquals(100, req1.length);

		Throwable sentinel = new AssertionError("Sentinel");
		req1.future.completeExceptionally(sentinel);
		try {
			first.get(1000, TimeUnit.MILLISECONDS);
			fail();
		}
		catch (ExecutionException e) {
			assertEquals(sentinel, e.getCause());
		}

		CompletableFuture<byte[]> second = cache.readMemory(50, 100);
		ReadRequestRecord req2 = memory.assertPollRead();
		assertEquals(50, req2.address);
		assertEquals(100, req2.length);
		req2.future.complete(inc(100));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);

		assertArrayEquals(inc(100), secondArr);
	}

	@Test
	public void testPartialResult() throws Exception {
		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(0, 100);
		ReadRequestRecord req1 = memory.assertPollRead();
		assertEquals(0, req1.address);
		assertEquals(100, req1.length);

		req1.future.complete(inc(50)); // request was for 100!
		byte[] firstArr = first.get(1000, TimeUnit.MILLISECONDS);
		assertArrayEquals(inc(50), firstArr);

		CompletableFuture<byte[]> second = cache.readMemory(25, 75);
		ReadRequestRecord req2 = memory.assertPollRead();
		assertEquals(50, req2.address);
		assertEquals(50, req2.length);

		req2.future.complete(inc(50));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);

		byte[] dinc = new byte[75];
		inc(dinc, 0, 25, 25);
		inc(dinc, 25, 50, 0);
		assertArrayEquals(dinc, secondArr);
	}

	@Test
	public void testDisjointParallellFirstErrs() throws Exception {
		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(0, 25);
		ReadRequestRecord req1 = memory.assertPollRead();
		assertEquals(0, req1.address);
		assertEquals(25, req1.length);

		CompletableFuture<byte[]> second = cache.readMemory(50, 25);
		ReadRequestRecord req2 = memory.assertPollRead();
		assertEquals(50, req2.address);
		assertEquals(25, req2.length);

		Throwable sentinel = new AssertionError("Sentinel");
		req1.future.completeExceptionally(sentinel);
		try {
			first.get(0, TimeUnit.MILLISECONDS);
			fail();
		}
		catch (ExecutionException e) {
			assertEquals(sentinel, e.getCause());
		}

		req2.future.complete(inc(25));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);
		assertArrayEquals(inc(25), secondArr);
	}

	@Test
	public void testPartialFromErr() throws Exception {
		CachedMemory cache = new CachedMemory(memory, memory);

		CompletableFuture<byte[]> first = cache.readMemory(50, 50);
		ReadRequestRecord req1 = memory.assertPollRead();
		assertEquals(50, req1.address);
		assertEquals(50, req1.length);

		CompletableFuture<byte[]> second = cache.readMemory(0, 100);
		ReadRequestRecord req2 = memory.assertPollRead();
		assertEquals(0, req2.address);
		assertEquals(50, req2.length);

		Throwable sentinel = new AssertionError("Sentinel");
		req1.future.completeExceptionally(sentinel);
		try {
			first.get(0, TimeUnit.MILLISECONDS);
			fail();
		}
		catch (ExecutionException e) {
			assertEquals(sentinel, e.getCause());
		}
		// First should still succeed partially
		req2.future.complete(inc(50));
		byte[] secondArr = second.get(1000, TimeUnit.MILLISECONDS);
		assertArrayEquals(inc(50), secondArr);
	}
}
