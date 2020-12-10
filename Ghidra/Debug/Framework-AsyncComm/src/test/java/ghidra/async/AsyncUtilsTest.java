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

import static ghidra.async.AsyncUtils.*;
import static org.junit.Assert.assertEquals;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Test;

public class AsyncUtilsTest {
	@Test
	public void testEach() throws Throwable {
		List<Integer> list = Arrays.asList(new Integer[] { 1, 2, 4, 3 });
		List<String> res = new ArrayList<>();
		each(TypeSpec.VOID, list.iterator(), (e, seq) -> {
			append("" + e, res).handle(seq::repeat);
		}).get(1000, TimeUnit.MILLISECONDS);

		List<String> exp = Arrays.asList(new String[] { "1", "2", "4", "3" });
		assertEquals(exp, res);
	}

	// This also tests the compile-time type checking
	@Test
	public void testSeq() throws Throwable {
		List<String> res = new ArrayList<>();
		sequence(TypeSpec.VOID).then((seq) -> {
			add(1, 2).handle(seq::next);
		}, TypeSpec.INT).then((sum, seq) -> {
			intToString(sum).handle(seq::next);
		}, TypeSpec.STRING).then((str, seq) -> {
			append(str, res).handle(seq::next);
		}).finish().get(1000, TimeUnit.MILLISECONDS);

		List<String> exp = Arrays.asList(new String[] { "3" });
		assertEquals(exp, res);
	}

	@Test
	public void testLoop() throws Throwable {
		AtomicInteger count = new AtomicInteger(0);
		List<Integer> res = new ArrayList<>();
		long result = loop(TypeSpec.LONG, (loop) -> {
			if (count.getAndIncrement() < 5) {
				add(count.get(), 10).handle(loop::consume);
			}
			else {
				loop.exit(0xdeadbeeff00dL, null);
			}
		}, TypeSpec.INT, (cur, loop) -> {
			res.add(cur);
			loop.repeat();
		}).get(1000, TimeUnit.MILLISECONDS);

		List<Integer> exp = Arrays.asList(new Integer[] { 11, 12, 13, 14, 15 });
		assertEquals(exp, res);
		assertEquals(0xdeadbeeff00dL, result);
	}

	@Test
	public void testNesting() throws Throwable {
		List<String> res = new ArrayList<>();
		sequence(TypeSpec.VOID).then((seq) -> {
			getListInts().handle(seq::next);
		}, TypeSpec.obj((List<Integer>) null)).then((list, seq) -> {
			each(TypeSpec.VOID, list.iterator(), (e, loop) -> {
				intToString(e).handle(loop::consume);
			}, TypeSpec.STRING, (str, loop) -> {
				res.add(str);
				loop.repeat();
			}).handle(seq::next);
		}).finish().get(1000, TimeUnit.MILLISECONDS);

		List<String> exp = Arrays.asList(new String[] { "1", "2", "3" });
		assertEquals(exp, res);
	}

	// Functions that communicate result via completion handler
	protected static CompletableFuture<Void> append(String message, List<String> to) {
		to.add(message);
		return AsyncUtils.NIL;
	}

	protected static CompletableFuture<Integer> add(int a, int b) {
		return CompletableFuture.completedFuture(a + b);
	}

	protected static CompletableFuture<String> intToString(int a) {
		return CompletableFuture.completedFuture(Integer.toString(a));
	}

	protected static CompletableFuture<List<Integer>> getListInts() {
		return CompletableFuture.completedFuture(Arrays.asList(new Integer[] { 1, 2, 3 }));
	}

	// Some dummies to construct examples for documentation

	protected static class Storage {
		protected CompletableFuture<List<Integer>> fetchList() {
			return getListInts();
		}

		protected void close() {
			// Empty
		}
	}

	protected static class Service {
		protected CompletableFuture<Integer> process(int val) {
			return CompletableFuture.completedFuture(val * 3);
		}

		protected void close() {
			// Empty
		}
	}

	protected static CompletableFuture<Storage> connectStorage(String address) {
		return CompletableFuture.completedFuture(new Storage());
	}

	protected static CompletableFuture<Service> connectService(String address) {
		return CompletableFuture.completedFuture(new Service());
	}

	protected static String ADDR1 = null;
	protected static String ADDR2 = null;

	class FetchAndProcess extends CompletableFuture<Integer> {
		Storage storage;
		Service service;
		int sum;

		FetchAndProcess(int start) {
			sum = start;
			connectStorage(ADDR1).handle(this::storageConnected);
		}

		Void storageConnected(Storage s, Throwable exc) {
			if (exc != null) {
				completeExceptionally(exc);
			}
			else {
				storage = s;
				connectService(ADDR2).handle(this::serviceConnected);
			}
			return null;
		}

		Void serviceConnected(Service s, Throwable exc) {
			if (exc != null) {
				completeExceptionally(exc);
			}
			else {
				service = s;
				storage.fetchList().handle(this::fetchedList);
			}
			return null;
		}

		Void fetchedList(List<Integer> list, Throwable exc) {
			if (exc != null) {
				completeExceptionally(exc);
			}
			else {
				List<CompletableFuture<Void>> futures = new ArrayList<>();
				for (int entry : list) {
					futures.add(service.process(entry).thenAccept((result) -> {
						sum += result;
					}));
				}
				CompletableFuture.allOf(futures.toArray(new CompletableFuture[list.size()]))
						.handle(this::processedList);
			}
			return null;
		}

		Void processedList(Void v, Throwable exc) {
			if (exc != null) {
				completeExceptionally(exc);
			}
			else {
				complete(sum);
			}
			return null;
		}
	}

	public CompletableFuture<Integer> doWorkWithClass(int start) {
		return new FetchAndProcess(start);
	}

	public CompletableFuture<Integer> doWorkWithComposition(int start) {
		AtomicReference<Storage> store = new AtomicReference<>();
		AtomicReference<Service> serve = new AtomicReference<>();
		AtomicInteger sum = new AtomicInteger(start);
		return connectStorage(ADDR1).thenCompose((s) -> {
			store.set(s);
			return connectService(ADDR2);
		}).thenCompose((s) -> {
			serve.set(s);
			return store.get().fetchList();
		}).thenCompose((list) -> {
			List<CompletableFuture<Void>> futures = new ArrayList<>();
			for (int entry : list) {
				futures.add(serve.get().process(entry).thenAccept((result) -> {
					sum.addAndGet(result);
				}));
			}
			return CompletableFuture.allOf(futures.toArray(new CompletableFuture[list.size()]));
		}).thenApply((v) -> {
			store.get().close();
			serve.get().close();
			return sum.get();
		});
	}

	static class ListNotFoundException extends Exception {
		// Just a placeholder for an example
	}

	public static final List<Integer> DEFAULT_LIST = null;

	public CompletableFuture<Integer> doWorkWithSeq(int start) {
		AtomicReference<Storage> store = new AtomicReference<>();
		AtomicReference<Service> serve = new AtomicReference<>();
		AtomicInteger sum = new AtomicInteger(start);
		return sequence(TypeSpec.INT).then((seq) -> {
			connectStorage(ADDR1).handle(seq::next);
		}, store).then((seq) -> {
			connectService(ADDR2).handle(seq::next);
		}, serve).then((seq) -> {
			store.get().fetchList().handle(seq::next);
		}, TypeSpec.obj((List<Integer>) null)).then((list, seq) -> {
			AsyncFence fence = new AsyncFence();
			for (int entry : list) {
				fence.include(sequence(TypeSpec.VOID).then((seq2) -> {
					serve.get().process(entry).handle(seq2::next);
				}, TypeSpec.INT).then((result, seq2) -> {
					sum.addAndGet(result);
					seq2.exit();
				}).finish());
			}
			fence.ready().handle(seq::next);
		}).then((seq) -> {
			store.get().close();
			serve.get().close();
			seq.exit(sum.get());
		}).finish().exceptionally((exc) -> {
			if (store.get() != null) {
				store.get().close();
			}
			if (serve.get() != null) {
				serve.get().close();
			}
			return ExceptionUtils.rethrow(exc);
		});
	}

	@Test
	public void testExample() throws Throwable {
		assertEquals(23, doWorkWithClass(5).get(1000, TimeUnit.MILLISECONDS).intValue());
		assertEquals(23, doWorkWithComposition(5).get(1000, TimeUnit.MILLISECONDS).intValue());
		assertEquals(23, doWorkWithSeq(5).get(1000, TimeUnit.MILLISECONDS).intValue());
	}

	private CompletableFuture<byte[]> receiveData() {
		// Placeholder for example
		return AsyncUtils.nil();
	}

	private void processData(byte[] data) {
		// Placeholder for example
	}

	public void exampleLoop1() {
		loop(TypeSpec.VOID, (loop) -> {
			receiveData().handle(loop::consume);
		}, TypeSpec.BYTE_ARRAY, (data, loop) -> {
			loop.repeat();
			processData(data);
		});
	}

	private CompletableFuture<Void> someTask() {
		// Placeholder for example
		return AsyncUtils.NIL;
	}

	public void exampleLoop2() {
		loop(TypeSpec.VOID, (loop) -> {
			someTask().handle(loop::repeat);
		});
	}

	private Set<Integer> mySet;

	private CompletableFuture<String> sendItem() {
		// Placeholder for example
		return AsyncUtils.nil();
	}

	private void logResult(String message) {
		// Placeholder for example
	}

	public void exampleEach1() {
		each(TypeSpec.VOID, mySet.iterator(), (item, loop) -> {
			sendItem().handle(loop::consume);
		}, TypeSpec.STRING, (message, loop) -> {
			loop.repeat();
			logResult(message);
		});
	}

	public void exampleEach2() {
		each(TypeSpec.VOID, mySet.iterator(), (item, loop) -> {
			sendItem().handle(loop::repeatIgnore);
		});
	}

	@Test
	public void testTwoSequencesInterwoven() {
		Deque<CompletableFuture<Void>> queue = new LinkedList<>();
		List<Integer> result = new ArrayList<>();

		sequence(TypeSpec.VOID).then((seq) -> {
			result.add(1);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			result.add(2);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			result.add(3);
			seq.exit();
		});
		sequence(TypeSpec.VOID).then((seq) -> {
			result.add(4);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			result.add(5);
			CompletableFuture<Void> future = new CompletableFuture<>();
			queue.add(future);
			future.handle(seq::next);
		}).then((seq) -> {
			result.add(6);
			seq.exit();
		});

		CompletableFuture<Void> future;
		while (null != (future = queue.poll())) {
			future.complete(null);
		}

		List<Integer> exp = Arrays.asList(new Integer[] { 1, 4, 2, 5, 3, 6 });
		assertEquals(exp, result);
	}
}
