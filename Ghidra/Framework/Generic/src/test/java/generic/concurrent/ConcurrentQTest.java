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
package generic.concurrent;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class ConcurrentQTest extends AbstractGenericTest {

	private static final int MAX_THREADS = 4;
	private static final int FAST_EXECUTION = 50;
	private static final int MEDIUM_EXECUTION = 150;
	private static final int SLOW_EXECUTION = 300;
	private static final int DELIBERATE_EXECUTION = 1000;
	private static final String TEST_THREAD_POOL = "TestThreadPool";

	private TaskMonitor monitor = new TaskMonitorAdapter();
	private GThreadPool threadPool;
	private ConcurrentQ<TestItem, TestResult> q;
	private TestCallback callback = new TestCallback();

	// @formatter:off
	@Before
	public void setUp() throws Exception {
		threadPool = GThreadPool.getSharedThreadPool(TEST_THREAD_POOL);
		threadPool.setMaxThreadCount(MAX_THREADS);

		monitor.setCancelEnabled(true);
		
		ConcurrentQBuilder<TestItem, TestResult> builder = new ConcurrentQBuilder<>();
		q = 	builder.setThreadPool(threadPool).
				    setCollectResults(true).
				    setMonitor(monitor).
				    build(callback);
	}
	
	// @formatter:on
	@After
	public void tearDown() throws Exception {
		GThreadPool pool = GThreadPool.getSharedThreadPool(TEST_THREAD_POOL);
		@SuppressWarnings("unchecked")
		Map<String, GThreadPool> poolMap =
			(Map<String, GThreadPool>) getInstanceField("sharedPoolMap", pool);
		GThreadPool gThreadPool = poolMap.get(TEST_THREAD_POOL);
		gThreadPool.shutdownNow();

		resetJavaThreadNumbering();
		poolMap.clear();
	}

	private void resetJavaThreadNumbering() {
		// in order to keep test "independent", need to reset the thread numbering from
		// the default thread factory
		GThreadPool pool = GThreadPool.getSharedThreadPool(TEST_THREAD_POOL);
		Object executor = getInstanceField("executor", pool);
		Object threadFactory = getInstanceField("threadFactory", executor);
		threadFactory = getInstanceField("threadFactory", threadFactory);
		AtomicInteger poolNumber = (AtomicInteger) getInstanceField("poolNumber", threadFactory);
		poolNumber.set(1);
	}

	@Test
	public void testFailure() throws Exception {

		List<TestItem> workList = new ArrayList<>();
		workList.add(new TestItem("One", SLOW_EXECUTION));
		workList.add(new TestItem("Two", FAST_EXECUTION, true));// simulate exception
		workList.add(new TestItem("Three", MEDIUM_EXECUTION));

		q.add(workList);
		List<QResult<TestItem, TestResult>> results = waitForResults();

		assertEquals("Expected same number of results as submitted jobs", 3, results.size());

		// since these jobs are done in parallel, the results should appear based on how fast
		// they execute.
		assertNotNull("Expected second job to have an exception", results.get(0).getError());

		assertEquals("Expected medium job second", "Three",
			results.get(1).getResult().getItemName());

		assertEquals("Expected slowest job last", "One", results.get(2).getResult().getItemName());

	}

	@Test
	public void testSequentialExecution() throws Exception {
		ConcurrentQBuilder<TestItem, TestResult> builder = new ConcurrentQBuilder<>();

		// @formatter:off
		q = 	builder.setThreadPool(threadPool).
				    setCollectResults(true).
				    setMaxInProgress(1).
				    build(new TestCallback());
		// @formatter:on

		List<TestItem> workList = new ArrayList<>();
		workList.add(new TestItem("One", SLOW_EXECUTION));
		workList.add(new TestItem("Two", FAST_EXECUTION));
		workList.add(new TestItem("Three", MEDIUM_EXECUTION));

		q.add(workList);
		List<QResult<TestItem, TestResult>> results = waitForResults();

		// Since this Q is set to only do one job at a time, the results should appear in the
		// order the jobs were submitted.
		assertCompletionOrder(results, "One", "Two", "Three");

		// Since they were sequential, make sure they all used the same thread
		String threadName = results.get(0).getResult().getThreadName();
		assertEquals(threadName, results.get(1).getResult().getThreadName());
		assertEquals(threadName, results.get(2).getResult().getThreadName());
	}

	@Test
	public void testParallelExecution() throws Exception {

		List<TestItem> workList = new ArrayList<>();
		workList.add(new TestItem("One", SLOW_EXECUTION));
		workList.add(new TestItem("Two", FAST_EXECUTION));
		workList.add(new TestItem("Three", MEDIUM_EXECUTION));

		q.add(workList);
		List<QResult<TestItem, TestResult>> results = waitForResults();

		// since these jobs are done in parallel, the results should appear based on how fast
		// they execute.
		assertCompletionOrder(results, "Two", "Three", "One");

	}

	@Test
	public void testAddIterator() throws Exception {
		List<TestItem> workList = new ArrayList<>();
		workList.add(new TestItem("One", SLOW_EXECUTION));
		workList.add(new TestItem("Two", FAST_EXECUTION));
		workList.add(new TestItem("Three", MEDIUM_EXECUTION));

		q.add(workList.iterator());
		List<QResult<TestItem, TestResult>> results = waitForResults();

		// since these jobs are done in parallel, the results should appear based on how fast
		// they execute.
		assertCompletionOrder(results, "Two", "Three", "One");
	}

	@Test
	public void testListenerCallback() throws Exception {
		TestListener listener = new TestListener();

		ConcurrentQBuilder<TestItem, TestResult> builder = new ConcurrentQBuilder<>();

		// @formatter:off
		q = 	builder.setListener(listener).
				    setThreadPool(threadPool).
				    setCollectResults(true).
				    build(new TestCallback());
		// @formatter:on

		List<TestItem> workList = new ArrayList<>();
		workList.add(new TestItem("One", SLOW_EXECUTION));
		workList.add(new TestItem("Two", FAST_EXECUTION, true));// simulate exception
		workList.add(new TestItem("Three", MEDIUM_EXECUTION));

		q.add(workList);
		q.waitForResults();

		List<QResult<TestItem, TestResult>> results = listener.list;
		// since these jobs are done in parallel, the results should appear based on how fast
		// they execute.
		assertNotNull("Expected second job to have an exception", results.get(0).getError());

		assertEquals("Expected medium job second", "Three",
			results.get(1).getResult().getItemName());

		assertEquals("Expected slowest job last", "One", results.get(2).getResult().getItemName());
	}

	@Test
	public void testWaitForLimitedTime() throws Exception {

		List<TestItem> workList = new ArrayList<>();
		workList.add(new TestItem("One", SLOW_EXECUTION));
		workList.add(new TestItem("Two", FAST_EXECUTION));
		workList.add(new TestItem("Three", MEDIUM_EXECUTION));
		q.add(workList);

		// wait for less time than the fastest to make sure we can return with no results
		List<QResult<TestItem, TestResult>> results = waitForResults(FAST_EXECUTION / 2);
		assertTrue(results.isEmpty());

		// Now wait so that the fastest will complete and we get 1 result
		results = waitForResults(FAST_EXECUTION);

		assertCompletionOrder(results, "Two");

		// Now wait for the rest to finish and get the final two results
		results = waitForResults(SLOW_EXECUTION);

		assertCompletionOrder(results, "Three", "One");
	}

	@Test
	public void testWaitUntilEmptyAndThreadsIdle() throws InterruptedException {
		List<TestItem> workList = new ArrayList<>();
		workList.add(new TestItem("One", DELIBERATE_EXECUTION));
		q.add(workList);

		//
		// Test that we timeout with a low value
		//
		assertFalse(q.waitUntilDone(10, TimeUnit.MILLISECONDS));
		q.cancelAllTasks(true);

		List<QResult<TestItem, TestResult>> results = waitForResults();
		assertEquals(1, results.size());
		assertTrue(results.get(0).isCancelled());

		//
		// Now make sure it does wait
		//
		workList = new ArrayList<>();
		workList.add(new TestItem("Two", FAST_EXECUTION));
		q.add(workList);

		assertTrue(q.waitUntilDone(SLOW_EXECUTION, TimeUnit.MILLISECONDS));

		results = waitForResults();
		assertEquals(1, results.size());
	}

	@Test
	public void testWaitWithTimeOutOnEmptyQueueDoesntBlock() throws InterruptedException {

		final CountDownLatch latch = new CountDownLatch(1);
		Thread runner = new Thread(() -> {
			try {
				q.waitForResults(3000, TimeUnit.MILLISECONDS);
				latch.countDown();
			}
			catch (InterruptedException e) {
				// shouldn't happen
			}
		});

		runner.start();

		// wait a bit to ensure that the thread gets scheduled and run
		assertTrue("Timed-out waiting for Thread to finish.  It must be blocking on an empty queue",
			latch.await(100, TimeUnit.MILLISECONDS));
	}

	@Test
	public void testWaitForeverOnEmptyQueueDoesntBlock() throws InterruptedException {

		final CountDownLatch latch = new CountDownLatch(1);
		Thread runner = new Thread(() -> {
			try {
				q.waitForResults();
				latch.countDown();
			}
			catch (InterruptedException e) {
				// shouldn't happen
			}
		});

		runner.start();

		// wait a bit to ensure that the thread gets scheduled and run
		assertTrue("Timed-out waiting for Thread to finish.  It must be blocking on an empty queue",
			latch.await(100, TimeUnit.MILLISECONDS));
	}

	// testCancelled
	@Test
	public void testCancelExecution() throws Exception {

		List<TestItem> workList = new ArrayList<>();
		workList.add(new TestItem("1", SLOW_EXECUTION));
		workList.add(new TestItem("2", FAST_EXECUTION));
		workList.add(new TestItem("3", MEDIUM_EXECUTION));
		workList.add(new TestItem("4", MEDIUM_EXECUTION));
		workList.add(new TestItem("5", MEDIUM_EXECUTION));
		workList.add(new TestItem("6", MEDIUM_EXECUTION));
		workList.add(new TestItem("7", MEDIUM_EXECUTION));
		workList.add(new TestItem("8", MEDIUM_EXECUTION));
		workList.add(new TestItem("9", MEDIUM_EXECUTION));
		workList.add(new TestItem("10", MEDIUM_EXECUTION));
		workList.add(new TestItem("11", MEDIUM_EXECUTION));
		workList.add(new TestItem("12", MEDIUM_EXECUTION));
		workList.add(new TestItem("13", MEDIUM_EXECUTION));
		workList.add(new TestItem("14", MEDIUM_EXECUTION));
		workList.add(new TestItem("15", MEDIUM_EXECUTION));
		workList.add(new TestItem("16", MEDIUM_EXECUTION));

		q.add(workList);

		// wait for just the fast job to complete
		List<QResult<TestItem, TestResult>> results = new ArrayList<>(
			q.waitForResults((FAST_EXECUTION + MEDIUM_EXECUTION) / 2, TimeUnit.MILLISECONDS));
		assertCompletionOrder(results, "2");
		List<TestItem> nonStartedList = q.cancelAllTasks(true);
		results = waitForResults();

		// expect 15 because one completed normally before we cancelled the rest
		assertEquals(15, nonStartedList.size() + results.size());
		for (QResult<TestItem, TestResult> result : results) {
			assertTrue(result.isCancelled());
		}
	}

	@Test
	public void testMaxThreads() throws InterruptedException {

		List<TestItem> workList = new ArrayList<>();
		workList.add(new TestItem("1", MEDIUM_EXECUTION));
		workList.add(new TestItem("2", MEDIUM_EXECUTION));
		workList.add(new TestItem("3", MEDIUM_EXECUTION));
		workList.add(new TestItem("4", MEDIUM_EXECUTION));
		workList.add(new TestItem("5", MEDIUM_EXECUTION));
		workList.add(new TestItem("6", MEDIUM_EXECUTION));
		q.add(workList);
		q.waitForResults(FAST_EXECUTION, TimeUnit.MILLISECONDS);

		List<TestItem> nonStartedItems = q.cancelAllTasks(true);

		// Since we allow at most 4 threads and gave 6 tasks, 4 should have been started, leaving
		// 2 remaining
		assertEquals(2, nonStartedItems.size());

		List<QResult<TestItem, TestResult>> results = waitForResults();
		assertEquals(4, results.size());
	}

	@Test
	public void testWaitUntilDoneOnEmptyQueue() throws Exception {
		CheckpointRunner checkpointRunner = new CheckpointRunner(new WaitUntilDoneCallable());

		assertTrue("Thread did not start", checkpointRunner.waitForStart(100));
		assertTrue("Timed-out waiting for Thread to finish.  It must be blocking on an empty queue",
			checkpointRunner.waitForFinish(100));
	}

	@Test
	public void testWaitUntilDone() throws Exception {

		CountDownLatch waitLatch = new CountDownLatch(1);

		List<TestItem> workList = new ArrayList<>();
		workList.add(new LatchTestItem("1", waitLatch, FAST_EXECUTION));
		workList.add(new TestItem("2", FAST_EXECUTION));
		workList.add(new TestItem("3", FAST_EXECUTION));
		workList.add(new TestItem("4", FAST_EXECUTION));
		q.add(workList);

		CheckpointRunner checkpointRunner = new CheckpointRunner(new WaitUntilDoneCallable());

		assertTrue("Thread did not start", checkpointRunner.waitForStart(500));
		assertTrue("waitUntilDone() call did not wait for all items",
			!checkpointRunner.hasFinished());

		waitLatch.countDown();

		// wait a bit to ensure that the thread gets scheduled and run
		assertTrue("Timed-out waiting for Thread to finish.  It must be blocking on an empty queue",
			checkpointRunner.waitForFinish(500));

		// empty call after some processing should not block
		checkpointRunner = new CheckpointRunner(new WaitUntilDoneCallable());
		assertTrue("Timed-out waiting for Thread to finish.  It must be blocking on an empty queue",
			checkpointRunner.waitForFinish(3000));
	}

	@Test
	public void testWaitUntilDoneWithExceptionBeforeWait() throws Exception {

		List<TestItem> workList = new ArrayList<>();
		workList.add(new TestItem("1", FAST_EXECUTION, true));
		workList.add(new TestItem("2", FAST_EXECUTION));
		q.add(workList);

		waitForEmptyQueue();

		CheckpointRunner checkpointRunner = new CheckpointRunner(new WaitUntilDoneCallable());

		try {
			checkpointRunner.waitForFinish(3000);
			Assert.fail("Did not get an exception while blocking on waitUntilDone()");
		}
		catch (Exception e) {
			// good!
		}
	}

	@Test
	public void testWaitUntilDoneWithExceptionWhileWaiting() throws Exception {
		CountDownLatch waitLatch = new CountDownLatch(1);

		List<TestItem> workList = new ArrayList<>();
		String exceptionItemName = "BillyBobDies";
		workList.add(new LatchTestExceptionItem(exceptionItemName, waitLatch, FAST_EXECUTION));
		workList.add(new TestItem("2", FAST_EXECUTION));
		q.add(workList);

		CheckpointRunner checkpointRunner = new CheckpointRunner(new WaitUntilDoneCallable());

		assertTrue("Thread did not start", checkpointRunner.waitForStart(500));
		assertTrue("waitUntilDone() call did not wait for all items",
			!checkpointRunner.hasFinished());

		try {
			waitLatch.countDown();

			// wait a bit to ensure that the thread gets scheduled and run
			assertFalse(
				"Timed-out waiting for Thread to finish.  It must be blocking on an empty queue",
				checkpointRunner.waitForFinish(100));
			Assert.fail("Did not get an exception while blocking on waitUntilDone()");
		}
		catch (Exception e) {
			// there was a time when we got the wrong exception
			assertTrue("Got the wrong exception!", e.getMessage().endsWith(exceptionItemName));
		}
	}

	@Test
	public void testWaitForNextResult() throws Exception {
		CountDownLatch waitLatch = new CountDownLatch(1);
		CountDownLatch waitLatch2 = new CountDownLatch(1);
		List<TestItem> workList = new ArrayList<>();
		workList.add(new LatchTestExceptionItem("1", waitLatch, FAST_EXECUTION));
		workList.add(new TestItem("2", FAST_EXECUTION));
		workList.add(new LatchTestItem("3", waitLatch2, FAST_EXECUTION));
		q.add(workList);

		CheckpointRunner checkpointRunner = new CheckpointRunner(new WaitForNextCallable());
		QResult<TestItem, TestResult> qResult = checkpointRunner.getResult();
		assertEquals("2", qResult.getResult().getItemName());

		waitLatch.countDown();

		checkpointRunner = new CheckpointRunner(new WaitForNextCallable());
		qResult = checkpointRunner.getResult();
		assertTrue(qResult.hasError());

		waitLatch2.countDown();

		checkpointRunner = new CheckpointRunner(new WaitForNextCallable());
		qResult = checkpointRunner.getResult();
		TestResult result = qResult.getResult();
		assertEquals("3", result.getItemName());

	}

	@Test
	public void testWaitForNextResultExceptionDoesNotStop() throws Exception {
		CountDownLatch waitLatch = new CountDownLatch(1);
		List<TestItem> workList = new ArrayList<>();
		workList.add(new LatchTestItem("1", waitLatch, FAST_EXECUTION));
		workList.add(new TestItem("2", FAST_EXECUTION));
		q.add(workList);

		CheckpointRunner checkpointRunner = new CheckpointRunner(new WaitForNextCallable());
		QResult<TestItem, TestResult> result = checkpointRunner.getResult();
		assertEquals("2", result.getResult().getItemName());

		waitLatch.countDown();

		checkpointRunner = new CheckpointRunner(new WaitForNextCallable());
		result = checkpointRunner.getResult();
		assertEquals("1", result.getResult().getItemName());
	}

	@Test
	public void testWaitUntilDoneIsCancellable() throws Exception {
		final CountDownLatch waitLatch = new CountDownLatch(MAX_THREADS);

		List<TestItem> workList = new ArrayList<>();
		workList.add(new LatchTestItem("1", waitLatch, FAST_EXECUTION));
		workList.add(new LatchTestItem("2", waitLatch, FAST_EXECUTION));
		workList.add(new LatchTestItem("3", waitLatch, FAST_EXECUTION));
		workList.add(new TestItem("4", FAST_EXECUTION));

		// add a bunch more items to give our test plenty of work to do
		for (int i = 0; i < 100; i++) {
			workList.add(new LatchTestItem("i" + i, waitLatch, FAST_EXECUTION));
		}

		int totalItems = workList.size();

		q.add(workList);

		CheckpointRunner checkpointRunner = new CheckpointRunner(new WaitUntilDoneCallable());

		assertTrue("Thread did not start", checkpointRunner.waitForStart(500));
		assertTrue("waitUntilDone() call did not wait for all items",
			!checkpointRunner.hasFinished());

		final CountDownLatch testThreadLatch = new CountDownLatch(1);
		Thread cancelThread = new Thread() {
			@Override
			public void run() {
				// WARNING: this is imprecise, but not sure how guarantee that the test thread
				//          has reached its blocking code
				try {
					testThreadLatch.await();
					sleep(300);// timing sensitivity
				}
				catch (InterruptedException e) {
					// shouldn't happen
				}

				// signal the queued items to proceed
				for (int i = 0; i < MAX_THREADS; i++) {
					waitLatch.countDown();
				}

//				Msg.debug(this, "cancelled -  before ");
				monitor.cancel();
//				Msg.debug(this, "cancelled -  after ");
			}
		};

		cancelThread.start();

		testThreadLatch.countDown();

//		Msg.debug(this, "WAITING!");
		q.waitUntilDone();// this call should block until cancelled (not until all work is done)
//		Msg.debug(this, "\tAFTER WAITING");

		assertTrue("Timed-out waiting for queued items", checkpointRunner.waitForFinish(3000));
		Assert.assertNotEquals(
			"All items were processed even though we cancelled the monitor - items " +
				"processed: " + callback.itemsProcessed(),
			callback.itemsProcessed(), totalItems);
	}

	@Test
	public void testOffer() throws Exception {
		//
		// The offer() method will block assuming 1) the Q was created with a blocking queue that
		// has a limited capacity and 2) that the capacity has been reached.
		//

		LinkedBlockingQueue<TestItem> queue = new LinkedBlockingQueue<>(1);

		threadPool = GThreadPool.getSharedThreadPool(TEST_THREAD_POOL);
		threadPool.setMaxThreadCount(2);

		//@formatter:off
		ConcurrentQBuilder<TestItem, TestResult > builder = new ConcurrentQBuilder<>();
		q = builder.setThreadPool(threadPool).
				    setMonitor(monitor).
				    setQueue(queue).
				    build(callback);
		//@formatter:on

		List<TestItem> workList = new ArrayList<>();
		StartStopTestItem one = new StartStopTestItem("1", FAST_EXECUTION);
		workList.add(one);
		StartStopTestItem two = new StartStopTestItem("2", FAST_EXECUTION);
		workList.add(two);
		StartStopTestItem three = new StartStopTestItem("3", FAST_EXECUTION);
		workList.add(three);
		StartStopTestItem four = new StartStopTestItem("4", FAST_EXECUTION);
		workList.add(four);

		OfferThread offerThread = new OfferThread(workList.iterator(), false);
		offerThread.start();

		waitForStarted(one, two);

		assertNotFinished(one, two);
		assertNotStarted(three, four);

		release(one);

		assertFinished(one);
		assertStarted(two, three);
		assertNotFinished(two, three);
		assertNotStarted(four);

		release(two);

		assertFinished(two);
		assertStarted(three, four);
		assertNotFinished(three, four);

		release(three);

		assertFinished(three);
		assertNotFinished(four);

		release(four);

		assertFinished(four);

		offerThread.join(2000);
		assertTrue(offerThread.finished());
	}

//==================================================================================================
// Private Methods
//==================================================================================================	
	private void assertCompletionOrder(List<QResult<TestItem, TestResult>> results,
			String... itemNames) throws Exception {
		assertEquals("Unexpected number of results!", itemNames.length, results.size());
		for (int i = 0; i < results.size(); i++) {
			assertEquals("Item completion order mismatch!", itemNames[i],
				results.get(i).getResult().getItemName());
		}
	}

	private void release(StartStopTestItem item) {
		item.release();
		item.waitForFinish();
	}

	private void assertFinished(StartStopTestItem item) {
		assertTrue("Item not finished: " + item, item.finished());
	}

	private void assertNotStarted(StartStopTestItem... items) {
		for (StartStopTestItem item : items) {
			assertFalse("Item started; expected blocked " + item, item.started());
		}
	}

	private void assertStarted(StartStopTestItem... items) {
		for (StartStopTestItem item : items) {
			// potential timing issue; wait for all items to start, in case we just freed-up space
			// in the queue
			item.waitForStart();
			assertTrue("Test item not started: " + item, item.started());
		}
	}

	private void assertNotFinished(StartStopTestItem... items) {
		for (StartStopTestItem item : items) {
			// potential timing issue; wait for all items to start, in case we just freed-up space
			// in the queue
			item.waitForStart();
			assertTrue("Test item not started: " + item, item.started());
			assertFalse("Test item finished when it should be blocked: " + item, item.finished());
		}
	}

	private void waitForStarted(StartStopTestItem... items) {
		for (StartStopTestItem item : items) {
			item.waitForStart();
		}
	}

	private void waitForEmptyQueue() {
		int waitTime = 100;
		int maxTries = 30;
		int numTries = 0;
		while (!q.isEmpty() && numTries++ < maxTries) {
			sleep(waitTime);
		}

		if (numTries == maxTries) {
			Assert.fail("Timed-out waiting for queue to finish processing");
		}
	}

	private ArrayList<QResult<TestItem, TestResult>> waitForResults() throws InterruptedException {
		return new ArrayList<>(q.waitForResults());
	}

	private ArrayList<QResult<TestItem, TestResult>> waitForResults(long timeout)
			throws InterruptedException {
		return new ArrayList<>(q.waitForResults(timeout, TimeUnit.MILLISECONDS));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class OfferThread extends Thread {

		private Iterator<TestItem> items;
		private boolean expectException;
		private volatile Exception exception;

		/* A thread to offer things to our bounded queue, which will block when full. */
		OfferThread(Iterator<TestItem> items, boolean expectException) {
			this.items = items;
			this.expectException = expectException;
		}

		@Override
		public void run() {
			try {
				q.offer(items);
			}
			catch (Exception e) {
				exception = e;
			}
		}

		boolean finished() throws Exception {
			if (expectException) {
				if (exception != null) {
					return false;
				}
				Assert.fail("Did not get an exception while offering items to queue");
				return true;
			}

			// did not expect an exception
			if (exception != null) {
				failWithException("Unexpected exception offer items to queue", exception);
				return false;
			}

			return true;
		}
	}

	private class TestCallback implements QCallback<TestItem, TestResult> {

		private volatile int totalItems = 0;

		int itemsProcessed() {
			return totalItems;
		}

		@Override
		public TestResult process(TestItem item, TaskMonitor m) {
//			Msg.debug(this, "process(): item " + item);
			totalItems++;
			if (m.isCancelled()) {
//				Msg.debug(this, "\tcancelled ");
				return null;
			}

			try {
				if (item instanceof LatchTestItem) {
					((LatchTestItem) item).await();
				}

				Thread.sleep(item.getWaitTime());
				if (item.fail()) {
					throw new RuntimeException("fail");
				}
			}
			catch (InterruptedException e) {
				return null;
			}
			TestResult result = new TestResult(item.name, Thread.currentThread().getName());
			return result;
		}
	}

	private class TestListener implements QItemListener<TestItem, TestResult> {
		List<QResult<TestItem, TestResult>> list = new ArrayList<>();

		@Override
		public void itemProcessed(QResult<TestItem, TestResult> result) {
			list.add(result);
		}
	}

	private class TestItem {
		protected String name;
		private long waitTime;
		private boolean fail;

		TestItem(String name, long waitTime) {
			this(name, waitTime, false);
		}

		TestItem(String name, long waitTime, boolean fail) {
			this.name = name;
			this.waitTime = waitTime;
			this.fail = fail;
		}

		@Override
		public String toString() {
			return name;
		}

		public long getWaitTime() {
			return waitTime;
		}

		public boolean fail() {
			return fail;
		}
	}

	private class TestResult {
		private String testItemName;
		private String threadName;

		public TestResult(String testItemName, String threadName) {
			this.testItemName = testItemName;
			this.threadName = threadName;
		}

		String getItemName() {
			return testItemName;
		}

		String getThreadName() {
			return threadName;
		}

	}

	private class LatchTestItem extends TestItem {

		CountDownLatch latch;

		LatchTestItem(String name, CountDownLatch latch, long waitTime) {
			super(name, waitTime);
			this.latch = latch;
		}

		void await() throws InterruptedException {
			latch.await();
		}
	}

	private class LatchTestExceptionItem extends LatchTestItem {

		LatchTestExceptionItem(String name, CountDownLatch latch, long waitTime) {
			super(name, latch, waitTime);
		}

		@Override
		public long getWaitTime() {
			throw new RuntimeException("Unexpected exception in process() - name: " + name);
		}
	}

	private class StartStopTestItem extends LatchTestItem {

		CountDownLatch started = new CountDownLatch(1);
		CountDownLatch finished = new CountDownLatch(1);

		StartStopTestItem(String name, long waitTime) {
			super(name, new CountDownLatch(1), waitTime);
		}

		@Override
		void await() throws InterruptedException {
//			Msg.debug(this, "Start stop item - started " + this + " ...");
			started.countDown();
			super.await();
//			Msg.debug(this, "Start stop item - finished " + this + " ...");
			finished.countDown();
		}

		void release() {
			latch.countDown();
		}

		void waitForStart() {
			try {
				if (!started.await(1, TimeUnit.SECONDS)) {
					Assert.fail("Item not started: " + this);
				}
			}
			catch (InterruptedException e) {
				Assert.fail("Interrupted while waiting for started: " + this);
			}
		}

		void waitForFinish() {
			try {
				if (!finished.await(1, TimeUnit.SECONDS)) {
					Assert.fail("Item not finished: " + this);
				}
			}
			catch (InterruptedException e) {
				Assert.fail("Interrupted while waiting for finished: " + this);
			}
		}

		boolean started() {
			return started.getCount() == 0;
		}

		boolean finished() {
			return finished.getCount() == 0;
		}

	}

	private class CheckpointRunner {
		private CountDownLatch startedLatch = new CountDownLatch(1);
		private CountDownLatch finishedLatch = new CountDownLatch(1);
		private AtomicReference<Exception> unexpectedException = new AtomicReference<>();
		private AtomicReference<QResult<TestItem, TestResult>> result = new AtomicReference<>();

		public CheckpointRunner(final Callable<QResult<TestItem, TestResult>> callable) {

			Thread runner = new Thread(() -> {
				try {
					startedLatch.countDown();
					QResult<TestItem, TestResult> callableResult = callable.call();
					result.set(callableResult);
				}
				catch (Exception e) {
					unexpectedException.set(e);
				}
				finishedLatch.countDown();
			});
			runner.start();
		}

		QResult<TestItem, TestResult> getResult() throws Exception {
			if (!waitForFinish(500)) {
				Assert.fail("Timed-out waiting for result from queue");
			}
			try {
				return result.get();
			}
			finally {
				checkException();
			}
		}

		void checkException() throws Exception {
			Exception exception = unexpectedException.get();
			if (exception != null) {
				throw new Exception(exception);
			}
		}

		boolean waitForStart(long time) throws Exception {
			checkException();
			try {
				return startedLatch.await(time, TimeUnit.MILLISECONDS);
			}
			finally {
				checkException();
			}
		}

//
//		boolean hasStarted() throws Exception {
//			checkException();
//			try {
//				return startedLatch.getCount() == 0;
//			}
//			finally {
//				checkException();
//			}
//		}

		boolean hasFinished() throws Exception {
			checkException();
			try {
				return finishedLatch.getCount() == 0;
			}
			finally {
				checkException();
			}
		}

		boolean waitForFinish(long time) throws Exception {
			checkException();
			try {
				return finishedLatch.await(time, TimeUnit.MILLISECONDS);
			}
			finally {
				checkException();
			}
		}
	}

	private class WaitUntilDoneCallable implements Callable<QResult<TestItem, TestResult>> {
		@Override
		public QResult<TestItem, TestResult> call() throws Exception {
			q.waitUntilDone();
			return null;
		}
	}

	private class WaitForNextCallable implements Callable<QResult<TestItem, TestResult>> {
		@Override
		public QResult<TestItem, TestResult> call() throws Exception {
			return q.waitForNextResult();
		}
	}
}
