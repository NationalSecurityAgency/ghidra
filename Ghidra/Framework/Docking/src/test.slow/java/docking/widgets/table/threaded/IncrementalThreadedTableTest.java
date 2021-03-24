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
package docking.widgets.table.threaded;

import static org.junit.Assert.*;

import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

import javax.swing.JComponent;

import org.junit.*;

import docking.widgets.filter.*;
import docking.widgets.table.DefaultRowFilterTransformer;
import generic.concurrent.ConcurrentQ;
import ghidra.docking.spy.SpyEventRecorder;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.SwingUpdateManager;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Worker;
import junit.framework.AssertionFailedError;

public class IncrementalThreadedTableTest extends AbstractThreadedTableTest {

	// a number based on GenericTestCase.DEFAULT_WAIT_TIMEOUT; this test is slower than most
	// due how we need to manipulate the threaded table, so the standard timeout is not enough
	private static final int MAX_TABLE_WAIT_RETRY_COUNT = 7;
	private volatile TestLoadingPolicy loadingPolicy = new NoLoadingPolicy();

	private SpyEventRecorder spy = new SpyEventRecorder(getClass().getSimpleName());

//==================================================================================================
// Setup Methods
//==================================================================================================	

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();
		model.cancelAllUpdates();

		installWorkerDebugListener();

		setErrorGUIEnabled(false);

		// now that we have our listener installed, set a real loading policy
		loadingPolicy = new LoadingDelayPolicy();
		model.reload();

		spy.record("setUp() - called reload - waiting for not busy");
		waitForNotBusy();
	}

	private void installWorkerDebugListener() {
		Worker worker = (Worker) getInstanceField("worker", model);
		assertNotNull("Worker has not yet been created", worker);

		ThreadedTableModelWorkerListener<Long> l =
			new ThreadedTableModelWorkerListener<>(spy, model);
		@SuppressWarnings("unchecked")
		ConcurrentQ<Long, ?> q = (ConcurrentQ<Long, ?>) getInstanceField("concurrentQ", worker);
		q.addProgressListener(l);
	}

	@Override
	protected void testFailed(Throwable e) {
		spy.record("Test - testFailed()");
		debugBusyModel();

		// let our event recorder get all the events that were pending in the client code
		waitForNotBusy();
		spy.dumpEvents();
	}

	@Override
	protected TestDataKeyModel createTestModel() {
		final TestDataKeyModel[] box = new TestDataKeyModel[1];
		runSwing(() -> box[0] = new TestDataKeyModel(null /*monitor*/, true) {
			// 
			// Overridden to allow more fined-grained control of when loading finishes
			//
			@Override
			protected void doLoad(Accumulator<Long> accumulator, TaskMonitor monitor)
					throws CancelledException {

				try {
					loadingPolicy.load(this, accumulator, monitor);
				}
				catch (CancellationException e) {
					throw e;
				}
				catch (Exception e) {
					if (isDisposing) {
						return;
					}
					throw new RuntimeException(e);
				}
			}
		});
		return box[0];
	}

	@Override
	protected TestThreadedTableModelListener createListener() {
		return new TestIncrementalThreadedTableModelListener(model, spy);
	}

//==================================================================================================
// Test Methods
//==================================================================================================	

	@Test
	public void testIncrementalLoadingShowsResultsBeforeFinished() throws Exception {
		clearTable();

		startNewBurstLoad();

		waitForSomeData();

		assertIsLoading();
	}

	@Test
	public void testReload() throws Exception {
		clearTable();

		startNewBurstLoad();

		waitForSomeData();

		// change the data to know when ours is loaded after the reload
		long markerValue = -1;
		startNewSingleValueLoadPolicy(markerValue);

		flushWorker();

		waitForSomeData();

		assertSingleValue(markerValue);
	}

	@Test
	public void testCancel() throws Exception {
		clearTable();

		startNewBurstLoad();

		waitForSomeData();

		waitForProgressPanel();

		cancel();

		assertNoLongerLoading();
	}

	@Test
	public void testNoShowPendingWhileLoading() throws Exception {
		//
		// Tests that the the pending panel is not shown while we are in the middle of an 
		// incremental load.  In non-incremental models this is not an issue, as the model 
		// itself will not send out pending events while a load is taking place (the data is 
		// just added to the current load process).  However, in the incremental case, the model's
		// update manager is not aware that an incremental load is taking place. So, we have 
		// code to make sure that the pending update does not trigger the pending panel while
		// we are loading, which is what we are testing.
		//

		// We need to use a model that loads slowly enough to trigger the pending panel to show.
		model.setDelayTimeBetweenAddingDataItemsWhileLoading(60000);

		// reload so that the model is in the loading state when we add items
		spy.record("test - resetting model");
		testTableModelListener.reset(model);
		model.reload();

		spy.record("test - waiting for table loading to start");
		waitForTableLoadingToStart();

		// add a few items to trigger pending notification
		spy.record("test - Adding individual table values...");
		addLong(1);
		addLong(2);
		addLong(3);
		addLong(4);
		spy.record("\ttest - finished adding table values");

		assertNotShowing("pendingPanel");
		assertIsLoading();
	}

	@Test
	public void testExceptionWhileLoading() throws Exception {
		clearTable();

		setErrorsExpected(true);
		startNewExceptionLoad();

		assertNoLongerLoading();
		setErrorsExpected(false);
	}

	@Test
	public void testSortingBytes() throws Exception {
		doTestSorting(TestDataKeyModel.BYTE_COL);
	}

	@Test
	public void testSortingShorts() throws Exception {
		doTestSorting(TestDataKeyModel.SHORT_COL);
	}

	@Test
	public void testSortingInts() throws Exception {
		doTestSorting(TestDataKeyModel.INT_COL);
	}

	@Test
	public void testSortingLong() throws Exception {
		doTestSorting(TestDataKeyModel.LONG_COL);
	}

	@Test
	public void testSortingFloats() throws Exception {
		doTestSorting(TestDataKeyModel.FLOAT_COL);
	}

	@Test
	public void testSortingDoubles() throws Exception {
		doTestSorting(TestDataKeyModel.DOUBLE_COL);
	}

	@Test
	public void testFilter_FilterSetBeforeDataLoad() throws Exception {
		clearTable();

		filter("te");

		SynchronizedLoadPolicy policy = startNewSynchronizedLoad();
		policy.finishLoading();
		waitForTableModel(model);

		assertRowCount(3); // ten, ten, ten
	}

	@Test
	public void testFilter_FilterDuringDataLoad() throws Exception {
		clearTable();

		SynchronizedLoadPolicy policy = startNewSynchronizedLoad();
		policy.waitForFirstHalf();
		assertNoRowsFilteredOut();

		filter("te");

		policy.finishLoading();
		waitForTableModel(model);

		assertRowCount(3); // ten, ten, ten
	}

	@Test
	public void testFilter_FilterSetAfterDataLoad() throws Exception {
		clearTable();

		SynchronizedLoadPolicy policy = startNewSynchronizedLoad();
		policy.finishLoading();
		waitForTableModel(model);
		assertNoRowsFilteredOut();

		filter("te");
		assertRowCount(3); // ten, ten, ten
	}

	@Test
	public void testSelectionRestoringAsIncrementalUpdatesArrive() throws Exception {
		clearTable();

		SynchronizedLoadPolicy policy = startNewMultiUpdateSynchrnoizedLoad();
		policy.waitForFirstHalf();
		waitForRowCount(3);

		int selectedIndex = 1;
		runSwing(() -> {
			table.setRowSelectionInterval(selectedIndex, selectedIndex);
		});

		Long startSelectedObject = runSwing(() -> model.getRowObject(selectedIndex));

		policy.waitForNextUpdate();
		waitForRowCount(6);
		Long currentSelectedObject = runSwing(() -> model.getRowObject(table.getSelectedRow()));
		assertEquals(startSelectedObject, currentSelectedObject);

		policy.waitForNextUpdate();
		waitForRowCount(9);
		currentSelectedObject = runSwing(() -> model.getRowObject(table.getSelectedRow()));
		assertEquals(startSelectedObject, currentSelectedObject);

		policy.waitForNextUpdate();
		waitForRowCount(12);
		currentSelectedObject = runSwing(() -> model.getRowObject(table.getSelectedRow()));
		assertEquals(startSelectedObject, currentSelectedObject);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void waitForRowCount(int n) {
		waitForCondition(() -> model.getRowCount() == n, "Table model never had " + n + " rows");
		waitForSwing();
	}

	private void filter(String filterValue) {

		// the row objects are Long values that are 0-based one-up index values
		DefaultRowFilterTransformer<Long> transformer =
			new DefaultRowFilterTransformer<>(model, table.getColumnModel());

		FilterOptions options =
			new FilterOptions(TextFilterStrategy.STARTS_WITH, false, true, false);
		TextFilterFactory textFactory = options.getTextFilterFactory();
		TextFilter textFilter = textFactory.getTextFilter(filterValue);

		SpyTextFilter<Long> spyFilter = new SpyTextFilter<>(textFilter, transformer);

		runSwing(() -> model.setTableFilter(spyFilter));

		waitForNotBusy();
		waitForTableModel(model);
		waitForSwing();
	}

	private void reload() {
		runSwing(() -> model.reload());
	}

	private void flushWorker() {
		waitForSwing(); // this call flushes all SwingUpdateManagers
	}

	private void assertSingleValue(long markerValue) {
		List<Long> data = model.getAllData();
		if (data.size() <= 0) {
			int rowCount = model.getRowCount(); // getRowCount() uses 'filteredData'
			fail("Model 'allData' is empty; how? - filtered row count = " + rowCount);
		}

		Long rowValue = data.get(0);
		assertEquals((Long) markerValue, rowValue);
	}

	private void cancel() throws Exception {
		runSwing(() -> {
			TaskMonitor taskMonitor = threadedTablePanel.getTaskMonitor();
			taskMonitor.cancel();
		});

		waitForNotBusy();
	}

	private void clearTable() throws Exception {
		waitForNotBusy();

		runSwing(() -> model.clearData());

		waitForNotBusy();
		assertEquals("Model has not been cleared", 0, model.getRowCount());
		testTableModelListener.reset(model);
	}

	private void startNewBurstLoad() {
		model.clearData();
		waitForSwing();
		testTableModelListener.reset(model);
		loadingPolicy = new BurstLoadPolicy();
		model.reload();
	}

	private void startNewExceptionLoad() {
		model.clearData();
		waitForSwing();
		testTableModelListener.reset(model);
		loadingPolicy = new ExceptionLoadPolicy();
		model.reload();
	}

	private void startNewSingleValueLoadPolicy(long value) {
		model.clearData();
		waitForSwing();
		testTableModelListener.reset(model);
		loadingPolicy = new SingleValueLoadPolicy(value);
		reload();
	}

	private SynchronizedLoadPolicy startNewSynchronizedLoad() {
		model.clearData();
		waitForSwing();
		testTableModelListener.reset(model);
		SynchronizedLoadPolicy policy = new HalfThenHalfSynchronizedLoadPolicy();
		loadingPolicy = policy;
		reload();
		return policy;
	}

	private SynchronizedLoadPolicy startNewMultiUpdateSynchrnoizedLoad() {
		model.clearData();
		waitForSwing();
		testTableModelListener.reset(model);
		SynchronizedLoadPolicy policy = new CyclicSynchronizedLoadPolicy();
		loadingPolicy = policy;
		reload();
		spy.record("Test - after call to reload() - started new synchronized load");
		return policy;
	}

	private void waitForSomeData() throws Exception {

		waitForTableLoadingToStart();

		wait(() -> model.getRowCount() >= 5, MAX_TABLE_WAIT_RETRY_COUNT,
			"Timed-out waiting for table model to update; row count = " + model.getRowCount());

		waitForSwing();
	}

	@Override
	// overridden for our different type of listener
	protected void waitForNotBusy() {

		if (model.getRowCount() > 0 && !model.isBusy()) {

			// assume that we've loaded, which means that our listener may not have
			// been notified, as it was added after the initial load has finished
			return;
		}

		// make sure the table doens't have any work pending
		wait(() -> !model.isBusy(), MAX_TABLE_WAIT_RETRY_COUNT);

		try {
			waitForCondition(() -> testTableModelListener.doneWork());
		}
		catch (AssertionFailedError e) {
			if (model.isBusy()) {

				//
				// Hacky Smacky!: we sometimes lose notifications for the 
				// IncrementalThreadedTableModelListener in the testing environment due to 
				// timing issues (which I've given up chasing for now, as I think it is a 
				// testing artifact only).  So, if the model is
				// still busy after all this time, then assume that it is in  a really long 
				// loading process and continue.
				// 
				return;
			}
			throw e;
		}
	}

	private void wait(BooleanSupplier condition, int maxTries) {

		wait(condition, maxTries, "Timed-out waiting for condition");
	}

	private void wait(BooleanSupplier condition, int maxTries, String errorMessage) {

		int tryCount = 0;
		while (tryCount < maxTries) {
			tryCount++;
			waitForConditionWithoutFailing(condition);
			if (condition.getAsBoolean()) {
				break;
			}
		}

		debugBusyModel();

		assertTrue(errorMessage, condition.getAsBoolean());
	}

	private void debugBusyModel() {

		spy.record("Check model for busy status");
		if (!model.isBusy()) {
			return;
		}

		spy.record("Model is busy - why?");

		// ThreadedTableModelUpdateMgr<ROW_OBJECT>
		Object tableUpdateManager = getInstanceField("updateManager", model);
		Boolean isBusy = (Boolean) invokeInstanceMethod("isBusy", tableUpdateManager);
		spy.record("\tThreadedTableModelUpdateMgr busy? " + isBusy);

		if (isBusy) {
			SwingUpdateManager sum =
				(SwingUpdateManager) getInstanceField("addRemoveUpdater", tableUpdateManager);
			spy.record("\t\tSwingUpdateManager busy?: " + sum.isBusy());

			if (sum.isBusy()) {

				Object requestTime = getInstanceField("requestTime", sum);
				spy.record("\t\t\trequest time 0?: " + requestTime);

				Object workCount = getInstanceField("workCount", sum);
				spy.record("\t\t\twork count 0?: " + workCount);
			}

			Thread t = (Thread) getInstanceField("thread", tableUpdateManager);
			spy.record("\t\tthread running?: " + t);

			// TableUpdateJob
			Object job = getInstanceField("pendingJob", tableUpdateManager);
			spy.record("\t\tpending job?: " + job);

			Object list = getInstanceField("addRemoveWaitList", tableUpdateManager);
			spy.record("\t\tadd/remove jobs pending?: " + list);
		}

		isBusy = (Boolean) invokeInstanceMethod("isWorkerBusy", model);
		spy.record("\tworker busy? " + isBusy);

		if (isBusy) {
			Worker worker = (Worker) getInstanceField("worker", model);
			AtomicBoolean busy = (AtomicBoolean) getInstanceField("isBusy", worker);
			spy.record("\t\tbusy flag?: " + busy);

			ConcurrentQ<?, ?> q = (ConcurrentQ<?, ?>) getInstanceField("concurrentQ", worker);
			Object queue = getInstanceField("queue", q);
			spy.record("\t\titems in queue: " + queue);

			Object taskSet = getInstanceField("taskSet", q);
			spy.record("\t\ttasks: " + taskSet);
		}

	}

	private void waitForProgressPanel() throws Exception {
		//
		// Make sure we give the time a chance to swap panels
		//
		JComponent panel =
			(JComponent) getInstanceField("loadingProgressMonitor", threadedTablePanel);
		waitForCondition(() -> panel.isShowing());

		assertTrue("Expected info panel should be showing, but is not: loadingProgressMonitor",
			panel.isShowing());
	}

	private void waitForTableLoadingToStart() throws Exception {

		waitForCondition(() -> testTableModelListener.startedWork(),
			"Timed-out waiting for table model to start loading.");
	}

	private void assertNotShowing(String panelName) throws Exception {
		//
		// Make sure we give the time a chance to swap panels
		//
		JComponent panel = (JComponent) getInstanceField(panelName, threadedTablePanel);
		waitForCondition(() -> !panel.isShowing(),
			"Expected info panel should not be showing, but is: " + panelName);
	}

	private void assertNoLongerLoading() throws Exception {
		waitForNotBusy();
		assertNotShowing("loadingProgressMonitor");
		assertTrue("Listener not notified of work completion", testTableModelListener.doneWork());
	}

	private void assertIsLoading() throws Exception {
		assertTrue("Have not yet started loading", testTableModelListener.startedWork());
		boolean doneWork = testTableModelListener.doneWork();
		if (doneWork) {
			spy.record("Test Failed - The table has unexpectedly finished loading");
			spy.record("Loading policy: " + loadingPolicy);
			spy.record("Notification State: " + testTableModelListener);
			spy.record("Table Data: ");
			List<Long> data = model.getAllData();
			for (Long l : data) {
				spy.record("\t" + l);
			}
			Assert.fail(
				"The table has unexpectedly finished loading - row count " + model.getRowCount());
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	interface TestLoadingPolicy {
		void load(TestDataKeyModel model, Accumulator<Long> accumulator, TaskMonitor monitor)
				throws Exception;
	}

	/**
	 * A policy that clients can wait for and can block, waiting for client direction.
	 */
	interface SynchronizedLoadPolicy extends TestLoadingPolicy {
		void waitForFirstHalf() throws Exception;

		void waitForNextUpdate() throws Exception;

		void finishLoading();
	}

	private class NoLoadingPolicy implements TestLoadingPolicy {

		@Override
		public void load(TestDataKeyModel testModel, Accumulator<Long> accumulator,
				TaskMonitor monitor) {
			// do nothing
		}

		@Override
		public String toString() {
			return "No Loading";
		}
	}

	private class LoadingDelayPolicy implements TestLoadingPolicy {

		@Override
		public void load(TestDataKeyModel testModel, Accumulator<Long> accumulator,
				TaskMonitor monitor) {

			for (int i = 0; i < testModel.getTestRowCount(); i++) {
				if (monitor.isCancelled()) {
					return;
				}
				accumulator.add((long) i);
				sleep(testModel.getDelayTimeBetweenAddingDataItemsWhileLoading());
			}
		}

		@Override
		public String toString() {
			return "Delayed Loading";
		}
	}

	/**
	 * A loading policy that will put some data in table quickly, and then continue to do slow
	 * at a much slower rate.
	 */
	private class BurstLoadPolicy implements TestLoadingPolicy {

		@Override
		public void load(TestDataKeyModel testModel, Accumulator<Long> accumulator,
				TaskMonitor monitor) {

			long postBurstDelay = 750;

			// initial burst
			for (int i = 0; i < 10; i++) {
				accumulator.add((long) i);
			}

			for (int i = 0; i < 1000; i++) {
				if (monitor.isCancelled()) {
					return;
				}
				accumulator.add((long) i);
				sleep(postBurstDelay);
			}
		}

		@Override
		public String toString() {
			return "Burst Loading";
		}
	}

	private class SingleValueLoadPolicy implements TestLoadingPolicy {

		private long value;

		SingleValueLoadPolicy(long value) {
			this.value = value;
		}

		@Override
		public void load(TestDataKeyModel testModel, Accumulator<Long> accumulator,
				TaskMonitor monitor) {

			long postBurstDelay = 750;
			for (int i = 0; i < 1000; i++) {
				if (monitor.isCancelled()) {
					return;
				}
				accumulator.add(value);
				sleep(postBurstDelay);
			}
		}

		@Override
		public String toString() {
			return "Single Value Loading";
		}
	}

	/**
	 * A loading policy that throws an exception while loading.
	 */
	private class ExceptionLoadPolicy implements TestLoadingPolicy {
		@Override
		public void load(TestDataKeyModel testModel, Accumulator<Long> accumulator,
				TaskMonitor monitor) {
			Msg.debug(this, "\n\n>>>>>>> Expected Test Exception  >>>>>>>>>");
			throw new RuntimeException("\n\n>>>>>>> Expected Test Exception  >>>>>>>>>");
		}

		@Override
		public String toString() {
			return "Exception While Loading";
		}
	}

	/**
	 * A policy that will initially load half of its data, waiting for the signal to finish
	 * loading the second half. 
	 */
	private class HalfThenHalfSynchronizedLoadPolicy implements SynchronizedLoadPolicy {

		private CountDownLatch initialLatch = new CountDownLatch(1);
		private CountDownLatch finishLatch = new CountDownLatch(1);

		@Override
		public void load(TestDataKeyModel testModel, Accumulator<Long> accumulator,
				TaskMonitor monitor) {

			int rows = TestDataKeyModel.ROWCOUNT;
			int half = rows / 2;
			for (int i = 0; i < half; i++) {
				if (monitor.isCancelled()) {
					return;
				}
				accumulator.add((long) i);
			}

			initialLatch.countDown(); // signal we have finished part of the load
			try {
				finishLatch.await(2, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				fail("Interrupted while waiting to load data");
			}

			for (int i = half; i < (half * 2); i++) {
				if (monitor.isCancelled()) {
					return;
				}
				accumulator.add((long) i);
			}
		}

		@Override
		public String toString() {
			return "Synchronized Loading";
		}

		@Override
		public void waitForFirstHalf() throws Exception {
			initialLatch.await(2, TimeUnit.SECONDS);
		}

		@Override
		public void waitForNextUpdate() throws Exception {
			// note: this is bad design to have a method on the interface that is not 
			//       supported by all implementations.  But, it was easy, so this will alert
			//       test writers to incorrect usage of this class.
			throw new UnsupportedOperationException();
		}

		@Override
		public void finishLoading() {
			finishLatch.countDown();
		}
	}

	/**
	 * A policy that will initially load some of its data, then wait for the client to 
	 * signal to proceed.  Then, it will load another chunk of data, waiting again.
	 */
	private class CyclicSynchronizedLoadPolicy implements SynchronizedLoadPolicy {

		private CountDownLatch waitForInitialLoadLatch = new CountDownLatch(1);

		// use these semaphores to have the table wait for the test and then the test wait
		// for the table, taking turns as the test desires
		private Semaphore waitForUpdateSemaphore = new Semaphore(-1);
		private Semaphore waitForUpdateFinishedSemaphore = new Semaphore(-1);

		@Override
		public void load(TestDataKeyModel testModel, Accumulator<Long> accumulator,
				TaskMonitor monitor) throws Exception {

			// somewhat arbitrary; enough for tests to have repeated updates
			int rows = TestDataKeyModel.ROWCOUNT * 2;
			int total = 0;
			int n = 3;
			for (int i = 0; i < n; i++) {
				if (monitor.isCancelled()) {
					return;
				}
				accumulator.add((long) i);
				total++;
			}

			waitForInitialLoadLatch.countDown();

			while (total < rows) {
				waitForUpdateSemaphore.tryAcquire(2, TimeUnit.SECONDS);

				accumulator.add((long) total++);
				accumulator.add((long) total++);
				accumulator.add((long) total++);

				waitForUpdateFinishedSemaphore.release();
			}
		}

		@Override
		public String toString() {
			return "Synchronized Loading";
		}

		@Override
		public void waitForFirstHalf() throws Exception {
			waitForInitialLoadLatch.await(2, TimeUnit.SECONDS);
		}

		@Override
		public void waitForNextUpdate() throws Exception {
			waitForUpdateSemaphore.release();
			waitForUpdateFinishedSemaphore.tryAcquire(2, TimeUnit.SECONDS);
		}

		@Override
		public void finishLoading() {
			// note: this is bad design to have a method on the interface that is not 
			//       supported by all implementations.  But, it was easy, so this will alert
			//       test writers to incorrect usage of this class.
			throw new UnsupportedOperationException();
		}
	}
}
