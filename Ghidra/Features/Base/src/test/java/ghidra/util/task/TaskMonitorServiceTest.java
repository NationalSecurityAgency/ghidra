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

import java.util.concurrent.atomic.*;

import org.junit.*;

import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;

/**
 * Tests for the {@link TaskMonitorService}
 */
public class TaskMonitorServiceTest extends AbstractGhidraHeadedIntegrationTest {

	@Before
	public void setup() {
		// nothing to do
	}
	
	@After
	public void teardown() {
		// nothing to do
	}
	
	/**
	 * Verifies that in a single-threaded environment, the {@link TaskMonitorService} 
	 * returns the correct instance of {@link TaskMonitor}. In this case, the initial
	 * monitor is registered by the {@link TaskLauncher task launcher}; the next call
	 * to {@link TaskMonitorService#getMonitor() getMonitor} should return the same.
	 */
	@Test
	public void testSingleThread() {
		
		TaskLauncher.launch(new Task("task1") {

			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				
				TaskMonitor newMonitor = TaskMonitorService.getMonitor();
				assertSame(newMonitor, monitor);
			}

		});

		waitForTasks();
	}

	/**
	 * Verifies that in a single-threaded environment, the {@link TaskMonitorService} 
	 * returns the same instance of {@link TaskMonitor} each time one is
	 * requested.
	 * <p>
	 * Note that the first time a monitor is requested it will always return the primary
	 * monitor that allows progress changes. Each subsequent time it will return the
	 * secondary monitor; these secondary monitors is what this test is verifying.
	 */
	@Test
	public void testSingleThreadSecondaryMonitors() {

		TaskLauncher.launch(new Task("task1") {

			@Override
			public void run(TaskMonitor monitor) throws CancelledException {

				// First monitor requested is always the primary - just make the call so 
				// we can get to retrieving some secondary monitors
				TaskMonitorService.getMonitor();

				TaskMonitor secondaryMonitor1 = TaskMonitorService.getMonitor();
				TaskMonitor secondaryMonitor2 = TaskMonitorService.getMonitor();
					
				assertEquals(secondaryMonitor1, secondaryMonitor2);
			}
			
		});
		
		waitForTasks();		
	}
	
	/**
	 * Verifies that in a multi-threaded environment, the {@link TaskMonitorService} 
	 * returns a different instance of {@link TaskMonitor} for each thread.
	 */
	@Test
	public void testMultipleThreads() {
		
		AtomicReference<TaskMonitor> localMonitor1 = new AtomicReference<>();
		AtomicReference<TaskMonitor> localMonitor2 = new AtomicReference<>();
		
		TaskLauncher.launch(new Task("task1") {

			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				localMonitor1.set(TaskMonitorService.getMonitor());
			}
			
		});
		
		TaskLauncher.launch(new Task("task2") {

			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				localMonitor2.set(TaskMonitorService.getMonitor());
			}
			
		});
		
		waitForTasks();
		
		assertNotSame(localMonitor1.get(), localMonitor2.get());
	}
		
	/**
	 * Tests that if we try to register a monitor while on the Swing thread an exception will be 
	 * thrown.
	 */
	@Test
	public void testSetMonitorOnSwingThread() {
		
		SystemUtilities.runSwingNow(() -> {

			try {
				TaskMonitorService.register(TaskMonitor.DUMMY);
			}
			catch (Exception e) {
				// expected catch
				return;
			}

			fail("Successful register of monitor on Swing thread (should not have been allowed)");
		});
		
		waitForTasks();
		
	}

	/**
	 * Verifies that if a client attempts to set a monitor on a thread that already has a monitor,
	 * an exception will be thrown.
	 * <p>
	 * Note: The first monitor is registered behind the scenes by the task launcher
	 */
	@Test
	public void testRegisterMultipleMonitors() {

		TaskLauncher.launch(new Task("task") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {

				try {
					TaskMonitorService.register(TaskMonitor.DUMMY);
				}
				catch (Exception ex) {
					// expected catch 
					return;
				}

				fail("Successful register of new monitor (should not have been allowed)");
			}
		});

		waitForTasks();
	}

	/**
	 * Verifies that unique monitor id's are correctly assigned to each thread that registers
	 * a monitor
	 */
	@Test
	public void testMonitorIds() {

		AtomicInteger monitor1Id = new AtomicInteger();
		AtomicInteger monitor2Id = new AtomicInteger();
		AtomicInteger monitor3Id = new AtomicInteger();

		Thread thread1 =
			new Thread(() -> monitor1Id.set(TaskMonitorService.register(TaskMonitor.DUMMY)));

		Thread thread2 =
			new Thread(() -> monitor2Id.set(TaskMonitorService.register(TaskMonitor.DUMMY)));

		Thread thread3 =
			new Thread(() -> monitor3Id.set(TaskMonitorService.register(TaskMonitor.DUMMY)));

		thread1.start();
		thread2.start();
		thread3.start();

		waitForTasks();

		boolean areIdsDifferent =
			(monitor1Id.get() != monitor2Id.get()) && (monitor2Id.get() != monitor3Id.get());
		assertTrue(areIdsDifferent);
	}

	/**
	 * Verifies that if a client attempts to remove a monitor with an invalid id the request
	 * will fail
	 */
	@Test
	public void testRemoveMonitorFail() {

		AtomicBoolean removed = new AtomicBoolean(true);

		// All monitor id's are positive integers; this is guaranteed to generated a failure
		final int BOGUS_ID = -1;

		Thread thread1 = new Thread(() -> {
			TaskMonitorService.register(TaskMonitor.DUMMY);
			try {
				TaskMonitorService.remove(BOGUS_ID);
			}
			catch (Exception e) {
				// expected catch
				removed.set(false);
			}
		});
		
		thread1.start();

		waitForTasks();

		assertFalse(removed.get());
	}

	/**
	 * Verifies that a monitor can be successfully removed given a correct id
	 */
	@Test
	public void testRemoveMonitorSuccess() {

		AtomicBoolean removed = new AtomicBoolean(false);

		AtomicInteger monitorId = new AtomicInteger();

		Thread thread1 = new Thread(() -> {
			monitorId.set(TaskMonitorService.register(TaskMonitor.DUMMY));

			try {
				TaskMonitorService.remove(monitorId.get());
				removed.set(true);
			}
			catch (Exception e) {
				// should not be here
				fail();
			}
		});

		thread1.start();

		waitForTasks();

		assertTrue(removed.get());
	}

	/**
	 * Verifies that the first monitor returned from the service will be the 
	 * primary monitor
	 */
	@Test
	public void testRetrievePrimaryMonitor() {

		TaskLauncher.launch(new Task("task") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {

				TaskMonitor monitor1 = TaskMonitorService.getMonitor();
				assertTrue(monitor1 instanceof TaskDialog);
			}
		});

		waitForTasks();
	}

	/**
	 * Verifies that any subsequent requests after the initial request will result in
	 * a {@link SecondaryTaskDialog} being returned
	 */
	@Test
	public void testRetrieveSecondaryMonitor() {

		TaskLauncher.launch(new Task("task") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {

				TaskMonitor monitor1 = TaskMonitorService.getMonitor();
				assertTrue(monitor1 instanceof TaskDialog);

				monitor1 = TaskMonitorService.getMonitor();
				assertTrue(monitor1 instanceof SecondaryTaskMonitor);
			}
		});

		waitForTasks();
	}

	/**
	 * Verifies that calling finish on a primary monitor will cause it to
	 * be set back to an uninitialized state.
	 */
	@Test
	public void testMonitorFinishPrimary() {

		TaskLauncher.launch(new Task("task") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {

				TaskMonitor monitor1 = TaskMonitorService.getMonitor();
				assertTrue(monitor1 instanceof TaskDialog);

				monitor1.finished();

				monitor1 = TaskMonitorService.getMonitor();
				assertTrue(monitor1 instanceof TaskDialog);
			}
		});

		waitForTasks();
	}

	/**
	 * Verifies that calling finish on a secondary monitor will NOT cause
	 * it to be uninitialized (only primary monitors can reset this state)
	 */
	@Test
	public void testMonitorFinishSecondary() {

		TaskLauncher.launch(new Task("task") {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {

				TaskMonitor monitor1 = TaskMonitorService.getMonitor();
				assertTrue(monitor1 instanceof TaskDialog);

				monitor1 = TaskMonitorService.getMonitor();
				assertTrue(monitor1 instanceof SecondaryTaskMonitor);

				monitor1.finished();

				monitor1 = TaskMonitorService.getMonitor();
				assertTrue(monitor1 instanceof SecondaryTaskMonitor);
			}
		});

		waitForTasks();
	}
}
