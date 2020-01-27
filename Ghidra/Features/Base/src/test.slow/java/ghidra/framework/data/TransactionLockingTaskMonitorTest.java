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
package ghidra.framework.data;

import static org.junit.Assert.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class TransactionLockingTaskMonitorTest extends AbstractGhidraHeadedIntegrationTest {

	// LockingTaskMonitor only functional in Headed mode

	private static final int THREAD_COUNT = 5;

	private DomainObjectAdapterDB program;

	private volatile Throwable throwable;

	private CountDownLatch coordinationStartLatch = new CountDownLatch(THREAD_COUNT);
	private CountDownLatch coordinationInTransactionLatch = new CountDownLatch(THREAD_COUNT);
	private CountDownLatch coordinationEndLatch = new CountDownLatch(THREAD_COUNT);

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("test", ProgramBuilder._X86, this);
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		program.release(this);
	}

	@Test
	public void testTransactionWaitForSnapshotLock() throws Exception {

		LockingTaskMonitor lockMonitor = program.lockForSnapshot(true, "Lock Test");
		try {
			for (int i = 0; i < THREAD_COUNT; i++) {
				Thread thread = new Thread(() -> {
					coordinationStartLatch.countDown();
					Integer txId = null;
					try {
						txId = program.startTransaction("Test");
					}
					catch (Throwable t) {
						t.printStackTrace();
						throwable = t;
					}
					finally {
						coordinationInTransactionLatch.countDown();
						if (txId != null) {
							program.endTransaction(txId, true);
						}
					}
					coordinationEndLatch.countDown();
				}, "Test-" + i);
				thread.start();
			}

			coordinationStartLatch.await(2, TimeUnit.SECONDS);

			// Provide some time for threads to invoke startTransaction 
			// which should block each thread.  This is needed to 
			// provide some confidence in the coordinationInTransactionLatch
			// assertion below.
			Thread.sleep(500);

			// No transaction should have been issued yet
			assertEquals(THREAD_COUNT, coordinationInTransactionLatch.getCount());
		}
		finally {
			lockMonitor.releaseLock();
		}

		// wait for all threads to obtain transaction
		coordinationInTransactionLatch.await(2, TimeUnit.SECONDS);

		// wait for all thread to terminate
		coordinationEndLatch.await(2, TimeUnit.SECONDS);

		assertNull("Error occurred in transaction thread", throwable);

	}

	@Test
	public void testTransactionWaitForLock() throws Exception {

		assertTrue("Obtain lock", program.lock("test"));
		try {
			for (int i = 0; i < THREAD_COUNT; i++) {
				Thread thread = new Thread(() -> {
					coordinationStartLatch.countDown();
					Integer txId = null;
					try {
						txId = program.startTransaction("Test");
					}
					catch (Throwable t) {
						t.printStackTrace();
						throwable = t;
					}
					finally {
						coordinationInTransactionLatch.countDown();
						if (txId != null) {
							program.endTransaction(txId, true);
						}
					}
					coordinationEndLatch.countDown();
				}, "Test-" + i);
				thread.start();
			}

			coordinationStartLatch.await(2, TimeUnit.SECONDS);

			Thread.sleep(500);

			// No transaction should have been issued yet
			assertEquals(THREAD_COUNT, coordinationInTransactionLatch.getCount());
		}
		finally {
			program.unlock();
		}

		// wait for all threads to obtain transaction
		coordinationInTransactionLatch.await(2, TimeUnit.SECONDS);

		// wait for all thread to terminate
		coordinationEndLatch.await(2, TimeUnit.SECONDS);

		assertNull("Error occurred in transaction thread", throwable);

	}
}
