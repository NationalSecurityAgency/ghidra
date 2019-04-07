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

import static org.junit.Assert.assertFalse;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.framework.model.DomainObjectLockedException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;
import mockit.*;

public class TransactionLockingTest extends AbstractGenericTest {

	private Program program;

	private CountDownLatch programLockedLatch = new CountDownLatch(1);
	private CountDownLatch lockExceptionLatch = new CountDownLatch(1);

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
	public void testTransactionWaitForLock() throws Exception {

		// Inject DomainObjectLockedException mock to trigger lockExceptionLatch
		new SpyDomainObjectLockedException();

		AtomicReference<Exception> exceptionRef = new AtomicReference<>();

		// setup transaction thread
		Thread txThread = new Thread(() -> {
			try {
				programLockedLatch.await(2, TimeUnit.SECONDS);
				int txId = program.startTransaction("Test"); // Block until lock released
				program.endTransaction(txId, true);
			}
			catch (Exception e) {
				exceptionRef.set(e);
			}

		}, "Tx-Thread");
		txThread.start();

		//setup lock thread
		Thread lockThread = new Thread(() -> {
			boolean gotLock = program.lock("TestLock");
			if (!gotLock) {
				exceptionRef.set(new AssertException("Failed to obtain lock"));
			}

			programLockedLatch.countDown(); // signal for startTransaction

			if (gotLock) {
				try {
					lockExceptionLatch.await(2, TimeUnit.SECONDS);
				}
				catch (InterruptedException e) {
					// unexpected
					exceptionRef.set(e);
				}
				finally {
					program.unlock();
				}
			}

		}, "Lock-Thread");
		lockThread.start();

		// wait for transaction test thread to complete
		txThread.join(2000);
		assertFalse("Tx-Thread may be hung", txThread.isAlive());

		Exception exc = exceptionRef.get();
		if (exc != null) {
			failWithException("Transaction Failure", exc);
		}

	}

	private class SpyDomainObjectLockedException extends MockUp<DomainObjectLockedException> {

		/**
		 * Mock/Inject constructor for DomainObjectLockedException to provide detection
		 * of its construction via lockExceptionLatch
		 * @param invocation
		 * @param reason
		 */
		@Mock
		public void $init(Invocation invocation, String reason) {
			lockExceptionLatch.countDown();
		}
	}
}
