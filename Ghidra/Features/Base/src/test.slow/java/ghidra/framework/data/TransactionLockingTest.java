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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.model.DomainObjectLockedException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;

public class TransactionLockingTest extends AbstractGenericTest {

	private Program program;

	// placeholder for exceptions encountered while testing; this will be checked at the end
	private Exception unexpectedException = null;

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("test", ProgramBuilder._X86, this);
		program = builder.getProgram();
	}

	/**
	 * This test attempts to verify 2 things: 1) that a client attempting to start a transaction
	 * on a locked domain object will get an exception, and 2) the client will keep waiting after
	 * getting the exception, due to the use of a while(true) loop in the system under test.
	 */
	@Test
	public void testTransactionWaitForLock() {

		//
		// The latch uses a count of 3, which is an arbitrary number greater than 1.  This allows
		// us to know that the system performed the expected spin/wait loop more than once.
		//
		CountDownLatch clientWaitLatch = new CountDownLatch(3);
		Function<DomainObjectLockedException, Boolean> exceptionHandler = e -> {
			clientWaitLatch.countDown();
			return true; // keep waiting; the client will get released by the lock thread
		};

		//
		// Thread that will block while waiting to start the transaction
		//
		CountDownLatch lockThreadLatch = new CountDownLatch(1);
		Thread txThread = new Thread(() -> {
			try {
				lockThreadLatch.await(2, TimeUnit.SECONDS);

				//
				// Cast to db to use package-level method for testing.
				//
				// The call to startTransaction() will block until our exception handler signals
				// to continue.
				//
				DomainObjectAdapterDB programDb = (DomainObjectAdapterDB) program;
				int txId = programDb.startTransaction("Test", null, exceptionHandler);
				program.endTransaction(txId, true);
			}
			catch (Exception e) {
				unexpectedException = e;
			}

		}, "Tx-Client-Thread");
		txThread.start();

		//
		// Thread that will acquire the program lock, which will block the other thread
		//
		Thread lockThread = new Thread(() -> {
			if (!program.lock("TestLock")) {
				unexpectedException = new AssertException("Failed to obtain program lock");
				lockThreadLatch.countDown(); // signal for the Transaction Thread to proceed
				return;
			}

			lockThreadLatch.countDown(); // signal for the Transaction Thread to proceed
			try {
				// keep blocking until we know the client has waited for our test exception handler
				// to signal to continue
				clientWaitLatch.await(2, TimeUnit.SECONDS);
			}
			catch (InterruptedException e) {
				unexpectedException = new AssertException(
					"Test thread interrupted waiting for client transaction thread", e);
			}
			finally {
				program.unlock();
			}

		}, "Program-Lock-Thread");
		lockThread.start();

		// wait for transaction test thread to complete
		try {
			txThread.join(2000);
		}
		catch (InterruptedException e) {
			unexpectedException = new AssertException(
				"Test thread interrupted waiting for client transaction thread", e);
		}

		if (unexpectedException != null) {
			failWithException("Unexpected test failure", unexpectedException);
		}

	}

}
