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
package ghidra.framework.store.local;

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.util.Msg;

/**
 * 
 */
public class LockFileTest extends AbstractGenericTest {

	private static final File DIRECTORY = new File(AbstractGenericTest.getTestDirectoryPath());
	private static final String LOCKNAME = "test";
	private static final File LOCKFILE = new File(DIRECTORY, LOCKNAME + ".lock");
	private static final int DEFAULT_MAX_LOCK_LEASE_PERIOD_MS = 1500;
	private static final int DEFAULT_LOCK_RENEWAL_PERIOD = DEFAULT_MAX_LOCK_LEASE_PERIOD_MS - 200;
	/**
	 * The default timeout for obtaining a lock.
	 */
	private static final int DEFAULT_TIMEOUT_MS = 3000;

	/**
	 * Constructor for LockFileTest.
	 * @param arg0
	 */
	public LockFileTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		LOCKFILE.delete();
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		LOCKFILE.delete();

	}

	@Test
	public void testLock() {

		LockFile lock1 = new LockFile(DIRECTORY, LOCKNAME, DEFAULT_MAX_LOCK_LEASE_PERIOD_MS,
			DEFAULT_LOCK_RENEWAL_PERIOD, DEFAULT_TIMEOUT_MS);
		LockFile lock2 = new LockFile(DIRECTORY, LOCKNAME, DEFAULT_MAX_LOCK_LEASE_PERIOD_MS,
			DEFAULT_LOCK_RENEWAL_PERIOD, DEFAULT_TIMEOUT_MS);

		System.out.println("Create lock: " + lock1);
		boolean rc = lock1.createLock(DEFAULT_TIMEOUT_MS, false);
		assertTrue(rc);

		System.out.println("Create a new lock w/ hold (must wait for old lock to expire)...");
		rc = lock2.createLock(DEFAULT_TIMEOUT_MS, true);
		assertTrue(rc);

		System.out.println("Verify that lock is holding...");
		rc = lock1.createLock(DEFAULT_TIMEOUT_MS, false);
		assertTrue(!rc);

		System.out.println("Verify again that lock is holding...");
		rc = lock1.createLock(DEFAULT_TIMEOUT_MS, false);
		assertTrue(!rc);

		System.out.println("Get second immediate lock...");
		rc = lock2.createLock(0, false);
		assertTrue(rc);

		System.out.println("Remove first lock immediate...");
		lock2.removeLock();
		assertTrue(lock2.haveLock()); // should still have lock
		assertTrue(lock2.haveLock(true));

		System.out.println("Remove second lock...");
		lock2.removeLock();
		assertTrue(!lock2.haveLock()); // should not have lock
		assertTrue(!lock2.haveLock(true));

		System.out.println("Create immediate lock: " + lock1);
		rc = lock1.createLock(0, false);
		assertTrue(rc);

		Msg.error(this, ">>>>>>>>>>>>>>>> Expected Exception");
		lock2.removeLock(); // should have no affect
		Msg.error(this, "<<<<<<<<<<<<<<<< End Expected Exception");
		assertTrue(lock1.haveLock(true));

		System.out.println("Remove lock...");
		lock1.removeLock();
		assertTrue(!lock1.haveLock(true));

	}

}
