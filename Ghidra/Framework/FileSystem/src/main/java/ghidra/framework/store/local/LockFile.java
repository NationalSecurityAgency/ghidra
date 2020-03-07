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

import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

import java.io.*;
import java.util.Date;
import java.util.Random;

/**
 * Provides for the creation and management of a named lock file. Keep in mind
 * that if a lock expires it may be removed without notice.  Care should be
 * taken to renew a lock file in a timely manner.
 * 
 * 
 */
public class LockFile {

	/**
	 * The maximum lock lease period in seconds.  To retain a 
	 * lock longer than this period of time, the renewLock() method must be 
	 * invoked before the lock expires.  This is the amount of time a user will have to 
	 * wait for a stuck lock to be removed.
	 */
	private static final int DEFAULT_MAX_LOCK_LEASE_PERIOD_MS = 15000; // 15 seconds
	private static final int DEFAULT_LOCK_RENEWAL_PERIOD = DEFAULT_MAX_LOCK_LEASE_PERIOD_MS - 2000;
	/**
	 * The default timeout for obtaining a lock.
	 */
	private static final int DEFAULT_TIMEOUT_MS = 30000; // 30 seconds
	private static final int MAX_DELETE_TRIES = 3;

	private int maxLockLeasePeriod = DEFAULT_MAX_LOCK_LEASE_PERIOD_MS;
	private int lockRenewalPeriod = DEFAULT_LOCK_RENEWAL_PERIOD;
	private int lockTimeout = DEFAULT_TIMEOUT_MS;

	private static final String LOCK = "lock";

	public static int nextInstanceId;
	private int instanceId;

	private static int debugId = getDebugId();

	private static int getDebugId() {
		int id = (new Random()).nextInt();
		if (id < 0) {
			id = -id;
		}
		return id;
	}

	private File lockFile;

	private long deltaTime = Long.MAX_VALUE;

	private Object waitLock = new Object(); // synchronization lock
	private GTimerMonitor waitTimerMonitor;
	private WaitForLockRunnable waitTask;

	private Object holdLock = new Object(); // synchronization lock
	private GTimerMonitor holdTimerMonitor;

	private int lockCount = 0;
	private long myLockTime = 0;

	// for testing
	LockFile(File dir, String name, int maxLockLeasePeriod, int lockRenewalPeriod, int lockTimeout) {
		this(dir, name, "");
		this.maxLockLeasePeriod = maxLockLeasePeriod;
		this.lockRenewalPeriod = lockRenewalPeriod;
		this.lockTimeout = lockTimeout;
	}

	/**
	 * Constructor.
	 * @param dir directory containing lock file
	 * @param name unmangled name of entity which this lock is associated with.
	 */
	public LockFile(File dir, String name) {
		this(dir, name, "");
	}

	/**
	 * Constructor.
	 * @param dir directory containing lock file
	 * @param name unmangled name of entity which this lock is associated with.
	 * @param lockType unique lock identifier (may not contain a '.')
	 */
	public LockFile(File dir, String name, String lockType) {

		if (lockType.indexOf('.') >= 0) {
			throw new AssertException("Illegal lockType");
		}

		lockFile = new File(dir, NamingUtilities.mangle(name) + "." + lockType + LOCK);

		instanceId = getNextInstanceId();

		Msg.trace(this, "Instantiated lock: " + getLockID());
	}

	/**
	 * Constructor.
	 * @param file file whose lock state will be controlled with this lock file.
	 */
	public LockFile(File file) {

		lockFile = new File(file.getParentFile(), file.getName() + "." + LOCK);

		instanceId = getNextInstanceId();

		Msg.trace(this, "Instantiated lock: " + getLockID());
	}

	/**
	 * @param dir directory containing lock file
	 * @param mangledName mangled name of file or entity which this lock is associated with.
	 * @return true if any lock exists within dir for the given entity name.
	 */
	private static boolean hasAnyLock(File dir, final String mangledName) {
		FileFilter filter = new FileFilter() {
			@Override
			public boolean accept(File pathname) {
				String fname = pathname.getName();
				if (fname.startsWith(mangledName) && fname.endsWith(LOCK)) {
					String s =
						fname.substring(mangledName.length(), fname.length() - LOCK.length());
					return s.indexOf('.') == 0 && s.indexOf('.', 1) < 0;
				}
				return false;
			}
		};
		File[] files = dir.listFiles(filter);
		return files != null && files.length != 0;
	}

	/**
	 * @param dir directory containing lock file
	 * @param name of entity which this lock is associated with.
	 * @return true if any lock exists within dir for the given entity name.
	 */
	public static boolean isLocked(File dir, String name) {
		return hasAnyLock(dir, NamingUtilities.mangle(name));
	}

	/**
	 * @param file file whose lock state is controlled with this lock file.
	 * @return true if any lock exists within dir for the given entity name.
	 */
	public static boolean isLocked(File file) {
		return hasAnyLock(file.getParentFile(), file.getName());
	}

	public static boolean containsLock(File dir) {
		File[] files = dir.listFiles();
		if (files == null)
			return false;
		for (int i = 0; i < files.length; i++) {
			if (files[i].isDirectory()) {
				if (containsLock(files[i]))
					return true;
			}
			else if (files[i].getName().endsWith(LOCK)) {
				return true;
			}
		}
		return false;
	}

	private static synchronized int getNextInstanceId() {
		return nextInstanceId++;
	}

	private static synchronized int getNextDebugId() {
		return ++debugId;
	}

	/**
	 * Determine if lock file was successfully created by this instance.
	 * This does not quarentee that the lock is still present if more
	 * than MAX_LOCK_LEASE_PERIOD has lapsed since lock was created.
	 * @return true if lock has been created, otherwise false.
	 */
	public boolean haveLock() {
		return lockCount != 0;
	}

	/**
	 * Determine if lock is still in place.
	 * Verifying the lock may be necessary when slow processes are holding 
	 * the lock without timely renewals.
	 * @return true if lock is still in place, otherwise false.
	 */
	public boolean haveLock(boolean verify) {
		if (lockCount != 0) {
			if (!verify || (myLockTime == lockFile.lastModified())) {
				return true;
			}
			Msg.trace(this, "lock was stolen : " + getLockID());
			lockCount = 0;
		}
		return false;
	}

	/**
	 * Renew the lease on a lock.
	 * This is accomplished by changing its last modification time.
	 * @return true if lock extension granted, else false.
	 */
	private boolean renewLock() {
		if (haveLock(true) && setLockOwner()) {
			//
			// File.setLastModified fails to work properly on Linux (JDK 1.4.2).
			// Lock file content re-written to update time
			//
			myLockTime = lockFile.lastModified();
			return true;
		}
		return false;
	}

	/**
	 * Return the name of the current lock owner
	 * or {@code "<Unknown>"} if not locked or could not be determined.
	 */
	public String getLockOwner() {
		return getLockOwner(false);
	}

	private String getLockOwner(boolean includeId) {
		String owner = null;
		FileInputStream fin = null;
		try {
			fin = new FileInputStream(lockFile);
			byte[] bytes = new byte[32];
			int cnt = fin.read(bytes);
			owner = new String(bytes, 0, cnt);
			if (!includeId) {
				int spaceIndex = owner.indexOf(' ');
				if (spaceIndex > 0) {
					owner = owner.substring(0, spaceIndex);
				}
			}
		}
		catch (Exception e) {
			owner = "<Unknown>";
		}
		finally {
			if (fin != null) {
				try {
					fin.close();
				}
				catch (IOException e1) {
					// we tried
				}
			}
		}
		return owner;
	}

	private boolean setLockOwner() {
		Msg.trace(this, "writing lock data : " + getLockID());
		BufferedOutputStream fout = null;
		boolean success = false;
		try {
			fout = new BufferedOutputStream(new FileOutputStream(lockFile, false));
			fout.write((SystemUtilities.getUserName() + " " + getNextDebugId()).getBytes());
			success = true;
		}
		catch (Exception e) {
			// we will check 'success' later
		}
		finally {
			if (fout != null) {
				try {
					fout.close();
				}
				catch (IOException e1) {
					// we tried
				}
			}
			if (!success) {
				lockFile.delete();
			}
		}
		return success;
	}

	private String getLockID() {
		return lockFile.getName() + "(" + instanceId + "," + Thread.currentThread().getName() + ")";
	}

	@Override
	public String toString() {
		return getLockID();
	}

	/**
	 * Remove the lock file.
	 * This method should be invoked when the corresponding transaction is complete.
	 */
	public synchronized void removeLock() {
		if (haveLock(true)) {
			if (--lockCount == 0) {
				holdLock(false);
				Msg.trace(this, "removing lock : " + getLockID());
				int tryCnt = MAX_DELETE_TRIES;
				while ((tryCnt-- > 0) && !lockFile.delete()) {
					Msg.warn(this, "Failed to remove lock file : " + getLockID());
				}
			}
			else {
				Msg.trace(this, "lock count reduced (" + lockCount + "): " + getLockID());
			}
		}
		else {
			Msg.trace(this, "attempted to remove lock which I do not own " + getLockOwner(true) +
				": " + getLockID());
			try {
				throw new AssertException("Lock time = " + lockFile.lastModified());
			}
			catch (Exception e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
		}
	}

	/**
	 * Create the lock file using the default timeout.
	 * Lock is guaranteed for MAX_LOCK_LEASE_PERIOD seconds.
	 * @return true if lock creation was successful.
	 */
	public boolean createLock() {
		return createLock(lockTimeout, false);
	}

	/**
	 * Create the lock file.
	 * If another lock file already exists, wait for it to expire
	 * within the specified timeout period.  Method will block
	 * until either the lock is obtained or the timeout period lapses.
	 * @param timeout maximum time in milliseconds to wait for lock.  
	 * @param hold if true the lock will be held and maintained until
	 * removed, otherwise it is only guaranteed for MAX_LOCK_LEASE_PERIOD seconds.
	 * @return true if lock creation was successful.
	 */
	public synchronized boolean createLock(int timeout, boolean hold) {

		synchronized (waitLock) {

			// Renew lock if we already have it
			if (lockCount != 0 && renewLock()) {
				++lockCount;
				Msg.trace(this, "increased lock count (" + lockCount + "): " + getLockID());
				if (hold)
					holdLock(true);
				return true;
			}

			// Check if we can get lock immediately	
			try {
				if (createLockFileNoWait(true)) {
					if (waitTask != null) {
						waitTask.abort = true;
					}
					++lockCount;
					Msg.trace(this, "increased lock count (" + lockCount + "): " + getLockID());
					if (hold)
						holdLock(true);
					return true;
				}
			}
			catch (IOException e) {
				Msg.showError(this, null, "Lock Failure", "Unable to write to lock file: " +
					lockFile.getAbsolutePath(), e);
				return false;
			}

			Msg.trace(this, "wait for lock...: " + getLockID());

			// Start lock wait/cleanup task	
			startWaitTimer(timeout != 0);

			if (timeout == 0)
				return false;
		}

		// Wait for waitTask 
		if (waitTask != null && timeout > 0) {
			synchronized (waitTask) {
				try {
					waitTask.wait(timeout);
				}
				catch (InterruptedException e) {
					return false;
				}
			}
		}

		synchronized (waitLock) {

			// Don't create lock if we timed-out
			if (waitTask != null) {
				synchronized (waitTask) {
					waitTask.create = false;
				}
			}

			// Hold lock if requested
			if (lockCount != 0) {
				if (hold)
					holdLock(true);
				return true;
			}

			Msg.trace(this, "failed to obtain lock...: " + getLockID());

			return false;
		}
	}

	/**
	 * Attempt once to create a lock file.
	 * @param testLock if true an expiration check will be performed on the lock
	 * @return true if the lock file successfully created, else false.
	 */
	private boolean createLockFileNoWait(boolean testLock) throws IOException {

		Msg.trace(this, "attempt lock creation...: " + getLockID());
		boolean lockCreated = lockFile.createNewFile();
		if (!lockCreated && testLock) {

			long ltime = lockFile.lastModified();
			if (ltime != 0) {
				if (deltaTime == Long.MAX_VALUE) {
					// Compute time delta between filesystem and my clock
					File testFile = File.createTempFile("test", ".tmp", lockFile.getParentFile());
					deltaTime = (new Date().getTime()) - testFile.lastModified();
					testFile.delete();
				}
				// Check for expired lock
				if (ltime < (new Date().getTime() - maxLockLeasePeriod - deltaTime)) {
					lockFile.delete();
					Msg.warn(this, "Forcefully removing lock owned by " + getLockOwner(true) +
						": " + getLockID());
					lockCreated = lockFile.createNewFile();
				}
			}
			else {
				lockCreated = lockFile.createNewFile();
			}
		}
		if (!lockCreated || !setLockOwner()) {
			Msg.trace(this, "lock denied by " + getLockOwner(true) + ": " + getLockID());
			return false;
		}
		Msg.trace(this, "lock created (" + debugId + "): " + getLockID());
		myLockTime = lockFile.lastModified();
		return true;
	}

	/**
	 * Start the wait task if it is not already running.
	 * Set the create flag within the wait task.
	 * @param create an attempt to create a lock file will be done if true, 
	 * otherwise only attempt to remove stale lock file. 
	 */
	private void startWaitTimer(boolean create) {
		synchronized (waitLock) {
			if (waitTask == null) {
				waitTask = new WaitForLockRunnable(create, 1000);
				waitTimerMonitor = GTimer.scheduleRepeatingRunnable(500, 1000, waitTask);
			}
			else {
				waitTask.create = create;
			}
		}
	}

	/**
	 * Cancel the current wait timer.
	 */
	private void endWaitTimer() {
		waitTimerMonitor.cancel();
		waitTimerMonitor = null;
		waitTask = null;
	}

	/**
	 * Provides a runnable class which waits for a lock to be removed.
	 * If the lock expires while waiting, the lock file is removed.
	 * No attempt should be made to create the lock file while this
	 * task is running.
	 */
	private class WaitForLockRunnable implements Runnable {

		private int interval;
		private boolean create;
		private long lastModTime;
		private int maxLeaseTime;

		private boolean abort = false;

		/**
		 * Constructor.
		 * @param create if true an attempt will be made to create the lock
		 * if the current lock is removed.
		 * @param interval time period in milliseconds which the run method is invoked.
		 */
		WaitForLockRunnable(boolean create, int interval) {
			this.interval = interval;
			this.create = create;
			maxLeaseTime = maxLockLeasePeriod;
			lastModTime = lockFile.lastModified();
		}

		private synchronized void terminate() {
			endWaitTimer();
			notifyAll();
		}

		/**
		 * Check to see if the current lock file has exceeded the
		 * maximum allowed lease time.
		 */
		@Override
		public void run() {

			synchronized (waitLock) {

				if (abort) {
					terminate();
					return;
				}

				maxLeaseTime -= interval;

				long mt = lockFile.lastModified();
				if (mt != 0L) {

					// Check for updated lock
					if (mt != lastModTime) {

						// Discontinue waiting if we are not trying to create lock
						// Since it is clearly not stuck
						if (!create) {
							terminate();
						}

						// Reset lease timer if we want to create lock
						else {
							maxLeaseTime = maxLockLeasePeriod;
							lastModTime = mt;
							Msg.trace(this, getLockOwner(true) + " grabbed lock before I could: " +
								getLockID());
						}
						return; // lock file still exists
					}

					Msg.trace(this, getLockOwner(true) + " has held lock for " +
						((maxLockLeasePeriod - maxLeaseTime) / 1000) + " seconds: " + getLockID());

					if (maxLeaseTime > 0)
						return;

					// Forcefully remove lock file if max lease time expired
					lockFile.delete();
					Msg.warn(this, "Forcefully removing lock owned by " + getLockOwner(true) +
						": " + getLockID());

					// Delay after forceful removal to avoid race condition!
					// If we create a new lock file immediately, another wait task 
					// could remove it due to the delay between checking the lastModified
					// time and actually removing the file.
					try {
						Thread.sleep(1000);
					}
					catch (InterruptedException e) {
						create = false;
					}

				}

				// Attempt to create lock if requested
				if (create) {
					try {
						if (createLockFileNoWait(false)) {
							Msg.trace(this, (new Date()) + " LockFile: lock granted after wait: " +
								getLockID());
							++lockCount;
							terminate();
						}
						else {
							// create failed - keep waiting
							maxLeaseTime = maxLockLeasePeriod;
							return;
						}
					}
					catch (IOException e) {
						Msg.showError(this, null, "Lock Failure", "Unable to write to lock file: " +
							lockFile.getAbsolutePath(), e);
						terminate();
					}
				}

				lastModTime = 0L;
			}
		}
	}

	/**
	 * Initiate lock hold.
	 * Lock will continue to be renewed until holdLockThread is interrupted.
	 */
	private void holdLock(boolean hold) {
		synchronized (holdLock) {
			if (holdTimerMonitor != null) {
				if (!hold) {
					holdTimerMonitor.cancel();
					holdTimerMonitor = null;
				}
			}
			else if (hold) {
				holdTimerMonitor =
					GTimer.scheduleRepeatingRunnable(lockRenewalPeriod, lockRenewalPeriod,
						new HoldLockRunnable());
			}
		}
	}

	private class HoldLockRunnable implements Runnable {

		@Override
		public void run() {
			synchronized (holdLock) {
				if (holdTimerMonitor == null) {
					// we were cancelled while waiting for the 'holdLock' lock
					return;
				}

				if (!renewLock()) {
					// We lost lock hold for some reason
					holdTimerMonitor.cancel();
					holdTimerMonitor = null;
				}
			}
		}
	}

	/**
	 * Cleanup lock resources and tasks.
	 * Invoking this method could prevent stale locks from being removed
	 * if createLock was invoked with a very short timeout.
	 * Use of dispose is optional - the associated wait task should 
	 * stop by it self allowing the LockFile object to be finalized.
	 */
	public synchronized void dispose() {
		holdLock(false);

		if (waitTimerMonitor != null) {
			waitTimerMonitor.cancel();
			waitTimerMonitor = null;
			waitTask = null;
		}
		if (lockCount != 0) {
			removeLock();
		}
	}

	/**
	 * Cleanup during garbage collection.
	 */
	@Override
	protected void finalize() {
		dispose();
	}

}
