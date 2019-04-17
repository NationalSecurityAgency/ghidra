/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.util;

import java.io.File;

public class ChannelLocker extends FileLocker {

	private static final String CHANNEL_LOCK_TYPE = "Channel Lock";
	private FileChannelLock channelLock;

	ChannelLocker(File lockFile) {
		super(lockFile);
	}

	@Override
	protected String getLockType() {
		return CHANNEL_LOCK_TYPE;
	}

	@Override
	public boolean lock() {
		if (canLock()) {
			return createLockFile();
		}

		return false;
	}

	private boolean canLock() {
		// if there is no existing lock type, then there is no lock.
		if (existingLockType == null) {
			return true;
		}

		return canChannelLock();
	}

	private boolean canChannelLock() {
		if (!CHANNEL_LOCK_TYPE.equals(existingLockType)) {
			// some other kind of locking mechanism already has a lock
			return false;
		}

		return isChannelLockAvailable();
	}

	private boolean isChannelLockAvailable() {
		FileChannelLock testChannelLock = new FileChannelLock(lockFile);
		boolean didLock = testChannelLock.lock();
		testChannelLock.release();
		return didLock;
	}

	@Override
	protected boolean createLockFile() {
		if (!super.createLockFile()) {
			return false;
		}

		// success with creation, now lock
		channelLock = new FileChannelLock(lockFile);
		isLocked = channelLock.lock();
		return isLocked;
	}

	@Override
	public void release() {
		if (channelLock != null) {
			channelLock.release();
		}
		super.release();
	}
}
