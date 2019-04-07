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
package ghidra.framework.project;

import generic.util.FileLocker;
import generic.util.LockFactory;
import ghidra.framework.model.ProjectLocator;

import java.io.File;

/**
 * A simple delegate for creating and using locks in Ghidra.
 */
class ProjectLock {

	private final File lockFile;

	FileLocker locker;

	public ProjectLock(ProjectLocator projectLocator) {
		this.lockFile = projectLocator.getProjectLockFile();

		// test for type of Locker
		locker = LockFactory.createFileLocker(lockFile);
	}

	boolean lock() {
		return locker.lock();
	}

	boolean forceLock() {
		return locker.forceLock();
	}

	boolean canForceLock() {
		return locker.canForceLock();
	}

	void release() {
		locker.release();
	}

	boolean isLocked() {
		return locker.isLocked();
	}

	String getExistingLockFileInformation() {
		return locker.getExistingLockFileInformation();
	}
}
