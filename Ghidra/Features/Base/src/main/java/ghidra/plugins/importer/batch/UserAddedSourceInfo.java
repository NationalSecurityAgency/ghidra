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
package ghidra.plugins.importer.batch;

import ghidra.formats.gfilesystem.FSRL;

/**
 * This class holds information regarding a single user-added source file added
 * to a batch import session.
 */
public class UserAddedSourceInfo {
	private final FSRL fsrl;
	private int fileCount;
	private int rawFileCount;
	private int containerCount;
	private int maxNestLevel;
	private boolean recurseTerminatedEarly;

	UserAddedSourceInfo(FSRL fsrl) {
		this.fsrl = fsrl;
	}

	public int getFileCount() {
		return fileCount;
	}

	public void setFileCount(int fileCount) {
		this.fileCount = fileCount;
	}

	public int getRawFileCount() {
		return rawFileCount;
	}

	public void setRawFileCount(int rawFileCount) {
		this.rawFileCount = rawFileCount;
	}

	public void incRawFileCount() {
		this.rawFileCount++;
	}

	public int getContainerCount() {
		return containerCount;
	}

	public void setContainerCount(int containerCount) {
		this.containerCount = containerCount;
	}

	public void incContainerCount() {
		this.containerCount++;
	}

	public int getMaxNestLevel() {
		return maxNestLevel;
	}

	public void setMaxNestLevel(int maxNestLevel) {
		this.maxNestLevel = maxNestLevel;
	}

	public boolean wasRecurseTerminatedEarly() {
		return recurseTerminatedEarly;
	}

	public void setRecurseTerminatedEarly(boolean recurseTerminatedEarly) {
		this.recurseTerminatedEarly = recurseTerminatedEarly;
	}

	public FSRL getFSRL() {
		return fsrl;
	}
}
