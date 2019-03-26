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
package db.buffers;

import java.io.File;

/**
 * <code>DummyBufferFileMgr</code> produces buffer file names and 
 * tracks the current buffer file version.  No maintenance of buffer
 * files is provided.
 */
public class DummyBufferFileMgr implements BufferFileManager {
	
	protected File dir;
	protected String name;
	protected boolean enableVersionFiles;
	protected boolean enableChangeFiles;
	protected int cur = 0;
	
	public DummyBufferFileMgr(File dir, String name, boolean enableVersionFiles, boolean enableChangeFiles) {
		this.dir = dir;
		this.name = name;
		this.enableVersionFiles = enableVersionFiles;
		this.enableChangeFiles = enableChangeFiles;
	}
	
	public int getCurrentVersion() {
		return cur;
	}
	public File getBufferFile(int version) {
		return new File(dir, name + version + ".bf" );
	}
	public File getVersionFile(int version) {
		if (enableVersionFiles) {
			return new File(dir, name + version + ".vf" );
		}
		return null;
	}
	public File getChangeDataFile(int version) {
		if (enableChangeFiles) {
			return new File(dir, name + version + ".cf" );
		}
		return null;
	}
	public File getChangeMapFile() {
		return null;
	}
	public void versionCreated(int version, String comment, long checkinId) {
		cur = version;
	}
	public void updateEnded(long checkinId) {
	}
}
