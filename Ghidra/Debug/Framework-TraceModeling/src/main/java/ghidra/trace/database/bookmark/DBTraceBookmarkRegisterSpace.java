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
package ghidra.trace.database.bookmark;

import java.io.IOException;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.bookmark.TraceBookmarkRegisterSpace;
import ghidra.util.exception.VersionException;

public class DBTraceBookmarkRegisterSpace extends DBTraceBookmarkSpace
		implements TraceBookmarkRegisterSpace {
	private final DBTraceThread thread;
	private final int frameLevel;

	public DBTraceBookmarkRegisterSpace(DBTraceBookmarkManager manager, AddressSpace space,
			DBTraceThread thread, int frameLevel) throws VersionException, IOException {
		super(manager, space);
		this.thread = thread;
		this.frameLevel = frameLevel;
	}

	@Override
	public DBTraceThread getThread() {
		return thread;
	}

	@Override
	public int getFrameLevel() {
		return frameLevel;
	}
}
