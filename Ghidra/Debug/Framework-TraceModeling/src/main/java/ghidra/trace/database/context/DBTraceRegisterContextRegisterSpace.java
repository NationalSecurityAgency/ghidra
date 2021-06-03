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
package ghidra.trace.database.context;

import java.io.IOException;

import db.DBHandle;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.context.TraceRegisterContextRegisterSpace;
import ghidra.util.exception.VersionException;

public class DBTraceRegisterContextRegisterSpace extends DBTraceRegisterContextSpace
		implements TraceRegisterContextRegisterSpace {
	private final DBTraceThread thread;
	private final int frameLevel;

	public DBTraceRegisterContextRegisterSpace(DBTraceRegisterContextManager manager, DBHandle dbh,
			AddressSpace space, DBTraceSpaceEntry ent, DBTraceThread thread)
			throws VersionException, IOException {
		super(manager, dbh, space, ent);
		this.thread = thread;
		this.frameLevel = ent.getFrameLevel();
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
