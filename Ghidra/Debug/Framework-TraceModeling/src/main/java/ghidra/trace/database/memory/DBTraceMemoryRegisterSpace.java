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
package ghidra.trace.database.memory;

import java.io.IOException;

import javax.help.UnsupportedOperationException;

import com.google.common.collect.Range;

import db.DBHandle;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.listing.DBTraceCodeRegisterSpace;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.memory.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;

public class DBTraceMemoryRegisterSpace extends DBTraceMemorySpace
		implements TraceMemoryRegisterSpace {
	protected final DBTraceThread thread;
	private final int frameLevel;

	public DBTraceMemoryRegisterSpace(DBTraceMemoryManager manager, DBHandle dbh,
			AddressSpace space, DBTraceSpaceEntry ent, DBTraceThread thread)
			throws IOException, VersionException {
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

	@Override
	public DBTraceCodeRegisterSpace getCodeSpace(boolean createIfAbsent) {
		return trace.getCodeManager().getCodeRegisterSpace(thread, frameLevel, createIfAbsent);
	}

	@Override
	public DBTraceMemoryRegion addRegion(String name, Range<Long> lifespan, AddressRange range,
			TraceMemoryFlag... flags)
			throws TraceOverlappedRegionException, DuplicateNameException {
		throw new UnsupportedOperationException();
	}
}
