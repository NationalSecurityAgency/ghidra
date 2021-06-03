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
package ghidra.trace.database.listing;

import java.io.IOException;

import db.DBHandle;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.listing.TraceCodeRegisterSpace;
import ghidra.util.exception.VersionException;

public class DBTraceCodeRegisterSpace extends DBTraceCodeSpace implements TraceCodeRegisterSpace {
	protected final DBTraceThread thread;
	private final int frameLevel;

	public DBTraceCodeRegisterSpace(DBTraceCodeManager manager, DBHandle dbh, AddressSpace space,
			DBTraceSpaceEntry ent, DBTraceThread thread) throws VersionException, IOException {
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
	protected DBTraceInstructionsRegisterView createInstructionsView() {
		return new DBTraceInstructionsRegisterView(this);
	}

	@Override
	protected DBTraceDefinedDataRegisterView createDefinedDataView() {
		return new DBTraceDefinedDataRegisterView(this);
	}

	@Override
	protected DBTraceDefinedUnitsRegisterView createDefinedUnitsView() {
		return new DBTraceDefinedUnitsRegisterView(this);
	}

	@Override
	protected DBTraceUndefinedDataRegisterView createUndefinedDataView() {
		return new DBTraceUndefinedDataRegisterView(this);
	}

	@Override
	protected DBTraceDataRegisterView createDataView() {
		return new DBTraceDataRegisterView(this);
	}

	@Override
	protected DBTraceCodeUnitsRegisterView createCodeUnitsView() {
		return new DBTraceCodeUnitsRegisterView(this);
	}

	@Override
	public DBTraceCodeUnitsRegisterView codeUnits() {
		return (DBTraceCodeUnitsRegisterView) codeUnits;
	}

	@Override
	public DBTraceInstructionsRegisterView instructions() {
		return (DBTraceInstructionsRegisterView) instructions;
	}

	@Override
	public DBTraceDataRegisterView data() {
		return (DBTraceDataRegisterView) data;
	}

	@Override
	public DBTraceDefinedDataRegisterView definedData() {
		return (DBTraceDefinedDataRegisterView) definedData;
	}

	@Override
	public DBTraceUndefinedDataRegisterView undefinedData() {
		return (DBTraceUndefinedDataRegisterView) undefinedData;
	}

	@Override
	public DBTraceDefinedUnitsRegisterView definedUnits() {
		return (DBTraceDefinedUnitsRegisterView) definedUnits;
	}
}
