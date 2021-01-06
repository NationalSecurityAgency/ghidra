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
package ghidra.trace.database.program;

import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.program.TraceVariableSnapProgramView;

/**
 * TODO
 * 
 * NOTE: Calling {@link CodeUnit#getProgram()} from units contained in this view does not return
 * this same view. Instead, it returns the (fixed-snap) view for the unit's snap.
 */
public class DBTraceVariableSnapProgramView extends DBTraceProgramView
		implements TraceVariableSnapProgramView {

	//private static final int SNAP_CHANGE_EVENT_THRESHHOLD = 100;

	public DBTraceVariableSnapProgramView(DBTrace trace, long snap, CompilerSpec compilerSpec) {
		super(trace, snap, compilerSpec);
	}

	/**
	 * Fires object-restored event on this view and all associated register views.
	 */
	protected void fireObjectRestored() {
		fireEventAllViews(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
	}

	@Override
	public void setSnap(long newSnap) {
		if (this.snap == newSnap) {
			return;
		}
		//long oldSnap = this.snap;
		this.snap = newSnap;
		viewport.setSnap(newSnap);
		memory.setSnap(newSnap);

		// TODO: I could be more particular, but this seems to work fast enough, now.
		fireObjectRestored();
	}
}
