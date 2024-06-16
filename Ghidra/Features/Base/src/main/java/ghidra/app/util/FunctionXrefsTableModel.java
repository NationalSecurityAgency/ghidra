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
package ghidra.app.util;

import java.util.Collection;
import java.util.Set;

import ghidra.app.plugin.core.navigation.locationreferences.ReferenceUtils;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.ReferencesFromTableModel;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

public class FunctionXrefsTableModel extends ReferencesFromTableModel {

	private Function function;
	private boolean showAllThunkXrefs;

	public FunctionXrefsTableModel(Function function, Collection<Reference> directRefs, ServiceProvider sp,
			Program program) {
		super(directRefs, sp, program);
		this.function = function;

		addTableColumn(new IsThunkTableColumn());
	}

	@Override
	protected void doLoad(Accumulator<ReferenceEndpoint> accumulator, TaskMonitor monitor)
			throws CancelledException {

		if (!showAllThunkXrefs) {
			super.doLoad(accumulator, monitor); // only include the supplied refs from our parent
			return;
		}

		Function baseFunction = function;
		if (function.isThunk()) {
			baseFunction = function.getThunkedFunction(true);
		}

		doLoadThunkFunctionReferences(baseFunction, accumulator, monitor);
	}

	private void doLoadThunkFunctionReferences(Function baseFunction,
			Accumulator<ReferenceEndpoint> accumulator, TaskMonitor monitor)
			throws CancelledException {

		addReferences(accumulator, baseFunction.getEntryPoint());

		Address[] thunks = baseFunction.getFunctionThunkAddresses(true);
		if (thunks == null) {
			return; // no thunks
		}

		for (Address address : thunks) {
			monitor.checkCancelled();
			addReferences(accumulator, address);
		}
	}

	private void addReferences(Accumulator<ReferenceEndpoint> accumulator, Address address) {

		ProgramLocation location = new ProgramLocation(program, address);
		Set<Reference> refs = XReferenceUtils.getAllXrefs(location);
		for (Reference ref : refs) {
			boolean offcut = ReferenceUtils.isOffcut(program, ref.getToAddress());
			accumulator.add(new ThunkIncomingReferenceEndpoint(ref, offcut));
		}
	}

	void toggleShowAllThunkXRefs() {
		this.showAllThunkXrefs = !showAllThunkXrefs;
		reload();
	}

//=================================================================================================
// Inner Classes
//=================================================================================================

	private class ThunkIncomingReferenceEndpoint extends IncomingReferenceEndpoint {

		public ThunkIncomingReferenceEndpoint(Reference r, boolean isOffcut) {
			super(r, isOffcut);
		}

	}

	private class IsThunkTableColumn
			extends AbstractProgramBasedDynamicTableColumn<ReferenceEndpoint, String> {

		@Override
		public String getColumnName() {
			return "Thunk?";
		}

		@Override
		public String getValue(ReferenceEndpoint rowObject, Settings settings, Program data,
				ServiceProvider sp) throws IllegalArgumentException {

			Address toAddress = rowObject.getReference().getToAddress();
			FunctionManager fm = program.getFunctionManager();
			Function f = fm.getFunctionAt(toAddress);
			if (f != null && f.isThunk()) {
				return "thunk";
			}
			return "";
		}

	}
}
