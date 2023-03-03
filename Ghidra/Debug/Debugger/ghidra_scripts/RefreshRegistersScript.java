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
import java.util.Set;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.*;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.util.PathMatcher;

public class RefreshRegistersScript extends GhidraScript {
	@Override
	protected void run() throws Exception {
		// There is no need to fish this from the ObjectUpdateService, you can get it directly
		DebuggerModelService modelService = state.getTool().getService(DebuggerModelService.class);
		// The current model is retrieved with one method, no need to stream or filter
		DebuggerObjectModel model = modelService.getCurrentModel();

		/**
		 * Navigating a model generically requires some introspection. Use the schema. We used to
		 * decouple the descriptions (RegisterContainer) from the values (RegisterBank), but we
		 * always realize the two interfaces on the same no it seems. Still, we need to work with
		 * values, so we search for all the Banks.
		 */
		PathMatcher allBanksMatcher =
			model.getRootSchema().searchFor(TargetRegisterBank.class, true);
		for (TargetObject objBank : allBanksMatcher.fetchSuccessors(model.fetchModelRoot().get())
				.get()
				.values()) {
			// Because of a bug in our path search, this type check is still necessary :(
			if (!(objBank instanceof TargetRegisterBank)) {
				continue;
			}
			TargetRegisterBank bank = (TargetRegisterBank) objBank;
			// This is equivalent to hitting the "Flush Caches" button in the Target Provider
			bank.invalidateCaches().get();
			// If you know the names of the registers to read
			bank.readRegistersNamed("rax", "rbx").get();
			// Values are coupled to elements, so we can also just refresh them to re-read all
			bank.fetchElements(RefreshBehavior.REFRESH_ALWAYS).get();
		}

		/**
		 * Alternatively, to refresh just the bank for the current thread or frame, we need to
		 * determine the active frame. We'll do that by asking the TraceManagerService. Then,
		 * because that's in "trace land," we'll use the TraceRecorder to map that into "target
		 * land." Generally, you'd then need to navigate the schema as before, but relative to the
		 * target object. Because fetching registers is so common, this is already built in to the
		 * recorder.
		 */
		DebuggerTraceManagerService traceManager =
			state.getTool().getService(DebuggerTraceManagerService.class);
		// There are also getCurreentTrace(), etc., if you want just the one thing
		DebuggerCoordinates current = traceManager.getCurrent();

		// Now, we need to get the relevant recorder
		TraceRecorder recorder = modelService.getRecorder(current.getTrace());
		// There's a chance of an NPE here if there is no "current frame"
		Set<TargetRegisterBank> banks =
			recorder.getTargetRegisterBanks(current.getThread(), current.getFrame());
		for (TargetRegisterBank bank : banks) {
			// Now do the same to the bank as before
			bank.invalidateCaches().get();
			bank.fetchElements(RefreshBehavior.REFRESH_ALWAYS).get();
		}
	}
}
