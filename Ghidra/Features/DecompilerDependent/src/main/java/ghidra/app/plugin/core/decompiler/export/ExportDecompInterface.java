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
package ghidra.app.plugin.core.decompiler.export;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileProcess;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.program.model.symbol.NameTransformer;
import ghidra.util.task.TaskMonitor;

public class ExportDecompInterface extends DecompInterface {

	@Override
	public synchronized ExportableDecompileResults decompileFunction(Function func, int timeoutSecs,
			TaskMonitor monitor) {

		Language pcodelanguage = getLanguage();
		NameTransformer transformer =
			(getOptions() == null) ? new IdentityNameTransformer()
					: getOptions().getNameTransformer();
		PcodeDataTypeManager dtmgr = new PcodeDataTypeManager(func.getProgram(), transformer);
		dtmgr.clearTemporaryIds();
		errorMessage = "";

		if (monitor != null) {
			monitor.addCancelledListener(monitorListener);
		}

		PackedDecode decoder = null;
		try {
			Address funcEntry = func.getEntryPoint();
			decompCallback.setFunction(func, funcEntry, null);
			EncodeDecodeSet activeSet = setupEncodeDecode(funcEntry);
			decoder = activeSet.mainResponse;
			verifyProcess();
			activeSet.mainQuery.clear();
			AddressXML.encode(activeSet.mainQuery, funcEntry);
			decompProcess.sendCommandTimeout("decompileAt", timeoutSecs, activeSet);
			errorMessage = decompCallback.getErrorMessage();
		}
		catch (Exception ex) {
			decoder.clear(); 	// Clear any partial result
			errorMessage = "Exception while decompiling " + func.getEntryPoint() + ": " +
				ex.getMessage() + '\n';
		}
		finally {
			if (monitor != null) {
				monitor.removeCancelledListener(monitorListener);
			}
		}

		DecompileProcess.DisposeState processState;
		if (decompProcess != null) {
			processState = decompProcess.getDisposeState();
			if (decompProcess.getDisposeState() == DecompileProcess.DisposeState.NOT_DISPOSED) {
				flushCache();
			}
		}
		else {
			processState = DecompileProcess.DisposeState.DISPOSED_ON_CANCEL;
		}

		return new ExportableDecompileResults(func, pcodelanguage, compilerSpec, dtmgr,
			errorMessage, decoder, processState);
	}
}
