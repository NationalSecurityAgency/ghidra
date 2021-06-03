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
package ghidra.app.cmd.label;

import java.util.List;

import ghidra.app.util.demangler.*;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

public class DemanglerCmd extends BackgroundCommand {

	private Address addr;
	private String mangled;
	private String result;
	private DemangledObject demangledObject;
	private static List<Demangler> demanglers;
	private DemanglerOptions options;

	public DemanglerCmd(Address addr, String mangled) {
		this(addr, mangled, new DemanglerOptions());
	}

	public DemanglerCmd(Address addr, String mangled, DemanglerOptions options) {
		super("Demangle Symbol", false, true, false);
		this.addr = addr;
		// Remove any @Address that is appended to the name.
		this.mangled = SymbolUtilities.getCleanSymbolName(mangled, addr);
		this.options = options;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		Program prog = (Program) obj;

		for (Demangler demangler : getDemanglers()) {
			if (!demangler.canDemangle(prog)) {
				continue;
			}

			if (!doDemangle(demangler, prog, monitor)) {
				return false; // some kind of error
			}

			if (result != null) {
				break; // successful; don't try a different demangler
			}
		}

		return true;
	}

	private boolean doDemangle(Demangler demangler, Program program, TaskMonitor monitor) {

		try {
			demangledObject = demangler.demangle(mangled, options);
		}
		catch (DemangledException e) {
			if (e.isInvalidMangledName()) {
				//ignore invalid names, consider as not an error
				return true; // no real error
			}

			setStatusMsg("Unable to demangle symbol: " + mangled + " at " + addr + ".  Message: " +
				e.getMessage());
			return false; // error

			// This produces too many messages for non-demangled symbols.  If we could
			// figure out a way to tell which symbol are those which are mangled and 
			// failing, then we should print those.  The problem is not knowing how to 
			// tell a mangled from a non-mangled symbol.
			// Msg.debug(this, "Unable to demangle name: " + mangled);
		}
		catch (Exception e) {
			// Demangler IndexOutOfBoundsException that we're not sure how to fix 
			setStatusMsg("Unable to demangle symbol: " + mangled + " at " + addr + ". Message: " +
				e.getMessage());
			return false;
		}

		if (demangledObject == null) {
			return true; // no error
		}

		try {
			if (demangledObject.applyTo(program, addr, options, monitor)) {
				result = demangledObject.getSignature(true);
				return true;
			}
		}
		catch (Exception e) {
			updateStatusForUnexpectedException(e);
			return false;
		}

		setStatusMsg(
			"Failed to apply mangled symbol at " + addr + "; name:  " + mangled + " (" +
				demangler.getClass().getName() + "/" + demangledObject.getClass().getName() + ")");
		return false; // error
	}

	private void updateStatusForUnexpectedException(Exception e) {
		String message = e.getMessage();
		if (message == null) {
			setStatusMsg("Unable to demangle symbol at " + addr.toString() + "; name: " + mangled +
				".  Message: " + e.toString());
		}
		else {
			setStatusMsg("Unable to demangle symbol at " + addr.toString() + "; name: " + mangled +
				".  Message: " + message);
		}

		Msg.error(this, getStatusMsg(), e);
	}

	public String getResult() {
		return result;
	}

	public DemangledObject getDemangledObject() {
		return demangledObject;
	}

	private static List<Demangler> getDemanglers() {
		if (demanglers == null) {
			demanglers = ClassSearcher.getInstances(Demangler.class);
		}
		return demanglers;
	}
}
