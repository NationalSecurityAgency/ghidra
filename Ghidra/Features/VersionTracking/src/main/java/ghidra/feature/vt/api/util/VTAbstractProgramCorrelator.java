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
package ghidra.feature.vt.api.util;

import ghidra.feature.vt.api.main.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface for Algorithms that correlate items (primarily functions) from one program to another, 
 * typically for purposes of version tracking. 
 *
 */
public abstract class VTAbstractProgramCorrelator implements VTProgramCorrelator {
	private final Program sourceProgram;

	private final AddressSetView sourceAddressSet;
	private final Program destinationProgram;
	private final AddressSetView destinationAddressSet;
	private final ToolOptions options;

	protected final ServiceProvider serviceProvider;

	/**
	 * Constructor
	 * @param sourceProgram The program that contains functions that are to be looked for in the
	 * destination program.  Typically, this is the program that has markup that is to be applied
	 * to the destination program.
	 * @param sourceAddressSet The set of addresses to use in the correlation.
	 * @param destinationProgram The program to search, looking for functions that match functions
	 * in the source program.  Typically, this is the program that markup is to be applied. 
	 * @param destinationAddressSet The set of addresses to search within the destination program.
	 * @param options An Options object that contains the set of options to be used by the 
	 * correlating algorithm.
	 */
	protected VTAbstractProgramCorrelator(ServiceProvider serviceProvider, Program sourceProgram,
			AddressSetView sourceAddressSet, Program destinationProgram,
			AddressSetView destinationAddressSet, ToolOptions options) {
		this.serviceProvider = serviceProvider;
		this.sourceProgram = sourceProgram;
		this.sourceAddressSet = sourceAddressSet;
		this.destinationProgram = destinationProgram;
		this.destinationAddressSet = destinationAddressSet;
		this.options = options;
	}

	/**
	 * Performs the correlation between two programs looking for how well functions in one program
	 * correlate to functions in another program.
	 * @param session An existing manager that may contain previous results that may 
	 *        influence this correlation.
	 * @param monitor a task monitor for reporting progress during the correlation.
	 * @throws CancelledException if the user cancels the correlation via the task monitor.
	 */
	@Override
	public final VTMatchSet correlate(VTSession session, TaskMonitor monitor)
			throws CancelledException {
		VTMatchSet matchSet = session.createMatchSet(this);
		doCorrelate(matchSet, monitor);
		return matchSet;
	}

	protected abstract void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor)
			throws CancelledException;

	@Override
	public ToolOptions getOptions() {
		return options.copy();
	}

	@Override
	public AddressSetView getSourceAddressSet() {
		return sourceAddressSet;
	}

	@Override
	public Program getSourceProgram() {
		return sourceProgram;
	}

	@Override
	public Program getDestinationProgram() {
		return destinationProgram;
	}

	@Override
	public AddressSetView getDestinationAddressSet() {
		return destinationAddressSet;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + sourceProgram.hashCode();
		result = prime * result + destinationProgram.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		VTAbstractProgramCorrelator other = (VTAbstractProgramCorrelator) obj;

		if (!destinationProgram.equals(other.destinationProgram)) {
			return false;
		}
		if (!sourceProgram.equals(other.sourceProgram)) {
			return false;
		}
		if (!SystemUtilities.isEqual(destinationAddressSet, other.destinationAddressSet)) {
			return false;
		}
		if (!SystemUtilities.isEqual(sourceAddressSet, other.sourceAddressSet)) {
			return false;
		}
		if (!options.equals(other.options)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return getName();
	}
}
