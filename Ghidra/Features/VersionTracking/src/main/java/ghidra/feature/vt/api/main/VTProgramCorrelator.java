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
package ghidra.feature.vt.api.main;

import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface VTProgramCorrelator {

	/**
	 * Performs the correlation between two programs looking for how well functions in one program
	 * correlate to functions in another program.
	 * @param session An existing manager that may contain previous results that may 
	 *        influence this correlation.
	 * @param monitor a task monitor for reporting progress during the correlation.
	 * @return the match set created by this correlator used to store results.
	 * 
	 * @throws CancelledException if the user cancels the correlation via the task monitor.
	 */
	public VTMatchSet correlate(VTSession session, TaskMonitor monitor) throws CancelledException;

	/**
	 * Return the name of the correlator.
	 * @return the name of the correlator
	 */
	public String getName();

	/**
	 * Returns a options object populated with the options for this correlator instance.
	 */
	public ToolOptions getOptions();

	/**
	 * Returns the address set associated with this correlator instance.
	 * @return  the address set associated with this correlator instance.
	 */
	public AddressSetView getSourceAddressSet();

	/**
	 * Returns the source program for this correlator instance.
	 * @return  the source program for this correlator instance.
	 */
	public Program getSourceProgram();

	/**
	 * Returns the destination program for this correlator instance.
	 * @return  the destination program for this correlator instance.
	 */
	public Program getDestinationProgram();

	/**
	 * Returns the address set associated with this correlator instance.
	 * @return  the address set associated with this correlator instance.
	 */
	public AddressSetView getDestinationAddressSet();
}
