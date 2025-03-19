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
package ghidra.pcode.emulate;

import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;

/**
 * A collection of breakpoints for the emulator
 * <p>
 * A BreakTable keeps track of an arbitrary number of breakpoints for an emulator.
 * Breakpoints are either associated with a particular user-defined pcode op,
 * or with a specific machine address (as in a standard debugger). Through the BreakTable
 * object, an emulator can invoke breakpoints through the two methods
 * <ul>
 *  <li>doPcodeOpBreak()</li>
 *  <li>doAddressBreak()</li>
 * </ul>
 *
 * depending on the type of breakpoint they currently want to invoke
 */

public interface BreakTable {

	/**
	 * Associate a particular emulator with breakpoints in this table
	 * <p>
	 * Breakpoints may need access to the context in which they are invoked. This
	 * routine provides the context for all breakpoints in the table.
	 * @param emu is the Emulate context
	 */
	public abstract void setEmulate(Emulate emu);

	/**
	 * Invoke any breakpoints associated with this particular pcodeop
	 * <p>
	 * Within the table, the first breakpoint which is designed to work with this particular
	 * kind of pcode operation is invoked.  If there was a breakpoint and it was designed
	 * to replace the action of the pcode op, then true is returned.
	 * @param curop is the instance of a pcode op to test for breakpoints
	 * @return true if the action of the pcode op is performed by the breakpoint
	 */
	public abstract boolean doPcodeOpBreak(PcodeOpRaw curop);

	/**
	 * Invoke any breakpoints associated with this machine address
	 * <p>
	 * Within the table, the first breakpoint which is designed to work with at this address
	 * is invoked.  If there was a breakpoint, and if it was designed to replace
	 * the action of the machine instruction, then true is returned.
	 * @param addr is address to test for breakpoints
	 * @return true is the machine instruction has been replaced by a breakpoint
	 */
	public abstract boolean doAddressBreak(Address addr);
}
