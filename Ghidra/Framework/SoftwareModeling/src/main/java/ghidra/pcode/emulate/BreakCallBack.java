/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

/// \brief A breakpoint object
///
/// This is a base class for breakpoint objects in an emulator.  The breakpoints are implemented
/// as callback method, which is overridden for the particular behavior needed by the emulator.
/// Each derived class must override either
///   - pcodeCallback()
///   - addressCallback()
///
/// depending on whether the breakpoint is tailored for a particular pcode op or for
/// a machine address.
public class BreakCallBack {
	protected Emulate emulate;		///< The emulator currently associated with this breakpoint

	public BreakCallBack() {		///< Generic breakpoint constructor
		emulate = null;
	}
  
	  /// This routine is invoked during emulation, if this breakpoint has somehow been associated with
	  /// this kind of pcode op.  The callback can perform any operation on the emulator context it wants.
	  /// It then returns \b true if these actions are intended to replace the action of the pcode op itself.
	  /// Or it returns \b false if the pcode op should still have its normal effect on the emulator context.
	  /// \param op is the particular pcode operation where the break occurs.
	  /// \return \b true if the normal pcode op action should not occur
	public boolean pcodeCallback(PcodeOpRaw op) { ///< Call back method for pcode based breakpoints
		return false;
	}
  
  
	/// This routine is invoked during emulation, if this breakpoint has somehow been associated with
	/// this address.  The callback can perform any operation on the emulator context it wants. It then
	/// returns \b true if these actions are intended to replace the action of the \b entire machine
	/// instruction at this address. Or it returns \b false if the machine instruction should still be
	/// executed normally.
	/// \param addr is the address where the break has occurred
	/// \return \b true if the machine instruction should not be executed
  public boolean addressCallback(Address addr) { ///< Call back method for address based breakpoints
	  return false;
  }
  public void setEmulate(Emulate emu) { ///< Associate a particular emulator with this breakpoint
	  emulate = emu;
  }
}
