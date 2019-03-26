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

import generic.stl.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;

/// \brief A basic instantiation of a breakpoint table
///
/// This object allows breakpoints to registered in the table via either
///   - registerPcodeCallback()  or
///   = registerAddressCallback()
///
/// Breakpoints are stored in map containers, and the core BreakTable methods
/// are implemented to search in these containers
public class BreakTableCallBack extends BreakTable {

	public static final String DEFAULT_NAME = "*";

	private Emulate emulate;
	private SleighLanguage language;
	// a container of address based breakpoints
	private MapSTL<Address, BreakCallBack> addressCallback =
			new ComparableMapSTL<>();
	// a container of pcode based breakpoints
	private MapSTL<Long, BreakCallBack> pcodeCallback = new ComparableMapSTL<>();
	private BreakCallBack defaultPcodeCallback;

	/// The break table needs a translator object so user-defined pcode ops can be registered against
	/// by name.
	/// \param t is the translator object
	public BreakTableCallBack(SleighLanguage language) {
		this.language = language;
	}

	/// Any time the emulator is about to execute a user-defined pcode op with the given name,
	/// the indicated breakpoint is invoked first. The break table does \e not assume responsibility
	/// for freeing the breakpoint object.
	/// \param name is the name of the user-defined pcode op
	/// \param func is the breakpoint object to associate with the pcode op
	public void registerPcodeCallback(String name, BreakCallBack func) {
		func.setEmulate(emulate);
		if (DEFAULT_NAME.equals(name)) {
			defaultPcodeCallback = func;
			return;
		}
		int numUserOps = language.getNumberOfUserDefinedOpNames();
		for (int i = 0; i < numUserOps; i++) {
			if (name.equals(language.getUserDefinedOpName(i))) {
				pcodeCallback.add((long) i, func);
				return;
			}
		}
		// tell them what names are valid, probably not worth doing, but hate just getting no context on an error...
		StringBuilder names = new StringBuilder();
		for (int i = 0; i < numUserOps; i++) {
			names.append(language.getUserDefinedOpName(i));
			if (i < (numUserOps - 1))
				names.append(", ");
		}
		throw new LowlevelError("Bad userop name: " + name + "\n" + "Must be one of:\n" + names);
	}

	/// Unregister the currently registered PcodeCallback handler for the
	/// specified name
	/// \param name is the name of the user-defined pcode op
	public void unregisterPcodeCallback(String name) {
		if (DEFAULT_NAME.equals(name)) {
			defaultPcodeCallback = null;
			return;
		}
		int numUserOps = language.getNumberOfUserDefinedOpNames();
		for (int i = 0; i < numUserOps; i++) {
			if (name.equals(language.getUserDefinedOpName(i))) {
				pcodeCallback.remove((long) i);
				return;
			}
		}
		throw new LowlevelError("Bad userop name: " + name);
	}

	/// Any time the emulator is about to execute (the pcode translation of) a particular machine
	/// instruction at this address, the indicated breakpoint is invoked first. The break table
	/// does \e not assume responsibility for freeing the breakpoint object.
	/// \param addr is the address associated with the breakpoint
	/// \param func is the breakpoint being registered
	public void registerAddressCallback(Address addr, BreakCallBack func) {
		func.setEmulate(emulate);
		addressCallback.add(addr, func);
	}

	public void unregisterAddressCallback(Address addr) {
		addressCallback.remove(addr);
	}

	/// This routine invokes the setEmulate method on each breakpoint currently in the table
	/// \param emu is the emulator to be associated with the breakpoints
	@Override
	public void setEmulate(Emulate emu) {
		// Make sure all callbbacks are aware of new emulator
		emulate = emu;
		IteratorSTL<Pair<Address, BreakCallBack>> iter1;

		for (iter1 = addressCallback.begin(); !iter1.isEnd(); iter1.increment()) {
			iter1.get().second.setEmulate(emu);
		}
		if (defaultPcodeCallback != null) {
			defaultPcodeCallback.setEmulate(emu);
		}
		IteratorSTL<Pair<Long, BreakCallBack>> iter2;
		for (iter2 = pcodeCallback.begin(); !iter2.isEnd(); iter2.increment()) {
			iter2.get().second.setEmulate(emu);
		}
	}

	/// This routine examines the pcode-op based container for any breakpoints associated with the
	/// given op.  If one is found, its pcodeCallback method is invoked.
	/// \param curop is pcode op being checked for breakpoints
	/// \return \b true if the breakpoint exists and returns \b true, otherwise return \b false
	@Override
	public boolean doPcodeOpBreak(PcodeOpRaw curop) {
		long val = curop.getInput(0).getOffset();
		IteratorSTL<Pair<Long, BreakCallBack>> iter = pcodeCallback.find(val);
		if (iter.isEnd()) {
			if (defaultPcodeCallback != null) {
				return defaultPcodeCallback.pcodeCallback(curop);
			}
			return false;
		}
		return iter.get().second.pcodeCallback(curop);
	}

	/// This routine examines the address based container for any breakpoints associated with the
	/// given address. If one is found, its addressCallback method is invoked.
	/// \param addr is the address being checked for breakpoints
	/// \return \b true if the breakpoint exists and returns \b true, otherwise return \b false
	@Override
	public boolean doAddressBreak(Address addr) {
		IteratorSTL<Pair<Address, BreakCallBack>> iter = addressCallback.find(addr);
		if (iter.isEnd()) {
			return false;
		}
		return iter.get().second.addressCallback(addr);
	}

}
