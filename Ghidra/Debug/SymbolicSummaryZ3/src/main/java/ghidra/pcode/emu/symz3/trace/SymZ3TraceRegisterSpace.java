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
package ghidra.pcode.emu.symz3.trace;

import java.util.Map.Entry;
import java.util.stream.Stream;

import com.microsoft.z3.Context;

import ghidra.pcode.emu.symz3.SymZ3RegisterMap;
import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.symz3.model.SymValueZ3;
import ghidra.util.Msg;

/**
 * The storage space for symbolic values in the register space, possibly obtained from a trace
 * 
 * <p>
 * This is the actual implementation of the in-memory storage for symbolic z3 values. For a
 * stand-alone emulator, this is the full state. For a trace- or Debugger-integrated emulator, this
 * is a cache of values loaded from a trace backing this emulator. Most likely, that trace is the
 * user's current trace.
 */
public class SymZ3TraceRegisterSpace extends SymZ3TraceSpace {
	private final SymZ3RegisterMap rmap = new SymZ3RegisterMap();
	private final Language language = property.getLanguage();

	public SymZ3TraceRegisterSpace(AddressSpace space, PcodeTracePropertyAccess<String> property) {
		super(space, property);
	}

	@Override
	public String printableSummary() {
		return rmap.printableSummary();
	}

	@Override
	public Stream<Entry<String, String>> streamValuations(Context ctx, Z3InfixPrinter z3p) {
		return rmap.streamValuations(ctx, z3p);
	}

	public SymValueZ3 whenMissing(Register r) {
		if (!this.property.hasSpace(space)) {
			// our map will create a symbolic value
			return rmap.getRegister(r);
		}
		String string = this.property.get(r.getAddress());
		if (string == null) {
			// our map will create a symbolic value
			return rmap.getRegister(r);
		}
		return SymValueZ3.parse(string);
	}

	private Register getRegister(SymValueZ3 offset, int size) {
		Long offsetLong = offset.toLong();
		if (offsetLong == null) {
			throw new AssertionError(
				"getRegister was given a symbolic register, should not be possible");
		}
		return language.getRegister(space, offset.toLong(), size);
	}

	@Override
	public void set(SymValueZ3 offset, int size, SymValueZ3 val) {
		assert offset != null;
		assert val != null;
		Register r = getRegister(offset, size);
		if (r == null) {
			Msg.warn(this, "set is ignoring set register with offset: " + offset + " and size: " +
				size + " to: " + val);
			return;
		}
		rmap.updateRegister(r, val);
	}

	@Override
	public SymValueZ3 get(SymValueZ3 offset, int size) {
		assert offset != null;
		Register r = getRegister(offset, size);
		if (r == null) {
			Msg.warn(this, "unable to get register with space: " + space.getSpaceID() +
				" offset_long: " + offset + " size: " + size);
			return null;
		}
		if (rmap.hasValueForRegister(r)) {
			SymValueZ3 result = rmap.getRegister(r);
			return result;
		}
		// attempt to get it from the backing
		return whenMissing(r);
	}

	@Override
	public void writeDown(PcodeTracePropertyAccess<String> into) {
		SymZ3WriteDownHelper.writeDown(rmap, into);
	}
}
