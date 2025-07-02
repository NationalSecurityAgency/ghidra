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
package ghidra.pcode.emu.symz3.plain;

import java.util.Map.Entry;
import java.util.stream.Stream;

import com.microsoft.z3.Context;

import ghidra.pcode.emu.symz3.SymZ3RegisterMap;
import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.symz3.model.SymValueZ3;
import ghidra.util.Msg;

/**
 * The storage space for registers in a SymZ3Space
 * 
 * <p>
 * The SymZ3Space is partitioned into separate storage spaces for registers, memory, etc. As such,
 * when the space is used for more complex emulators (e.g., based on trace) This class is not
 * extended. E.g., there exists a TraceSymZ3Space that derives from SymZ3Space, but the individual
 * pieces use composition instead of inheritance. E.g., most all of the functionality is delegated
 * to the SymZ3RegisterMap and there is just a bit of plumbing here.
 */
public class SymZ3RegisterSpace extends SymZ3Space {
	private final SymZ3RegisterMap rmap = new SymZ3RegisterMap();

	private final AddressSpace space;
	private final Language language;

	public SymZ3RegisterSpace(AddressSpace space, Language language) {
		super();
		this.space = space;
		this.language = language;
	}

	@Override
	public String printableSummary() {
		return rmap.printableSummary();
	}

	@Override
	public Stream<Entry<String, String>> streamValuations(Context ctx, Z3InfixPrinter z3p) {
		return rmap.streamValuations(ctx, z3p);
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
		Register r = getRegister(offset, size);
		if (r == null) {
			Msg.warn(this, "set is ignoring set register with offset: " + offset + " and size: " +
				size + " to: " + val);
			return;
		}
		this.rmap.updateRegister(r, val);
	}

	@Override
	public SymValueZ3 get(SymValueZ3 offset, int size) {
		Register r = getRegister(offset, size);
		if (r == null) {
			Msg.warn(this, "unable to get register with space: " + space.getSpaceID() +
				" offset_long: " + offset + " size: " + size);
			return null;
		}
		SymValueZ3 result = this.rmap.getRegister(r);
		return result;
	}
}
