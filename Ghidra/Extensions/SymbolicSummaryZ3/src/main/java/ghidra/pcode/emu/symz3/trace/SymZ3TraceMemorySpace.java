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

import java.math.BigInteger;
import java.util.Map.Entry;
import java.util.stream.Stream;

import com.microsoft.z3.Context;

import ghidra.pcode.emu.symz3.SymZ3MemoryMap;
import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.*;
import ghidra.symz3.model.SymValueZ3;
import ghidra.util.Msg;

public class SymZ3TraceMemorySpace extends SymZ3TraceSpace {
	private final SymZ3MemoryMap mmap = new SymZ3MemoryMap(property.getLanguage());;

	public SymZ3TraceMemorySpace(AddressSpace space, PcodeTracePropertyAccess<String> property) {
		super(space, property);
	}

	public SymValueZ3 extractionHelper(String string, int size) {
		throw new AssertionError("need to implement extraction from: " + string);
	}

	public SymValueZ3 whenMissing(SymValueZ3 offset, int size) {
		if (!this.property.hasSpace(space)) {
			// our map will create a symbolic value
			Msg.info(this, "no backing, so our map created a missing symbolic value");
			return mmap.load(offset, size, true);
		}
		// if the address is concrete, we fetch using the address
		BigInteger bi = offset.toBigInteger();
		if (bi == null) {
			String string = this.property.get(Address.NO_ADDRESS);
			if (string != null) {
				Msg.info(this, "fetch from memory using the backing but symbolic address");
				return extractionHelper(string, size);
			}
		}
		else {
			try {
				Address addr = space.getAddress(bi.toString(16));
				String string = this.property.get(addr);
				if (string != null) {
					Msg.info(this, "fetch from memory using the backing and concrete address: " +
						addr + " deserializing: " + string);
					SymValueZ3 result = SymValueZ3.parse(string);
					Msg.info(this, "with result: " + result);
					return result;
				}
			}
			catch (AddressFormatException e) {
				;
			}
		}
		Msg.info(this,
			"we had a backing, but couldn't find the address, using map to create symbolic value");
		return mmap.load(offset, size, true);
	}

	@Override
	public SymValueZ3 get(SymValueZ3 offset, int size) {
		if (mmap.hasValueFor(offset, size)) {
			return mmap.load(offset, size, true);
		}
		return whenMissing(offset, size);
	}

	@Override
	public void set(SymValueZ3 offset, int size, SymValueZ3 val) {
		mmap.store(offset, size, val);
	}

	@Override
	public String printableSummary() {
		return mmap.printableSummary();
	}

	@Override
	public Stream<Entry<String, String>> streamValuations(Context ctx, Z3InfixPrinter z3p) {
		return mmap.streamValuations(ctx, z3p);
	}

	@Override
	public void writeDown(PcodeTracePropertyAccess<String> into) {
		SymZ3WriteDownHelper.writeDown(mmap, this.space, into);
	}
}
