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

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Stream;

import com.microsoft.z3.*;

import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.AddressSpace;
import ghidra.symz3.model.SymValueZ3;

/**
 * The storage space for unique registers
 * 
 * <p>
 * This is the actual implementation of the in-memory storage for symbolic z3 values. For a
 * stand-alone emulator, this is the full state. For a trace- or Debugger-integrated emulator, this
 * is a cache of values loaded from a trace backing this emulator. Most likely, that trace is the
 * user's current trace.
 */
public class SymZ3TraceUniqueSpace extends SymZ3TraceSpace {
	private final Map<String, SymValueZ3> uniqvals = new HashMap<String, SymValueZ3>();

	public SymZ3TraceUniqueSpace(AddressSpace space, PcodeTracePropertyAccess<String> property) {
		super(space, property);
	}

	private String label(long offset, int size) {
		return "" + offset + ":" + size;
	}

	public void set(long offset, int size, SymValueZ3 val) {
		this.updateUnique(label(offset, size), val);
	}

	public SymValueZ3 get(long offset, int size) {
		return this.getUnique(label(offset, size));
	}

	public void updateUnique(String s, SymValueZ3 value) {
		uniqvals.put(s, value);
	}

	public SymValueZ3 getUnique(String s) {
		return uniqvals.get(s);
	}

	@Override
	public String printableSummary() {
		return "";
	}

	@Override
	public Stream<Entry<String, String>> streamValuations(Context ctx, Z3InfixPrinter z3p) {
		return Stream.of();
	}

	@Override
	public void set(SymValueZ3 offset, int size, SymValueZ3 val) {
		assert val != null;
		try (Context ctx = new Context()) {
			BitVecExpr b = offset.getBitVecExpr(ctx);
			if (b.isNumeral()) {
				BitVecNum bvn = (BitVecNum) b;
				this.set(bvn.getLong(), size, val);
			}
			else {
				throw new AssertionError("how can we have a symbolic offset for a unique set:" +
					offset + "is numeral? " + b.isNumeral() + " is BV numeral: " + b.isBVNumeral());
			}
		}
	}

	@Override
	public SymValueZ3 get(SymValueZ3 offset, int size) {
		try (Context ctx = new Context()) {
			BitVecExpr b = offset.getBitVecExpr(ctx);
			if (b.isNumeral()) {
				BitVecNum bvn = (BitVecNum) b;
				return this.get(bvn.getLong(), size);
			}
			throw new AssertionError("how can we have a symbolic offset for unique get?");
		}
	}

	@Override
	public void writeDown(PcodeTracePropertyAccess<String> into) {
		return;
	}
}
