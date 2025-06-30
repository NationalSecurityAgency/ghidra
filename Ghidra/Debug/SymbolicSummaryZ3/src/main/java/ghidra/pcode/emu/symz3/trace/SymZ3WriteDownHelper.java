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

import com.microsoft.z3.Context;

import ghidra.pcode.emu.symz3.SymZ3MemoryMap;
import ghidra.pcode.emu.symz3.SymZ3RegisterMap;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.symz3.model.SymValueZ3;

public class SymZ3WriteDownHelper {
	public static void writeDown(SymZ3RegisterMap rmap, PcodeTracePropertyAccess<String> property) {
		for (Entry<Register, SymValueZ3> entry : rmap.regvals.entrySet()) {
			SymValueZ3 symval = entry.getValue();
			if (symval == null) {
				throw new AssertionError(
					"Register " + entry.getKey() + " has a null value in the map!");
			}
			Register key = entry.getKey();
			Address address = key.getAddress();
			String serialized_value = symval.serialize();
			property.put(address, serialized_value);
		}
	}

	public static void writeDown(SymZ3MemoryMap mmap, AddressSpace space,
			PcodeTracePropertyAccess<String> into) {
		/**
		 * Symbolic addresses all get stored as a single string in NO_ADDRESS, but concrete
		 * addresses we can store using the map.
		 */
		for (Entry<String, SymValueZ3> entry : mmap.memvals.entrySet()) {
			/**
			 * some improvement could be made here, we have a serialized string as an address, but
			 * it might be just a number.
			 * 
			 * This is really HACKY HACKY
			 * 
			 * TODO: some refactoring needed
			 */
			try (Context ctx = new Context()) {
				SymValueZ3 symAddr =
					new SymValueZ3(ctx, SymValueZ3.deserializeBitVecExpr(ctx, entry.getKey()));

				String serializedValue = entry.getValue().serialize();
				BigInteger bi = symAddr.toBigInteger();
				Boolean handled = false;
				if (bi != null) {
					try {
						Address address = space.getAddress(bi.toString(16));
						handled = true;
						into.put(address, serializedValue);
					}
					catch (AddressFormatException e) {
						// NOTE: Falls through to unhandled case
					}
				}
				if (!handled) {
					/**
					 * need to explore this.. for now we will grab and append, and not check for
					 * replacement so yes, this needs fixed...
					 */
					Address fakeAddress = Address.NO_ADDRESS;
					String existing = into.get(fakeAddress);
					existing = existing + "::" + symAddr + "<==>" + serializedValue;
					into.put(fakeAddress, existing);
				}
			}
		}
	}
}
