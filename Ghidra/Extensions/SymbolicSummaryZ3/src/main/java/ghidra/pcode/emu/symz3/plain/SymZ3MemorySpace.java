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

import ghidra.pcode.emu.symz3.SymZ3MemoryMap;
import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.program.model.lang.Language;
import ghidra.symz3.model.SymValueZ3;

/**
 * The storage space for memory in a SymZ3Space. See SymZ3MemoryMap for limitations which are
 * extensive.
 * 
 * <p>
 * The SymZ3Space is partitioned into separate storage spaces for registers, memory, etc. As such,
 * when the space is used for more complex emulators (e.g., based on trace) This class is not
 * extended. E.g., there exists a TraceSymZ3Space that derives from SymZ3Space, but the individual
 * pieces use composition instead of inheritance. E.g., most all of the functionality is delegated
 * to the SymZ3MemoryMap and there is just a bit of plumbing here.
 */
public class SymZ3MemorySpace extends SymZ3Space {

	private SymZ3MemoryMap mmap;

	public SymZ3MemorySpace(Language language) {
		super();
		mmap = new SymZ3MemoryMap(language);
	}

	@Override
	public SymValueZ3 get(SymValueZ3 offset, int size) {
		return mmap.load(offset, size, true);
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
}
