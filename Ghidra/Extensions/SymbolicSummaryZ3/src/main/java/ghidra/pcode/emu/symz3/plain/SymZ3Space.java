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

import java.util.Map;
import java.util.stream.Stream;

import com.microsoft.z3.Context;

import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.symz3.model.SymValueZ3;

/**
 * The storage space for symbolic values
 * <p>
 * This is the actual implementation of the in-memory storage for symbolic z3 values. For a
 * stand-alone emulator, this is the full state. For a trace- or Debugger-integrated emulator, this
 * is a cache of values loaded from a trace backing this emulator. Most likely, that trace is the
 * user's current trace.
 */
public abstract class SymZ3Space {
	public abstract void set(SymValueZ3 offset, int size, SymValueZ3 val);

	public abstract SymValueZ3 get(SymValueZ3 offset, int size);

	public abstract String printableSummary();

	public abstract Stream<Map.Entry<String, String>> streamValuations(Context ctx,
			Z3InfixPrinter z3p);
}
