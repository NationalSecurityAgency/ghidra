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
package ghidra.pcode.emu.jit.gen.type;

import ghidra.pcode.emu.jit.gen.op.LoadOpGen;
import ghidra.pcode.emu.jit.gen.op.StoreOpGen;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;

/**
 * A generator whose implementation is to emit invocations of a named method in
 * {@link JitCompiledPassage}.
 * 
 * <p>
 * This is needed by {@link LoadOpGen} and {@link StoreOpGen}.
 */
public interface MethodAccessGen extends TypedAccessGen {
	/**
	 * Choose the name of a method, e.g. {@link JitCompiledPassage#readInt1(byte[], int)} to use for
	 * the given variable size.
	 * 
	 * @param size the size in bytes
	 * @return the name of the method
	 */
	String chooseName(int size);
}
