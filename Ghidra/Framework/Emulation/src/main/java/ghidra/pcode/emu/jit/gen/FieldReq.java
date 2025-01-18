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
package ghidra.pcode.emu.jit.gen;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;

/**
 * A field request for a pre-fetched or pre-constructed element
 */
public interface FieldReq {
	/**
	 * Derive a suitable name for the field
	 * 
	 * @return the name
	 */
	String name();

	/**
	 * Emit code to load the field onto the JVM stack
	 * 
	 * @param gen the code generator
	 * @param rv the visitor often for the {@link JitCompiledPassage#run(int) run} method, but could
	 *            be the static initializer or constructor
	 */
	void generateLoadCode(JitCodeGenerator gen, MethodVisitor rv);
}
