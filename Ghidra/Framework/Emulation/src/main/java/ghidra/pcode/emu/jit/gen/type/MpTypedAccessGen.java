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

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

/**
 * A generator for a multi-precision integer type.
 * 
 * <p>
 * This depends on the generator for single integer types. Each will need to work out how to compose
 * the leg generator given the stack ordering, byte order, and read/write operation.
 */
public interface MpTypedAccessGen extends TypedAccessGen {
	/**
	 * Get a generator for individual legs of this multi-precision access generator
	 * 
	 * @return the leg generator
	 */
	ExportsLegAccessGen getLegGen();

	/**
	 * {@inheritDoc}
	 *
	 * <p>
	 * This uses several JVM stack entries. The varnode must be too large to fit in a single JVM
	 * primitive, or else it does not require "multi-precision" handling. A leg that spans blocks is
	 * handled as in
	 * {@link ExportsLegAccessGen#generateMpCodeLeg(JitCodeGenerator, AddressSpace, long, int, int, MethodVisitor)}.
	 * The legs are ordered on the stack such that the least significant portion is on top.
	 * 
	 * @param gen the code generator
	 * @param vn the varnode
	 * @param rv the method visitor
	 */
	@Override
	void generateCode(JitCodeGenerator gen, Varnode vn, MethodVisitor rv);
}
