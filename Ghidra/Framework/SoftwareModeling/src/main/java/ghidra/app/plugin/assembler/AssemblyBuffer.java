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
package ghidra.app.plugin.assembler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * A convenience for accumulating bytes output by an {@link Assembler}
 * 
 * <p>
 * This is most useful when there is not a {@link Program} available for assembly. If a program is
 * available, consider using {@link Assembler#assemble(Address, String...)} and reading the bytes
 * from the program. If not, or the program should not be modified, then the pattern of use is
 * generally:
 * 
 * <pre>
 * Address start = space.getAdddress(0x00400000);
 * Assembler asm = Assemblers.getAssembler(...);
 * AssemblyBuffer buffer = new AssemblyBuffer(asm, start);
 * 
 * buffer.assemble("PUSH R15");
 * buffer.assemble("PUSH R14");
 * buffer.assemble("PUSH R13");
 * ...
 * byte[] bytes = buffer.getBytes();
 * state.setVar(start, bytes.length, true, bytes);
 * </pre>
 */
public class AssemblyBuffer {
	private final ByteArrayOutputStream baos = new ByteArrayOutputStream();
	private final Assembler asm;
	private final Address entry;

	/**
	 * Create a buffer with the given assembler starting at the given entry
	 * 
	 * @param asm the assembler
	 * @param entry the starting address where the resulting code will be located
	 */
	public AssemblyBuffer(Assembler asm, Address entry) {
		this.asm = asm;
		this.entry = entry;
	}

	/**
	 * Get the address of the "cursor" where the next instruction will be assembled
	 * 
	 * @return the address
	 */
	public Address getNext() {
		return entry.add(baos.size());
	}

	/**
	 * Assemble a line and append it to the buffer
	 * 
	 * @param line the line
	 * @return the resulting bytes for the assembled instruction
	 * @throws AssemblySyntaxException if the instruction cannot be parsed
	 * @throws AssemblySemanticException if the instruction cannot be encoded
	 * @throws IOException if the buffer cannot be written
	 */
	public byte[] assemble(String line)
			throws AssemblySyntaxException, AssemblySemanticException, IOException {
		return emit(asm.assembleLine(getNext(), line));
	}

	/**
	 * Append arbitrary bytes to the buffer
	 * 
	 * @param bytes the bytes to append
	 * @return bytes
	 * @throws IOException if the bufgfer cannot be written
	 */
	public byte[] emit(byte[] bytes) throws IOException {
		baos.write(bytes);
		return bytes;
	}

	/**
	 * Get the complete buffer of bytes
	 * 
	 * <p>
	 * However used, the bytes should be placed at the {@code entry} given at construction, unless
	 * the client is certain the code is position independent.
	 * 
	 * @return the bytes
	 */
	public byte[] getBytes() {
		return baos.toByteArray();
	}
}
