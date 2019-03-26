/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.lang;

import ghidra.program.model.listing.Instruction;

/**
 * <code>ParallelInstructionLanguageHelper</code> provides the ability via a language 
 * specified property to identify certain parallel instruction attributes. 
 * Implementations must define a public default constructor.
 * <p>
 * The following assumptions exist for parallel packets/groups of instructions:</p>
 * <ul>
 * <li>All instructions in a packet/group which are not the last instruction in the
 * packet/group must have a fall-through.</li>
 * </ul>
 */
public interface ParallelInstructionLanguageHelper {

	/**
	 * Return the mnemonic prefix (i.e., || ) for the specified instriction.
	 * @param instr
	 * @return mnemonic prefix or null if not applicable
	 */
	String getMnemonicPrefix(Instruction instr);

	/**
	 * Determine if the specified instruction is executed in parallel with 
	 * the instruction preceding it.
	 * @param instruction
	 * @return true if parallel else false
	 */
	boolean isParallelInstruction(Instruction instruction);

	/**
	 * Determine if the specified instruction is the last instruction in a parallel
	 * instruction group.  The group is defined as a sequential set of instructions 
	 * which are executed in parallel.  It is assumed that all terminal flows 
	 * will only be present in the semantics of the last instruction in a parallel
	 * group.
	 * <p>
	 * This method is primarily intended to assist disassembly to keep parallel 
	 * instruction packets/groups intact within a single InstructionBlock to 
	 * facilitate the pcode crossbuild directive.  Such cases are expected to
	 * defer all flows to the last instruction in the packet and flows should never
	 * have a destination in the middle of a packet/group.  If pcode crossbuild's
	 * are never utilized this method may always return false.
	 * @param instruction
	 * @return true if instruction is last in a parallel group or if no other
	 * instruction is executed in parallel with the specified instruction.
	 */
	boolean isEndOfParallelInstructionGroup(Instruction instruction);

}
