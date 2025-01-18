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
package ghidra.pcode.emu;

import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;

/**
 * A means of decoding machine instructions from the bytes contained in the machine state
 */
public interface InstructionDecoder {
	/**
	 * Get the language for this decoder
	 * 
	 * @return the language
	 */
	Language getLanguage();

	/**
	 * Decode the instruction starting at the given address using the given context
	 * 
	 * <p>
	 * This method cannot return null. If a decode error occurs, it must throw an exception.
	 * 
	 * @param address the address to start decoding
	 * @param context the disassembler/decode context
	 * @return the instruction
	 */
	PseudoInstruction decodeInstruction(Address address, RegisterValue context);

	/**
	 * Inform the decoder that the emulator thread just branched
	 * 
	 * @param address
	 */
	void branched(Address address);

	/**
	 * Get the last instruction decoded
	 * 
	 * @return the instruction
	 */
	Instruction getLastInstruction();

	/**
	 * Get the length of the last decoded instruction, including delay slots
	 * 
	 * @return the length
	 */
	int getLastLengthWithDelays();
}
