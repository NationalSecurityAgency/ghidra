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
package ghidra.app.util.pcode;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

/**
 * An appender to receive formatted p-code ops.
 * 
 * <p>
 * Using {@link AbstractAppender} is highly recommended, as it makes available methods for
 * displaying elements according to established Ghidra conventions.
 *
 * @param <T> the type of the final formatted output
 */
interface Appender<T> {
	/**
	 * Get the language of the p-code being formatted
	 * 
	 * @return
	 */
	Language getLanguage();

	/**
	 * Append a line label, usually meant to be on its own line
	 * 
	 * @param label the label number
	 */
	default void appendLineLabel(long label) {
		appendLineLabelRef(label);
	}

	/**
	 * Append indentation, usually meant for the beginning of a line
	 */
	default void appendIndent() {
		appendCharacter(' ');
		appendCharacter(' ');
	}

	/**
	 * Append a reference to the given line label
	 * 
	 * @param label the label number
	 */
	void appendLineLabelRef(long label);

	/**
	 * Append the given opcode
	 * 
	 * @param opcode the op's opcode
	 */
	void appendMnemonic(int opcode);

	/**
	 * Append the the given userop
	 * 
	 * @param id the userop id
	 */
	void appendUserop(int id);

	/**
	 * Append the given varnode in raw form
	 * 
	 * @param space the address space
	 * @param offset the offset in the space
	 * @param size the size in bytes
	 */
	void appendRawVarnode(AddressSpace space, long offset, long size);

	/**
	 * Append a character
	 * 
	 * <p>
	 * <b>NOTE:</b> if extra spacing is desired, esp., surrounding the equals sign, it must be
	 * appended manually.
	 * 
	 * @param c the character
	 */
	void appendCharacter(char c);

	/**
	 * Append an address in word-offcut form
	 * 
	 * @param wordOffset the word offset
	 * @param offcut the byte within the word
	 */
	void appendAddressWordOffcut(long wordOffset, long offcut);

	/**
	 * Append a local label
	 * 
	 * @param label the label name, e.g., {@code instr_next}
	 */
	void appendLabel(String label);

	/**
	 * Append a register
	 * 
	 * @param register the register
	 */
	void appendRegister(Register register);

	/**
	 * Append a scalar value
	 * 
	 * @param value the value
	 */
	void appendScalar(long value);

	/**
	 * Append an address space
	 * 
	 * @param space the space
	 */
	void appendSpace(AddressSpace space);

	/**
	 * Append a unique variable
	 * 
	 * @param offset the offset in unique space
	 */
	void appendUnique(long offset);

	/**
	 * Finish formatting and return the final result
	 * 
	 * @return the final result
	 */
	T finish();
}
