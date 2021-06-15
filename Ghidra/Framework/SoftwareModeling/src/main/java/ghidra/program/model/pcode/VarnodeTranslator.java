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
/**
 * Helper class used to Translate from Pcode Varnodes to Registers/Constants/Etc...
 * 
 * 
 */
package ghidra.program.model.pcode;

import java.util.List;

import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

public class VarnodeTranslator {
	Language language;

	public VarnodeTranslator(Language lang) {
		this.language = lang;
	}

	public VarnodeTranslator(Program program) {
		this(program.getLanguage());
	}

	/**
	 * @return true if this program's language supports pcode
	 */
	public boolean supportsPcode() {
		return language.supportsPcode();
	}

	/**
	 * Translate the Varnode into a register if possible
	 * 
	 * @param node
	 *            varnode to translate
	 * @return Register or null if node is not a register
	 */
	public Register getRegister(Varnode node) {
		if (node == null) {
			return null;
		}

		return language.getRegister(node.getAddress(), node.getSize());
	}

	/**
	 * Get a varnode that maps to the given register
	 * 
	 * @param register
	 *            register to translate into a varnode
	 * @return varnode that reprents the register
	 */
	public Varnode getVarnode(Register register) {
		Varnode node = new Varnode(register.getAddress(), register.getMinimumByteSize());
		return node;
	}

	/**
	 * Get all defined registers for the program this translator was created
	 * with.
	 * 
	 * @return all defined registers as unmodifiable list
	 */
	public List<Register> getRegisters() {
		return language.getRegisters();
	}
}
