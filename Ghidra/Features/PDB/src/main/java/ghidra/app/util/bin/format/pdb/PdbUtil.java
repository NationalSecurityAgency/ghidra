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
package ghidra.app.util.bin.format.pdb;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.Conv;

final class PdbUtil {

	/**
	 * Returns an address using the relative offset + image base.
	 * @param program the {@link Program} for which to act
	 * @param relativeOffset the relative offset
	 * @return the calculated {@link Address}
	 */
	final static Address reladdr(Program program, int relativeOffset) {
		return reladdr(program, relativeOffset & Conv.INT_MASK);
	}

	/**
	 * Returns an address using the relative offset + image base.
	 * @param program the {@link Program} for which to act
	 * @param relativeOffset the relative offset
	 * @return the calculated {@link Address}
	 */
	final static Address reladdr(Program program, long relativeOffset) {
		return program.getImageBase().add(relativeOffset);
	}

	/**
	 * Append comment if not already present
	 * @param program program
	 * @param address listing address
	 * @param text comment text
	 * @param commentType comment type ({@link CodeUnit}
	 */
	final static void appendComment(Program program, Address address, String text,
			int commentType) {

		String comment = program.getListing().getComment(commentType, address);
		if (comment != null) {
			if (comment.contains(text)) {
				return;
			}
			text = comment + "\n" + text;
		}

		SetCommentCmd.createComment(program, address, text, commentType);

	}

	/**
	 * Returns true is this symbol represents a function.
	 * For example, "FunctionName@4" or "MyFunction@22".
	 * @param program the {@link Program} for which to check
	 * @param symbol the symbol to check
	 * @param addr {@link Address} of the symbol
	 * @param length the length for the check
	 * @return {@code true} upon success
	 */
	final static boolean isFunction(Program program, String symbol, Address addr, int length) {
		int atpos = symbol.lastIndexOf('@');
		if (atpos > 0) {
			String s = symbol.substring(atpos + 1);
			try {
				Integer.parseInt(s);
			}
			catch (NumberFormatException e) {
				return false;
			}
			//check to make sure it is all code....
			PseudoDisassembler dis = new PseudoDisassembler(program);
			Address tmp = addr;
			while (tmp.subtract(addr) < length) {
				try {
					PseudoInstruction instr = dis.disassemble(tmp);
					tmp = tmp.add(instr.getLength());
				}
				catch (Exception e) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	final static void clearComponents(Composite composite) {
		if (composite instanceof Structure) {
			((Structure) composite).deleteAll();
		}
		else {
			while (composite.getNumComponents() > 0) {
				composite.delete(0);
			}
		}
	}

	/**
	 * Returns an appropriate string based on the pass iteration.
	 * For example:
	 * 1st pass
	 * 2nd pass
	 * 3rd pass
	 * 4th pass
	 * ...
	 * 8th pass
	 * ...
	 * 23rd pass
	 * etc.
	 * @param pass the number value of the pass to make pretty
	 * @return the string result
	 */
	final static String getPass(int pass) {
		if (pass > 20) {
			pass = (pass % 10);
		}
		switch (pass) {
			case 1:
				return pass + "st pass";
			case 2:
				return pass + "nd pass";
			case 3:
				return pass + "rd pass";
		}
		return pass + "th pass";
	}

}
