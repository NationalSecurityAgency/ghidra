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

import ghidra.app.cmd.comments.SetCommentsCmd;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.Conv;
import ghidra.util.task.TaskMonitor;

final class PdbUtil {

	/**
	 * Returns an address using the relative offset + image base.
	 */
	final static Address reladdr(Program program, int relativeOffset) {
		return reladdr(program, relativeOffset & Conv.INT_MASK);
	}

	/**
	 * Returns an address using the relative offset + image base.
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

		SetCommentsCmd.createComment(program, address, text, commentType);

	}

	/**
	 * Returns true is this symbol represents a function.
	 * For example, "FunctionName@4" or "MyFunction@22".
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

	final static void ensureSize(int expectedLength, Composite composite, MessageLog log) {
		int actualLength = composite.getLength();
		if (actualLength < expectedLength) {

			composite.setInternallyAligned(false);
			if (composite instanceof Structure) {
				Structure struct = (Structure) composite;
				// if this is an empty structure, the structure will lie to us
				//    and say it has one element so add 1 to growth factor
				struct.growStructure(
					expectedLength - actualLength + (struct.isNotYetDefined() ? 1 : 0));
			}
			// must be a union data type
			else {
				DataType datatype = new ArrayDataType(DataType.DEFAULT, expectedLength,
					DataType.DEFAULT.getLength());
				composite.add(datatype);
			}
		}
		else if (actualLength > expectedLength) {
			log.appendMsg("Warning: Composite data type generated from PDB has size mismatch. " +
				composite.getName() + ": expected 0x" + Integer.toHexString(expectedLength) +
				", but was 0x" + Integer.toHexString(actualLength));
		}
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

	final static void createMandatoryDataTypes(PdbParserNEW parser, TaskMonitor monitor) {

		DataTypeManager dtm = parser.getProgramDataTypeManager();

		parser.addDataType(new TypedefDataType("wchar", WideCharDataType.dataType));

		parser.addDataType(
			new TypedefDataType("__int8", AbstractIntegerDataType.getSignedDataType(1, dtm)));
		parser.addDataType(
			new TypedefDataType("__uint8", AbstractIntegerDataType.getUnsignedDataType(1, dtm)));

		parser.addDataType(
			new TypedefDataType("__int16", AbstractIntegerDataType.getSignedDataType(2, dtm)));
		parser.addDataType(
			new TypedefDataType("__uint16", AbstractIntegerDataType.getUnsignedDataType(2, dtm)));

		parser.addDataType(
			new TypedefDataType("__int32", AbstractIntegerDataType.getSignedDataType(4, dtm)));
		parser.addDataType(
			new TypedefDataType("__uint32", AbstractIntegerDataType.getUnsignedDataType(2, dtm)));

		parser.addDataType(
			new TypedefDataType("__int64", AbstractIntegerDataType.getSignedDataType(8, dtm)));
		parser.addDataType(
			new TypedefDataType("__uint64", AbstractIntegerDataType.getUnsignedDataType(8, dtm)));
	}

}
