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
package ghidra.util.formatter;

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;

public class InstructionHtmlFormatter {
	private final static boolean SPACE_AFTER_SEP = true;

	public String formatInstruction(Instruction instruction) {
		InstructionHtmlAppender appender = new InstructionHtmlAppender();
		appender.appendMnemonic(instruction.getMnemonicString());
		appender.appendSeparator(" ");

		int numOperands = instruction.getNumOperands();
		if (numOperands == 0) {
			return appender.finish();
		}

		formatSeparator(instruction, 0, appender);

		for (int opIndex = 0; opIndex < numOperands; opIndex++) {
			List<Object> operandRepresentationList =
				instruction.getDefaultOperandRepresentationList(opIndex);
			formatOperand(instruction, operandRepresentationList, opIndex, appender);
		}

		return appender.finish();
	}

	void formatSeparator(Instruction instruction, int separatorIndex,
			InstructionHtmlAppender appender) {
		String separator = instruction.getSeparator(separatorIndex);
		if (separator == null) {
			return;
		}
		if (SPACE_AFTER_SEP) {
			separator += " ";
		}
		appender.appendSeparator(separator);
	}

	void formatOperand(Instruction instruction, List<Object> opRepList, int opIndex,
			InstructionHtmlAppender appender) {
		if (opRepList == null) {
			appender.appendBadRef(opRepList == null ? "<UNSUPPORTED>" : opRepList.toString());
			return;
		}
		for (int subOpIndex = 0; subOpIndex < opRepList.size(); subOpIndex++) {
			formatSubOperand(instruction, opRepList.get(subOpIndex), opIndex, subOpIndex,
				appender);
		}
		formatSeparator(instruction, opIndex + 1, appender);
	}

	void formatSubOperand(Instruction instruction, Object opRep, int opIndex, int subOpIndex,
			InstructionHtmlAppender appender) {
		switch (opRep) {
			case VariableOffset vo -> formatSubOperand(instruction, vo.getObjects(), opIndex,
				subOpIndex, appender);
			case List<?> l -> formatSubOperand(instruction, l, opIndex, subOpIndex, appender);
			case String s -> formatSeparator(instruction, s, opIndex, subOpIndex, appender);
			case Register r -> formatRegister(instruction, r, opIndex, subOpIndex, appender);
			case Scalar s -> formatScalar(instruction, s, opIndex, subOpIndex, appender);
			case Address a -> formatAddress(instruction, a, opIndex, subOpIndex, appender);
			case Character c -> formatSeparator(instruction, c, opIndex, subOpIndex, appender);
			case Equate e -> formatEquate(instruction, e, opIndex, subOpIndex, appender);
			case LabelString l -> formatLabelString(instruction, l, opIndex, subOpIndex,
				appender);
			default -> formatSeparator(instruction, opRep.toString(), opIndex, subOpIndex,
				appender);
		}
	}

	void formatSeparator(Instruction instruction, String opRep, int opIndex, int subOpIndex,
			InstructionHtmlAppender appender) {
		appender.appendSeparator(opRep);
	}

	void formatSeparator(Instruction instruction, Character opRep, int opIndex, int subOpIndex,
			InstructionHtmlAppender appender) {
		appender.appendSeparator(opRep);
	}

	void formatRegister(Instruction instruction, Register opRep, int opIndex, int subOpIndex,
			InstructionHtmlAppender appender) {
		appender.appendRegister(opRep.toString());
	}

	void formatScalar(Instruction instruction, Scalar opRep, int opIndex, int subOpIndex,
			InstructionHtmlAppender appender) {
		appender.appendScalar(opRep.toString());
	}

	void formatAddress(Instruction instruction, Address opRep, int opIndex, int subOpIndex,
			InstructionHtmlAppender appender) {
		appender.appendAddress(opRep.toString());
	}

	void formatEquate(Instruction instruction, Equate opRep, int opIndex, int subOpIndex,
			InstructionHtmlAppender appender) {
		appender.appendScalar(opRep.toString());
	}

	void formatLabelString(Instruction instruction, LabelString l, int opIndex, int subOpIndex,
			InstructionHtmlAppender appender) {
		switch (l.getLabelType()) {
			case VARIABLE -> appender.appendVariableRef(l.toString());
			default -> appender.appendSeparator(l.toString());
		}
	}
}
