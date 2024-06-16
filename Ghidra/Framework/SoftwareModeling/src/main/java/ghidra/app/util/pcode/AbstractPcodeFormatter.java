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

import java.util.List;

import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;

/**
 * An abstract p-code formatter which can take a list of p-code ops or op templates and consistently
 * format them. The general pattern is to extend this class and specify another class which extends
 * an {@link AbstractAppender}. In most cases, it is only necessary to override
 * {@link #formatOpTemplate(Appender, OpTpl)}. Otherwise, most formatting logic is implemented by
 * the appender.
 *
 * @see {@link StringPcodeFormatter} for an example
 * @see {@link AbstractAppender}
 * @param <T> the type of this formatter's output, e.g., {@link String}
 * @param <A> the type of the appender
 */
public abstract class AbstractPcodeFormatter<T, A extends Appender<T>>
		implements PcodeFormatter<T> {

	/**
	 * A result instructing the formatter whether or not to continue
	 */
	protected enum FormatResult {
		CONTINUE, TERMINATE;
	}

	/**
	 * Create the appender for a formatting invocation
	 * 
	 * @param language the language of the p-code to format
	 * @param indent indicates whether each line should be indented to accommodate line labels
	 * @return the new appender
	 */
	protected abstract A createAppender(Language language, boolean indent);

	/**
	 * Check if this formatter is configured to display raw p-code
	 * 
	 * @return true if displaying raw, false otherwise
	 */
	protected boolean isFormatRaw() {
		return false;
	}

	@Override
	public T formatTemplates(Language language, List<OpTpl> pcodeOpTemplates) {
		boolean indent = hasLabel(pcodeOpTemplates);
		A appender = createAppender(language, indent);

		for (OpTpl template : pcodeOpTemplates) {
			if (FormatResult.TERMINATE == formatOpTemplate(appender, template)) {
				break;
			}
		}
		return appender.finish();
	}

	/**
	 * Format a single op template
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param op the template to format
	 * @return instructions to continue or terminate. The loop in
	 *         {@link #formatTemplates(Language, List)} is terminated if this method returns
	 *         {@link FormatResult#TERMINATE}.
	 */
	protected FormatResult formatOpTemplate(A appender, OpTpl op) {
		int opcode = op.getOpcode();
		if (PcodeOp.PTRADD == opcode) {
			appender.appendLineLabel(op.getInput()[0].getOffset().getReal());
			return FormatResult.CONTINUE;
		}

		appender.appendIndent();

		if (opcode >= PcodeOp.PCODE_MAX) {
			throw new RuntimeException("Unsupported opcode encountered: " + opcode);
		}
		VarnodeTpl output = op.getOutput();
		if (output != null) {
			formatOutput(appender, opcode, output);
			appender.appendCharacter('=');
		}
		appender.appendMnemonic(opcode);
		VarnodeTpl[] inputs = op.getInput();
		for (int i = 0; i < inputs.length; i++) {
			if (i > 0) {
				appender.appendCharacter(',');
			}
			appender.appendCharacter(' ');
			if (i == 0) {
				if (!isFormatRaw()) {
					if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
						formatMemoryInput(appender, inputs[0], inputs[1]);
						++i;
						continue;
					}
					if (opcode == PcodeOp.CALLOTHER) {
						formatCallOtherName(appender, inputs[0]);
						continue;
					}
				}
				if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
					if (formatLabelInput(appender, inputs[i])) {
						continue;
					}
				}
			}
			formatInput(appender, opcode, i, inputs[i]);
		}
		return FormatResult.CONTINUE;
	}

	/**
	 * Format an output varnode
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param opcode the op's opcode
	 * @param output the varnode to format
	 */
	protected void formatOutput(A appender, int opcode, VarnodeTpl output) {
		formatVarnode(appender, opcode, -1, output);
	}

	/**
	 * Format an input varnode
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param opcode the op's opcode
	 * @param opIndex the operand's index
	 * @param input the varnode to format
	 */
	protected void formatInput(A appender, int opcode, int opIndex, VarnodeTpl input) {
		formatVarnode(appender, opcode, opIndex, input);
	}

	/**
	 * Format a varnode
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param opcode the op's opcode
	 * @param opIndex the operand's index (-1 is output, 0 is first input)
	 * @param vTpl the varnode to format
	 */
	protected void formatVarnode(A appender, int opcode, int opIndex, VarnodeTpl vTpl) {
		ConstTpl space = vTpl.getSpace();
		ConstTpl offset = vTpl.getOffset();
		ConstTpl size = vTpl.getSize();

		if (space.getType() == ConstTpl.J_CURSPACE) {
			if (offset.getType() == ConstTpl.J_START) {
				appender.appendLabel("inst_start");
			}
			else if (offset.getType() == ConstTpl.J_NEXT) {
				appender.appendLabel("inst_next");
			}
			else if (offset.getType() == ConstTpl.J_NEXT2) {
				appender.appendLabel("inst_next2");
			}
			else {
				formatAddress(appender, null, offset, size);
			}
		}
		else if (space.getType() == ConstTpl.SPACEID) {
			if (isFormatRaw() && offset.getType() == ConstTpl.REAL &&
				size.getType() == ConstTpl.REAL) {
				formatVarnodeRaw(appender, space.getSpaceId(), offset, size);
			}
			else {
				formatVarnodeNice(appender, space.getSpaceId(), offset, size);
			}
		}
		else {
			throw new RuntimeException("Unsupported space template type: " + space.getType());
		}
	}

	/**
	 * Format a varnode in nice (non-raw) form
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param space the address space of the varnode
	 * @param offset the offset in the address space
	 * @param size the size in bytes
	 */
	protected void formatVarnodeNice(A appender, AddressSpace space, ConstTpl offset,
			ConstTpl size) {
		if (space.isConstantSpace()) {
			formatConstant(appender, offset, size);
		}
		else if (space.isUniqueSpace()) {
			formatUnique(appender, offset, size);
		}
		else {
			formatAddress(appender, space, offset, size);
		}
	}

	/**
	 * Format a varnode in raw form
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param space the address space of the varnode
	 * @param offset the offset in the address space
	 * @param size the size in bytes
	 */
	protected void formatVarnodeRaw(A appender, AddressSpace space, ConstTpl offset,
			ConstTpl size) {
		appender.appendRawVarnode(space, offset.getReal(), size.getReal());
	}

	/**
	 * Format a unique variable
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param offset the offset in unique space
	 * @param size the size in bytes
	 */
	protected void formatUnique(A appender, ConstTpl offset, ConstTpl size) {
		if (offset.getType() != ConstTpl.REAL) {
			throw new RuntimeException("Unsupported unique offset type: " + offset.getType());
		}
		if (size.getType() != ConstTpl.REAL) {
			throw new RuntimeException("Unsupported unique size type: " + size.getType());
		}
		appender.appendUnique(offset.getReal());
		formatSize(appender, size);
	}

	/**
	 * Format a memory variable
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param addrSpace the address space of the variable
	 * @param offset the offset in the address space
	 * @param size the size in bytes
	 */
	protected void formatAddress(A appender, AddressSpace addrSpace,
			ConstTpl offset, ConstTpl size) {
		if (offset.getType() != ConstTpl.REAL) {
			throw new RuntimeException("Unsupported address offset type: " + offset.getType());
		}

		long offsetValue = offset.getReal();
		if (addrSpace == null) {
			appender.appendCharacter('*');
			appender.appendAddressWordOffcut(offsetValue, 0);
			if (size.getType() != ConstTpl.J_CURSPACE_SIZE) {
				formatSize(appender, size);
			}
			return;
		}

		long sizeValue = size.getReal();
		Register reg =
			appender.getLanguage().getRegister(addrSpace.getAddress(offsetValue), (int) sizeValue);
		if (reg != null) {
			appender.appendRegister(reg);
			if (reg.getMinimumByteSize() > sizeValue) {
				appender.appendCharacter(':');
				appender.appendScalar(sizeValue);
			}
			return;
		}
		appender.appendCharacter('*');
		appender.appendCharacter('[');
		appender.appendSpace(addrSpace);
		appender.appendCharacter(']');

		long wordOffset = offsetValue / addrSpace.getAddressableUnitSize();
		long offcut = offsetValue % addrSpace.getAddressableUnitSize();
		appender.appendAddressWordOffcut(wordOffset, offcut);
		formatSize(appender, size);
		return;
	}

	/**
	 * Format a constant
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param offset the value of the constant
	 * @param size the size in bytes
	 */
	protected void formatConstant(A appender, ConstTpl offset, ConstTpl size) {
		if (offset.getType() != ConstTpl.REAL) {
			throw new RuntimeException("Unsupported constant offset type: " + offset.getType());
		}
		long value = offset.getReal();
		appender.appendScalar(value);
		formatSize(appender, size);
	}

	/**
	 * Format a size indicator
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param size the size in bytes
	 */
	protected void formatSize(A appender, ConstTpl size) {
		if (size.getType() != ConstTpl.REAL) {
			throw new RuntimeException("Unsupported address size type: " + size.getType());
		}
		if (size.getReal() != 0) {
			appender.appendCharacter(':');
			appender.appendScalar(size.getReal());
		}
	}

	/**
	 * Format a p-code userop name (CALLOTHER)
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param input0 the constant varnode giving the userop id
	 */
	protected void formatCallOtherName(A appender, VarnodeTpl input0) {
		if (!input0.getSpace().isConstSpace() || input0.getOffset().getType() != ConstTpl.REAL) {
			throw new RuntimeException("Expected constant input[0] for CALLOTHER pcode op");
		}

		int id = (int) input0.getOffset().getReal();
		appender.appendCharacter('"');
		appender.appendUserop(id);
		appender.appendCharacter('"');
	}

	/**
	 * Try to format a local label (e.g., {@code instr_next})
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param input0 the relative jump varnode
	 * @return true if the varnode was formatted, false if not
	 */
	protected boolean formatLabelInput(A appender, VarnodeTpl input0) {
		if (input0.getSpace().isConstSpace() &&
			input0.getOffset().getType() == ConstTpl.J_RELATIVE) {
			appender.appendLineLabelRef(input0.getOffset().getReal());
			return true;
		}
		return false;
	}

	/**
	 * Format the memory location for a LOAD or STORE op
	 * 
	 * @param appender the appender to receive the formatted text
	 * @param input0 the const varnode giving the address space id
	 * @param input1 the varnode giving the address offset
	 */
	protected void formatMemoryInput(A appender, VarnodeTpl input0, VarnodeTpl input1) {
		if (!input0.getSpace().isConstSpace() || input0.getOffset().getType() != ConstTpl.REAL) {
			throw new RuntimeException("Expected constant input[0] for LOAD/STORE pcode op");
		}
		int id = (int) input0.getOffset().getReal();
		AddressSpace space = appender.getLanguage().getAddressFactory().getAddressSpace(id);
		if (space == null) {
			Msg.error(this, "Address space id not found: " + id);
		}
		appender.appendSpace(space);
		appender.appendCharacter('(');
		formatVarnode(appender, -1, 0, input1);
		appender.appendCharacter(')');
	}

	private static boolean hasLabel(List<OpTpl> pcodeOpTemplates) {
		for (OpTpl op : pcodeOpTemplates) {
			if (isLineLabel(op)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if the given template represents a line label
	 * 
	 * <p>
	 * The {@link PcodeOp#PTRADD} op is ordinarily only use in high p-code. We reuse (read "abuse")
	 * it to hold a display slot for line labels later referred to in {@link PcodeOp#BRANCH} and
	 * {@link PcodeOp#CBRANCH} ops. This method checks if the given op template is one of those
	 * placeholders.
	 * 
	 * @param template the op template
	 * @return true if it's a line label
	 */
	protected static boolean isLineLabel(OpTpl template) {
		// Overloaded: PTRADD is high p-code
		return template.getOpcode() == PcodeOp.PTRADD;
	}

}
