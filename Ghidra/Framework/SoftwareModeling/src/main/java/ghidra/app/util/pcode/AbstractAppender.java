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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;

/**
 * A base implementation of {@link Appender} suitable for most cases.
 *
 * @param <T> the type of output of the formatter
 */
public abstract class AbstractAppender<T> implements Appender<T> {
	protected final Language language;
	protected final boolean indent;

	/**
	 * Create a new appender.
	 * 
	 * @param language the language of the p-code ops to format
	 * @param indent whether or not to indent
	 */
	public AbstractAppender(Language language, boolean indent) {
		this.language = language;
		this.indent = indent;
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	@Override
	public void appendAddressWordOffcut(long wordOffset, long offcut) {
		appendString(stringifyWordOffcut(wordOffset, offcut));
	}

	@Override
	public void appendCharacter(char c) {
		if (c == '=') {
			appendString(" = "); // HACK
		}
		else {
			appendString(Character.toString(c));
		}
	}

	@Override
	public void appendIndent() {
		if (indent) {
			appendCharacter(' ');
			appendCharacter(' ');
		}
	}

	@Override
	public void appendLabel(String label) {
		appendString(label);
	}

	@Override
	public void appendLineLabelRef(long label) {
		appendString(stringifyLineLabel(label));
	}

	@Override
	public void appendMnemonic(int opcode) {
		appendString(stringifyOpMnemonic(opcode));
	}

	@Override
	public void appendRawVarnode(AddressSpace space, long offset, long size) {
		appendString(stringifyRawVarnode(space, offset, size));
	}

	@Override
	public void appendRegister(Register register) {
		appendString(stringifyRegister(register));
	}

	@Override
	public void appendScalar(long value) {
		appendString(stringifyScalarValue(value));
	}

	@Override
	public void appendSpace(AddressSpace space) {
		appendString(stringifySpace(space));
	}

	/**
	 * Append a plain string.
	 * 
	 * <p>
	 * By default, all append method delegate to this, so either it must be implemented, or every
	 * other append method must be overridden to avoid ever invoking this method. The default
	 * implementation throws an assertion error.
	 * 
	 * @param string the string to append
	 */
	protected void appendString(String string) {
		throw new AssertionError(
			"Either this shouldn't happen, or you should accept the string");
	}

	@Override
	public void appendUnique(long offset) {
		appendString(stringifyUnique(offset));
	}

	@Override
	public void appendUserop(int id) {
		appendString(stringifyUserop(language, id));
	}

	/**
	 * Covert the given line label to a string as it should be conventionally displayed.
	 * 
	 * @param label the label number
	 * @return the display string, e.g., {@code <L1>}
	 */
	protected String stringifyLineLabel(long label) {
		return "<" + label + ">";
	}

	/**
	 * Convert the given opcode to a string as it should be conventionally displayed.
	 * 
	 * @param opcode the opcode
	 * @return the display string, i.e., its mnemonic
	 */
	protected String stringifyOpMnemonic(int opcode) {
		return PcodeOp.getMnemonic(opcode);
	}

	/**
	 * Convert the given varnode to its raw conventional form.
	 * 
	 * @param space the address space
	 * @param offset the offset in the space
	 * @param size the size in bytes
	 * @return the raw display string
	 */
	protected String stringifyRawVarnode(AddressSpace space, long offset, long size) {
		return "(" + space.getName() + ", 0x" + Long.toHexString(offset) + ", " + size + ")";
	}

	/**
	 * Convert the given register to a string as it should be conventionally displayed.
	 * 
	 * @param register the register
	 * @return the display string, i.e., its name
	 */
	protected String stringifyRegister(Register register) {
		return register.getName();
	}

	/**
	 * Convert the given scalar to a string as it should be conventionally displayed.
	 * 
	 * @param value the value
	 * @return the display string, i.e., its decimal value if small, or hex value is large
	 */
	protected String stringifyScalarValue(long value) {
		if (value >= -64 && value <= 64) {
			return Long.toString(value);
		}
		else {
			return "0x" + Long.toHexString(value);
		}
	}

	/**
	 * Convert the given address space to a string as it should be conventionally displayed.
	 * 
	 * @param space the address space
	 * @return the display string, i.e., its name
	 */
	protected String stringifySpace(AddressSpace space) {
		if (space == null) {
			return "unknown";
		}
		return space.getName();
	}

	/**
	 * Convert a given unique variable to a string as it should be conventionally displayed.
	 * 
	 * @param offset the variable's offset
	 * @return the display string, e.g., {@code $U1234}
	 */
	protected String stringifyUnique(long offset) {
		return "$U" + Long.toHexString(offset);
	}

	/**
	 * Lookup a given userop name
	 * 
	 * @param language the language containing the userop
	 * @param id the userop id
	 * @return the display string, i.e., its name, or null if it doesn't exist
	 */
	protected String stringifyUseropUnchecked(Language language, int id) {
		if (!(language instanceof SleighLanguage)) {
			throw new RuntimeException("Expected Sleigh language for CALLOTHER op");
		}
		return ((SleighLanguage) language).getUserDefinedOpName(id);
	}

	/**
	 * Convert a given userop to a string as it should be conventionally displayed.
	 * 
	 * @param language the langauge containing the userop
	 * @param id the userop id
	 * @return the display string, i.e., its name or "unknown"
	 */
	protected String stringifyUserop(Language language, int id) {
		String pseudoOp = stringifyUseropUnchecked(language, id);
		if (pseudoOp == null) {
			Msg.error(this, "Pseudo-op index not found: " + id);
			pseudoOp = "unknown";
		}
		return pseudoOp;
	}

	/**
	 * Convert a given word-offcut style address to a string as it should be conventionally
	 * displayed.
	 * 
	 * @param wordOffset the offset of the word in memory
	 * @param offcut the byte "offcut" within the word
	 * @return the display string, e.g., {@code 0x1234.1}
	 */
	protected String stringifyWordOffcut(long wordOffset, long offcut) {
		String str = "0x" + Long.toHexString(wordOffset);
		if (offcut != 0) {
			str += "." + offcut;
		}
		return str;
	}
}
