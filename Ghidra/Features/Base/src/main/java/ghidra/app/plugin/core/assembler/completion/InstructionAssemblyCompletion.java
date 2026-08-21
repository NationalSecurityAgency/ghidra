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
package ghidra.app.plugin.core.assembler.completion;

import java.math.BigInteger;
import java.util.Map.Entry;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * Represents an encoding for a complete assembly instruction
 * 
 * <p>
 * These provide no insertion text, since their activation should be handled by a custom listener.
 */
public class InstructionAssemblyCompletion extends AssemblyCompletion {
	private final byte[] data;
	final ContextChanges contextChanges;

	public InstructionAssemblyCompletion(Program program, Language language, Address at, String text,
			byte[] data, RegisterValue ctxVal, int preference) {
		// LATER: Description to display constructor tree information?
		super("", NumericUtilities.convertBytesToString(data, " "), switch (preference) {
			case 10000 -> AssemblyAutocompleter.FG_PREFERENCE_MOST;
			case 5000 -> AssemblyAutocompleter.FG_PREFERENCE_MIDDLE;
			default -> AssemblyAutocompleter.FG_PREFERENCE_LEAST;
		}, -preference);
		this.data = data;
		this.contextChanges = new ContextChanges(ctxVal);

		try {
			if (program != null) {
				// Handle flow context first
				contextChanges.addFlow(program.getProgramContext(), at.addWrap(data.length));
				// drop prototype, just want context changes (globalsets)
				language.parse(new ByteMemBufferImpl(at, data, language.isBigEndian()),
					contextChanges, false);
			}
		}
		catch (InsufficientBytesException | UnknownInstructionException e) {
			Msg.error(this, "Cannot disassembly just-assembled instruction?: " +
				NumericUtilities.convertBytesToString(data));
		}
		adjustOrderByContextChanges(program);
	}

	private void adjustOrderByContextChanges(Program program) {
		if (program == null) {
			return;
		}
		ProgramContext ctx = program.getProgramContext();
		Register ctxReg = ctx.getBaseContextRegister();
		for (Entry<Address, RegisterValue> ent : contextChanges.contextsOut.entrySet()) {
			RegisterValue defVal = ctx.getDefaultDisassemblyContext();
			RegisterValue newVal = defVal.combineValues(ent.getValue());
			RegisterValue curVal =
				defVal.combineValues(ctx.getRegisterValue(ctxReg, ent.getKey()));
			BigInteger changed =
				newVal.getUnsignedValueIgnoreMask().xor(curVal.getUnsignedValueIgnoreMask());
			order += changed.bitCount();
		}
	}

	/**
	 * Get the assembled instruction bytes
	 * 
	 * @return the bytes
	 */
	public byte[] getData() {
		return data;
	}

	@Override
	public int compareTo(AssemblyCompletion ac) {
		if (this.order != ac.order) {
			return this.order - ac.order;
		}
		if (!(ac instanceof InstructionAssemblyCompletion)) {
			return super.compareTo(ac);
		}
		InstructionAssemblyCompletion that = (InstructionAssemblyCompletion) ac;
		if (this.data.length != that.data.length) {
			return this.data.length - that.data.length;
		}
		return super.compareTo(ac);
	}
}
