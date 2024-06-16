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

import java.lang.reflect.Constructor;

import ghidra.app.emulator.AdaptedMemoryState;
import ghidra.app.emulator.Emulator;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.*;
import ghidra.pcode.exec.ConcretionError;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.memstate.MemoryBank;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;

/**
 * A p-code thread which incorporates per-architecture state modifiers
 * 
 * <p>
 * All machines that include a concrete state piece, i.e., all emulators, should use threads derived
 * from this class. This implementation assumes that the modified state can be concretized. This
 * doesn't necessarily require the machine to be a concrete emulator, but an abstract machine must
 * avoid or handle {@link ConcretionError}s arising from state modifiers.
 * 
 * <p>
 * For a complete example of a p-code emulator, see {@link PcodeEmulator}.
 * 
 * <p>
 * TODO: "State modifiers" are a feature of the older {@link Emulator}. They are crudely
 * incorporated into threads extended from this abstract class, so that they do not yet need to be
 * ported to this emulator.
 */
public class ModifiedPcodeThread<T> extends DefaultPcodeThread<T> {

	/**
	 * Glue for incorporating state modifiers
	 * 
	 * <p>
	 * This allows the modifiers to change the context and counter of the thread.
	 */
	protected class GlueEmulate extends Emulate {
		public GlueEmulate(SleighLanguage lang, MemoryState s, BreakTable b) {
			super(lang, s, b);
		}

		@Override
		public Language getLanguage() {
			return language;
		}

		@Override
		public void setExecuteAddress(Address addr) {
			overrideCounter(addr);
		}

		@Override
		public Address getExecuteAddress() {
			return getCounter();
		}

		@Override
		public void setContextRegisterValue(RegisterValue regValue) {
			overrideContext(regValue);
		}

		@Override
		public RegisterValue getContextRegisterValue() {
			return getContext();
		}
	}

	/**
	 * Part of the glue that makes existing state modifiers work in new emulation framework
	 * 
	 * <p>
	 * <b>NOTE:</b> These are instantiated one per thread, rather than sharing one across the
	 * machine, because some of the modifiers are stateful and assume a single-threaded model. The
	 * best way to mitigate that assumption is to ensure a modifier is responsible for only a single
	 * thread, even though a machine may have multiple threads.
	 */
	protected final EmulateInstructionStateModifier modifier;
	protected final Emulate emulate;

	/**
	 * Construct a new thread with the given name belonging to the given machine
	 * 
	 * @see PcodeMachine#newThread(String)
	 * @param name the name of the new thread
	 * @param machine the machine to which the new thread belongs
	 */
	public ModifiedPcodeThread(String name, AbstractPcodeMachine<T> machine) {
		super(name, machine);

		/**
		 * These two exist as a way to integrate the language-specific injects that are already
		 * written for {@link Emulator}.
		 */
		emulate = new GlueEmulate(language, new AdaptedMemoryState<>(state, Reason.EXECUTE_READ) {
			@Override
			public void setMemoryBank(MemoryBank bank) {
				// Ignore
			}
		}, new BreakTableCallBack(language));
		modifier = createModifier();
	}

	/**
	 * Construct a modifier for the given language
	 * 
	 * @return the state modifier
	 */
	protected EmulateInstructionStateModifier createModifier() {
		String classname = language
				.getProperty(GhidraLanguagePropertyKeys.EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS);
		if (classname == null) {
			return null;
		}
		try {
			Class<?> c = Class.forName(classname);
			if (!EmulateInstructionStateModifier.class.isAssignableFrom(c)) {
				Msg.error(this,
					"Language " + language.getLanguageID() + " does not specify a valid " +
						GhidraLanguagePropertyKeys.EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS);
				throw new RuntimeException(classname + " does not implement interface " +
					EmulateInstructionStateModifier.class.getName());
			}
			Constructor<?> constructor = c.getConstructor(Emulate.class);
			return (EmulateInstructionStateModifier) constructor.newInstance(emulate);
		}
		catch (Exception e) {
			Msg.error(this, "Language " + language.getLanguageID() + " does not specify a valid " +
				GhidraLanguagePropertyKeys.EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS);
			throw new RuntimeException(
				"Failed to instantiate " + classname + " for language " + language.getLanguageID(),
				e);
		}
	}

	@Override
	public void overrideCounter(Address counter) {
		super.overrideCounter(counter);
		if (modifier != null) {
			modifier.initialExecuteCallback(emulate, counter, getContext());
		}
	}

	@Override
	protected void postExecuteInstruction() {
		if (modifier != null) {
			modifier.postExecuteCallback(emulate,
				instruction == null ? null : instruction.getAddress(), frame.copyCode(),
				frame.getBranched(), getCounter());
		}
	}

	@Override
	protected boolean onMissingUseropDef(PcodeOp op, String opName) {
		if (modifier != null) {
			return modifier.executeCallOther(op);
		}
		return super.onMissingUseropDef(op, opName);
	}
}
