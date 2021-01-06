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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emulate.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;

/**
 * A p-code thread which executes on concrete bytes and incorporates per-architecture state
 * modifiers
 */
public class BytesPcodeThread extends DefaultPcodeThread<byte[]> {

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

	protected class GlueMemoryState extends MemoryState {
		public GlueMemoryState(Language language) {
			super(language);
		}

		@Override
		public int getChunk(byte[] res, AddressSpace spc, long off, int size,
				boolean stopOnUnintialized) {
			byte[] var = state.getVar(spc, off, size, true);
			System.arraycopy(var, 0, res, 0, var.length);
			return var.length;
		}

		@Override
		public void setChunk(byte[] val, AddressSpace spc, long off, int size) {
			state.setVar(spc, off, size, true, val);
		}

		@Override
		public void setInitialized(boolean initialized, AddressSpace spc, long off, int size) {
			// Do nothing
		}
	}

	protected class GluePcodeThreadExecutor extends PcodeThreadExecutor {
		public GluePcodeThreadExecutor(Language language, PcodeArithmetic<byte[]> arithmetic,
				PcodeExecutorStatePiece<byte[], byte[]> state) {
			super(language, arithmetic, state);
		}

		@Override
		public void executeCallother(PcodeOp op, PcodeFrame frame,
				SleighUseropLibrary<byte[]> library) {
			// Prefer one in the library. Fall-back to state modifier's impl
			try {
				super.executeCallother(op, frame, library);
			}
			catch (SleighLinkException e) {
				if (modifier == null || !modifier.executeCallOther(op)) {
					throw e;
				}
			}
		}
	}

	// Part of the glue that makes existing state modifiers work in new emulation framework
	protected final EmulateInstructionStateModifier modifier;
	protected final Emulate emulate;

	protected Address savedCounter;

	public BytesPcodeThread(String name, AbstractPcodeMachine<byte[]> machine,
			SleighUseropLibrary<byte[]> library) {
		super(name, machine, library);

		/**
		 * These two exist as a way to integrate the language-specific injects that are already
		 * written for the established concrete emulator.
		 */
		emulate = new GlueEmulate(language, new GlueMemoryState(language),
			new BreakTableCallBack(language));
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
	protected PcodeThreadExecutor createExecutor() {
		return new GluePcodeThreadExecutor(language, arithmetic, state);
	}

	@Override
	protected void preExecuteInstruction() {
		if (modifier != null) {
			savedCounter = getCounter();
			modifier.initialExecuteCallback(emulate, savedCounter, getContext());
		}
	}

	@Override
	protected void postExecuteInstruction() {
		if (modifier != null) {
			modifier.postExecuteCallback(emulate, savedCounter, frame.copyCode(),
				frame.getBranched(), getCounter());
		}
	}
}
