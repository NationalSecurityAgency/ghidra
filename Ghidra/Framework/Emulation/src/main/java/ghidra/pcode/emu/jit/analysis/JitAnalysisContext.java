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
package ghidra.pcode.emu.jit.analysis;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.jit.*;
import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A collection of state that is shared among several phases of the translation process.
 * 
 * @see JitCompiler
 */
public class JitAnalysisContext {
	private final JitConfiguration config;
	private final JitPassage passage;
	private final SleighLanguage language;
	private final Endian endian;

	/**
	 * Construct a new context, starting with the given configuration and source passage
	 * 
	 * @param config the JIT compiler's configuration
	 * @param passage the passage selected for translation
	 */
	public JitAnalysisContext(JitConfiguration config, JitPassage passage) {
		this.config = config;
		this.passage = passage;
		this.language = passage.getLanguage();
		this.endian = language.isBigEndian() ? Endian.BIG : Endian.LITTLE;
	}

	/**
	 * Get the JIT compiler configuration
	 * 
	 * @return the configuration
	 */
	public JitConfiguration getConfiguration() {
		return config;
	}

	/**
	 * Get the source passage
	 * 
	 * @return the passage
	 */
	public JitPassage getPassage() {
		return passage;
	}

	/**
	 * Get the translation source (i.e., emulation target) language
	 * 
	 * @return the language
	 */
	public SleighLanguage getLanguage() {
		return language;
	}

	/**
	 * Get the endianness of the translation source, i.e., emulation target.
	 * 
	 * @return the endianness
	 */
	public Endian getEndian() {
		return endian;
	}

	/**
	 * Check if the given p-code op is the first of an instruction.
	 * 
	 * @param op the op to check
	 * @return the address-context pair
	 * @see JitPassage#getOpEntry(PcodeOp)
	 */
	public AddrCtx getOpEntry(PcodeOp op) {
		return passage.getOpEntry(op);
	}

	/**
	 * Get the error message for a given p-code op
	 * 
	 * @param op the p-code op generating the error
	 * @return the message
	 * @see JitPassage#getErrorMessage(PcodeOp)
	 */
	public String getErrorMessage(PcodeOp op) {
		return passage.getErrorMessage(op);
	}
}
