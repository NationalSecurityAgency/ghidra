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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.BytesPcodeArithmetic;
import ghidra.pcode.exec.SleighUseropLibrary;

/**
 * A p-code machine which executes on concrete bytes and incorporates per-architecture state
 * modifiers
 */
public abstract class AbstractPcodeEmulator extends AbstractPcodeMachine<byte[]> {
	public AbstractPcodeEmulator(SleighLanguage language, SleighUseropLibrary<byte[]> library) {
		super(language, BytesPcodeArithmetic.forLanguage(language), library);
	}

	@Override
	protected BytesPcodeThread createThread(String name) {
		return new BytesPcodeThread(name, this, library);
	}
}
