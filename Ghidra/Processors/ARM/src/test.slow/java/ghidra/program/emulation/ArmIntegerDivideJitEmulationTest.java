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
package ghidra.program.emulation;

import java.lang.invoke.MethodHandles;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.jit.JitConfiguration;
import ghidra.pcode.emu.jit.JitPcodeEmulator;

/**
 * Runs the ARM integer divide scenarios on the JIT-accelerated p-code emulator
 */
public class ArmIntegerDivideJitEmulationTest extends AbstractArmIntegerDivideEmulationTest {
	@Override
	protected PcodeEmulator createEmulator(SleighLanguage lang) {
		return new JitPcodeEmulator(lang, new JitConfiguration(), MethodHandles.lookup());
	}
}
