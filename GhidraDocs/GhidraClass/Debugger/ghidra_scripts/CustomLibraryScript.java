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
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeUseropLibrary;

public class CustomLibraryScript extends GhidraScript {
	@Override
	protected void run() throws Exception {
		PcodeEmulator emu = new PcodeEmulator(currentProgram.getLanguage()) {
			@Override
			protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
				return super.createUseropLibrary()
						.compose(new ModelingScript.StructuredStdLibPcodeUseropLibrary<>(
							currentProgram.getCompilerSpec()));
			}
		};
		emu.inject(currentAddress, """
				__libc_strlen();
				__X86_64_RET();
				""");

		// TODO: Initialize the emulator's memory from the current program

		PcodeThread<byte[]> thread = emu.newThread();

		// TODO: Initialize the thread's registers

		while (true) {
			monitor.checkCanceled();
			thread.stepInstruction(100);
		}
	}
}
