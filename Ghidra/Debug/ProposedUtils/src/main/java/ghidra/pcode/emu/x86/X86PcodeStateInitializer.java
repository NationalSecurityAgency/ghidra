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
package ghidra.pcode.emu.x86;

import java.util.List;

import ghidra.pcode.emu.PcodeStateInitializer;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.Msg;

public class X86PcodeStateInitializer implements PcodeStateInitializer {
	private static final List<LanguageID> LANG_IDS = List.of(
		new LanguageID("x86:LE:32:default"),
		new LanguageID("x86:LE:64:default"));
	private static final List<String> SOURCE = List.of(
		"FS_OFFSET = 0;",
		"GS_OFFSET = 0;");

	@Override
	public boolean isApplicable(Language language) {
		return false;
		//return LANG_IDS.contains(language.getLanguageID());
	}

	@Override
	public <T> void initializeThread(PcodeThread<T> thread) {
		Msg.warn(this, "Segmentation is not emulated. Initializing FS_OFFSET and FS_OFFSET to 0.");

		PcodeProgram init = thread.getMachine().compileSleigh("initializer", SOURCE);
		thread.getExecutor().execute(init, thread.getUseropLibrary());
	}
}
