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
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.util.Msg;

public class ForceRedisassembly extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			Msg.showError(this, null, "No Program Error", "No active program found");
			return;
		}
		ProgramDB program = (ProgramDB) currentProgram;

		Language lang = null;

		program.setLanguage(lang, null, true, monitor);
	}
}
