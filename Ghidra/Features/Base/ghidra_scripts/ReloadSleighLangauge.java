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
// Reloads the language specification associated with a program at runtime.
// @category sleigh
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Language;
import ghidra.util.Msg;

import java.io.IOException;

public class ReloadSleighLangauge extends GhidraScript {

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			return;
		}
		Language language = currentProgram.getLanguage();
		try {
			language.reloadLanguage(monitor);
		}
		catch (IOException e) {
			Msg.showError(this, this.state.getParamPanel(), "Reload Sleigh Language Failed",
				e.getMessage());
			return;
		}
		currentProgram.setLanguage(language, currentProgram.getCompilerSpec().getCompilerSpecID(),
			true, monitor);
	}
}
