/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.util.LanguageTranslator;
import ghidra.program.util.LanguageTranslatorAdapter;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;


public class ForceRedisassembly extends GhidraScript {
	
	@Override
    public void run() throws Exception {
		
		if (currentProgram == null) {
			Msg.showError(this, null, "No Program Error", "No active program found");
			return;
		}
		ProgramDB program = (ProgramDB)currentProgram;
		
		Language lang = program.getLanguage();
		
		LanguageTranslator translator = new MyLanguageTranslator(lang.getLanguageID(), lang.getVersion());
		if (!translator.isValid()) {
			return;
		}
		
		program.setLanguage(translator, program.getCompilerSpec().getCompilerSpecID(), true, monitor);
	}

	private static class MyLanguageTranslator extends LanguageTranslatorAdapter {
		protected MyLanguageTranslator(LanguageID languageId, int version) {
			super(languageId, version, languageId, version);
		}
		@Override
		public boolean isValid() {
			if (super.isValid()) {
				try {
					validateDefaultSpaceMap();
				} catch (IncompatibleLanguageException e) {
				    throw new AssertException();
				}
				Register newContextReg = getNewLanguage().getContextBaseRegister();
				if (newContextReg != null) {
					Register oldContextReg = getOldLanguage().getContextBaseRegister();
					if (oldContextReg == null || !isSameRegisterConstruction(oldContextReg, newContextReg)) {
						throw new AssertException();
					}
				}
				return true;
			}
			return false;
		}
		
		@Override
		public String toString() {
			return "[" + getOldLanguageID() + " (Version " + getOldVersion() + ")] -> [" + 
				getNewLanguageID() + " (Version " + getNewVersion() + ")] {Forced Re-Disassembly Translator}";
		}
	}
}
