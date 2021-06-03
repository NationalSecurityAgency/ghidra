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
//Example skeleton script that iterates over all strings and sets the translation value for each
//@category Strings

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.TranslationSettingsDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.util.DefinedDataIterator;
import util.CollectionUtils;

public class TranslateStringsScript extends GhidraScript {

	private String translateString(String s) {
		// customize here
		return "TODO " + s + " TODO";
	}

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			return;
		}

		int count = 0;
		monitor.initialize(currentProgram.getListing().getNumDefinedData());
		monitor.setMessage("Translating strings");
		for (Data data : CollectionUtils.asIterable(
			DefinedDataIterator.definedStrings(currentProgram, currentSelection))) {
			if (monitor.isCancelled()) {
				break;
			}
			StringDataInstance str = StringDataInstance.getStringDataInstance(data);
			String s = str.getStringValue();
			if (s != null) {
				TranslationSettingsDefinition.TRANSLATION.setTranslatedValue(data,
					translateString(s));
				TranslationSettingsDefinition.TRANSLATION.setShowTranslated(data, true);
				count++;
				monitor.incrementProgress(1);
			}
		}
		println("Translated " + count + " strings.");
	}

}
