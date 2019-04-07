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
package ghidra.app.plugin.core.string.translate;

import static ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION;

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.OptionDialog;
import ghidra.app.services.StringTranslationService;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskLauncher;

/**
 * This class allows users to manually translate strings.
 */
public class ManualStringTranslationService implements StringTranslationService {

	private static final int MAX_STR_PROMPT = 30;

	@Override
	public String getTranslationServiceName() {
		return "Manual";
	}

	@Override
	public HelpLocation getHelpLocation() {
		return StringTranslationService.createStringTranslationServiceHelpLocation(
			TranslateStringsPlugin.class, this);
	}

	@Override
	public void translate(Program program, List<ProgramLocation> stringLocations) {
		TaskLauncher.launchModal("Manually translate strings", monitor -> {

			int id = program.startTransaction("Translate strings");
			try {
				for (int instanceNum = 0; instanceNum < stringLocations.size(); instanceNum++) {
					ProgramLocation progLoc = stringLocations.get(instanceNum);
					Data data = DataUtilities.getDataAtLocation(progLoc);
					StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
					String strValue = stringData.getStringValue();
					if (strValue != null) {
						strValue = strValue.length() > MAX_STR_PROMPT
								? strValue.substring(0, MAX_STR_PROMPT) + "..."
								: strValue;
						String previous =
							StringUtils.defaultString(stringData.getTranslatedValue());
						String translatedValue = OptionDialog.showInputSingleLineDialog(null,
							"Translate " + (instanceNum + 1) + " of " + stringLocations.size(),
							"Translate \"" + strValue + "\"", previous);
						if (translatedValue == null) {
							break;
						}
						if (!translatedValue.trim().isEmpty()) {
							TRANSLATION.setTranslatedValue(data, translatedValue);
							TRANSLATION.setShowTranslated(data, true);
						}
					}
				}
			}
			finally {
				program.endTransaction(id, true);
			}
		});
	}

	/**
	 * Helper method called by Defined String table model to set the value for a single item.
	 * <p>
	 * This method is here to keep it adjacent to the manual string translation logic.
	 *
	 * @param program current {@link Program}
	 * @param stringLocation {@link ProgramLocation} of the string to set new translation
	 * @param newValue String manual translated value
	 */
	public static void setTranslatedValue(Program program, ProgramLocation stringLocation,
			String newValue) {

		Data data = DataUtilities.getDataAtLocation(stringLocation);
		StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);

		int id = program.startTransaction("Set string translated value");
		try {
			// remove the translation settings if the new value is empty or exactly equal to the
			// actual string data instance value.
			if (newValue.isEmpty() || newValue.equals(sdi.getStringValue())) {
				TRANSLATION.clear(data);
			}
			else {
				TRANSLATION.setTranslatedValue(data, newValue);
				TRANSLATION.setShowTranslated(data, true);
			}
		}
		finally {
			program.endTransaction(id, true);
		}

	}

}
