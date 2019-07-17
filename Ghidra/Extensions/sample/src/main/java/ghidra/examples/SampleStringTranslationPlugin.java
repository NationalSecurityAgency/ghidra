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
package ghidra.examples;

import static ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION;

import java.util.List;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.StringTranslationService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskLauncher;

/**
 * Example / toy string translation service.
 * <p>
 * When creating your own string translation service plugin, your class's name must end with the
 * substring "Plugin".
 * <p>
 * If done correctly, your plugin will automatically be listed in the Ghidra plugin config
 * screen.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Sample String Translation",
	description = "Sample String Translation Service Plugin.  Morphs strings by inserting " +
				"'yeehaw' or 'woot' at various places.",
	servicesProvided = { StringTranslationService.class }
)
//@formatter:on
public class SampleStringTranslationPlugin extends Plugin implements StringTranslationService {

	public SampleStringTranslationPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public String getTranslationServiceName() {
		return "Sample Translation Service";
	}

	@Override
	public void translate(Program program, List<ProgramLocation> dataLocations) {
		TaskLauncher.launchModal("Yeehaw-ify strings", monitor -> {

			int id = program.startTransaction("Yeehaw-ify strings");
			try {
				for (ProgramLocation progLoc : dataLocations) {
					Data data = DataUtilities.getDataAtLocation(progLoc);
					StringDataInstance str = StringDataInstance.getStringDataInstance(data);
					String s = str.getStringValue();

					if (s != null) {
						//
						// This is where a real translation should occur
						//
						String translatedValue = s.replaceAll("([ _,;:.])", "$1YEEHAW!$1");
						if (translatedValue.length() == s.length()) {
							translatedValue = s + " !WOOT!";
						}
						TRANSLATION.setTranslatedValue(data, translatedValue);
						TRANSLATION.setShowTranslated(data, true);
					}
				}
			}
			finally {
				program.endTransaction(id, true);
			}
		});
	}

}
