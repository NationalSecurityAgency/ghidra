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
package ghidra.app.services;

import java.util.List;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * Interface for providing string translating services.
 * <p>
 * Implementations of this interface are usually done via a Plugin
 * and then registered via {@link Plugin}'s registerServiceProvided().
 */
public interface StringTranslationService {
	/**
	 * Returns the name of this translation service.  Used when building menus to allow
	 * the user to pick a translation service.
	 *
	 * @return string name.
	 */
	public String getTranslationServiceName();

	/**
	 * Returns the {@link HelpLocation} instance that describes where to direct the user
	 * for help when they hit f1.
	 *
	 * @return {@link HelpLocation} instance or null.
	 */
	public default HelpLocation getHelpLocation() {
		return null;
	}

	/**
	 * Requests this translation service to translate the specified string data instances.
	 * <p>
	 * The implementation generally should not block when performing this action.
	 *
	 * @param program the program containing the data instances.
	 * @param stringLocations {@link List} of string locations.
	 */
	public void translate(Program program, List<ProgramLocation> stringLocations);

	/**
	 * Helper that creates a {@link HelpLocation} based on the plugin and sts.
	 *
	 * @param pluginClass Plugin that provides the string translation service
	 * @param sts {@link StringTranslationService}
	 * @return HelpLocation with topic equal to the plugin name and anchor something like
	 * "MyTranslationServiceName_String_Translation_Service".
	 */
	public static HelpLocation createStringTranslationServiceHelpLocation(
			Class<? extends Plugin> pluginClass, StringTranslationService sts) {
		return new HelpLocation(PluginDescription.getPluginDescription(pluginClass).getName(),
			sts.getTranslationServiceName() + "_String_Translation_Service");
	}

}
