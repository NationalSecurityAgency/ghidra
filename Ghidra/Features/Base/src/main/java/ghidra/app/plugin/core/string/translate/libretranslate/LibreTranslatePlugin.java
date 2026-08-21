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
package ghidra.app.plugin.core.string.translate.libretranslate;

import static ghidra.framework.options.OptionType.*;

import java.net.*;
import java.util.List;

import docking.options.OptionsService;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.StringTranslationService;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "String translations using LibreTranslate",
	description =
			"Uses an external LibreTranslate server to translate strings.\n" + 
			"See LibreTranslate's website for links to their docs about\n" + 
			"API keys or instructions for self-hosting your own instance.",
	servicesProvided = { StringTranslationService.class }
)
//@formatter:on
public class LibreTranslatePlugin extends Plugin implements OptionsChangeListener {
	public static final String LIBRE_TRANSLATE_SERVICE_NAME = "LibreTranslate";

	private static final String STRINGS_OPTION = "Strings";
	private static final String LT_OPTION = "LibreTranslate";
	private static final String SOURCE_LANG_OPTION = "Source Language";
	private static final String API_KEY_OPTION = "API Key";
	private static final String URL_OPTION = "URL";
	private static final String TARGET_LANG_OPTION = "Target Language";
	private static final String BATCHSIZE_OPTION = "Batch Size";
	private static final String HTTP_TIMEOUT_OPTION = "HTTP Timeout";
	private static final String HTTP_TIMEOUT_PER_ELEMENT_OPTION = "HTTP Timeout [per string]";

	private static final int BATCHSIZE_DEFAULT = 50;
	private static final int BATCHSIZE_MAX = 1000;
	private static final int TIMEOUT_DEFAULT = 20 * 1000; // 20 seconds
	private static final int TIMEOUT_PERSTRING_DEFAULT = 1 * 1000; // 1 second per batched string

	public enum SOURCE_LANGUAGE_OPTION { AUTO, PROMPT }

	private ToolOptions stringOptions;
	private StringTranslationService serviceInstance;

	public LibreTranslatePlugin(PluginTool tool) {
		super(tool);

		initOptions();
		updateServiceInstance();
	}

	private void initOptions() {
		HelpLocation helpLoc = new HelpLocation("LibreTranslatePlugin", "Configuration");

		stringOptions = tool.getOptions(STRINGS_OPTION);
		stringOptions.registerOption(subOpt(URL_OPTION), STRING_TYPE, "", helpLoc,
			"LibreTranslate server URL.  Required.  Example: http://localhost:5000/");
		stringOptions.registerOption(subOpt(API_KEY_OPTION), STRING_TYPE, "", helpLoc,
			"LibreTranslate API Key.  Optional, but possibly required by the server.");
		stringOptions.registerOption(subOpt(SOURCE_LANG_OPTION), OptionType.ENUM_TYPE,
			SOURCE_LANGUAGE_OPTION.AUTO, helpLoc,
			"Source language code option, either 'auto' or prompted each time.");
		stringOptions.registerOption(subOpt(TARGET_LANG_OPTION), STRING_TYPE, "en", helpLoc,
			"Target language code.  Defaults to 'en'.  See LibreTranslate's docs for list.");
		stringOptions.registerOption(subOpt(BATCHSIZE_OPTION), INT_TYPE, BATCHSIZE_DEFAULT, helpLoc,
			"Maximum number of requests to batch together.");
		stringOptions.registerOption(subOpt(HTTP_TIMEOUT_OPTION), INT_TYPE, TIMEOUT_DEFAULT,
			helpLoc,
			"Time to wait for HTTP requests to the LibreTranslate server to finish. (milliseconds)");
		stringOptions.registerOption(subOpt(HTTP_TIMEOUT_PER_ELEMENT_OPTION), INT_TYPE,
			TIMEOUT_PERSTRING_DEFAULT, helpLoc,
			"Additional time (per translated string) to wait for HTTP requests to finish. (milliseconds)");

		stringOptions.addOptionsChangeListener(this);
	}

	@Override
	protected void dispose() {
		if (stringOptions != null) {
			stringOptions.removeOptionsChangeListener(this);
			stringOptions = null;
		}

		super.dispose();
	}

	@Override
	public void optionsChanged(ToolOptions newOptions, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.startsWith(subOpt(""))) {
			updateServiceInstance();
		}
	}

	private void updateServiceInstance() {
		if (serviceInstance != null) {
			deregisterService(StringTranslationService.class, serviceInstance);
			serviceInstance = null;
		}

		String urlStr = stringOptions.getString(subOpt(URL_OPTION), "");
		String apiKey = stringOptions.getString(subOpt(API_KEY_OPTION), "");
		SOURCE_LANGUAGE_OPTION srcLangOption =
			stringOptions.getEnum(subOpt(SOURCE_LANG_OPTION), SOURCE_LANGUAGE_OPTION.AUTO);
		String targetLangCode = stringOptions.getString(subOpt(TARGET_LANG_OPTION), "en");

		int batchSize = stringOptions.getInt(subOpt(BATCHSIZE_OPTION), BATCHSIZE_DEFAULT);
		batchSize = Math.clamp(batchSize, 1, BATCHSIZE_MAX);

		int timeout = stringOptions.getInt(subOpt(HTTP_TIMEOUT_OPTION), TIMEOUT_DEFAULT);
		int timeoutPerString = stringOptions.getInt(subOpt(HTTP_TIMEOUT_PER_ELEMENT_OPTION),
			TIMEOUT_PERSTRING_DEFAULT);
		timeout = Math.clamp(timeout, 1000, 3600000 /* 1 hour */);
		timeoutPerString = Math.clamp(timeoutPerString, 1, 60 * 1000 /* 60 seconds */);

		if (urlStr != null && !urlStr.isBlank()) {
			try {
				URI serverURI = URI.create(urlStr).toURL().toURI(); // round trip to URL to make sure it is valid
				serviceInstance = new LibreTranslateStringTranslationService(serverURI, apiKey,
					srcLangOption, targetLangCode, batchSize, timeout, timeoutPerString);
			}
			catch (IllegalArgumentException | MalformedURLException | URISyntaxException e) {
				Msg.warn(this, "Invalid URL for LibreTranslate option: " + urlStr);
				tool.setStatusInfo("Invalid URL for LibreTranslate option: " + urlStr);
				// fall thru
			}
		}

		if (serviceInstance == null) {
			// Create a non-functional stub instance that only displays the
			// Tool options for this LibreTranslate Service
			serviceInstance = new StringTranslationService() {
				@Override
				public void translate(Program program, List<ProgramLocation> stringLocations,
						TranslateOptions options) {
					OptionsService optionService = tool.getService(OptionsService.class);
					if (optionService != null) {
						optionService.showOptionsDialog(STRINGS_OPTION + "." + LT_OPTION, null);
						Swing.runLater(() -> {
							// if the serviceInstance was changed to a valid obj, re-try to translate the strings
							if (serviceInstance instanceof LibreTranslateStringTranslationService) {
								serviceInstance.translate(program, stringLocations, options);
							}
						});
					}
				}

				@Override
				public String getTranslationServiceName() {
					return LIBRE_TRANSLATE_SERVICE_NAME;
				}
			};
		}

		registerDynamicServiceProvided(StringTranslationService.class, serviceInstance);
	}

	private String subOpt(String optName) {
		return LT_OPTION + Options.DELIMITER + optName;
	}

}
