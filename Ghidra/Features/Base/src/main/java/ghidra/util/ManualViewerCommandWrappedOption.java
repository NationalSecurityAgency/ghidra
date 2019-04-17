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
package ghidra.util;

import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.framework.options.CustomOption;
import ghidra.framework.options.SaveState;

public class ManualViewerCommandWrappedOption implements CustomOption {
	public static final String OPTIONS_CATEGORY_NAME = "Processor Manuals";
	public static final String MANUAL_VIEWER_OPTIONS = "Manual Viewer Options";

	static final String HTTP_URL_REPLACEMENT_STRING = "${HTTP_URL}";
	static final String FILE_URL_REPLACEMENT_STRING = "${FILE_URL}";
	static final String FILENAME_REPLACEMENT_STRING = "${FILENAME}";

	private static final String COMMAND_STRING = "commandString";
	private static final String COMMAND_ARGUMENTS = "commandArguments";
	private static final String URL_STRING = "urlReplacementString";

	private static final String DEFAULT_URL_REPLACEMENT_STRING =
		ManualViewerCommandWrappedOption.HTTP_URL_REPLACEMENT_STRING;

	private String commandString;
	private String[] commandArguments;
	private String urlReplacementString;

	public ManualViewerCommandWrappedOption() {
		// required for persistence
	}

	@Override
	public void readState(SaveState saveState) {
		commandString = saveState.getString(COMMAND_STRING, null);
		commandArguments = saveState.getStrings(COMMAND_ARGUMENTS, null);
		urlReplacementString = saveState.getString(URL_STRING, null);
	}

	@Override
	public void writeState(SaveState saveState) {
		saveState.putString(COMMAND_STRING, commandString);
		saveState.putStrings(COMMAND_ARGUMENTS, commandArguments);
		saveState.putString(URL_STRING, urlReplacementString);
	}

	@Override
	public int hashCode() {
		int hash = 0;

		hash += commandString == null ? 0 : commandString.hashCode();
		hash += urlReplacementString == null ? 0 : urlReplacementString.hashCode();

		if (commandArguments != null) {
			for (String arg : commandArguments) {
				hash += arg.hashCode();
			}
		}

		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ManualViewerCommandWrappedOption)) {
			return false;
		}

		if (this == obj) {
			return true;
		}

		ManualViewerCommandWrappedOption otherOption = (ManualViewerCommandWrappedOption) obj;
		return SystemUtilities.isEqual(commandString, otherOption.commandString) &&
			SystemUtilities.isEqual(urlReplacementString, otherOption.urlReplacementString) &&
			SystemUtilities.isArrayEqual(commandArguments, otherOption.commandArguments);
	}

	public String getCommandString() {
		return commandString;
	}

	public void setCommandString(String commandString) {
		this.commandString = commandString;
	}

	public String[] getCommandArguments() {
		return commandArguments;
	}

	public void setCommandArguments(String[] commandArguments) {
		this.commandArguments = commandArguments;
	}

	public String getUrlReplacementString() {
		return urlReplacementString;
	}

	public void setUrlReplacementString(String urlReplacementString) {
		this.urlReplacementString = urlReplacementString;
	}

	public static ManualViewerCommandWrappedOption getDefaultBrowserLoaderOptions() {
		ManualViewerCommandWrappedOption option = new ManualViewerCommandWrappedOption();

		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
			option.setCommandString("cmd.exe");
			String[] args = new String[] { "/c", "start" };
			option.setCommandArguments(args);
			option.setUrlReplacementString(DEFAULT_URL_REPLACEMENT_STRING);
		}
		else if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.LINUX) {
			option.setCommandString("firefox");
			option.setCommandArguments(new String[] {});
			option.setUrlReplacementString(DEFAULT_URL_REPLACEMENT_STRING);
		}
		else if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X) {
			option.setCommandString("open");
			option.setCommandArguments(new String[] {});
			option.setUrlReplacementString(DEFAULT_URL_REPLACEMENT_STRING);
		}
		else {
			option.setCommandString("");
			option.setCommandArguments(new String[] {});
			option.setUrlReplacementString(DEFAULT_URL_REPLACEMENT_STRING);
		}

		return option;
	}
}
