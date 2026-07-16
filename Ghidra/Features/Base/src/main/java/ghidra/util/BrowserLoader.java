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
package ghidra.util;

import static ghidra.util.ManualViewerCommandWrappedOption.*;

import java.io.File;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import docking.options.OptionsService;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;

/** 
 *  BrowserLoader opens a web browser and displays the given url. 
 *  
 *  @see ManualViewerCommandWrappedOption
 */
public class BrowserLoader {

	/**
	 * Display the content specified by url in a web browser window.  This call will launch 
	 * a new thread and then immediately return.
	 * @param url The URL to show.
	 */
	public static void display(URL url) {
		display(url, null, null);
	}

	/**
	 * Display the content specified by url in a web browser window.  This call will launch 
	 * a new thread and then immediately return.
	 * 
	 * @param url The web URL to show (e.g., http://localhost...).
	 * @param fileURL The file URL to show (e.g., file:///path/to/file).
	 * @param serviceProvider A service provider from which to get system resources.
	 */
	public static void display(URL url, URL fileURL, ServiceProvider serviceProvider) {
		if (url == null) {
			return;
		}

		// open the browser in a new thread because the call may block
		(new Thread(new BrowserRunner(url, fileURL, serviceProvider))).start();
	}

	private static void displayFromBrowserRunner(URL url, URL fileURL,
			ServiceProvider serviceProvider) {
		try {
			if (serviceProvider == null) {
				displayBrowserForExternalURL(url);
			}
			else {
				displayBrowser(url, fileURL, serviceProvider);
			}
		}
		catch (Exception e) {
			Msg.showError(BrowserLoader.class, null, "Error Loading Browser",
				"Error loading browser for URL: " + url, e);
		}
	}

	private static void displayBrowserForExternalURL(URL url) throws Exception {
		String[] arguments =
			generateCommandArguments(url, null,
				ManualViewerCommandWrappedOption.getDefaultBrowserLoaderOptions());
		Process p = Runtime.getRuntime().exec(arguments);
		p.waitFor();
		p.exitValue();  // thought to help memory problems on some versions of windows
	}

	private static void displayBrowser(URL url, URL fileURL, ServiceProvider serviceProvider) {
		OptionsService service = serviceProvider.getService(OptionsService.class);
		ToolOptions options =
			service.getOptions(ManualViewerCommandWrappedOption.OPTIONS_CATEGORY_NAME);

		// add a listener to know when the user updates the options
		ImmediateOptionsChangeListener listener = new ImmediateOptionsChangeListener();
		options.addOptionsChangeListener(listener);

		ManualViewerCommandWrappedOption defaultOption =
			ManualViewerCommandWrappedOption.getDefaultBrowserLoaderOptions();
		ManualViewerCommandWrappedOption customOption =
			(ManualViewerCommandWrappedOption) options.getCustomOption(
				MANUAL_VIEWER_OPTIONS, defaultOption);

		boolean success = tryToDisplayBrowser(url, fileURL, customOption);
		while (!success) {
			// get browser options from user and try again
			// -show error message
			LaunchErrorDialog dialog = new LaunchErrorDialog(url, fileURL);
			dialog.setVisible(true);
			if (dialog.isCancelled()) {
				return;
			}

			// -if not cancelled, then show the options dialog
			service.showOptionsDialog(OPTIONS_CATEGORY_NAME,
				OPTIONS_CATEGORY_NAME);
			if (!listener.hasChanged()) {
				return;  // the user didn't change the options, so we can't do anything
			}

			// -if not cancelled, then reread the options
			customOption =
				(ManualViewerCommandWrappedOption) options.getCustomOption(
					ManualViewerCommandWrappedOption.MANUAL_VIEWER_OPTIONS, defaultOption);
			success = tryToDisplayBrowser(url, fileURL, customOption);
		}
	}

	private static boolean tryToDisplayBrowser(URL url, URL fileURL,
			ManualViewerCommandWrappedOption option) {

		String[] processCommands = generateCommandArguments(url, fileURL, option);

		Process p = null;
		try {
			p = Runtime.getRuntime().exec(processCommands);
		}
		catch (Exception exc) {
			return false;
		}

		try {
			p.waitFor();
			p.exitValue();  // thought to help memory problems on some versions of windows
		}
		catch (InterruptedException e) {
			// we tried; the user can just launch again
		}

		return true;
	}

	/*	 
	 	 See the help page for example output.
	 */
	private static String[] generateCommandArguments(URL url, URL fileURL,
			ManualViewerCommandWrappedOption option) {

		List<String> resultArgs = new ArrayList<String>();
		resultArgs.add(option.getCommandString());

		// Substitute ${PAGE} (the manual page, carried as a "#page=N" fragment on the file URL)
		// and ${FILENAME} (the local file path) tokens into the user-supplied arguments.  
		// If the user places ${FILENAME} themselves, the file is not also appended at the end below.
		String pageNumber = getManualPageNumber(fileURL);
		String fileName = getManualFilePath(fileURL);
		boolean fileNameInArgs = false;
		String[] rawArgs = option.getCommandArguments();
		for (String string : rawArgs) {
			if (string.contains(FILENAME_REPLACEMENT_STRING)) {
				fileNameInArgs = true;
			}

			string = string.replace(PAGE_REPLACEMENT_STRING, pageNumber);
			if (fileName != null) {
				string = string.replace(FILENAME_REPLACEMENT_STRING, fileName);
			}
			resultArgs.add(string);
		}

		// The user already positioned the file via the ${FILENAME} token; don't append it again.
		if (fileNameInArgs) {
			return resultArgs.toArray(new String[resultArgs.size()]);
		}

		String urlString = option.getFileFormat();
		String urlArg;
		if (urlString.equals(HTTP_URL_REPLACEMENT_STRING) || fileURL == null) {
			urlArg = url.toExternalForm();
		}
		else if (urlString.equals(FILE_URL_REPLACEMENT_STRING)) {
			urlArg = fileURL.toExternalForm();
		}
		else {
			urlArg = fileName;
		}

		List<String> cmdExeArgs = fixupCmdExeCall(rawArgs, urlArg);
		if (!cmdExeArgs.isEmpty()) {
			resultArgs.addAll(cmdExeArgs);
		}
		else {
			resultArgs.add(urlArg);
		}

		return resultArgs.toArray(new String[resultArgs.size()]);
	}

	private static List<String> fixupCmdExeCall(String[] rawArgs, String urlArg) {
		// If launching "cmd.exe /c start URL", surround the URL with double quotes to protect
		// against special characters being misinterpreted by the shell.
		// NOTE: If not already present, a double-quoted title must be inserted since the URL
		// argument that follows will start with a double quote.
		List<String> result = new ArrayList<>();
		if (rawArgs.length < 2) {
			return result;
		}

		if (!(rawArgs[0].equalsIgnoreCase("/c") && rawArgs[1].equalsIgnoreCase("start"))) {
			return result;
		}

		if (rawArgs.length == 2) {
			result.add("\"Title\"");
		}

		result.add('"' + urlArg + '"');
		return result;
	}

	/**
	 * Returns the decoded local file path for the given file URL (without the {@code #page=N}
	 * fragment, which {@link URL#getPath()} already excludes), so viewers receive a real path
	 * rather than a percent-encoded one.
	 * @param fileURL the file URL (may be null)
	 * @return the absolute local file path, or null if {@code fileURL} is null
	 */
	private static String getManualFilePath(URL fileURL) {
		if (fileURL == null) {
			return null;
		}
		String path = URLDecoder.decode(fileURL.getPath(), StandardCharsets.UTF_8);
		return new File(path).getAbsolutePath();
	}

	/**
	 * Extracts the manual page number from the {@code #page=N} fragment of the given file URL.
	 * @param fileURL the file URL (may be null)
	 * @return the page number, or {@code "1"} if none is present
	 */
	private static String getManualPageNumber(URL fileURL) {
		if (fileURL != null) {
			String ref = fileURL.getRef();
			if (ref != null && ref.startsWith("page=")) {
				String page = ref.substring("page=".length());
				if (!page.isBlank()) {
					return page;
				}
			}
		}
		return "1";
	}

//==================================================================================================
//  Inner Classes
//==================================================================================================

	static class ImmediateOptionsChangeListener implements OptionsChangeListener {
		private boolean hasChanged = false;

		@Override
		public void optionsChanged(ToolOptions theOptions, String name, Object oldValue,
				Object newValue) {
			hasChanged = true;
		}

		boolean hasChanged() {
			return hasChanged;
		}
	}

	static class BrowserRunner implements Runnable {
		private final URL url;
		private final ServiceProvider serviceProvider;
		private final URL fileURL;

		private BrowserRunner(URL url, URL fileURL, ServiceProvider serviceProvider) {
			this.url = url;
			this.fileURL = fileURL;
			this.serviceProvider = serviceProvider;
		}

		@Override
		public void run() {
			displayFromBrowserRunner(url, fileURL, serviceProvider);
		}
	}
}
