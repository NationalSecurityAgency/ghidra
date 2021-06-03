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

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.util.OptionsService;

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
				ManualViewerCommandWrappedOption.MANUAL_VIEWER_OPTIONS, defaultOption);

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
			service.showOptionsDialog(ManualViewerCommandWrappedOption.OPTIONS_CATEGORY_NAME,
				ManualViewerCommandWrappedOption.OPTIONS_CATEGORY_NAME);
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

	private static String[] generateCommandArguments(URL url, URL fileURL,
			ManualViewerCommandWrappedOption option) {

		List<String> argumentList = new ArrayList<String>();
		argumentList.add(option.getCommandString());

		String[] commandArguments = option.getCommandArguments();
		for (String string : commandArguments) {
			argumentList.add(string);
		}

		String urlString = option.getUrlReplacementString();
		if (urlString.equals(ManualViewerCommandWrappedOption.HTTP_URL_REPLACEMENT_STRING) ||
			fileURL == null) {
			argumentList.add(url.toExternalForm());
		}
		else if (urlString.equals(ManualViewerCommandWrappedOption.FILE_URL_REPLACEMENT_STRING)) {
			argumentList.add(fileURL.toExternalForm());
		}
		else {
			argumentList.add(new File(fileURL.getFile()).getAbsolutePath());
		}

		return argumentList.toArray(new String[argumentList.size()]);
	}

//==================================================================================================
//  Inner Classes
//==================================================================================================

	static class ImmediateOptionsChangeListener implements OptionsChangeListener {
		private boolean hasChanged = false;

		@Override
		public void optionsChanged(ToolOptions theOptions, String name, Object oldValue, Object newValue) {
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
