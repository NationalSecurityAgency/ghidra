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
package ghidradev.ghidrascripteditor;

import java.io.IOException;
import java.net.ServerSocket;

import ghidradev.*;
import ghidradev.ghidrascripteditor.preferences.GhidraScriptEditorPreferences;

/**
 * High level driver for initializing the Ghidra Script Editor subcomponent.  Should get called 
 * by the startup extension.  This subcomponent is responsible for receiving a script from Ghidra's
 * script manager to Eclipse over a socket.
 * 
 * @see GhidraDevStartup
 */
public class ScriptEditorInitializer {

	private static ServerSocket serverSocket;

	/**
	 * Initializes the Ghidra Script Editor subcomponent.  Nothing in the package should be
	 * used until this initialization happens.  Should be called during Eclipse startup.
	 * 
	 * @param firstTimeConsent True if the user has just consented to opening ports; otherwise, 
	 *   false.
	 * @see GhidraDevStartup
	 */
	public static void init(boolean firstTimeConsent) {
		if (firstTimeConsent) {
			GhidraScriptEditorPreferences.setScriptEditorEnabled(true);
		}
		listen(GhidraScriptEditorPreferences.getScriptEditorPort());
	}

	/**
	 * Listens for socket connections on the given port.  If there is a problem listening,
	 * a popup is displayed for the user.
	 * 
	 * @param port The port to listen on.  If the port is -1, this method doesn't do anything.
	 */
	private static void listen(int port) {

		if (!GhidraScriptEditorPreferences.isScriptEditorEnabled()) {
			EclipseMessageUtils.info(
				Activator.PLUGIN_ID + " Script Editor port listening is disabled in preferences.");
			return;
		}

		if (port == -1) {
			EclipseMessageUtils.info(Activator.PLUGIN_ID +
				" Script Editor port listening is disabled, port not set in preferences.");
			return;
		}

		try {
			serverSocket = new ServerSocket(port);
			EclipseMessageUtils.info(
				Activator.PLUGIN_ID + " Script Editor is listening on port " + port);
			Activator.getDefault().registerCloseable(serverSocket);
		}
		catch (IOException e) {
			EclipseMessageUtils.showErrorDialog(Activator.PLUGIN_ID + " Script Editor",
				"Failed to listen for connections on port " + port +
					".  The Script Editor features will be disabled until a valid port is selected in preferences.");
			return;
		}

		new Thread(new SocketSetupRunnable(serverSocket)).start();
	}

	/**
	 * Called when the script editor preferences change.
	 * 
	 * @param enabledWasChanged True if the enablement was changed to a new value.
	 * @param portWasChanged True if the port preferences was changed to a new value.
	 */
	public static void notifyPreferencesChanged(boolean enabledWasChanged, boolean portWasChanged) {
		if (!enabledWasChanged && !portWasChanged) {
			return;
		}

		// Close the old server socket.  Its job is done.
		try {
			if (serverSocket != null) {
				serverSocket.close();
				Activator.getDefault().unregisterCloseable(serverSocket);
				serverSocket = null;
			}
		}
		catch (IOException e) {
			// Oh well, we tried.  This port probably won't work next time they pick it.
		}

		// Listen on the new port
		listen(GhidraScriptEditorPreferences.getScriptEditorPort());
	}
}
