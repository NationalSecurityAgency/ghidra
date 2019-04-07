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

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

import org.eclipse.swt.widgets.Display;

/**
 * Code intended to run in a new thread that accepts client connections on the given
 * server socket, and opens the requested file in an editor.
 */
public class SocketSetupRunnable implements Runnable {

	private ServerSocket serverSocket = null;

	/**
	 * Creates a new runnable.
	 * 
	 * @param serverSocket The server socket that will be accepting client connections.
	 */
	public SocketSetupRunnable(ServerSocket serverSocket) {
		this.serverSocket = serverSocket;
	}

	@Override
	public void run() {
		while (!serverSocket.isClosed()) {
			try (Socket socket = serverSocket.accept();
					BufferedReader input =
						new BufferedReader(new InputStreamReader(socket.getInputStream()));
					PrintWriter output = new PrintWriter(socket.getOutputStream())) {
				String line;
				while ((line = input.readLine()) != null) {
					String command = line.substring(0, line.indexOf('_'));
					if (command.equals("open")) {
						openInEditor(line.substring(line.indexOf('_') + 1));
					}
				}
			}
			catch (IOException e) {
				// Socket was closed
			}
		}
	}

	/**
	 * Opens the given file in an editor.
	 * 
	 * @param path The path to the file to open.
	 */
	private void openInEditor(String path) {
		File fileToOpen = new File(path);
		if (fileToOpen.exists() && fileToOpen.isFile()) {
			Display.getDefault().asyncExec(new OpenFileRunnable(path));
		}
	}
}
