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
package ghidra.dbg.isf;

import java.io.*;
import java.net.Socket;

import com.google.protobuf.AbstractMessage;

import ghidra.dbg.isf.protocol.Isf.RootMessage;
import ghidra.util.Msg;

public class IsfConnectionHandler extends Thread {

	private Socket socket;
	private IsfClientHandler handler;

	public IsfConnectionHandler(Socket socket, IsfClientHandler handler) {
		this.socket = socket;
		this.handler = handler;
	}

	@Override
	public void run() {
		try {
			Msg.info(this, "Handler started...");
			InputStream inputStream = socket.getInputStream();
			while (!socket.isClosed()) {
				RootMessage root = RootMessage.parseDelimitedFrom(inputStream);
				if (root != null) {
					AbstractMessage msg = handler.processMessage(root);
					OutputStream out = socket.getOutputStream();
					msg.writeDelimitedTo(out);
					out.flush();
				}
			}
		}
		catch (IOException e) {
			Msg.error(this, e);
		}
	}
}
