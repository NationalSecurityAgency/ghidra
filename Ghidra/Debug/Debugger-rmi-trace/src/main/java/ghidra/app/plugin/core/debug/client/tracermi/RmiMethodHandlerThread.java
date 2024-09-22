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
package ghidra.app.plugin.core.debug.client.tracermi;

import ghidra.rmi.trace.TraceRmi.*;
import ghidra.util.Msg;

public class RmiMethodHandlerThread extends Thread {

	private RmiClient client;
	private ProtobufSocket<RootMessage> socket;
	private boolean terminated = false;

	public RmiMethodHandlerThread(RmiClient client, ProtobufSocket<RootMessage> socket) {
		this.client = client;
		this.socket = socket;
	}

	@Override
	public void run() {
		while (!terminated) {
			try {
				RootMessage msg = socket.recv();
				if (msg.hasXrequestInvokeMethod()) {
					try {
						XRequestInvokeMethod req = msg.getXrequestInvokeMethod();
						int id = req.getOid().getId();
						RmiTrace trace = client.traces.get(id);
						trace.handleInvokeMethod(req);
					}
					catch (Exception e) {
						e.printStackTrace();
					}
					continue;
				}			
				RootMessage request = client.getRequestsPoll();
				if (msg.hasError()) {
					Msg.error(this, msg);
				}
				else if (msg.hasReplyCreateObject()) {
					ReplyCreateObject reply = msg.getReplyCreateObject();
					RmiTrace trace = client.traces.get(request.getRequestCreateObject().getOid().getId());
					trace.handleCreateObject(reply);
				}
				else if (msg.hasReplyCreateTrace()) {
					ReplyCreateTrace reply = msg.getReplyCreateTrace();
					RmiTrace trace = client.traces.get(request.getRequestCreateTrace().getOid().getId());
					trace.handleCreateTrace(reply);
				}
			}
			catch (Exception e) {
				Msg.error(this, e.getMessage());
			} 
		}
		Msg.info(this, "Handler exiting");
	}
		
	public void close() {
		terminated = true;
	}
	
}
