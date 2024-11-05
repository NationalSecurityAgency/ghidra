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

import ghidra.app.plugin.core.debug.client.tracermi.RmiClient.RequestResult;
import ghidra.app.plugin.core.debug.client.tracermi.RmiClient.RmiException;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.util.Msg;

public class RmiReplyHandlerThread extends Thread {

	private RmiClient client;
	private ProtobufSocket<RootMessage> socket;
	private boolean terminated = false;

	public RmiReplyHandlerThread(RmiClient client, ProtobufSocket<RootMessage> socket) {
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
						XReplyInvokeMethod reply = trace.handleInvokeMethod(req);
						socket.send(RootMessage.newBuilder().setXreplyInvokeMethod(reply).build());
					}
					catch (Exception e) {
						Msg.error(this, "Error handling method invocation", e);
						socket.send(RootMessage.newBuilder()
								.setXreplyInvokeMethod(
									XReplyInvokeMethod.newBuilder().setError(e.toString()))
								.build());
					}
					continue;
				}

				RequestResult result = client.pollRequest();
				if (result == null) {
					System.err.println("REPLY without request: " + msg);
					continue;
				}
				RootMessage request = result.request;

				switch (msg.getMsgCase()) {
					case ERROR -> {
						Msg.error(this, msg.getError().getMessage());
						result.completeExceptionally(new RmiException(msg.getError().getMessage()));
					}
					case REPLY_CREATE_OBJECT -> {
						ReplyCreateObject reply = msg.getReplyCreateObject();
						RmiTrace trace =
							client.traces.get(request.getRequestCreateObject().getOid().getId());
						result.complete(trace.handleCreateObject(reply));
					}
					case REPLY_CREATE_TRACE -> {
						ReplyCreateTrace reply = msg.getReplyCreateTrace();
						RmiTrace trace =
							client.traces.get(request.getRequestCreateTrace().getOid().getId());
						result.complete(trace.handleCreateTrace(reply));
					}
					case REPLY_GET_VALUES -> {
						ReplyGetValues reply = msg.getReplyGetValues();
						RmiTrace trace =
							client.traces.get(request.getRequestGetValues().getOid().getId());
						result.complete(trace.handleGetValues(reply));
					}
					case REPLY_DISASSEMBLE -> {
						ReplyDisassemble reply = msg.getReplyDisassemble();
						RmiTrace trace =
							client.traces.get(request.getRequestDisassemble().getOid().getId());
						result.complete(trace.handleDisassemble(reply));
					}
					default -> result.complete(null);
				}
			}
			catch (Exception e) {
				if (e.getMessage() == null) {
					Msg.error(this, "Error processing reply", e);
				}
				else {
					Msg.error(this, e.getMessage());
				}
			}
		}
		Msg.info(this, "Handler exiting");
	}

	public void close() {
		terminated = true;
	}

}
