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
package ghidra.app.plugin.core.debug.service.tracermi;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.channels.SocketChannel;

import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.framework.Application;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.rmi.trace.TraceRmi.Compiler;

public class TestTraceRmiClient {
	final ProtobufSocket<RootMessage> socket;

	public TestTraceRmiClient(SocketChannel channel) {
		this.socket = new ProtobufSocket<>(channel, RootMessage::parseFrom);
	}

	public void sendNegotiate(String description) throws IOException {
		socket.send(RootMessage.newBuilder()
				.setRequestNegotiate(RequestNegotiate.newBuilder()
						.setVersion(TraceRmiHandler.VERSION)
						.setDescription(description))
				.build());
	}

	public void recvNegotiate() throws IOException {
		assertEquals(RootMessage.newBuilder()
				.setReplyNegotiate(ReplyNegotiate.newBuilder()
						.setDescription(
							Application.getName() + " " +
								Application.getApplicationVersion()))
				.build(),
			socket.recv());
	}

	public void createTrace(int id, String name) throws IOException {
		socket.send(RootMessage.newBuilder()
				.setRequestCreateTrace(RequestCreateTrace.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(id))
						.setLanguage(Language.newBuilder()
								.setId("Toy:BE:64:default"))
						.setCompiler(Compiler.newBuilder()
								.setId("default"))
						.setPath(FilePath.newBuilder()
								.setPath("test/" + name)))
				.build());
		assertEquals(RootMessage.newBuilder()
				.setReplyCreateTrace(ReplyCreateTrace.newBuilder())
				.build(),
			socket.recv());
	}

	public void startTx(int traceId, int txId, String description) throws IOException {
		socket.send(RootMessage.newBuilder()
				.setRequestStartTx(RequestStartTx.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setTxid(TxId.newBuilder().setId(txId))
						.setDescription(description))
				.build());
		assertEquals(RootMessage.newBuilder()
				.setReplyStartTx(ReplyStartTx.newBuilder())
				.build(),
			socket.recv());
	}

	public void endTx(int traceId, int txId) throws IOException {
		socket.send(RootMessage.newBuilder()
				.setRequestEndTx(RequestEndTx.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setTxid(TxId.newBuilder().setId(txId))
						.setAbort(false))
				.build());
		assertEquals(RootMessage.newBuilder()
				.setReplyEndTx(ReplyEndTx.newBuilder())
				.build(),
			socket.recv());
	}

	public class Tx implements AutoCloseable {
		private final int traceId;
		private final int txId;

		public Tx(int traceId, int txId, String description) throws IOException {
			this.traceId = traceId;
			this.txId = txId;
			startTx(traceId, txId, description);
		}

		@Override
		public void close() throws Exception {
			endTx(traceId, txId);
		}
	}

	public void snapshot(int traceId, long snap, String description) throws IOException {
		socket.send(RootMessage.newBuilder()
				.setRequestSnapshot(RequestSnapshot.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setSnap(Snap.newBuilder()
								.setSnap(snap))
						.setDescription(description))
				.build());
		assertEquals(RootMessage.newBuilder()
				.setReplySnapshot(ReplySnapshot.newBuilder())
				.build(),
			socket.recv());
	}

	public void createRootObject(int traceId, TargetObjectSchema schema) throws IOException {
		String xmlCtx = XmlSchemaContext.serialize(schema.getContext());
		socket.send(RootMessage.newBuilder()
				.setRequestCreateRootObject(RequestCreateRootObject.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setSchemaContext(xmlCtx)
						.setRootSchema(schema.getName().toString()))
				.build());
		assertEquals(RootMessage.newBuilder()
				.setReplyCreateObject(ReplyCreateObject.newBuilder()
						.setObject(ObjSpec.newBuilder()
								.setId(0)))
				.build(),
			socket.recv());
	}

	public void activate(int traceId, String path) throws IOException {
		socket.send(RootMessage.newBuilder()
				.setRequestActivate(RequestActivate.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setObject(ObjSpec.newBuilder()
								.setPath(ObjPath.newBuilder()
										.setPath(path))))
				.build());
		assertEquals(RootMessage.newBuilder()
				.setReplyActivate(ReplyActivate.newBuilder())
				.build(),
			socket.recv());
	}
}
