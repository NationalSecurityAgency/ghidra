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
package ghidra.dbg.gadp.client;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;

import org.junit.Test;

import ghidra.async.*;
import ghidra.dbg.gadp.GadpVersion;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.util.AsyncProtobufMessageChannel;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;

public class GadpClientTest implements AsyncTestUtils {
	private static final String HELLO_WORLD = "Hello, World!";
	private static final String TEST_HOST = "localhost";

	public static final DefaultSchemaContext SCHEMA_CONTEXT = new DefaultSchemaContext();
	public static final TargetObjectSchema ROOT_SCHEMA =
		SCHEMA_CONTEXT.builder(new SchemaName("Root"))
				.setAttributeResyncMode(ResyncMode.ONCE)
				.buildAndAdd();

	interface TestClientHandler {
		void handle(SocketChannel cli, GadpVersion version) throws Exception;
	}

	class TestServer implements AutoCloseable {
		private final ServerSocketChannel srv;
		private final SocketAddress addr;
		private SocketChannel cli;
		private int seqno = 0;

		private final ByteBuffer inbuf = ByteBuffer.allocate(1024);
		private final ByteBuffer outbuf = ByteBuffer.allocate(1024);

		public TestServer() throws IOException {
			this.srv = ServerSocketChannel.open();
			this.srv.bind(new InetSocketAddress(TEST_HOST, 0), 1);
			this.addr = this.srv.getLocalAddress();
		}

		@Override
		public void close() throws Exception {
			//cli.configureBlocking(false); // Cannot wait forever
			assertEquals(-1, cli.read(inbuf));
			cli.close();
			srv.close();
		}

		public void accept() throws IOException {
			this.cli = srv.accept();
			cli.configureBlocking(false); // Cannot wait forever
		}

		public void nextSeq() {
			seqno++;
		}

		public void expect(Gadp.RootMessage msg) throws Throwable {
			long start = System.currentTimeMillis();
			Msg.debug(this, "Expecting: " + msg);

			while (true) {
				try {
					//dumpBuffer(inbuf);
					Gadp.RootMessage recv =
						AsyncProtobufMessageChannel.unmarshall(Gadp.RootMessage::parseFrom, inbuf);

					Msg.trace(this, "Server Received: " + recv);
					assertEquals(msg, recv);
					return;
				}
				catch (BufferUnderflowException e) {
					Msg.trace(this, "Waiting for data. Currently have " + inbuf.position());
					Thread.yield();
					if (Thread.interrupted()) {
						return;
					}
					int len = cli.read(inbuf);
					Msg.trace(this, "Read " + len + " bytes");
					if (len < 0) {
						throw new AssertionError("Socket is closed");
					}
					else if (len == 0) {
						if (Long.compareUnsigned(System.currentTimeMillis() - start,
							TIMEOUT_MS) > 0) {
							throw new TimeoutException("Timeout out expecting: " + msg);
						}
						Thread.sleep(100);
					}
				}
			}
		}

		public void send(Gadp.RootMessage msg) throws IOException {
			Msg.debug(this, "Server Sending: " + msg);
			outbuf.clear();
			AsyncProtobufMessageChannel.marshall(msg, outbuf);
			outbuf.flip();
			while (outbuf.hasRemaining()) {
				if (Thread.interrupted()) {
					return;
				}
				cli.write(outbuf);
			}
		}

		public void expectRequestConnect() throws Throwable {
			expect(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setConnectRequest(GadpVersion.makeRequest())
					.build());
		}

		public void sendReplyConnect(GadpVersion version) throws IOException {

			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setConnectReply(Gadp.ConnectReply.newBuilder()
							.setVersion(version.getName())
							.setSchemaContext(XmlSchemaContext.serialize(SCHEMA_CONTEXT))
							.setRootSchema(ROOT_SCHEMA.getName().toString()))
					.build());
		}

		public void handleConnect(GadpVersion version) throws Throwable {
			expectRequestConnect();
			sendReplyConnect(version);
			nextSeq();
		}

		public void sendNotifyObjectCreated(List<String> path, List<String> interfaces,
				String typeHint) throws IOException {
			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(path))
							.setObjectCreatedEvent(Gadp.ObjectCreatedEvent.newBuilder()
									.addAllInterface(interfaces)
									.setTypeHint(typeHint)))
					.build());
		}

		public void sendNotifyRootAdded() throws IOException {
			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setRootAddedEvent(Gadp.RootAddedEvent.getDefaultInstance()))
					.build());
		}

		public void notifyAddRoot() throws IOException {
			sendNotifyObjectCreated(List.of(), List.of(), "Root");
			sendNotifyRootAdded();
		}

		public void expectRequestPing(String content) throws Throwable {
			expect(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setPingRequest(Gadp.PingRequest.newBuilder()
							.setContent(content))
					.build());
		}

		public void sendReplyPing(String content) throws IOException {
			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setPingReply(Gadp.PingReply.newBuilder()
							.setContent(content))
					.build());
		}

		public void handlePing() throws Throwable {
			expectRequestPing(HELLO_WORLD);
			sendReplyPing(HELLO_WORLD);
			nextSeq();
		}

		public Gadp.ModelObjectDelta.Builder makeAttributeDelta(List<String> parentPath,
				Map<String, Object> primitives, Map<String, List<String>> objects) {
			Gadp.ModelObjectDelta.Builder delta = Gadp.ModelObjectDelta.newBuilder();
			if (primitives != null) {
				for (Map.Entry<String, ?> ent : primitives.entrySet()) {
					delta.addAdded(GadpValueUtils.makeNamedValue(parentPath, ent));
				}
			}
			if (objects != null) {
				for (Map.Entry<String, List<String>> ent : objects.entrySet()) {
					if (PathUtils.isLink(parentPath, ent.getKey(), ent.getValue())) {
						delta.addAdded(Gadp.NamedValue.newBuilder()
								.setName(ent.getKey())
								.setValue(Gadp.Value.newBuilder()
										.setPathValue(GadpValueUtils.makePath(ent.getValue()))));
					}
					else {
						delta.addAdded(Gadp.NamedValue.newBuilder()
								.setName(ent.getKey())
								.setValue(Gadp.Value.newBuilder()
										.setObjectStub(Gadp.ModelObjectStub.getDefaultInstance())));
					}
				}
			}
			return delta;
		}

		public Gadp.ModelObjectDelta.Builder makeElementDelta(List<String> parentPath,
				Map<String, List<String>> objects) {
			Gadp.ModelObjectDelta.Builder delta = Gadp.ModelObjectDelta.newBuilder();
			if (objects != null) {
				for (Map.Entry<String, List<String>> ent : objects.entrySet()) {
					if (PathUtils.isElementLink(parentPath, ent.getKey(), ent.getValue())) {
						delta.addAdded(Gadp.NamedValue.newBuilder()
								.setName(ent.getKey())
								.setValue(Gadp.Value.newBuilder()
										.setPathValue(GadpValueUtils.makePath(ent.getValue()))));
					}
					else {
						delta.addAdded(Gadp.NamedValue.newBuilder()
								.setName(ent.getKey())
								.setValue(Gadp.Value.newBuilder()
										.setObjectStub(Gadp.ModelObjectStub.getDefaultInstance())));
					}
				}
			}
			return delta;
		}

		public void expectRequestResync(List<String> path, boolean refreshAttributes,
				boolean refreshElements) throws Throwable {
			expect(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setResyncRequest(Gadp.ResyncRequest.newBuilder()
							.setPath(GadpValueUtils.makePath(path))
							.setAttributes(refreshAttributes)
							.setElements(refreshElements))
					.build());
		}

		public void sendNotifyObjects(List<String> parentPath, Map<String, List<String>> elements,
				Map<String, List<String>> attrObjects, Map<String, Object> attrPrimitives)
				throws IOException {
			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(parentPath))
							.setModelObjectEvent(Gadp.ModelObjectEvent.newBuilder()
									.setAttributeDelta(
										makeAttributeDelta(parentPath, attrPrimitives,
											attrObjects))
									.setElementDelta(makeElementDelta(parentPath, elements))))
					.build());
		}

		public void sendReplyResync() throws IOException {
			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setResyncReply(Gadp.ResyncReply.getDefaultInstance())
					.build());
		}

		public void handleResyncAttributes(List<String> path, boolean refresh,
				Map<String, List<String>> objects, Map<String, Object> primitives)
				throws Throwable {
			expectRequestResync(path, refresh, false);
			if (primitives != null || objects != null) {
				sendNotifyObjects(path, null, objects, primitives);
			}
			sendReplyResync();
			nextSeq();
		}

		public void handleResyncElements(List<String> path, boolean refresh,
				Map<String, List<String>> objects) throws Throwable {
			expectRequestResync(path, false, refresh);
			if (objects != null) {
				sendNotifyObjects(path, objects, null, null);
			}
			sendReplyResync();
			nextSeq();
		}
	}

	protected void dumpBuffer(ByteBuffer buf) {
		for (byte b : buf.array()) {
			System.err.print(String.format("%02x", b));
		}
		System.err.println();
		for (int i = 0; i < buf.position(); i++) {
			System.err.print("  ");
		}
		System.err.print("^ ");
		if (!buf.hasRemaining()) {
			System.err.println("(empty)");
		}
		else {
			for (int i = buf.position() + 2; i < buf.limit(); i++) {
				System.err.print("  ");
			}
			System.err.println(" |");
		}
	}

	protected void seqConnectDisconnect(SocketChannel cli, GadpVersion version) {
		// Nothing to add
	}

	@Test
	public void testConnectDisconnect() throws Throwable {
		try (TestServer srv = new TestServer();
				AsynchronousSocketChannel socket = AsynchronousSocketChannel.open()) {
			GadpClient client = new GadpClient("Test", socket);

			CompletableFuture<Void> sockConnect =
				AsyncUtils.completable(TypeSpec.VOID, socket::connect, srv.addr);
			srv.accept();
			waitOn(sockConnect);

			CompletableFuture<Void> gadpConnect = client.connect();
			srv.handleConnect(GadpVersion.VER1);
			waitOn(gadpConnect);

			waitOn(client.close());
		}
	}

	@Test
	public void testPing() throws Throwable {
		try (TestServer srv = new TestServer();
				AsynchronousSocketChannel socket = AsynchronousSocketChannel.open()) {
			GadpClient client = new GadpClient("Test", socket);

			CompletableFuture<Void> sockConnect =
				AsyncUtils.completable(TypeSpec.VOID, socket::connect, srv.addr);
			srv.accept();
			waitOn(sockConnect);

			CompletableFuture<Void> gadpConnect = client.connect();
			srv.handleConnect(GadpVersion.VER1);
			waitOn(gadpConnect);

			CompletableFuture<Void> ping = client.ping(HELLO_WORLD);
			srv.handlePing();
			waitOn(ping);

			waitOn(client.close());
		}
	}

	@Test
	public void testResyncOnceModelValueDeduped() throws Throwable {
		try (TestServer srv = new TestServer();
				AsynchronousSocketChannel socket = AsynchronousSocketChannel.open()) {
			GadpClient client = new GadpClient("Test", socket);

			CompletableFuture<Void> sockConnect =
				AsyncUtils.completable(TypeSpec.VOID, socket::connect, srv.addr);
			srv.accept();
			waitOn(sockConnect);

			CompletableFuture<Void> gadpConnect = client.connect();
			srv.handleConnect(GadpVersion.VER1);
			waitOn(gadpConnect);
			CompletableFuture<?> cfRoot = client.fetchModelRoot();
			srv.notifyAddRoot();
			waitOn(cfRoot);

			CompletableFuture<?> fetchVal1 = client.fetchModelValue(PathUtils.parse("value"));
			CompletableFuture<?> fetchVal2 = client.fetchModelValue(PathUtils.parse("value"));
			srv.handleResyncAttributes(List.of(), false, null, Map.of("value", HELLO_WORLD));
			assertEquals(HELLO_WORLD, waitOn(fetchVal1));
			assertEquals(HELLO_WORLD, waitOn(fetchVal2));

			CompletableFuture<?> fetchVal3 = client.fetchModelValue(PathUtils.parse("value"), true);
			srv.handleResyncAttributes(List.of(), true, null, Map.of("value", "Hi"));
			assertEquals("Hi", waitOn(fetchVal3));
		}
	}
}
