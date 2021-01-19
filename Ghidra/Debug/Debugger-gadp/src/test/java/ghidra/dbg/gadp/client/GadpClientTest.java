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
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.Test;

import generic.Unique;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.gadp.GadpVersion;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.util.AsyncProtobufMessageChannel;
import ghidra.dbg.gadp.util.GadpValueUtils;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.ElementsChangedListener;
import ghidra.dbg.util.ElementsChangedListener.ElementsChangedInvocation;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class GadpClientTest {
	private static final long TIMEOUT_MILLISECONDS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;
	private static final String HELLO_WORLD = "Hello, World!";
	private static final String TEST_HOST = "localhost";

	protected static <T> T waitOn(CompletableFuture<T> future) throws Throwable {
		try {
			return future.get(TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
		}
		catch (Exception e) {
			throw AsyncUtils.unwrapThrowable(e);
		}
	}

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
			cli.configureBlocking(false); // Cannot wait forever
			assertEquals(-1, cli.read(inbuf));
			cli.close();
			srv.close();
		}

		public void accept() throws IOException {
			this.cli = srv.accept();
		}

		public void expect(Gadp.RootMessage msg)
				throws IOException, PacketDecodeException, PacketEncodeException {
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
				}
			}
		}

		public void send(Gadp.RootMessage msg)
				throws PacketEncodeException, IOException {
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

		public void handleConnect(GadpVersion version)
				throws IOException, PacketDecodeException, PacketEncodeException {
			expect(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setConnectRequest(GadpVersion.makeRequest())
					.build());
			// TODO: Test schemas here?
			// Seems they're already hit well enough in dependent tests
			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setConnectReply(Gadp.ConnectReply.newBuilder()
							.setVersion(version.getName())
							.setSchemaContext("<context/>")
							.setRootSchema("OBJECT"))
					.build());
			seqno++;
		}

		public void handlePing()
				throws IOException, PacketDecodeException, PacketEncodeException {
			expect(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setPingRequest(Gadp.PingRequest.newBuilder()
							.setContent(HELLO_WORLD))
					.build());
			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setPingReply(Gadp.PingReply.newBuilder()
							.setContent(HELLO_WORLD))
					.build());
			seqno++;
		}

		public void handleSubscribeValue(List<String> path, Object value)
				throws Exception {
			expect(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setSubscribeRequest(Gadp.SubscribeRequest.newBuilder()
							.setPath(GadpValueUtils.makePath(path))
							.setSubscribe(true))
					.build());
			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setSubscribeReply(Gadp.SubscribeReply.newBuilder()
							.setValue(GadpValueUtils.makeValue(path, value)))
					.build());
			seqno++;
		}

		public void handleFetchObject(List<String> path) throws Exception {
			expect(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setSubscribeRequest(Gadp.SubscribeRequest.newBuilder()
							.setPath(GadpValueUtils.makePath(path))
							.setSubscribe(true))
					.build());
			Gadp.SubscribeReply.Builder reply = Gadp.SubscribeReply.newBuilder()
					.setValue(Gadp.Value.newBuilder()
							.setObjectInfo(Gadp.ModelObjectInfo.newBuilder()
									.setPath(GadpValueUtils.makePath(path))));
			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setSubscribeReply(reply)
					.build());
			seqno++;
		}

		public void handleFetchElements(List<String> path, Collection<String> indices)
				throws Exception {
			expect(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setSubscribeRequest(Gadp.SubscribeRequest.newBuilder()
							.setPath(GadpValueUtils.makePath(path))
							.setSubscribe(true)
							.setFetchElements(true))
					.build());
			Gadp.SubscribeReply.Builder reply = Gadp.SubscribeReply.newBuilder()
					.setValue(Gadp.Value.newBuilder()
							.setObjectInfo(Gadp.ModelObjectInfo.newBuilder()
									.setPath(GadpValueUtils.makePath(path))
									.addAllElementIndex(indices)));
			send(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setSubscribeReply(reply)
					.build());
			seqno++;
		}

		public void sendModelEvent(List<String> path, Collection<String> indicesAdded)
				throws Exception {
			Gadp.ModelObjectEvent.Builder evt = Gadp.ModelObjectEvent.newBuilder();
			evt.setDelta(Gadp.ModelObjectDelta.newBuilder()
					.addAllIndexAdded(indicesAdded));
			send(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(path))
							.setModelObjectEvent(evt))
					.build());
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
	public void testGetObjectRefInListener() throws Throwable {
		ElementsChangedListener elemL = new ElementsChangedListener();

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

			CompletableFuture<? extends TargetObject> fetchParent =
				client.fetchModelObject(PathUtils.parse("Parent"));
			srv.handleFetchObject(PathUtils.parse("Parent"));
			TargetObject parent = waitOn(fetchParent);
			parent.addListener(elemL);

			CompletableFuture<? extends Map<String, ? extends TargetObjectRef>> fetchElements =
				parent.fetchElements();
			srv.handleFetchElements(PathUtils.parse("Parent"), List.of());
			assertEquals(Map.of(), waitOn(fetchElements));

			srv.sendModelEvent(PathUtils.parse("Parent"), List.of("0"));
			waitOn(elemL.count.waitValue(1));
			ElementsChangedInvocation changed = Unique.assertOne(elemL.invocations);
			assertEquals(parent, changed.parent);
			TargetObjectRef childRef = Unique.assertOne(changed.added.values());
			assertEquals(PathUtils.parse("Parent[0]"), childRef.getPath());

			// Not cached, since fetchElements just lists refs
			CompletableFuture<? extends TargetObject> fetchChild = childRef.fetch();
			srv.handleFetchObject(PathUtils.parse("Parent[0]"));
			TargetObject child = waitOn(fetchChild);
			assertEquals(Map.of("0", child), parent.getCachedElements());
		}
		assertEquals(1, elemL.count.get().intValue()); // After connection is closed
	}

	@Test
	public void testGetModelValueDeduped() throws Throwable {
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

			CompletableFuture<?> fetchVal1 = client.fetchModelValue(PathUtils.parse("value"));
			CompletableFuture<?> fetchVal2 = client.fetchModelValue(PathUtils.parse("value"));
			srv.handleSubscribeValue(PathUtils.parse("value"), HELLO_WORLD);
			assertEquals(HELLO_WORLD, waitOn(fetchVal1));
			assertEquals(HELLO_WORLD, waitOn(fetchVal2));

			// Because parent not cached, it should send another request
			CompletableFuture<?> fetchVal3 = client.fetchModelValue(PathUtils.parse("value"));
			srv.handleSubscribeValue(PathUtils.parse("value"), "Hi");
			assertEquals("Hi", waitOn(fetchVal3));
		}
	}
}
