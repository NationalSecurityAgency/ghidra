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
package ghidra.dbg.sctl.client;

import static ghidra.async.AsyncUtils.completable;
import static ghidra.async.AsyncUtils.sequence;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.ArrayList;
import java.util.Random;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Test;

import ghidra.async.AsyncFence;
import ghidra.async.TypeSpec;
import ghidra.comm.packet.binary.ByteBufferPacketCodec;
import ghidra.comm.packet.err.PacketDecodeException;
import ghidra.comm.packet.err.PacketEncodeException;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.sctl.dialect.SctlDialect;
import ghidra.dbg.sctl.protocol.*;
import ghidra.dbg.sctl.protocol.common.reply.*;
import ghidra.dbg.sctl.protocol.common.request.*;
import ghidra.dbg.sctl.protocol.v2012base.x86.SctlX86Context;
import ghidra.dbg.sctl.protocol.v2012base.x86.linux.Sctl2012LinuxStatus;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class SctlClientTest {
	private static final String DEFAULT_PROTOCOL_VERSION = "sctl-2012:x86-linux-2012";
	private static final String EXPECT_VERSIONS =
		"sctl-2012:any-any-2018,x86-linux-2012-bus,x86-win-2012-bus,x86-linux-2012,x86-win-2012";
	private static final long TIMEOUT_MILLISECONDS =
		SystemUtilities.isInTestingBatchMode() ? 1000 : Long.MAX_VALUE;

	protected static <T> T waitOn(TestServerThread srv, CompletableFuture<T> future)
			throws Throwable {
		try {
			AsyncFence fence = new AsyncFence();
			fence.include(srv);
			fence.include(future.exceptionally(exc -> {
				// Cheating, but I want to see the real exception
				srv.completeExceptionally(exc); // srv.cancel(true);
				return ExceptionUtils.rethrow(exc);
			}));
			fence.ready().get(TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
			return future.getNow(null);
		}
		catch (ExecutionException e) {
			throw e.getCause();
		}
	}

	interface TestClientHandler {
		void handle(SocketChannel cli, SctlDialect dialect) throws Exception;
	}

	class TestServerThread extends CompletableFuture<Void> implements AutoCloseable {
		private final TestClientHandler handler;
		private final int port;
		private final String version;
		private final SctlDialect dialect;
		private final Thread thread;

		public TestServerThread(TestClientHandler handler, int port, String version) {
			this.handler = handler;
			this.port = port;
			this.version = version;
			this.dialect = SctlVersionInfo.agreeDialect(version);
			this.thread = new Thread(this::run);
		}

		@Override
		public void close() throws Exception {
			thread.interrupt();
			thread.join(500);
		}

		private void run() {
			try (ServerSocketChannel srv = ServerSocketChannel.open()) {
				synchronized (this) {
					srv.bind(new InetSocketAddress("localhost", port));
					notifyAll();
				}
				SocketChannel cli = srv.accept();
				handleVersion(cli, version);
				handler.handle(cli, dialect);
				complete(null);
			}
			catch (ClosedByInterruptException e) {
				complete(null);
				return;
			}
			catch (Throwable e) {
				completeExceptionally(e);
				e.printStackTrace();
			}
		}

		public void start() {
			thread.start();
		}
	}

	private static final String HELLO_WORLD = "Hello, World!";

	private static final String TEST_HOST = "localhost";
	private static int PORT = new Random().nextInt(2000) + 1024;
	private static InetSocketAddress ADDR;

	private static final int TEST_CTLID = 1234;
	private static final int TEST_PID = 5678;

	private final SctlMarshaller marshaller = new SctlMarshaller();
	private final ByteBuffer inbuf = ByteBuffer.allocate(1024);
	private final ByteBuffer outbuf = ByteBuffer.allocate(1024);

	protected void expect(SocketChannel cli, SctlDialect dialect, AbstractSelSctlPacket pkt)
			throws IOException, PacketDecodeException, PacketEncodeException {
		// Ensure the packet can be encoded, and initialize meta fields
		Msg.trace(this, "Expecting: " + pkt);
		marshaller.setPacketFactory(dialect.getPacketFactory());
		ByteBufferPacketCodec.getInstance().encodePacket(pkt);

		// Now, receive the expected packet
		while (true) {
			try {
				inbuf.flip();
				AbstractSelSctlPacket recv = marshaller.unmarshall(inbuf);
				inbuf.compact();

				Msg.debug(this, "Server Received: " + recv);
				assertEquals(pkt, recv);
				return;
			}
			catch (BufferUnderflowException e) {
				inbuf.compact();
				Msg.trace(this, "Waiting for data. Currently have " + inbuf.position());
				if (Thread.interrupted()) {
					return;
				}
				int len = cli.read(inbuf);
				Msg.trace(this, "Read " + len + " bytes");
			}
		}
	}

	protected void handleAttach(SocketChannel cli, SctlDialect dialect, int tag)
			throws IOException, PacketDecodeException, PacketEncodeException {
		expect(cli, dialect, dialect.createSel(tag, new SctlAttachRequest(TEST_PID)));
		SctlX86Context ctx = new SctlX86Context();
		ctx.rax = 0x1122334455667788L;
		AbstractSctlAttachReply reply = dialect.create(AbstractSctlAttachReply.class);
		reply.ctlid = TEST_CTLID;
		reply.ctx = ctx;
		send(cli, dialect, dialect.createSel(tag, reply));
	}

	protected void handleStat(SocketChannel cli, SctlDialect dialect, int tag)
			throws IOException, PacketDecodeException, PacketEncodeException {
		expect(cli, dialect, dialect.createSel(tag, new SctlStatusRequest(TEST_CTLID)));
		SctlStatusReply reply = new SctlStatusReply();
		Sctl2012LinuxStatus status = new Sctl2012LinuxStatus();
		reply.status = status;
		status.pid = TEST_PID;
		status.bins = new ArrayList<>();
		status.regions = new ArrayList<>();
		send(cli, dialect, dialect.createSel(tag, reply));
	}

	protected void handleContinue(SocketChannel cli, SctlDialect dialect, int tag)
			throws IOException, PacketDecodeException, PacketEncodeException {
		expect(cli, dialect, dialect.createSel(tag, new SctlContinueRequest(TEST_CTLID)));
		send(cli, dialect, dialect.createSel(tag, new SctlContinueReply()));
	}

	protected void handleDetach(SocketChannel cli, SctlDialect dialect, int tag)
			throws IOException, PacketDecodeException, PacketEncodeException {
		expect(cli, dialect, dialect.createSel(tag, new SctlDetachRequest(TEST_CTLID)));
		send(cli, dialect, dialect.createSel(tag, new SctlDetachReply()));
	}

	protected void handlePing(SocketChannel cli, SctlDialect dialect, int tag)
			throws IOException, PacketDecodeException, PacketEncodeException {
		expect(cli, dialect, dialect.createSel(tag, new SctlPingRequest(HELLO_WORLD)));
		send(cli, dialect,
			dialect.createSel(tag, new SctlPingReply(HELLO_WORLD.getBytes().length)));
	}

	protected void handleVersion(SocketChannel cli, String version)
			throws IOException, PacketDecodeException, PacketEncodeException {
		SctlDialect dialect = SctlDialect.NULL_DIALECT;
		expect(cli, dialect, dialect.createSel(0, new SctlVersionRequest(EXPECT_VERSIONS)));
		send(cli, dialect, dialect.createSel(0, new SctlVersionReply(version)));
	}

	protected TestServerThread runServer(TestClientHandler handler) throws InterruptedException {
		return runServer(handler, DEFAULT_PROTOCOL_VERSION);
	}

	protected TestServerThread runServer(TestClientHandler handler, String version)
			throws InterruptedException {
		PORT++;
		ADDR = new InetSocketAddress(TEST_HOST, PORT);
		TestServerThread result = new TestServerThread(handler, PORT, version);
		result.start();
		synchronized (result) {
			result.wait();
		}
		return result;
	}

	protected void send(SocketChannel cli, SctlDialect dialect, AbstractSelSctlPacket pkt)
			throws PacketEncodeException, IOException {
		Msg.debug(this, "Server Sending: " + pkt);
		marshaller.setPacketFactory(dialect.getPacketFactory());
		marshaller.marshall(outbuf, pkt);
		outbuf.flip();
		while (outbuf.hasRemaining()) {
			if (Thread.interrupted()) {
				return;
			}
			cli.write(outbuf);
		}
		outbuf.clear();
	}

	protected void seqAttachContinueDetach(SocketChannel cli, SctlDialect dialect)
			throws IOException, PacketDecodeException, PacketEncodeException {
		handleAttach(cli, dialect, 1);
		handleStat(cli, dialect, 2);
		handleContinue(cli, dialect, 3);
		handleDetach(cli, dialect, 4);
	}

	private static String keyInt(int i) {
		return PathUtils.makeKey(PathUtils.makeIndex(i));
	}

	private static TypedTargetObjectRef<? extends TargetAttachable<?>> refPid(
			DebuggerObjectModel model, int pid) {
		return model.createRef("Attachable", keyInt(pid)).as(TargetAttachable.tclass);
	}

	@Test
	public void testAttachContinueDetach() throws Throwable {
		try (TestServerThread srv = runServer(this::seqAttachContinueDetach)) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> thread = new AtomicReference<>();
			waitOn(srv, sequence(TypeSpec.VOID).then(seq -> {
				completable(TypeSpec.VOID, socket::connect, ADDR).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Connecting");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Attaching");
				TargetAttacher<?> attacher = root.get().as(TargetAttacher.tclass);
				attacher.attach(refPid(client, TEST_PID)).handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Getting created thread");
				client.fetchModelObject("Processes", keyInt(TEST_CTLID), "Threads",
					keyInt(TEST_CTLID)).handle(seq::next);
			}, thread).then(seq -> {
				Msg.debug(this, "Continuing");
				TargetResumable<?> resumable = thread.get().as(TargetResumable.tclass);
				resumable.resume().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Detaching");
				TargetDetachable<?> detachable = thread.get().as(TargetDetachable.tclass);
				detachable.detach().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Disconnecting");
				client.close().handle(seq::next);
			}).finish());
			socket.close();
		}
	}

	protected void seqAttachDetach(SocketChannel cli, SctlDialect dialect)
			throws IOException, PacketDecodeException, PacketEncodeException {
		handleAttach(cli, dialect, 1);
		handleStat(cli, dialect, 2);
		handleDetach(cli, dialect, 3);
	}

	@Test
	public void testAttachDetach() throws Throwable {
		try (TestServerThread srv = runServer(this::seqAttachDetach)) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			AtomicReference<TargetObject> root = new AtomicReference<>();
			AtomicReference<TargetObject> thread = new AtomicReference<>();
			waitOn(srv, sequence(TypeSpec.VOID).then(seq -> {
				completable(TypeSpec.VOID, socket::connect, ADDR).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Connecting");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Getting model root");
				client.fetchModelRoot().handle(seq::next);
			}, root).then(seq -> {
				Msg.debug(this, "Attaching");
				TargetAttacher<?> attacher = root.get().as(TargetAttacher.tclass);
				attacher.attach(refPid(client, TEST_PID)).handle(seq::nextIgnore);
			}).then(seq -> {
				Msg.debug(this, "Getting created thread");
				client.fetchModelObject("Processes", keyInt(TEST_CTLID), "Threads",
					keyInt(TEST_CTLID)).handle(seq::next);
			}, thread).then(seq -> {
				Msg.debug(this, "Detaching");
				TargetDetachable<?> detachable = thread.get().as(TargetDetachable.tclass);
				detachable.detach().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Disconnecting");
				client.close().handle(seq::next);
			}).finish());
			socket.close();
		}
	}

	protected void seqPing(SocketChannel cli, SctlDialect dialect)
			throws IOException, PacketDecodeException, PacketEncodeException {
		handlePing(cli, dialect, 1);
	}

	@Test
	public void testPing() throws Throwable {
		try (TestServerThread srv = runServer(this::seqPing)) {
			AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
			SctlClient client = new SctlClient("Test", socket);
			waitOn(srv, sequence(TypeSpec.VOID).then(seq -> {
				completable(TypeSpec.VOID, socket::connect, ADDR).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Connecting");
				client.connect().handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Pinging");
				client.ping(HELLO_WORLD).handle(seq::next);
			}).then(seq -> {
				Msg.debug(this, "Disconnecting");
				client.close().handle(seq::next);
			}).finish());
			socket.close();
		}
	}

	/**
	 * NOTE: I'm no longer testing the "bus" stuff, since pretty much all extension we made to SCTL
	 * are now deprecated by GADP.
	 */
}
