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
package ghidra.dbg.gadp;

import static org.junit.Assert.*;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import org.junit.Ignore;
import org.junit.Test;

import com.google.protobuf.GeneratedMessageV3;

import generic.ID;
import generic.Unique;
import ghidra.async.*;
import ghidra.dbg.*;
import ghidra.dbg.agent.*;
import ghidra.dbg.attributes.TargetStringList;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.gadp.GadpClientServerTest.EventListener.CallEntry;
import ghidra.dbg.gadp.client.GadpClient;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.protocol.Gadp.RootMessage;
import ghidra.dbg.gadp.server.AbstractGadpServer;
import ghidra.dbg.gadp.server.GadpClientHandler;
import ghidra.dbg.gadp.util.AsyncProtobufMessageChannel;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.testutil.*;
import ghidra.dbg.testutil.AttributesChangedListener.AttributesChangedInvocation;
import ghidra.dbg.testutil.ElementsChangedListener.ElementsChangedInvocation;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class GadpClientServerTest implements AsyncTestUtils {
	public static final long TIMEOUT_MILLISECONDS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;

	protected interface DecoratedAsyncByteChannel extends AsynchronousByteChannel {
		AsynchronousByteChannel getDelegate();

		@Override
		default void close() throws IOException {
			getDelegate().close();
		}

		@Override
		default boolean isOpen() {
			return getDelegate().isOpen();
		}

		@Override
		default <A> void read(ByteBuffer dst, A attachment,
				CompletionHandler<Integer, ? super A> handler) {
			getDelegate().read(dst, attachment, handler);
		}

		@Override
		default Future<Integer> read(ByteBuffer dst) {
			return getDelegate().read(dst);
		}

		@Override
		default <A> void write(ByteBuffer src, A attachment,
				CompletionHandler<Integer, ? super A> handler) {
			getDelegate().write(src, attachment, handler);
		}

		@Override
		default Future<Integer> write(ByteBuffer src) {
			return getDelegate().write(src);
		}
	}

	protected static class MonitoredAsyncByteChannel implements DecoratedAsyncByteChannel {
		private AsynchronousByteChannel delegate;

		private int writeCount = 0;

		public MonitoredAsyncByteChannel(AsynchronousByteChannel delegate) {
			this.delegate = delegate;
		}

		@Override
		public AsynchronousByteChannel getDelegate() {
			return delegate;
		}

		@Override
		public <A> void write(ByteBuffer src, A attachment,
				CompletionHandler<Integer, ? super A> handler) {
			writeCount++;
			DecoratedAsyncByteChannel.super.write(src, attachment, handler);
		}

		@Override
		public Future<Integer> write(ByteBuffer src) {
			writeCount++;
			return DecoratedAsyncByteChannel.super.write(src);
		}

		private void reset() {
			writeCount = 0;
		}
	}

	public static class MonitoredAsyncProtobufMessageChannel<S extends GeneratedMessageV3, R extends GeneratedMessageV3>
			extends AsyncProtobufMessageChannel<S, R> {
		interface MessageRecord<S, R> {
			S assertSent();

			R assertReceived();
		}

		public static class MessageSent<S, R> implements MessageRecord<S, R> {
			public final S message;

			public MessageSent(S message) {
				this.message = message;
			}

			@Override
			public S assertSent() {
				return message;
			}

			@Override
			public R assertReceived() {
				fail();
				return null;
			}
		}

		public static class MessageReceived<S, R> implements MessageRecord<S, R> {
			public final R message;

			public MessageReceived(R message) {
				this.message = message;
			}

			@Override
			public S assertSent() {
				fail();
				return null;
			}

			@Override
			public R assertReceived() {
				return message;
			}
		}

		List<MessageRecord<S, R>> record = new ArrayList<>();
		AsyncReference<Integer, Void> count = new AsyncReference<>();

		public MonitoredAsyncProtobufMessageChannel(AsynchronousByteChannel channel) {
			super(channel);
		}

		@Override
		public <R2 extends R> CompletableFuture<R2> read(IOFunction<R2> receiver) {
			return super.read(receiver).thenApply(msg -> {
				synchronized (this) {
					record.add(new MessageReceived<>(msg));
					count.set(record.size(), null);
				}
				return msg;
			});
		}

		@Override
		public CompletableFuture<Integer> write(S msg) {
			return super.write(msg).thenApply(s -> {
				synchronized (this) {
					record.add(new MessageSent<>(msg));
					count.set(record.size(), null);
				}
				return s;
			});
		}

		public synchronized void clear() {
			record.clear();
			count.set(0, null);
		}
	}

	public static class MonitoredGadpClient extends GadpClient {
		public MonitoredGadpClient(String description, AsynchronousByteChannel channel) {
			super(description, channel);
		}

		@Override
		protected AsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage> createMessageChannel(
				AsynchronousByteChannel channel) {
			return new MonitoredAsyncProtobufMessageChannel<>(channel);
		}

		MonitoredAsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage> getMessageChannel() {
			return (MonitoredAsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage>) messageChannel;
		}
	}

	public static class PrintingAsyncProtobufMessageChannel<//
			S extends GeneratedMessageV3, R extends GeneratedMessageV3>
			extends AsyncProtobufMessageChannel<S, R> {
		private final String sendPrefix;
		private final String recvPrefix;

		public PrintingAsyncProtobufMessageChannel(String local, String peer,
				AsynchronousByteChannel channel) {
			super(channel);
			this.sendPrefix = local + "->" + peer + ": ";
			this.recvPrefix = local + "<-" + peer + ": ";
		}

		@Override
		public CompletableFuture<Integer> write(S msg) {
			Msg.debug(this, sendPrefix + msg);
			return super.write(msg).thenApplyAsync(c -> {
				return c;
			});
		}

		@Override
		public <R2 extends R> CompletableFuture<R2> read(IOFunction<R2> receiver) {
			return super.read(receiver).thenApplyAsync(msg -> {
				Msg.debug(this, recvPrefix + msg);
				return msg;
			});
		}
	}

	public static class PrintingGadpClient extends GadpClient {
		public PrintingGadpClient(String description, AsynchronousByteChannel channel) {
			super(description, channel);
		}

		@Override
		protected AsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage> createMessageChannel(
				AsynchronousByteChannel channel) {
			return new PrintingAsyncProtobufMessageChannel<>("C", "S", channel);
		}
	}

	@TargetObjectSchemaInfo(name = "Session")
	public class TestGadpTargetSession extends DefaultTargetModelRoot implements TargetFocusScope {
		protected final TestGadpTargetAvailableContainer available =
			new TestGadpTargetAvailableContainer(this);
		protected final TestGadpTargetProcessContainer processes =
			new TestGadpTargetProcessContainer(this);
		protected final TestGadpTargetAvailableLinkContainer links =
			new TestGadpTargetAvailableLinkContainer(this);

		public TestGadpTargetSession(TestGadpObjectModel model, TargetObjectSchema schema) {
			super(model, "Session", schema);

			changeAttributes(List.of(), List.of(available, processes), Map.ofEntries(
				Map.entry(FOCUS_ATTRIBUTE_NAME, this)),
				"Initialized");
		}

		@Override
		public AbstractDebuggerObjectModel getModel() {
			return super.getModel();
		}

		@TargetAttributeType(name = "Available", required = true, fixed = true)
		public TestGadpTargetAvailableContainer getAvailable() {
			return available;
		}

		@TargetAttributeType(name = "Processes", required = true, fixed = true)
		public TestGadpTargetProcessContainer getProcesses() {
			return processes;
		}

		public void addLinks() throws Throwable {
			waitOn(available.fetchElements());
			links.setElements(List.of(), Map.of("1", available.getCachedElements().get("2"), "2",
				available.getCachedElements().get("1")), "Initialized");
			changeAttributes(List.of(), List.of(links), Map.of(), "Adding links");
		}

		public void setFocus(TestGadpTargetProcess process) {
			changeAttributes(List.of(), List.of(), Map.of(FOCUS_ATTRIBUTE_NAME, process),
				"New Process");
		}

		@Override
		public CompletableFuture<Void> requestFocus(TargetObject obj) {
			throw new UnsupportedOperationException();
		}
	}

	public class TestTargetObject<E extends TargetObject, P extends TargetObject>
			extends DefaultTargetObject<E, P> {

		public TestTargetObject(AbstractDebuggerObjectModel model, P parent, String key,
				String typeHint) {
			super(model, parent, key, typeHint);
		}

		@Override
		public AbstractDebuggerObjectModel getModel() {
			return super.getModel();
		}

		@Override
		protected CompletableFuture<Void> requestAttributes(boolean refresh) {
			if (refresh) {
				List<String> toRemove = new ArrayList<>();
				for (String name : attributes.keySet()) {
					if (PathUtils.isInvocation(name)) {
						toRemove.add(name);
					}
				}
				changeAttributes(toRemove, Map.of(), "Refreshed");
			}
			return super.requestAttributes(refresh);
		}
	}

	private static final TargetParameterMap PARAMS = TargetParameterMap.copyOf(Map.of("whom",
		ParameterDescription.create(String.class, "whom", true, "World", "Whom to greet",
			"The person or people to greet"),
		"others",
		ParameterDescription.create(TargetStringList.class, "others", false, TargetStringList.of(),
			"Others to greet", "List of other people to greet individually")));

	public class TestGadpTargetMethod extends TestTargetObject<TargetObject, TestTargetObject<?, ?>>
			implements TargetMethod {

		public TestGadpTargetMethod(TestTargetObject<?, ?> parent, String key) {
			super(parent.getModel(), parent, key, "Method");

			setAttributes(Map.of(
				PARAMETERS_ATTRIBUTE_NAME, PARAMS,
				RETURN_TYPE_ATTRIBUTE_NAME, Integer.class),
				"Initialized");
		}

		@Override
		public CompletableFuture<Object> invoke(Map<String, ?> arguments) {
			TestMethodInvocation invocation = new TestMethodInvocation(arguments);
			invocations.offer(invocation);
			return model.gateFuture(invocation.thenApply(obj -> {
				parent.changeAttributes(List.of(),
					Map.ofEntries(Map.entry("greet(" + arguments.get("arg") + ")", obj)),
					"greet() invoked");
				return obj;
			}));
		}
	}

	private static final TargetParameterMap ORDERED_PARAMS = TargetMethod.makeParameters(
		ParameterDescription.create(String.class, "H", true, "", "H", "H"),
		ParameterDescription.create(String.class, "e", true, "", "e", "e"),
		ParameterDescription.create(String.class, "l", true, "", "l", "l"),
		ParameterDescription.create(String.class, "m", true, "", "l", "l"),
		ParameterDescription.create(String.class, "o", true, "", "o", "o"),
		ParameterDescription.create(String.class, "W", true, "", "W", "W"),
		ParameterDescription.create(String.class, "p", true, "", "o", "o"),
		ParameterDescription.create(String.class, "r", true, "", "r", "r"),
		ParameterDescription.create(String.class, "n", true, "", "l", "l"),
		ParameterDescription.create(String.class, "d", true, "", "d", "d"));

	public class TestGadpTargetMethodWithManyParameters
			extends TestTargetObject<TargetObject, TestTargetObject<?, ?>> implements TargetMethod {

		public TestGadpTargetMethodWithManyParameters(TestTargetObject<?, ?> parent, String key) {
			super(parent.getModel(), parent, key, "MethodPlus");

			setAttributes(Map.of(
				PARAMETERS_ATTRIBUTE_NAME, ORDERED_PARAMS,
				RETURN_TYPE_ATTRIBUTE_NAME, Integer.class),
				"Initialized");
		}

		@Override
		public CompletableFuture<Object> invoke(Map<String, ?> arguments) {
			fail("I wasn't expecting that");
			return AsyncUtils.nil();
		}
	}

	@TargetObjectSchemaInfo(name = "ProcessContainer")
	public class TestGadpTargetProcessContainer
			extends TestTargetObject<TestGadpTargetProcess, TestGadpTargetSession>
			implements TargetLauncher, TargetConfigurable {

		static final String BASE_ATTRIBUTE_NAME = "base";

		int base = 10;

		public TestGadpTargetProcessContainer(TestGadpTargetSession session) {
			super(session.getModel(), session, "Processes", "ProcessContainer");

			changeAttributes(List.of(), Map.ofEntries(
				Map.entry(BASE_ATTRIBUTE_NAME, base)),
				"Initialized");
		}

		@Override
		public CompletableFuture<Void> launch(Map<String, ?> args) {
			launches.offer(args);
			long pid = args.containsKey("pid") ? (Long) args.get("pid") : 0;
			TestGadpTargetProcess process = new TestGadpTargetProcess(this, pid, base);
			changeElements(List.of(), List.of(process), Map.of(), "Launched");
			parent.setFocus(process);
			return AsyncUtils.NIL;
		}

		@Override
		public CompletableFuture<Void> writeConfigurationOption(String key, Object value) {
			if (BASE_ATTRIBUTE_NAME.equals(key)) {
				if (!(value instanceof Integer)) {
					throw new DebuggerIllegalArgumentException(
						"base must be an Integer in [0, 36]");
				}
				int base = (Integer) value;
				if (base < 0 || 36 < base) {
					throw new DebuggerIllegalArgumentException(
						"base must be an Integer in [0, 36]");
				}
				setBase(base);
			}
			else {
				throw new DebuggerIllegalArgumentException("unrecognized option: '" + key + "'");
			}
			return AsyncUtils.NIL;
		}

		public void setBase(int base) {
			this.base = base;
			for (TestGadpTargetProcess proc : elements.values()) {
				proc.setBase(base);
			}
		}
	}

	@TargetObjectSchemaInfo(name = "Process")
	public class TestGadpTargetProcess
			extends TestTargetObject<TargetObject, TestGadpTargetProcessContainer>
			implements TargetProcess {
		final long pid;
		int base = 10;

		public TestGadpTargetProcess(TestGadpTargetProcessContainer processes, long pid, int base) {
			super(processes.getModel(), processes, PathUtils.makeKey(PathUtils.makeIndex(pid)),
				"Process");
			this.pid = pid;
			setBase(base);
		}

		void setBase(int base) {
			this.base = base;
			updateDisplay("Reconfigured base");
		}

		void updateDisplay(String reason) {
			changeAttributes(List.of(),
				Map.ofEntries(Map.entry(DISPLAY_ATTRIBUTE_NAME, computeDisplay())),
				reason);
		}

		String computeDisplay() {
			return Long.toString(pid, base);
		}
	}

	@TargetObjectSchemaInfo(name = "AvailableContainer", elementResync = ResyncMode.ALWAYS)
	public class TestGadpTargetAvailableContainer
			extends TestTargetObject<TestGadpTargetAvailable, TestGadpTargetSession> {

		public TestGadpTargetAvailableContainer(TestGadpTargetSession session) {
			super(session.getModel(), session, "Available", "AvailableContainer");

			setAttributes(List.of(
				new TestGadpTargetMethod(this, "greet"),
				new TestGadpTargetMethodWithManyParameters(this, "bigGreet")),
				Map.of(), "Initialized");
		}

		@Override
		public CompletableFuture<Void> requestElements(boolean refresh) {
			setElements(List.of(new TestGadpTargetAvailable(this, 1, "echo"),
				new TestGadpTargetAvailable(this, 2, "dd")), Map.of(), "Refreshed");
			return super.requestElements(refresh);
		}
	}

	@TargetObjectSchemaInfo(name = "Available")
	public class TestGadpTargetAvailable
			extends TestTargetObject<TargetObject, TestGadpTargetAvailableContainer>
			implements TargetAttachable {

		public TestGadpTargetAvailable(TestGadpTargetAvailableContainer available, int pid,
				String cmd) {
			super(available.getModel(), available, PathUtils.makeKey(PathUtils.makeIndex(pid)),
				"Available");
			changeAttributes(List.of(), Map.of("pid", pid, "cmd", cmd //
			), "Initialized");
		}
	}

	/**
	 * This is a totally contrived concept, probably not found in any actual debugger. I just need
	 * something to have element links for testing.
	 */
	public class TestGadpTargetAvailableLinkContainer
			extends TestTargetObject<TestGadpTargetAvailable, TestGadpTargetSession> {
		public TestGadpTargetAvailableLinkContainer(TestGadpTargetSession session) {
			super(session.getModel(), session, "Links", "AvailableLinkContainer");
		}
	}

	public static class BlankObjectModel extends AbstractDebuggerObjectModel {
		private final AddressSpace ram =
			new GenericAddressSpace("RAM", 64, AddressSpace.TYPE_RAM, 0);
		private final AddressFactory factory =
			new DefaultAddressFactory(new AddressSpace[] { ram });

		@Override
		public AddressFactory getAddressFactory() {
			return factory;
		}
	}

	// TODO: Refactor with other Fake and Test. Probably put in Framework-Debugging....
	public class TestGadpObjectModel extends BlankObjectModel {
		private TargetObjectSchema rootSchema = EnumerableTargetObjectSchema.OBJECT;
		private TestGadpTargetSession session;

		public TestGadpObjectModel(boolean createSession) {
			if (createSession) {
				AnnotatedSchemaContext ctx = new AnnotatedSchemaContext();
				rootSchema = ctx.getSchemaForClass(TestGadpTargetSession.class);
				session = new TestGadpTargetSession(this, rootSchema);
				addModelRoot(session);
			}
		}

		@Override // file access
		protected void addModelRoot(SpiTargetObject root) {
			super.addModelRoot(root);
		}

		@Override
		public TargetObjectSchema getRootSchema() {
			return rootSchema;
		}
	}

	public class TestGadpServer extends AbstractGadpServer {
		final TestGadpObjectModel model;

		public TestGadpServer(SocketAddress addr) throws IOException {
			this(new TestGadpObjectModel(true), addr);
		}

		public TestGadpServer(TestGadpObjectModel model, SocketAddress addr) throws IOException {
			super(model, addr);
			this.model = model;
		}
	}

	public class PrintingTestGadpServer extends TestGadpServer {
		public PrintingTestGadpServer(SocketAddress addr) throws IOException {
			super(addr);
		}

		@Override
		protected GadpClientHandler newHandler(AsynchronousSocketChannel sock) {
			return new GadpClientHandler(this, sock) {
				@Override
				protected AsyncProtobufMessageChannel<RootMessage, RootMessage> createMessageChannel(
						AsynchronousByteChannel byteChannel) {
					return new PrintingAsyncProtobufMessageChannel<>("S", "C", byteChannel);
				}
			};
		}
	}

	public class ServerRunner implements AutoCloseable {
		TestGadpServer server;

		public ServerRunner() throws IOException {
			server = createServer(new InetSocketAddress("localhost", 0));
			server.launchAsyncService();
		}

		protected TestGadpServer createServer(SocketAddress addr) throws IOException {
			return new TestGadpServer(addr);
		}

		@Override
		public void close() throws Exception {
			server.terminate();
		}
	}

	public class PrintingServerRunner extends ServerRunner {
		public PrintingServerRunner() throws IOException {
			super();
		}

		@Override
		protected TestGadpServer createServer(SocketAddress addr) throws IOException {
			return new PrintingTestGadpServer(addr);
		}
	}

	class TestMethodInvocation extends CompletableFuture<Object> {
		final Map<String, ?> args;

		public TestMethodInvocation(Map<String, ?> args) {
			this.args = args;
		}
	}

	protected Deque<Map<String, ?>> launches = new LinkedList<>();

	protected static class AsyncDeque<T> {
		private final Deque<T> deque = new LinkedList<>();
		private final AsyncReference<Integer, Void> count = new AsyncReference<>(0);

		public boolean offer(T e) {
			boolean result = deque.offer(e);
			count.set(deque.size(), null);
			return result;
		}

		public T poll() {
			T result = deque.poll();
			count.set(deque.size(), null);
			return result;
		}

		public void clear() {
			deque.clear();
			count.set(0, null);
		}
	}

	protected AsyncDeque<TestMethodInvocation> invocations = new AsyncDeque<>();

	protected AsynchronousSocketChannel socketChannel() throws IOException {
		// Note, it looks like the executor knows to shut itself down on GC
		AsynchronousChannelGroup group =
			AsynchronousChannelGroup.withThreadPool(Executors.newSingleThreadExecutor());
		return AsynchronousSocketChannel.open(group);
	}

	@Test
	public void testConnectDisconnect() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);

			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testFetchModelValue() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			Object rootVal = waitOn(client.fetchModelValue(List.of()));
			TargetObject root = (TargetObject) rootVal;
			assertEquals(List.of(), root.getPath());
			Object cmd = waitOn(client.fetchModelValue(PathUtils.parse("Available[1].cmd")));
			assertEquals("echo", cmd);
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	@Ignore("Developer's desk only")
	public void stressTest() throws Throwable {
		for (int i = 0; i < 1000; i++) {
			try {
				System.out.println("ITERATION: " + i);
				testFetchModelValueCached();
			}
			catch (Throwable e) {
				System.err.println("Failed on iteration " + i);
				throw e;
			}
		}
	}

	@Test // Sanity check on underlying model
	public void testFetchModelValueCachedNoGadp() throws Throwable {
		TestGadpObjectModel model = new TestGadpObjectModel(true);
		Object rootVal = waitOn(model.fetchModelValue(List.of()));
		TargetObject root = (TargetObject) rootVal;
		assertEquals(List.of(), root.getPath());
		// Do fetchAll to create objects and populate their caches
		Map<String, ? extends TargetObject> available =
			waitOn(model.fetchObjectElements(PathUtils.parse("Available")));
		assertEquals(2, available.size());
		Object cmd = waitOn(model.fetchModelValue(PathUtils.parse("Available[1].cmd")));
		assertEquals("echo", cmd);
	}

	@Test
	public void testFetchModelValueCached() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		MonitoredAsyncByteChannel monitored = new MonitoredAsyncByteChannel(socket);
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", monitored);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			Object rootVal = waitOn(client.fetchModelValue(List.of()));
			TargetObject root = (TargetObject) rootVal;
			assertEquals(List.of(), root.getPath());
			// Do fetchAll to create objects and populate their caches
			Map<String, ? extends TargetObject> available =
				waitOn(client.fetchObjectElements(PathUtils.parse("Available")));
			assertEquals(2, available.size());
			monitored.reset();
			Object cmd = waitOn(client.fetchModelValue(PathUtils.parse("Available[1].cmd")));
			assertEquals("echo", cmd);
			// Just 1 to request .cmd, since the above will only have covered Available[]
			assertEquals(1, monitored.writeCount);
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testInvoke() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject greet =
				waitOn(client.fetchModelObject(PathUtils.parse("Available.greet")));
			assertTrue(greet.getInterfaceNames().contains("Method"));
			TargetMethod method = greet.as(TargetMethod.class);

			assertEquals(PARAMS, method.getParameters());
			assertEquals(Integer.class, method.getReturnType());

			CompletableFuture<Object> future = method
					.invoke(Map.of("whom", "GADP", "others", TargetStringList.of("Alice", "Bob")));
			waitOn(invocations.count.waitValue(1));
			TestMethodInvocation invocation = invocations.poll();
			assertEquals(Map.of("whom", "GADP", "others", TargetStringList.of("Alice", "Bob")),
				invocation.args);
			invocation.complete(42);
			int result = (Integer) waitOn(future);
			assertEquals(42, result);
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testInvokeMethodCached() throws Throwable {
		// TODO: Disambiguate / deconflict these two "method" cases
		try (AsynchronousSocketChannel socket = socketChannel();
				ServerRunner runner = new ServerRunner()) {
			MonitoredAsyncByteChannel monitored = new MonitoredAsyncByteChannel(socket);
			GadpClient client = new GadpClient("Test", monitored);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			// Ensure the proxy's cache is in play
			TargetObject avail = waitOn(client.fetchModelObject(PathUtils.parse("Available")));
			/**
			 * TODO: Need to think about what should happen if invocation is generated before
			 * attributes are fetched the first time.
			 */
			Map<String, ?> attrs = waitOn(avail.fetchAttributes());
			TargetMethod method = (TargetMethod) attrs.get("greet");
			assertNotNull(method);
			CompletableFuture<?> future1 = avail.fetchAttribute("greet(World)");

			waitOn(invocations.count.waitValue(1));
			TestMethodInvocation invocation1 = invocations.poll();
			assertEquals(Map.of("arg", "World"), invocation1.args);
			invocation1.complete("Hello, World!");
			assertEquals("Hello, World!", waitOn(future1));
			// Should not have to wait
			assertEquals("Hello, World!", waitOn(avail.fetchAttribute("greet(World)")));
			assertEquals(0, invocations.count.get().intValue());

			// Flush the cache
			waitOn(avail.fetchAttributes(true));
			CompletableFuture<?> future2 = avail.fetchAttribute("greet(World)");
			waitOn(invocations.count.waitValue(1));
			TestMethodInvocation invocation2 = invocations.poll();
			invocation2.complete("Hello, World?");
			assertEquals("Hello, World?", waitOn(future2));

			waitOn(client.close());
		}
	}

	@Test
	public void testMethodParametersOrderPreserved() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject greet =
				waitOn(client.fetchModelObject(PathUtils.parse("Available.bigGreet")));
			assertTrue(greet.getInterfaceNames().contains("Method"));
			TargetMethod method = greet.as(TargetMethod.class);

			TargetParameterMap params = method.getParameters();
			assertEquals(ORDERED_PARAMS, params);

			assertEquals("HelmoWprnd",
				params.values().stream().map(p -> p.name).collect(Collectors.joining()));

			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testListRoot() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			Map<String, ? extends TargetObject> elements =
				waitOn(client.fetchObjectElements(List.of()));
			assertEquals(0, elements.size());
			Map<String, ?> attributes = waitOn(client.fetchObjectAttributes(List.of()));
			assertEquals(Set.of("Processes", "Available", TargetObject.DISPLAY_ATTRIBUTE_NAME,
				TargetFocusScope.FOCUS_ATTRIBUTE_NAME), attributes.keySet());
			Object procContAttr = attributes.get("Processes");
			TargetObject procCont = (TargetObject) procContAttr;
			assertEquals(List.of("Processes"), procCont.getPath());
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testLaunch() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject procCont = waitOn(client.fetchModelObject(List.of("Processes")));
			assertTrue(procCont.getInterfaceNames().contains("Launcher"));
			TargetLauncher launcher = procCont.as(TargetLauncher.class);
			waitOn(launcher.launch(
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "/bin/echo Hello, World!")));
			waitOn(client.close());
		}
		finally {
			socket.close();
		}

		assertEquals(Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "/bin/echo Hello, World!"),
			launches.poll());
		assertNull(launches.poll());
	}

	@Test
	public void testGetAvailableWithObjectGettingListener() throws Throwable {
		List<ElementsChangedInvocation> invocations = new ArrayList<>();
		// Any listener which calls .get on a child ref would do....
		// This object-getting listener is the pattern that revealed this problem, though.
		DebuggerModelListener listener = new DebuggerModelListener() {
			@Override
			public void elementsChanged(TargetObject parent, Collection<String> removed,
					Map<String, ? extends TargetObject> added) {
				invocations.add(new ElementsChangedInvocation(parent, removed, added));
			}
		};
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject avail = waitOn(client.fetchModelObject(List.of("Available")));
			avail.addListener(listener);
			Map<String, ? extends TargetObject> elements = waitOn(avail.fetchElements());
			Msg.debug(this, "Elements: " + elements);
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testFocus() throws Throwable {
		// Interesting because it involves a non-object-valued attribute (link)
		// Need to check callback as well as getAttributes

		CompletableFuture<List<String>> focusPath = new CompletableFuture<>();
		AtomicBoolean failed = new AtomicBoolean();
		DebuggerModelListener focusListener =
			new AnnotatedDebuggerAttributeListener(MethodHandles.lookup()) {
				@AttributeCallback(TargetFocusScope.FOCUS_ATTRIBUTE_NAME)
				public void focusChanged(TargetObject object, TargetObject focused) {
					Msg.info(this, "Focus changed to " + focused);
					if (!focusPath.complete(focused.getPath())) {
						failed.set(true);
					}
				}
			};
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject session = waitOn(client.fetchModelObject(List.of()));
			session.addListener(focusListener);
			TargetObject procCont = waitOn(client.fetchModelObject(List.of("Processes")));
			assertTrue(procCont.getInterfaceNames().contains("Launcher"));
			TargetLauncher launcher = procCont.as(TargetLauncher.class);
			waitOn(launcher.launch(
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "/bin/echo Hello, World!")));
			launches.clear(); // Don't care. Just free it up.
			Map<String, ?> attrs = waitOn(client.fetchObjectAttributes(List.of()));
			assertTrue(attrs.containsKey(TargetFocusScope.FOCUS_ATTRIBUTE_NAME));
			TargetObject focus = (TargetObject) attrs.get(TargetFocusScope.FOCUS_ATTRIBUTE_NAME);
			// NOTE: Could be actual object, but need not be
			assertEquals(List.of("Processes", "[0]"), focus.getPath());
			waitOn(focusPath);
			waitOn(client.close());

			assertFalse(failed.get());
		}
		finally {
			socket.close();
		}
		assertEquals(List.of("Processes", "[0]"), focusPath.getNow(null));
	}

	@Test
	public void testSubscribeNoSuchPath() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			assertNull(waitOn(client.fetchModelObject(List.of("NotHere"))));
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testSubscribeLaunchForChildrenChanged() throws Throwable {
		ElementsChangedListener elemL = new ElementsChangedListener();

		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);

			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject procContainer = waitOn(client.fetchModelObject(List.of("Processes")));
			assertTrue(procContainer.getInterfaceNames().contains("Launcher"));
			procContainer.addListener(elemL);
			TargetLauncher launcher = procContainer.as(TargetLauncher.class);
			waitOn(launcher.launch(
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "/bin/echo Hello, World!")));
			waitOn(elemL.count.waitValue(1));

			waitOn(client.close());

			assertEquals(1, elemL.invocations.size());
			ElementsChangedInvocation eci = elemL.invocations.get(0);
			assertEquals(procContainer, eci.parent);
			assertEquals(List.of(), List.copyOf(eci.removed));
			assertEquals(1, eci.added.size());
			Entry<String, ? extends TargetObject> ent = eci.added.entrySet().iterator().next();
			assertEquals("0", ent.getKey());
			assertEquals(List.of("Processes", "[0]"), ent.getValue().getPath());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testReplaceElement() throws Throwable {
		ElementsChangedListener elemL = new ElementsChangedListener();
		InvalidatedListener invL = new InvalidatedListener();

		try (AsynchronousSocketChannel socket = socketChannel();
				ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			populateAvailableAndSync(client, runner);
			TargetObject availCont = client.getModelObject(PathUtils.parse("Available"));

			client.addModelListener(elemL);
			client.addModelListener(invL);

			Map<String, ? extends TargetObject> avail1 = availCont.getCachedElements();
			elemL.clear();
			TestGadpTargetAvailableContainer ssAvail = runner.server.model.session.available;
			ssAvail.setElements(List.of(new TestGadpTargetAvailable(ssAvail, 1, "cat") //
			), "Changed");

			waitOn(invL.count.waitUntil(c -> c >= 2));
			waitOn(elemL.count.waitUntil(c -> c >= 2));

			for (TargetObject a : avail1.values()) {
				assertFalse(a.isValid());
			}

			Map<String, ? extends TargetObject> avail2 = availCont.getCachedElements();
			assertEquals(1, avail2.size());
			assertEquals("cat", avail2.get("1").getCachedAttribute("cmd"));

			ElementsChangedInvocation removed = elemL.invocations.remove();
			assertSame(availCont, removed.parent);
			assertEquals(Map.of(), removed.added);
			assertEquals(Set.of("1"), Set.copyOf(removed.removed));

			ElementsChangedInvocation changed = Unique.assertOne(elemL.invocations);
			assertSame(availCont, changed.parent);
			assertEquals(Set.of("1"), changed.added.keySet());
			assertEquals(Set.of("2"), Set.copyOf(changed.removed));
			assertSame(avail2.get("1"), Unique.assertOne(changed.added.values()));

			Map<ID<TargetObject>, String> actualInv = invL.invocations.stream()
					.collect(Collectors.toMap(ii -> ID.of(ii.object), ii -> ii.reason));
			Map<ID<TargetObject>, String> expectedInv =
				Map.ofEntries(Map.entry(ID.of(avail1.get("1")), "Replaced"),
					Map.entry(ID.of(avail1.get("2")), "Changed"));
			assertEquals(expectedInv, actualInv);
		}
	}

	@Test
	public void testReplaceAttribute() throws Throwable {
		AttributesChangedListener attrL = new AttributesChangedListener();

		try (AsynchronousSocketChannel socket = socketChannel();
				ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			TargetObject echoAvail =
				waitOn(client.fetchModelObject(PathUtils.parse("Available[1]")));
			echoAvail.addListener(attrL);
			assertEquals(Map.ofEntries(Map.entry("pid", 1), Map.entry("cmd", "echo"),
				Map.entry("_display", "[1]")), waitOn(echoAvail.fetchAttributes()));

			TestGadpTargetAvailable ssEchoAvail =
				runner.server.model.session.available.getCachedElements().get("1");

			ssEchoAvail.changeAttributes(List.of("pid"),
				Map.ofEntries(Map.entry("cmd", "echo"), Map.entry("args", "Hello, World!")),
				"Changed");

			waitOn(attrL.count.waitValue(1));

			assertEquals(Map.ofEntries(Map.entry("cmd", "echo"), Map.entry("args", "Hello, World!"),
				Map.entry("_display", "[1]")), echoAvail.getCachedAttributes());

			AttributesChangedInvocation changed = Unique.assertOne(attrL.invocations);
			assertSame(echoAvail, changed.parent);
			assertEquals(Set.of("pid"), Set.copyOf(changed.removed));
			assertEquals(Map.ofEntries(Map.entry("args", "Hello, World!")), changed.added);
		}
	}

	@Test
	public void testSubtreeInvalidationDeduped() throws Throwable {
		InvalidatedListener invL = new InvalidatedListener();

		try (AsynchronousSocketChannel socket = socketChannel();
				ServerRunner runner = new ServerRunner()) {
			MonitoredGadpClient client = new MonitoredGadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			populateAvailableAndSync(client, runner);

			client.addModelListener(invL);
			client.getMessageChannel().clear();
			runner.server.model.session.changeAttributes(List.of("Available"), Map.of(), "Clear");

			/**
			 * Yes, should see all invalidations for the user side, but only one message should be
			 * sent, for the root of the invalidated sub tree
			 */
			waitOn(invL.count.waitValue(4)); // NB: Available + {[1],[2],.greet}
			// NB. Expect single invalidation message, followed by invalidation message
			waitOn(client.getMessageChannel().count.waitUntil(v -> v >= 1));

			assertEquals(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(Gadp.Path.newBuilder().addAllE(List.of("Available")))
							.setObjectInvalidateEvent(
								Gadp.ObjectInvalidateEvent.newBuilder().setReason("Clear")))
					.build(),
				client.getMessageChannel().record.get(0).assertReceived());
		}
	}

	protected void populateAvailableAndSync(DebuggerObjectModel client, ServerRunner runner)
			throws Throwable {
		// Cause these to exist
		client.fetchModelValue(PathUtils.parse("Available[1]"));
		client.fetchModelValue(PathUtils.parse("Available[2]"));
		Map<String, String> initEntries = Map.ofEntries(Map.entry("args", "Init"));
		var syncL = new DebuggerModelListener() {
			CompletableFuture<?> here = new CompletableFuture<>();
			CompletableFuture<?> init = new CompletableFuture<>();

			@Override
			public void attributesChanged(TargetObject object, Collection<String> removed,
					Map<String, ?> added) {
				if ("Available[1]".equals(object.getJoinedPath("."))) {
					if (added.entrySet().containsAll(initEntries.entrySet())) {
						init.complete(null);
					}
				}
			}

			@Override
			public void elementsChanged(TargetObject object, Collection<String> removed,
					Map<String, ? extends TargetObject> added) {
				for (TargetObject obj : added.values()) {
					if ("Available[1]".equals(obj.getJoinedPath("."))) {
						here.complete(null);
					}
				}
			}
		};
		client.addModelListener(syncL, true);

		waitOn(syncL.here);
		TestGadpTargetAvailable ssAvail1 =
			runner.server.model.session.available.getCachedElements().get("1");
		ssAvail1.changeAttributes(List.of(), initEntries, "Changed");
		waitOn(syncL.init);

		client.removeModelListener(syncL);
	}

	@Test
	public void testNoEventsAfterInvalidated() throws Throwable {
		AttributesChangedListener attrL = new AttributesChangedListener();

		try (AsynchronousSocketChannel socket = socketChannel();
				ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			client.addModelListener(attrL);

			populateAvailableAndSync(client, runner);
			// NB: copy
			Map<String, TestGadpTargetAvailable> ssAvail =
				runner.server.model.session.available.getCachedElements();
			TestGadpTargetAvailable ssAvail1 = ssAvail.get("1");
			TestGadpTargetAvailable ssAvail2 = ssAvail.get("2");

			// Now, begin the actual test
			var invL = new DebuggerModelListener() {
				CompletableFuture<?> gone = new CompletableFuture<>();

				@Override
				public void invalidated(TargetObject object, TargetObject branch, String reason) {
					if ("Available[1]".equals(object.getJoinedPath("."))) {
						gone.complete(null);
					}
				}
			};
			client.addModelListener(invL, true);
			runner.server.model.session.available.changeElements(List.of("1"), List.of(), Map.of(),
				"1 is Gone");
			waitOn(invL.gone);
			attrL.clear();

			// Should produce nothing
			ssAvail1.changeAttributes(List.of(),
				Map.ofEntries(Map.entry("args", "Hello, World!")), "Changed");
			// Produce something, so we know we didn't get the other thing
			Map<String, String> expectedEntries = Map.ofEntries(Map.entry("args", "if=/dev/null"));
			ssAvail2.changeAttributes(List.of(), List.of(), expectedEntries, "Observe");

			waitOn(attrL.count.waitValue(1));

			AttributesChangedInvocation changed = Unique.assertOne(attrL.invocations);
			assertEquals("Available[2]", changed.parent.getJoinedPath("."));
			assertEquals(Set.of(), Set.copyOf(changed.removed));
			assertEquals(expectedEntries, changed.added);
		}
	}

	@Test
	public void testProxyWithLinkedElements() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObjectAddedWaiter waiter = new TargetObjectAddedWaiter(client);
			runner.server.model.session.addLinks();
			TargetObject canonical =
				(TargetObject) waitOn(waiter.wait(PathUtils.parse("Available[2]")));
			TargetObject link = (TargetObject) waitOn(waiter.wait(PathUtils.parse("Links[1]")));
			assertSame(canonical, link);
			assertEquals(PathUtils.parse("Available[2]"), link.getPath());
			waitOn(client.close());
			waiter.close();
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testFetchModelValueFollowsLink() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObjectAddedWaiter waiter = new TargetObjectAddedWaiter(client);
			runner.server.model.session.addLinks();
			waitOn(waiter.wait(PathUtils.parse("Links[2]")));
			assertEquals("echo", waitOn(client.fetchModelValue(PathUtils.parse("Links[2].cmd"))));
			waitOn(client.close());
			waiter.close();
		}
		finally {
			socket.close();
		}
	}

	public static class EventListener implements DebuggerModelListener {
		public static class CallEntry {
			public final String methodName;
			public final List<Object> args;

			public CallEntry(String methodName, List<Object> args) {
				this.methodName = methodName;
				this.args = args;
			}

			@Override
			public String toString() {
				return String.format("<CallEntry %s(%s)>", methodName, args);
			}

			@Override
			public int hashCode() {
				return Objects.hash(methodName, args);
			}

			@Override
			public boolean equals(Object obj) {
				if (this == obj) {
					return true;
				}
				if (!(obj instanceof CallEntry)) {
					return false;
				}
				CallEntry that = (CallEntry) obj;
				if (!Objects.equals(this.methodName, that.methodName)) {
					return false;
				}
				if (!Objects.equals(this.args, that.args)) {
					return false;
				}
				return true;
			}
		}

		public final List<CallEntry> record = new ArrayList<>();

		@Override
		public void created(TargetObject object) {
			record.add(new CallEntry("created", List.of(object)));
		}

		@Override
		public void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			record.add(new CallEntry("attributesChanged", List.of(parent, removed, added)));
		}

		@Override
		public void elementsChanged(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObject> added) {
			record.add(new CallEntry("elementsChanged", List.of(parent, removed, added)));
		}

		@Override
		public void rootAdded(TargetObject root) {
			record.add(new CallEntry("rootAdded", List.of(root)));
		}
	}

	@Test
	public void testConnectBeforeRootCreated() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner() {
			@Override
			protected TestGadpServer createServer(SocketAddress addr) throws IOException {
				return new TestGadpServer(new TestGadpObjectModel(false), addr);
			}
		}) {
			GadpClient client = new PrintingGadpClient("Test", socket);
			EventListener listener = new EventListener();
			client.addModelListener(listener, true);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			DefaultTargetObject<?, ?> root =
				new DefaultTargetModelRoot(runner.server.model, "Root");
			DefaultTargetObject<?, ?> a =
				new DefaultTargetObject<>(runner.server.model, root, "a", "A");
			a.changeAttributes(List.of(), Map.of("test", 6), "Because");
			root.changeAttributes(List.of(), List.of(a), Map.of(), "Because");
			runner.server.model.addModelRoot(root);
			waitOn(client.fetchModelRoot());
			waitOn(client.flushEvents());

			assertEquals(List.of(new CallEntry("created", List.of(client.getModelRoot())),
				new CallEntry("attributesChanged",
					List.of(client.getModelRoot(), Set.of(),
						Map.ofEntries(Map.entry("_display", "<root>")))),
				new CallEntry("created", List.of(client.getModelObject(PathUtils.parse("a")))),
				new CallEntry("attributesChanged",
					List.of(client.getModelObject(PathUtils.parse("a")), Set.of(),
						Map.ofEntries(Map.entry("_display", "a")))),
				new CallEntry("attributesChanged",
					List.of(client.getModelObject(PathUtils.parse("a")), Set.of(),
						Map.ofEntries(Map.entry("test", 6)))),
				new CallEntry("attributesChanged",
					List.of(client.getModelRoot(), Set.of(),
						Map.ofEntries(
							Map.entry("a", client.getModelObject(PathUtils.parse("a")))))),
				new CallEntry("rootAdded", List.of(client.getModelRoot()))), listener.record);
		}
	}

	@Test
	public void testConnectBetweenRootCreatedAndAdded() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner() {
			@Override
			protected TestGadpServer createServer(SocketAddress addr) throws IOException {
				return new TestGadpServer(new TestGadpObjectModel(false), addr);
			}
		}) {
			GadpClient client = new PrintingGadpClient("Test", socket);
			EventListener listener = new EventListener();
			client.addModelListener(listener, true);

			DefaultTargetObject<?, ?> root =
				new DefaultTargetModelRoot(runner.server.model, "Root");
			DefaultTargetObject<?, ?> a =
				new DefaultTargetObject<>(runner.server.model, root, "a", "A");
			a.changeAttributes(List.of(), Map.of("test", 6), "Because");

			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			root.changeAttributes(List.of(), List.of(a), Map.of(), "Because");
			runner.server.model.addModelRoot(root);
			waitOn(client.fetchModelRoot());
			waitOn(client.flushEvents());

			assertEquals(List.of(new CallEntry("created", List.of(client.getModelRoot())),
				new CallEntry("attributesChanged",
					List.of(client.getModelRoot(), Set.of(),
						Map.ofEntries(Map.entry("_display", "<root>")))),
				new CallEntry("created", List.of(client.getModelObject(PathUtils.parse("a")))),
				new CallEntry("attributesChanged",
					List.of(client.getModelObject(PathUtils.parse("a")), Set.of(),
						Map.ofEntries(Map.entry("_display", "a")))),
				new CallEntry("attributesChanged",
					List.of(client.getModelObject(PathUtils.parse("a")), Set.of(),
						Map.ofEntries(Map.entry("test", 6)))),
				new CallEntry("attributesChanged",
					List.of(client.getModelRoot(), Set.of(),
						Map.ofEntries(
							Map.entry("a", client.getModelObject(PathUtils.parse("a")))))),
				new CallEntry("rootAdded", List.of(client.getModelRoot()))), listener.record);
		}
	}

	@Test
	public void testConnectAfterRootAdded() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner() {
			@Override
			protected TestGadpServer createServer(SocketAddress addr) throws IOException {
				return new TestGadpServer(new TestGadpObjectModel(false), addr);
			}
		}) {

			GadpClient client = new PrintingGadpClient("Test", socket);
			EventListener listener = new EventListener();
			client.addModelListener(listener, true);

			DefaultTargetObject<?, ?> root =
				new DefaultTargetModelRoot(runner.server.model, "Root");
			DefaultTargetObject<?, ?> a =
				new DefaultTargetObject<>(runner.server.model, root, "a", "A");
			a.changeAttributes(List.of(), Map.of("test", 6), "Because");
			root.changeAttributes(List.of(), List.of(a), Map.of(), "Because");
			runner.server.model.addModelRoot(root);
			waitOn(runner.server.model.flushEvents());

			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			waitOn(client.fetchModelRoot());
			waitOn(client.flushEvents());

			assertEquals(List.of(new CallEntry("created", List.of(client.getModelRoot())),
				new CallEntry("attributesChanged", List.of( // Defaults upon client-side construction
					client.getModelRoot(), Set.of(),
					Map.ofEntries(Map.entry("_display", "<root>")))),
				new CallEntry("created", List.of(client.getModelObject(PathUtils.parse("a")))),
				new CallEntry("attributesChanged", List.of( // Defaults
					client.getModelObject(PathUtils.parse("a")), Set.of(),
					Map.ofEntries(Map.entry("_display", "a")))),
				new CallEntry("attributesChanged",
					List.of(client.getModelObject(PathUtils.parse("a")), Set.of(),
						Map.ofEntries(Map.entry("test", 6)))),
				new CallEntry("attributesChanged",
					List.of(client.getModelRoot(), Set.of(),
						Map.ofEntries(
							Map.entry("a", client.getModelObject(PathUtils.parse("a")))))),
				new CallEntry("rootAdded", List.of(client.getModelRoot()))), listener.record);
		}
	}

	@Test
	public void testWriteConfigurationOption() throws Throwable {
		AsynchronousSocketChannel socket = socketChannel();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new PrintingGadpClient("Test", socket);

			try (TargetObjectAddedWaiter waiter = new TargetObjectAddedWaiter(client)) {
				waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
					runner.server.getLocalAddress()));
				waitOn(client.connect());

				TargetObject procs =
					(TargetObject) waitOn(waiter.wait(PathUtils.parse("Processes")));
				waitOn(((TargetConfigurable) procs).writeConfigurationOption(
					TestGadpTargetProcessContainer.BASE_ATTRIBUTE_NAME, 8));
				waitOn(((TargetLauncher) procs).launch(Map.ofEntries(Map.entry("pid", 1000L))));

				TargetProcess p1000 =
					(TargetProcess) waitOn(waiter.wait(PathUtils.parse("Processes[1000]")));

				assertEquals("1750", p1000.getDisplay());

				waitOn(((TargetConfigurable) procs).writeConfigurationOption(
					TestGadpTargetProcessContainer.BASE_ATTRIBUTE_NAME, 10));

				// NB. attribute change should arrive before completion of write
				assertEquals("1000", p1000.getDisplay());
			}
		}
	}
}
