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

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.Ignore;
import org.junit.Test;

import com.google.protobuf.GeneratedMessageV3;

import generic.ID;
import generic.Unique;
import ghidra.async.*;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.agent.*;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.attributes.TargetStringList;
import ghidra.dbg.gadp.client.GadpClient;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.server.AbstractGadpServer;
import ghidra.dbg.gadp.util.AsyncProtobufMessageChannel;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetFocusScope.TargetFocusScopeListener;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetObject.TargetObjectFetchingListener;
import ghidra.dbg.target.TargetObject.TargetObjectListener;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.*;
import ghidra.dbg.util.AttributesChangedListener.AttributesChangedInvocation;
import ghidra.dbg.util.ElementsChangedListener.ElementsChangedInvocation;
import ghidra.program.model.address.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class GadpClientServerTest {
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

	protected static <T> T waitOn(CompletableFuture<T> future) throws Throwable {
		try {
			return future.get(TIMEOUT_MILLISECONDS, TimeUnit.MILLISECONDS);
		}
		catch (Exception e) {
			throw AsyncUtils.unwrapThrowable(e);
		}
	}

	@TargetObjectSchemaInfo(name = "Session")
	public class TestGadpTargetSession extends DefaultTargetModelRoot
			implements TargetFocusScope<TestGadpTargetSession> {
		protected final TestGadpTargetAvailableContainer available =
			new TestGadpTargetAvailableContainer(this);
		protected final TestGadpTargetProcessContainer processes =
			new TestGadpTargetProcessContainer(this);
		protected final TestGadpTargetAvailableLinkContainer links =
			new TestGadpTargetAvailableLinkContainer(this);

		public TestGadpTargetSession(FakeDebuggerObjectModel model) {
			super(model, "Session");

			changeAttributes(List.of(), List.of(available, processes), Map.of(), "Initialized");
		}

		@TargetAttributeType(name = "Available", required = true, fixed = true)
		public TestGadpTargetAvailableContainer getAvailable() {
			return available;
		}

		@TargetAttributeType(name = "Processes", required = true, fixed = true)
		public TestGadpTargetProcessContainer getProcesses() {
			return processes;
		}

		public void addLinks() {
			assertNotNull(available.fetchElements().getNow(null));
			links.setElements(List.of(), Map.of(
				"1", available.getCachedElements().get("2"),
				"2", available.getCachedElements().get("1")),
				"Initialized");
			changeAttributes(List.of(), List.of(links), Map.of(), "Adding links");
		}

		public void setFocus(TestGadpTargetProcess process) {
			changeAttributes(List.of(), List.of(), Map.of(
				FOCUS_ATTRIBUTE_NAME, process),
				"New Process");
			listeners.fire(TargetFocusScopeListener.class).focusChanged(this, process);
		}

		@Override
		public CompletableFuture<Void> requestFocus(TargetObjectRef obj) {
			throw new UnsupportedOperationException();
		}
	}

	public class TestTargetObject<E extends TargetObject, P extends TargetObject>
			extends DefaultTargetObject<E, P> {

		public TestTargetObject(DebuggerObjectModel model, P parent, String key, String typeHint) {
			super(model, parent, key, typeHint);
		}

		@Override
		public CompletableFuture<?> fetchAttribute(String name) {
			if (!PathUtils.isInvocation(name)) {
				return super.fetchAttribute(name);
			}
			Map.Entry<String, String> invocation = PathUtils.parseInvocation(name);
			TestTargetMethod method =
				getTypedAttributeNowByName(invocation.getKey(), TestTargetMethod.class, null);
			if (method == null) {
				return AsyncUtils.nil();
			}
			Object ret = method.testInvoke(invocation.getValue());
			changeAttributes(List.of(), Map.of(name, ret), "Invoked " + name);
			return CompletableFuture.completedFuture(ret);
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

	private static final TargetParameterMap PARAMS = TargetParameterMap.copyOf(Map.of(
		"whom", ParameterDescription.create(String.class, "whom", true, "World",
			"Whom to greet", "The person or people to greet"),
		"others", ParameterDescription.create(TargetStringList.class, "others",
			false, TargetStringList.of(), "Others to greet",
			"List of other people to greet individually")));

	public class TestTargetMethod extends TestTargetObject<TargetObject, TargetObject>
			implements TargetMethod<TestTargetMethod> {
		private Function<String, ?> method;

		public TestTargetMethod(TargetObject parent, String key,
				Function<String, ?> method) {
			super(parent.getModel(), parent, key, "Method");
			this.method = method;

			setAttributes(Map.of(
				PARAMETERS_ATTRIBUTE_NAME, PARAMS,
				RETURN_TYPE_ATTRIBUTE_NAME, Integer.class),
				"Initialized");
		}

		public Object testInvoke(String paramsExpr) {
			return method.apply(paramsExpr);
		}

		@Override
		public CompletableFuture<Object> invoke(Map<String, ?> arguments) {
			TestMethodInvocation invocation = new TestMethodInvocation(arguments);
			invocations.offer(invocation);
			invocationCount.set(invocations.size(), null);
			return invocation;
		}
	}

	public class TestGadpTargetProcessContainer
			extends TestTargetObject<TestGadpTargetProcess, TestGadpTargetSession>
			implements TargetLauncher<TestGadpTargetProcessContainer> {
		public TestGadpTargetProcessContainer(TestGadpTargetSession session) {
			super(session.getModel(), session, "Processes", "ProcessContainer");
		}

		@Override
		public CompletableFuture<Void> launch(Map<String, ?> args) {
			launches.offer(args);
			TestGadpTargetProcess process = new TestGadpTargetProcess(this, 0);
			changeElements(List.of(), List.of(process), Map.of(), "Launched");
			parent.setFocus(process);
			return AsyncUtils.NIL;
		}
	}

	public class TestGadpTargetProcess
			extends TestTargetObject<TargetObject, TestGadpTargetProcessContainer> {
		public TestGadpTargetProcess(TestGadpTargetProcessContainer processes, int index) {
			super(processes.getModel(), processes,
				PathUtils.makeKey(PathUtils.makeIndex(index)),
				"Process");
		}
	}

	public class TestGadpTargetAvailableContainer
			extends TestTargetObject<TestGadpTargetAvailable, TestGadpTargetSession> {
		public char punct = '!';

		public TestGadpTargetAvailableContainer(TestGadpTargetSession session) {
			super(session.getModel(), session, "Available", "AvailableContainer");

			setAttributes(List.of(
				new TestTargetMethod(this, "greet", p -> "Hello, " + p + punct)),
				Map.of(), "Initialized");
		}

		@Override
		public CompletableFuture<Void> requestElements(
				boolean refresh) {
			setElements(List.of(
				new TestGadpTargetAvailable(this, 1, "echo"),
				new TestGadpTargetAvailable(this, 2, "dd")),
				Map.of(), "Refreshed");
			return super.requestElements(refresh);
		}
	}

	public class TestGadpTargetAvailable
			extends TestTargetObject<TargetObject, TestGadpTargetAvailableContainer>
			implements TargetAttachable<TestGadpTargetAvailable> {

		public TestGadpTargetAvailable(TestGadpTargetAvailableContainer available, int pid,
				String cmd) {
			super(available.getModel(), available, PathUtils.makeKey(PathUtils.makeIndex(pid)),
				"Available");
			setAttributes(List.of(), Map.of(
				"pid", pid,
				"cmd", cmd //
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

	// TODO: Refactor with other Fake and Test. Probably put in Framework-Debugging....
	public class FakeDebuggerObjectModel extends AbstractDebuggerObjectModel {
		private final TestGadpTargetSession session = new TestGadpTargetSession(this);

		private final AddressSpace ram =
			new GenericAddressSpace("RAM", 64, AddressSpace.TYPE_RAM, 0);
		private final AddressFactory factory =
			new DefaultAddressFactory(new AddressSpace[] { ram });

		@Override
		public CompletableFuture<? extends TargetObject> fetchModelRoot() {
			return CompletableFuture.completedFuture(session);
		}

		@Override
		public AddressFactory getAddressFactory() {
			return factory;
		}

		@Override
		public CompletableFuture<Void> close() {
			return AsyncUtils.NIL;
		}
	}

	public class TestGadpServer extends AbstractGadpServer {
		@SuppressWarnings("hiding")
		final FakeDebuggerObjectModel model;

		public TestGadpServer(SocketAddress addr) throws IOException {
			super(new FakeDebuggerObjectModel(), addr);
			this.model = (FakeDebuggerObjectModel) getModel();
		}
	}

	public class ServerRunner implements AutoCloseable {
		TestGadpServer server;

		public ServerRunner() throws IOException {
			server = new TestGadpServer(new InetSocketAddress("localhost", 0));
			server.launchAsyncService();
		}

		@Override
		public void close() throws Exception {
			server.terminate();
		}
	}

	class TestMethodInvocation extends CompletableFuture<Object> {
		final Map<String, ?> args;

		public TestMethodInvocation(Map<String, ?> args) {
			this.args = args;
		}
	}

	protected Deque<Map<String, ?>> launches = new LinkedList<>();
	protected AsyncReference<Integer, Void> invocationCount = new AsyncReference<>();
	protected Deque<TestMethodInvocation> invocations = new LinkedList<>();

	@Test
	public void testConnectDisconnect() throws Throwable {
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
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
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
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
	public void testFetchModelValueCached() throws Throwable {
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
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
				waitOn(client.fetchObjectElements(PathUtils.parse("Available"))
						.thenCompose(DebugModelConventions::fetchAll));
			assertEquals(2, available.size());
			monitored.reset();
			Object cmd = waitOn(client.fetchModelValue(PathUtils.parse("Available[1].cmd")));
			assertEquals("echo", cmd);
			assertEquals(0, monitored.writeCount);
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testInvoke() throws Throwable {
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject procCont =
				waitOn(client.fetchModelObject(PathUtils.parse("Available.greet")));
			assertTrue(procCont.getInterfaceNames().contains("Method"));
			TargetMethod<?> method = procCont.as(TargetMethod.tclass);

			assertEquals(PARAMS, method.getParameters());
			assertEquals(Integer.class, method.getReturnType());

			CompletableFuture<Object> future = method.invoke(Map.of(
				"whom", "GADP",
				"others", TargetStringList.of("Alice", "Bob")));
			waitOn(invocationCount.waitValue(1));
			TestMethodInvocation invocation = invocations.poll();
			assertEquals(Map.of(
				"whom", "GADP",
				"others", TargetStringList.of("Alice", "Bob")),
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
		try (AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
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
			TargetObjectRef methodRef = (TargetObjectRef) attrs.get("greet");
			TargetMethod<?> method = waitOn(methodRef.as(TargetMethod.tclass).fetch());
			assertNotNull(method);
			assertEquals("Hello, World!", waitOn(avail.fetchAttribute("greet(World)")));
			runner.server.model.session.available.punct = '?';
			assertEquals("Hello, World!", waitOn(avail.fetchAttribute("greet(World)")));

			// Flush the cache
			waitOn(avail.fetchAttributes(true));
			assertEquals("Hello, World?", waitOn(avail.fetchAttribute("greet(World)")));

			waitOn(client.close());
		}
	}

	@Test
	public void testListRoot() throws Throwable {
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			Map<String, ? extends TargetObjectRef> elements =
				waitOn(client.fetchObjectElements(List.of()));
			assertEquals(0, elements.size());
			Map<String, ?> attributes = waitOn(client.fetchObjectAttributes(List.of()));
			assertEquals(Set.of(
				"Processes", "Available",
				TargetObject.DISPLAY_ATTRIBUTE_NAME,
				TargetObject.UPDATE_MODE_ATTRIBUTE_NAME),
				attributes.keySet());
			Object procContAttr = attributes.get("Processes");
			TargetObjectRef procContRef = (TargetObjectRef) procContAttr;
			assertEquals(List.of("Processes"), procContRef.getPath());
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testLaunch() throws Throwable {
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject procCont = waitOn(client.fetchModelObject(List.of("Processes")));
			assertTrue(procCont.getInterfaceNames().contains("Launcher"));
			TargetLauncher<?> launcher = procCont.as(TargetLauncher.tclass);
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
		TargetObjectListener listener = new TargetObjectFetchingListener() {
			@Override
			public void elementsChangedObjects(TargetObject parent, Collection<String> removed,
					Map<String, ? extends TargetObject> added) {
				invocations.add(new ElementsChangedInvocation(parent, removed, added));
			}
		};
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject avail = waitOn(client.fetchModelObject(List.of("Available")));
			avail.addListener(listener);
			Map<String, ? extends TargetObjectRef> elements = waitOn(avail.fetchElements());
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
		TargetFocusScopeListener focusListener = new TargetFocusScopeListener() {
			@Override
			public void focusChanged(TargetFocusScope<?> object, TargetObjectRef focused) {
				Msg.info(this, "Focus changed to " + focused);
				if (!focusPath.complete(focused.getPath())) {
					failed.set(true);
				}
			}
		};
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject session = waitOn(client.fetchModelObject(List.of()));
			session.addListener(focusListener);
			TargetObject procCont = waitOn(client.fetchModelObject(List.of("Processes")));
			assertTrue(procCont.getInterfaceNames().contains("Launcher"));
			TargetLauncher<?> launcher = procCont.as(TargetLauncher.tclass);
			waitOn(launcher.launch(
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "/bin/echo Hello, World!")));
			launches.clear(); // Don't care. Just free it up.
			Map<String, ?> attrs = waitOn(client.fetchObjectAttributes(List.of()));
			assertTrue(attrs.containsKey(TargetFocusScope.FOCUS_ATTRIBUTE_NAME));
			TargetObjectRef ref =
				(TargetObjectRef) attrs.get(TargetFocusScope.FOCUS_ATTRIBUTE_NAME);
			// NOTE: Could be actual object, but need not be
			assertEquals(List.of("Processes", "[0]"), ref.getPath());
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
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
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

		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);

			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			TargetObject procContainer = waitOn(client.fetchModelObject(List.of("Processes")));
			assertTrue(procContainer.getInterfaceNames().contains("Launcher"));
			procContainer.addListener(elemL);
			TargetLauncher<?> launcher = procContainer.as(TargetLauncher.tclass);
			waitOn(launcher.launch(
				Map.of(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, "/bin/echo Hello, World!")));
			waitOn(elemL.count.waitValue(1));

			waitOn(client.close());

			assertEquals(1, elemL.invocations.size());
			ElementsChangedInvocation eci = elemL.invocations.get(0);
			assertEquals(procContainer, eci.parent);
			assertEquals(List.of(), List.copyOf(eci.removed));
			assertEquals(1, eci.added.size());
			Entry<String, ? extends TargetObjectRef> ent =
				eci.added.entrySet().iterator().next();
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

		try (AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
				ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			TargetObject availCont =
				waitOn(client.fetchModelObject(PathUtils.parse("Available")));
			availCont.addListener(elemL);
			Map<String, ? extends TargetObject> avail1 = waitOn(availCont.fetchElements()
					.thenCompose(DebugModelConventions::fetchAll));
			assertEquals(2, avail1.size());
			for (TargetObject a : avail1.values()) {
				assertTrue(a.isValid());
				a.addListener(invL);
			}

			elemL.clear();
			TestGadpTargetAvailableContainer ssAvail = runner.server.model.session.available;
			ssAvail.setElements(List.of(
				new TestGadpTargetAvailable(ssAvail, 1, "cat") //
			), "Changed");

			waitOn(invL.count.waitValue(2));
			waitOn(elemL.count.waitValue(1));

			for (TargetObject a : avail1.values()) {
				assertFalse(a.isValid());
			}

			assertEquals(1, availCont.getCachedElements().size());
			Map<String, ? extends TargetObject> avail2 = waitOn(availCont.fetchElements()
					.thenCompose(DebugModelConventions::fetchAll));
			assertEquals(1, avail2.size());
			assertEquals("cat", avail2.get("1").getCachedAttribute("cmd"));

			ElementsChangedInvocation changed = Unique.assertOne(elemL.invocations);
			assertSame(availCont, changed.parent);
			// Use equals here, since the listener only gets the ref
			assertEquals(avail2.get("1"), Unique.assertOne(changed.added.values()));

			Map<ID<TargetObject>, String> actualInv = invL.invocations.stream()
					.collect(Collectors.toMap(ii -> ID.of(ii.object), ii -> ii.reason));
			Map<ID<TargetObject>, String> expectedInv =
				avail1.values()
						.stream()
						.collect(Collectors.toMap(o -> ID.of(o), o -> "Changed"));
			assertEquals(expectedInv, actualInv);
		}
	}

	@Test
	public void testReplaceAttribute() throws Throwable {
		AttributesChangedListener attrL = new AttributesChangedListener();

		try (AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
				ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			TargetObject echoAvail =
				waitOn(client.fetchModelObject(PathUtils.parse("Available[1]")));
			echoAvail.addListener(attrL);
			assertEquals(Map.of(
				"pid", 1,
				"cmd", "echo" //
			), waitOn(echoAvail.fetchAttributes()));

			TestGadpTargetAvailable ssEchoAvail =
				runner.server.model.session.available.getCachedElements().get("1");

			ssEchoAvail.setAttributes(Map.of(
				"cmd", "echo",
				"args", "Hello, World!" //
			), "Changed");

			waitOn(attrL.count.waitValue(1));

			assertEquals(Map.of(
				"cmd", "echo",
				"args", "Hello, World!" //
			), echoAvail.getCachedAttributes());

			AttributesChangedInvocation changed = Unique.assertOne(attrL.invocations);
			assertSame(echoAvail, changed.parent);
			assertEquals(Set.of("pid"), Set.copyOf(changed.removed));
			assertEquals(Map.of(
				"args", "Hello, World!" //
			), changed.added);
		}
	}

	@Test
	public void testSubtreeInvalidationDeduped() throws Throwable {
		InvalidatedListener invL = new InvalidatedListener();

		try (AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
				ServerRunner runner = new ServerRunner()) {
			MonitoredGadpClient client = new MonitoredGadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			TargetObject availCont =
				waitOn(client.fetchModelObject(PathUtils.parse("Available")));
			availCont.addListener(invL);
			for (TargetObject avail : waitOn(availCont.fetchElements()
					.thenCompose(DebugModelConventions::fetchAll)).values()) {
				avail.addListener(invL);
			}

			client.getMessageChannel().clear();
			runner.server.model.session.changeAttributes(List.of("Available"), Map.of(), "Clear");

			/**
			 * Yes, should see all invalidations for the user side, but only one message should be
			 * sent, for the root of the invalidated sub tree
			 */
			waitOn(invL.count.waitValue(3));
			// NB. will not see attribute change, since not subscribed to root
			waitOn(client.getMessageChannel().count.waitUntil(v -> v >= 1));

			assertEquals(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(Gadp.Path.newBuilder()
									.addAllE(List.of("Available")))
							.setObjectInvalidateEvent(Gadp.ObjectInvalidateEvent.newBuilder()
									.setReason("Clear")))
					.build(),
				client.getMessageChannel().record.get(0).assertReceived());
		}
	}

	@Test
	public void testNoEventsAfterInvalidated() throws Throwable {
		AttributesChangedListener attrL = new AttributesChangedListener();

		try (AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
				ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());

			TargetObject echoAvail =
				waitOn(client.fetchModelObject(PathUtils.parse("Available[1]")));
			echoAvail.addListener(attrL);
			assertEquals(Map.of(
				"pid", 1,
				"cmd", "echo" //
			), waitOn(echoAvail.fetchAttributes()));

			TargetObject ddAvail = waitOn(client.fetchModelObject(PathUtils.parse("Available[2]")));
			ddAvail.addListener(attrL);
			assertEquals(Map.of(
				"pid", 2,
				"cmd", "dd" //
			), waitOn(ddAvail.fetchAttributes()));

			// NB: copy
			Map<String, TestGadpTargetAvailable> ssAvail =
				runner.server.model.session.available.getCachedElements();

			runner.server.model.session.available.changeElements(List.of("1"), List.of(), Map.of(),
				"1 is Gone");
			// Should produce nothing
			(ssAvail.get("1")).setAttributes(List.of(), Map.of(
				"cmd", "echo",
				"args", "Hello, World!"),
				"Changed");
			// Produce something, so we know we didn't get the other thing
			(ssAvail.get("2")).changeAttributes(List.of(), List.of(), Map.of(
				"args", "if=/dev/null"),
				"Observe");

			waitOn(attrL.count.waitValue(1));

			AttributesChangedInvocation changed = Unique.assertOne(attrL.invocations);
			assertSame(ddAvail, changed.parent);
			assertEquals(Set.of(), Set.copyOf(changed.removed));
			assertEquals(Map.of(
				"args", "if=/dev/null" //
			), changed.added);
		}
	}

	@Test
	public void testProxyWithLinkedElementsCanonicalFirst() throws Throwable {
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			runner.server.model.session.addLinks();
			TargetObject canonical =
				waitOn(client.fetchModelObject(PathUtils.parse("Available[2]")));
			TargetObject link =
				waitOn(client.fetchModelObject(PathUtils.parse("Links[1]")));
			assertSame(canonical, link);
			assertEquals(PathUtils.parse("Available[2]"), link.getPath());
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testProxyWithLinkedElementsLinkFirst() throws Throwable {
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			runner.server.model.session.addLinks();
			TargetObjectRef linkRef =
				(TargetObjectRef) waitOn(client.fetchModelValue(PathUtils.parse("Links[1]")));
			assertFalse(linkRef instanceof TargetObject);
			TargetObject link =
				waitOn(client.fetchModelObject(PathUtils.parse("Links[1]")));
			TargetObject canonical =
				waitOn(client.fetchModelObject(PathUtils.parse("Available[2]")));
			assertSame(canonical, link);
			assertEquals(PathUtils.parse("Available[2]"), link.getPath());
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	public void testFetchModelValueFollowsLink() throws Throwable {
		AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
		try (ServerRunner runner = new ServerRunner()) {
			GadpClient client = new GadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			runner.server.model.session.addLinks();
			assertEquals("echo", waitOn(client.fetchModelValue(PathUtils.parse("Links[2].cmd"))));
			waitOn(client.close());
		}
		finally {
			socket.close();
		}
	}

	@Test
	@Ignore("TODO")
	public void testCachingWithLinks() throws Throwable {

		try (AsynchronousSocketChannel socket = AsynchronousSocketChannel.open();
				ServerRunner runner = new ServerRunner()) {
			MonitoredGadpClient client = new MonitoredGadpClient("Test", socket);
			waitOn(AsyncUtils.completable(TypeSpec.VOID, socket::connect,
				runner.server.getLocalAddress()));
			waitOn(client.connect());
			runner.server.model.session.addLinks();

			client.getMessageChannel().clear();
			assertEquals("echo", waitOn(client.fetchModelValue(PathUtils.parse("Links[2].cmd"))));
			assertEquals(2, client.getMessageChannel().record.size());
			assertEquals(Gadp.RootMessage.MsgCase.SUBSCRIBE_REQUEST,
				client.getMessageChannel().record.get(0).assertSent().getMsgCase());
			assertEquals(Gadp.RootMessage.MsgCase.SUBSCRIBE_REPLY,
				client.getMessageChannel().record.get(1).assertReceived().getMsgCase());

			// Since I don't have the parent, as usual, no cache
			client.getMessageChannel().clear();
			assertEquals("echo", waitOn(client.fetchModelValue(PathUtils.parse("Links[2].cmd"))));
			assertEquals(2, client.getMessageChannel().record.size());

			/**
			 * Now, fetch Links[2] first, and repeat the experiment It should still not use the
			 * cache, because we won't know if Links[2] still points to Available[1]. Technically,
			 * Available[1] is what will be cached. Index 2 of Links will not be cached until/if
			 * Links is fetched.
			 */
			client.getMessageChannel().clear();
			TargetObject avail1 = waitOn(client.fetchModelObject(PathUtils.parse("Links[2]")));
			// Odd, but I believe it's correct since the first reply comes back with a ref
			assertEquals(4, client.getMessageChannel().record.size());
			assertNotNull(avail1);
			client.getMessageChannel().clear();
			assertEquals("echo", waitOn(client.fetchModelValue(PathUtils.parse("Links[2].cmd"))));
			assertEquals(2, client.getMessageChannel().record.size());
			client.getMessageChannel().clear();
			assertEquals("echo", waitOn(client.fetchModelValue(PathUtils.parse("Links[2].cmd"))));
			assertEquals(2, client.getMessageChannel().record.size());

			// Now, fetch Links, and its elements to ensure it is cached
			TargetObject links = waitOn(client.fetchModelObject(PathUtils.parse("Links")));
			assertSame(avail1, waitOn(links.fetchElement("2")));

			client.getMessageChannel().clear();
			assertSame(avail1, waitOn(links.fetchElement("2")));
			assertEquals(2, client.getMessageChannel().record.size());
			assertEquals("Links[2]", PathUtils.toString(client.getMessageChannel().record.get(0)
					.assertSent()
					.getSubscribeRequest()
					.getPath()
					.getEList()));

			TODO();
			waitOn(client.close());
		}
	}
}
