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
package agent;

import static org.junit.Assert.*;

import java.io.*;
import java.net.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.hamcrest.Matchers;
import org.junit.*;

import db.NoTransactionException;
import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.app.services.TraceRmiService;
import ghidra.debug.api.tracermi.*;
import ghidra.framework.*;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginsConfiguration;
import ghidra.framework.plugintool.util.*;
import ghidra.pty.*;
import ghidra.pty.PtyChild.Echo;
import ghidra.pty.testutil.DummyProc;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.schema.PrimitiveTraceObjectSchema.MinimalSchemaContext;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class TraceRmiPythonClientTest extends AbstractGhidraHeadedDebuggerTest {
	public static final String PREAMBLE =
		"""
				import socket
				from typing import Annotated, Any, Optional

				from concurrent.futures import ThreadPoolExecutor
				from ghidratrace import sch
				from ghidratrace.client import (Client, Address, AddressRange, TraceObject,
				    MethodRegistry, Schedule, TraceRmiError, ParamDesc)

				registry = MethodRegistry(ThreadPoolExecutor())

				def connect(addr):
				    cs = socket.socket()
				    cs.connect(addr)
				    return Client(cs, "test-client", registry)

				""";
	protected static final int CONNECT_TIMEOUT_MS = 3000;
	protected static final int TIMEOUT_SECONDS = 10;
	protected static final int QUIT_TIMEOUT_MS = 1000;

	protected TraceRmiService traceRmi;
	private Path pathToPython;

	@BeforeClass
	public static void setupPython() throws Throwable {
		if (SystemUtilities.isInTestingBatchMode()) {
			return; // gradle should already have done it
		}
		String gradle = switch (OperatingSystem.CURRENT_OPERATING_SYSTEM) {
			case WINDOWS -> DummyProc.which("gradle.bat");
			default -> "gradle";
		};
		assertEquals(0, new ProcessBuilder(gradle, "Debugger-rmi-trace:assemblePyPackage")
				.directory(TestApplicationUtils.getInstallationDirectory())
				.inheritIO()
				.start()
				.waitFor());
	}

	protected void setPythonPath(Map<String, String> env) throws IOException {
		String sep =
			OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS ? ";" : ":";
		String rmiPyPkg = Application.getModuleSubDirectory("Debugger-rmi-trace",
			"build/pypkg/src").getAbsolutePath();
		String add = rmiPyPkg;
		env.compute("PYTHONPATH", (k, v) -> v == null ? add : (v + sep + add));
	}

	protected Path getPathToPython() {
		try {
			return Paths.get(DummyProc.which("python3"));
		}
		catch (RuntimeException e) {
			return Paths.get(DummyProc.which("python"));
		}
	}

	@Before
	public void setupTraceRmi() throws Throwable {
		traceRmi = addPlugin(tool, TraceRmiPlugin.class);

		pathToPython = getPathToPython();
	}

	protected void addAllDebuggerPlugins() throws PluginException {
		PluginsConfiguration plugConf = new PluginsConfiguration() {
			@Override
			protected boolean accepts(Class<? extends Plugin> pluginClass) {
				return !ApplicationLevelOnlyPlugin.class.isAssignableFrom(pluginClass);
			}
		};

		for (PluginDescription pd : plugConf
				.getPluginDescriptions(PluginPackage.getPluginPackage("Debugger"))) {
			addPlugin(tool, pd.getPluginClass());
		}
	}

	protected static String addrToStringForPython(InetAddress address) {
		if (address.isAnyLocalAddress()) {
			return "127.0.0.1"; // Can't connect to 0.0.0.0 as such. Choose localhost.
		}
		return address.getHostAddress();
	}

	protected static String sockToStringForPython(SocketAddress address) {
		if (address instanceof InetSocketAddress tcp) {
			return "('%s', %d)".formatted(addrToStringForPython(tcp.getAddress()), tcp.getPort());
		}
		throw new AssertionError("Unhandled address type " + address);
	}

	protected static class PyError extends RuntimeException {
		public final int exitCode;
		public final String out;

		public PyError(int exitCode, String out) {
			super("""
					exitCode=%d:
					----out----
					%s
					""".formatted(exitCode, out));
			this.exitCode = exitCode;
			this.out = out;
		}
	}

	protected record PyResult(boolean timedOut, int exitCode, String out) {
		protected String handle() {
			if (0 != exitCode || out.contains("Traceback")) {
				throw new PyError(exitCode, out);
			}
			return out;
		}
	}

	protected record ExecInPy(PtySession session, PrintWriter stdin,
			CompletableFuture<PyResult> future) {}

	@SuppressWarnings("resource") // Do not close stdin 
	protected ExecInPy execInPy(String script) throws IOException {
		Map<String, String> env = new HashMap<>(System.getenv());
		setPythonPath(env);
		Pty pty = PtyFactory.local().openpty();

		PtySession session =
			pty.getChild().session(new String[] { pathToPython.toString() }, env, Echo.ON);

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		new Thread(() -> {
			InputStream is = pty.getParent().getInputStream();
			byte[] buf = new byte[1024];
			while (true) {
				try {
					int len = is.read(buf);
					out.write(buf, 0, len);
					System.out.write(buf, 0, len);
				}
				catch (IOException e) {
					System.out.println("<EOF>");
					return;
				}
			}
		}).start();

		PrintWriter stdin = new PrintWriter(pty.getParent().getOutputStream());
		script.lines().forEach(stdin::println); // to transform newlines.
		stdin.flush();
		return new ExecInPy(session, stdin, CompletableFuture.supplyAsync(() -> {
			try {
				int exitCode = session.waitExited(TIMEOUT_SECONDS, TimeUnit.SECONDS);
				Msg.info(this, "Python exited with code " + exitCode);
				return new PyResult(false, exitCode, out.toString());
			}
			catch (TimeoutException e) {
				Msg.error(this, "Timed out waiting for GDB");
				session.destroyForcibly();
				try {
					session.waitExited(TIMEOUT_SECONDS, TimeUnit.SECONDS);
				}
				catch (InterruptedException | TimeoutException e1) {
					throw new AssertionError(e1);
				}
				return new PyResult(true, -1, out.toString());
			}
			catch (Exception e) {
				return ExceptionUtils.rethrow(e);
			}
			finally {
				session.destroyForcibly();
			}
		}));
	}

	protected String runThrowError(String script) throws Exception {
		CompletableFuture<PyResult> result = execInPy(script).future;
		return result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
	}

	protected record PyAndConnection(ExecInPy exec, TraceRmiConnection connection)
			implements AutoCloseable {

		protected RemoteMethod getMethod(String name) {
			return Objects.requireNonNull(connection.getMethods().get(name));
		}

		@Override
		public void close() throws Exception {
			Msg.info(this, "Cleaning up python");
			try {
				exec.stdin.println("exit()");
				exec.stdin.close();
				PyResult r = exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
				r.handle();
				waitForPass(() -> assertTrue(connection.isClosed()));
			}
			finally {
				exec.stdin.close();
				exec.session.destroyForcibly();
			}
		}
	}

	protected PyAndConnection startAndConnectPy(Function<String, String> scriptSupplier)
			throws Exception {
		TraceRmiAcceptor acceptor = traceRmi.acceptOne(null);
		ExecInPy exec =
			execInPy(scriptSupplier.apply(sockToStringForPython(acceptor.getAddress())));
		acceptor.setTimeout(CONNECT_TIMEOUT_MS);
		try {
			TraceRmiConnection connection = acceptor.accept();
			return new PyAndConnection(exec, connection);
		}
		catch (SocketTimeoutException e) {
			Msg.error(this, "Timed out waiting for client connection");
			exec.session.destroyForcibly();
			exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
			throw e;
		}
	}

	protected PyAndConnection startAndConnectPy() throws Exception {
		return startAndConnectPy(addr -> """
				%s
				c = connect(%s)
				""".formatted(PREAMBLE, addr));
	}

	@SuppressWarnings("resource")
	protected String runThrowError(Function<String, String> scriptSupplier)
			throws Exception {
		PyAndConnection conn = startAndConnectPy(scriptSupplier);
		PyResult r = conn.exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
		String stdout = r.handle();
		waitForPass(() -> assertTrue(conn.connection.isClosed()));
		return stdout;
	}

	protected ManagedDomainObject openDomainObject(String path) throws Exception {
		DomainFile df = env.getProject().getProjectData().getFile(path);
		assertNotNull(df);
		return new ManagedDomainObject(df, false, false, monitor);
	}

	protected ManagedDomainObject waitDomainObject(String path) throws Exception {
		DomainFile df;
		long start = System.currentTimeMillis();
		while (true) {
			df = env.getProject().getProjectData().getFile(path);
			if (df != null) {
				return new ManagedDomainObject(df, false, false, monitor);
			}
			Thread.sleep(1000);
			if (System.currentTimeMillis() - start > 30000) {
				throw new TimeoutException("30 seconds expired waiting for domain file");
			}
		}
	}

	protected void waitTxDone() {
		waitFor(() -> tb.trace.getCurrentTransactionInfo() == null);
	}

	@Test
	public void testConnect() throws Exception {
		runThrowError(addr -> """
				%s
				c = connect(%s)
				exit()
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testClose() throws Exception {
		runThrowError(addr -> """
				%s
				c = connect(%s)
				c.close()
				exit()
				""".formatted(PREAMBLE, addr));
	}

	@Test
	public void testCreateTrace() throws Exception {
		runThrowError(addr -> """
				%s
				c = connect(%s)
				trace = c.create_trace("/test", "DATA:LE:64:default", "pointer64", extra=None)
				print(trace)
				exit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject obj = openDomainObject("/New Traces/test")) {
			switch (obj.get()) {
				case Trace trace -> {
				}
				default -> fail("Wrong type");
			}
		}
	}

	@Test
	public void testMethodRegistrationAndInvocation() throws Exception {
		try (PyAndConnection pac = startAndConnectPy(addr -> """
				%s

				@registry.method()
				def py_eval(expr: str) -> str:
				    return repr(eval(expr))

				c = connect(%s)
				""".formatted(PREAMBLE, addr))) {
			RemoteMethod pyEval = pac.getMethod("py_eval");

			assertEquals(String.class,
				MinimalSchemaContext.INSTANCE.getSchema(pyEval.retType()).getType());
			assertEquals("expr", Unique.assertOne(pyEval.parameters().keySet()));
			assertEquals(String.class,
				MinimalSchemaContext.INSTANCE.getSchema(pyEval.parameters().get("expr").type())
						.getType());

			String result = (String) pyEval.invoke(Map.ofEntries(
				Map.entry("expr", "c")));
			assertThat(result, Matchers.startsWith("<ghidratrace.Client <socket.socket"));
		}
	}

	@Test
	public void testRegisterAnnotated() throws Exception {
		try (PyAndConnection pac = startAndConnectPy(addr -> """
				%s

				@registry.method()
				def py_eval(expr: Annotated[str, ParamDesc(display="Expression")]) -> Annotated[
				    Any, ParamDesc(schema=sch.STRING)]:
				    return repr(eval(expr))

				c = connect(%s)
				""".formatted(PREAMBLE, addr))) {
			RemoteMethod pyEval = pac.getMethod("py_eval");

			assertEquals(String.class,
				MinimalSchemaContext.INSTANCE.getSchema(pyEval.retType()).getType());
			assertEquals("expr", Unique.assertOne(pyEval.parameters().keySet()));

			RemoteParameter param = pyEval.parameters().get("expr");
			assertEquals(String.class,
				MinimalSchemaContext.INSTANCE.getSchema(param.type()).getType());
			assertEquals("Expression", param.display());

			String result = (String) pyEval.invoke(Map.ofEntries(
				Map.entry("expr", "c")));
			assertThat(result, Matchers.startsWith("<ghidratrace.Client <socket.socket"));
		}
	}

	@Test
	public void testRegisterOptional() throws Exception {
		try (PyAndConnection pac = startAndConnectPy(addr -> """
				%s

				@registry.method()
				def py_eval(expr: Optional[str]) -> Optional[str]:
				    return repr(eval(expr))

				c = connect(%s)
				""".formatted(PREAMBLE, addr))) {
			RemoteMethod pyEval = pac.getMethod("py_eval");

			assertEquals(String.class,
				MinimalSchemaContext.INSTANCE.getSchema(pyEval.retType()).getType());
			assertEquals("expr", Unique.assertOne(pyEval.parameters().keySet()));

			RemoteParameter param = pyEval.parameters().get("expr");
			assertEquals(String.class,
				MinimalSchemaContext.INSTANCE.getSchema(param.type()).getType());

			String result = (String) pyEval.invoke(Map.ofEntries(
				Map.entry("expr", "c")));
			assertThat(result, Matchers.startsWith("<ghidratrace.Client <socket.socket"));
		}
	}

	@Test
	public void testRegisterObject() throws Exception {
		try (PyAndConnection pac = startAndConnectPy(addr -> """
				%s

				class Session(TraceObject):
				    pass

				@registry.method()
				def py_eval(session: Session, expr: str) -> str:
				    return repr(eval(expr))

				c = connect(%s)
				""".formatted(PREAMBLE, addr))) {
			RemoteMethod pyEval = pac.getMethod("py_eval");

			assertEquals(String.class,
				MinimalSchemaContext.INSTANCE.getSchema(pyEval.retType()).getType());
			assertEquals(Set.of("session", "expr"), pyEval.parameters().keySet());

			RemoteParameter param = pyEval.parameters().get("session");
			assertEquals(new SchemaName("Session"), param.type());
		}
	}

	@Test
	public void testRegisterObjectBad() throws Exception {
		String out = runThrowError(addr -> """
				%s
				c = connect(%s)

				class Session(object):
				    pass

				def py_eval(session: Session, expr: str) -> str:
				    return repr(eval(expr))

				try:
				    registry.method()(py_eval)
				except TypeError as e:
				    print(f"---ERR:{e}---")

				exit()
				""".formatted(PREAMBLE, addr));
		assertThat(out, Matchers.containsString(
			"---ERR:Cannot get schema for <class '__main__.Session'>---"));
	}

	@Test
	public void testSnapshotDefaultNoTx() throws Exception {
		String out = runThrowError(addr -> """
				%s
				c = connect(%s)
				trace = c.create_trace("/test", "DATA:LE:64:default", "pointer64", extra=None)

				try:
				    trace.snapshot("Test")
				    raise Exception("Expected error")
				except TraceRmiError as e:
				    print(f"---ERR:{e}---")

				exit()
				""".formatted(PREAMBLE, addr));
		assertThat(out,
			Matchers.containsString("---ERR:%s".formatted(NoTransactionException.class.getName())));
	}

	@Test
	public void testSnapshotDefault() throws Exception {
		runThrowError(addr -> """
				%s
				c = connect(%s)
				trace = c.create_trace("/test", "DATA:LE:64:default", "pointer64", extra=None)

				with trace.open_tx("Create snapshot") as tx:
				    trace.snapshot("Test")

				exit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject obj = openDomainObject("/New Traces/test")) {
			Trace trace = (Trace) obj.get();
			TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(0, false);
			assertEquals("Test", snapshot.getDescription());
		}
	}

	@Test
	public void testSnapshotSnapOnly() throws Exception {
		runThrowError(addr -> """
				%s
				c = connect(%s)
				trace = c.create_trace("/test", "DATA:LE:64:default", "pointer64", extra=None)

				with trace.open_tx("Create snapshot") as tx:
				    trace.snapshot("Test", time=Schedule(10, 0))

				exit()
				""".formatted(PREAMBLE, addr));
		try (ManagedDomainObject obj = openDomainObject("/New Traces/test")) {
			Trace trace = (Trace) obj.get();
			TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(10, false);
			assertEquals("Test", snapshot.getDescription());
		}
	}

	protected Matcher matchOne(String out, Pattern pat) {
		return Unique.assertOne(out.lines().map(pat::matcher).filter(Matcher::find));
	}

	@Test
	public void testSnapshotSchedule() throws Exception {
		String out = runThrowError(addr -> """
				%s
				c = connect(%s)
				trace = c.create_trace("/test", "DATA:LE:64:default", "pointer64", extra=None)

				with trace.open_tx("Create snapshot") as tx:
				    snap = trace.snapshot("Test", time=Schedule(10, 500))
				    print(f"---SNAP:{snap}---")

				exit()
				""".formatted(PREAMBLE, addr));

		long snap = Long.parseLong(matchOne(out, Pattern.compile("---SNAP:(-?\\d*)---")).group(1));
		assertThat(snap, Matchers.lessThan(0L));
		try (ManagedDomainObject obj = openDomainObject("/New Traces/test")) {
			Trace trace = (Trace) obj.get();
			TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(snap, false);
			assertEquals("Test", snapshot.getDescription());
		}
	}

	@Test
	public void testSnapshotScheduleInBatch() throws Exception {
		String out = runThrowError(addr -> """
				%s
				c = connect(%s)
				trace = c.create_trace("/test", "DATA:LE:64:default", "pointer64", extra=None)

				with trace.open_tx("Create snapshot") as tx:
				    with c.batch() as b:
				        snap = trace.snapshot("Test", time=Schedule(10, 500))
				        print(f"---SNAP:{snap}---")

				exit()
				""".formatted(PREAMBLE, addr));

		long snap = Long.parseLong(matchOne(out, Pattern.compile("---SNAP:(-?\\d*)---")).group(1));
		assertThat(snap, Matchers.lessThan(0L));
		try (ManagedDomainObject obj = openDomainObject("/New Traces/test")) {
			Trace trace = (Trace) obj.get();
			TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(snap, false);
			assertEquals("Test", snapshot.getDescription());
		}
	}
}
