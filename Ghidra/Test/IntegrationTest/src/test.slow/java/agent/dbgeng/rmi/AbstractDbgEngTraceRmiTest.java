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
package agent.dbgeng.rmi;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Before;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.service.rmi.trace.*;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.app.services.TraceRmiService;
import ghidra.dbg.testutil.DummyProc;
import ghidra.framework.*;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginsConfiguration;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

public abstract class AbstractDbgEngTraceRmiTest extends AbstractGhidraHeadedDebuggerGUITest {
	/**
	 * Some features have to be disabled to avoid permissions issues in the test container. Namely,
	 * don't try to disable ASLR.
	 */
	public static final String PREAMBLE = """
			from ghidradbg.commands import *
			""";
	// Connecting should be the first thing the script does, so use a tight timeout.
	protected static final int CONNECT_TIMEOUT_MS = 3000;
	protected static final int TIMEOUT_SECONDS = 300;
	protected static final int QUIT_TIMEOUT_MS = 1000;

	protected TraceRmiService traceRmi;
	private Path pythonPath;
	private Path outFile;
	private Path errFile;

	@Before
	public void assertOS() {
		assumeTrue(OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS);
	}

	//@BeforeClass
	public static void setupPython() throws Throwable {
		new ProcessBuilder("gradle", "Debugger-agent-dbgeng:assemblePyPackage")
				.directory(TestApplicationUtils.getInstallationDirectory())
				.inheritIO()
				.start()
				.waitFor();
	}

	protected void setPythonPath(ProcessBuilder pb) throws IOException {
		String sep =
			OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS ? ";" : ":";
		String rmiPyPkg = Application.getModuleSubDirectory("Debugger-rmi-trace",
			"build/pypkg/src").getAbsolutePath();
		String gdbPyPkg = Application.getModuleSubDirectory("Debugger-agent-dbgeng",
			"build/pypkg/src").getAbsolutePath();
		String add = rmiPyPkg + sep + gdbPyPkg;
		pb.environment().compute("PYTHONPATH", (k, v) -> v == null ? add : (v + sep + add));
	}

	@Before
	public void setupTraceRmi() throws Throwable {
		traceRmi = addPlugin(tool, TraceRmiPlugin.class);

		try {
			pythonPath = Paths.get(DummyProc.which("python3"));
		}
		catch (RuntimeException e) {
			pythonPath = Paths.get(DummyProc.which("python"));
		}
		outFile = Files.createTempFile("pydbgout", null);
		errFile = Files.createTempFile("pydbgerr", null);
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
			return addrToStringForPython(tcp.getAddress()) + ":" + tcp.getPort();
		}
		throw new AssertionError("Unhandled address type " + address);
	}

	protected record PythonResult(boolean timedOut, int exitCode, String stdout, String stderr) {
		protected String handle() {
			if (stderr.contains("Error") || (0 != exitCode && 1 != exitCode && 143 != exitCode)) {
				throw new PythonError(exitCode, stdout, stderr);
			}
			return stdout;
		}
	}

	protected record ExecInPython(Process python, CompletableFuture<PythonResult> future) {
	}

	@SuppressWarnings("resource") // Do not close stdin 
	protected ExecInPython execInPython(String script) throws IOException {
		ProcessBuilder pb = new ProcessBuilder(pythonPath.toString(), "-i");
		setPythonPath(pb);

		// If commands come from file, Python will quit after EOF.
		Msg.info(this, "outFile: " + outFile);
		Msg.info(this, "errFile: " + errFile);

		//pb.inheritIO();
		pb.redirectInput(ProcessBuilder.Redirect.PIPE);
		pb.redirectOutput(outFile.toFile());
		pb.redirectError(errFile.toFile());
		Process pyproc = pb.start();
		OutputStream stdin = pyproc.getOutputStream();
		stdin.write(script.getBytes());
		stdin.flush();
		//stdin.close();
		return new ExecInPython(pyproc, CompletableFuture.supplyAsync(() -> {
			try {
				if (!pyproc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
					Msg.error(this, "Timed out waiting for Python");
					pyproc.destroyForcibly();
					pyproc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
					return new PythonResult(true, -1, Files.readString(outFile),
						Files.readString(errFile));
				}
				Msg.info(this, "Python exited with code " + pyproc.exitValue());
				return new PythonResult(false, pyproc.exitValue(), Files.readString(outFile),
					Files.readString(errFile));
			}
			catch (Exception e) {
				return ExceptionUtils.rethrow(e);
			}
			finally {
				pyproc.destroyForcibly();
			}
		}));
	}

	public static class PythonError extends RuntimeException {
		public final int exitCode;
		public final String stdout;
		public final String stderr;

		public PythonError(int exitCode, String stdout, String stderr) {
			super("""
					exitCode=%d:
					----stdout----
					%s
					----stderr----
					%s
					""".formatted(exitCode, stdout, stderr));
			this.exitCode = exitCode;
			this.stdout = stdout;
			this.stderr = stderr;
		}
	}

	protected String runThrowError(String script) throws Exception {
		CompletableFuture<PythonResult> result = execInPython(script).future;
		return result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
	}

	protected record PythonAndHandler(ExecInPython exec, TraceRmiHandler handler)
			implements AutoCloseable {
		protected RemoteMethod getMethod(String name) {
			return Objects.requireNonNull(handler.getMethods().get(name));
		}

		public void execute(String cmd) {
			RemoteMethod execute = getMethod("execute");
			execute.invoke(Map.of("cmd", cmd));
		}

		public RemoteAsyncResult executeAsync(String cmd) {
			RemoteMethod execute = getMethod("execute");
			return execute.invokeAsync(Map.of("cmd", cmd));
		}

		public String executeCapture(String expr) {
			RemoteMethod execute = getMethod("evaluate");
			return (String) execute.invoke(Map.of("expr", expr));
		}

		@Override
		public void close() throws Exception {
			Msg.info(this, "Cleaning up python");
			exec.python().destroy();
			try {
				PythonResult r = exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
				r.handle();
				waitForPass(() -> assertTrue(handler.isClosed()));
			}
			finally {
				exec.python.destroyForcibly();
			}
		}
	}

	protected PythonAndHandler startAndConnectPython(Function<String, String> scriptSupplier)
			throws Exception {
		TraceRmiAcceptor acceptor = traceRmi.acceptOne(null);
		ExecInPython exec =
			execInPython(scriptSupplier.apply(sockToStringForPython(acceptor.getAddress())));
		acceptor.setTimeout(CONNECT_TIMEOUT_MS);
		try {
			TraceRmiHandler handler = acceptor.accept();
			return new PythonAndHandler(exec, handler);
		}
		catch (SocketTimeoutException e) {
			exec.python.destroyForcibly();
			exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
			throw e;
		}
	}

	protected PythonAndHandler startAndConnectPython() throws Exception {
		return startAndConnectPython(addr -> """
				%s
				ghidra_trace_connect('%s')
				""".formatted(PREAMBLE, addr));
	}

	@SuppressWarnings("resource")
	protected String runThrowError(Function<String, String> scriptSupplier)
			throws Exception {
		PythonAndHandler conn = startAndConnectPython(scriptSupplier);
		PythonResult r = conn.exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
		String stdout = r.handle();
		waitForPass(() -> assertTrue(conn.handler.isClosed()));
		return stdout;
	}

	protected void waitStopped() {
		TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]", Lifespan.at(0)));
		waitForPass(() -> assertEquals("STOPPED", tb.objValue(proc, 0, "_state")));
		waitTxDone();
	}

	protected void waitRunning() {
		TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]", Lifespan.at(0)));
		waitForPass(() -> assertEquals("RUNNING", tb.objValue(proc, 0, "_state")));
		waitTxDone();
	}

	protected String extractOutSection(String out, String head) {
		String[] split = out.split("\n");
		String xout = "";
		for (String s : split) {
			if (!s.startsWith("(python)") && !s.equals("")) {
				xout += s + "\n";
			}
		}
		return xout.split(head)[1].split("---")[0].replace("(python)", "").trim();
	}

	record MemDump(long address, byte[] data) {
	}

	protected MemDump parseHexDump(String dump) throws IOException {
		// First, get the address. Assume contiguous, so only need top line.
		List<String> lines = List.of(dump.split("\n"));
		List<String> toksLine0 = List.of(lines.get(0).split("\\s+"));
		String addrstr = toksLine0.get(0);
		if (addrstr.contains(":")) {
			addrstr = addrstr.substring(0, addrstr.indexOf(":"));
		}
		long address = Long.parseLong(addrstr, 16);

		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		for (String l : lines) {
			List<String> parts = List.of(l.split(":"));
			assertEquals(2, parts.size());
			String hex = parts.get(1).substring(0, 48);
			byte[] lineData = NumericUtilities.convertStringToBytes(hex);
			assertNotNull("Converted to null: " + hex, parts.get(1));
			buf.write(lineData);
		}
		return new MemDump(address, buf.toByteArray());
	}

	record RegDump() {
	}

	protected RegDump parseRegDump(String dump) {
		return new RegDump();
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

	protected void assertBreakLoc(TraceObjectValue locVal, String key, Address addr, int len,
			Set<TraceBreakpointKind> kinds, String expression) throws Exception {
		assertEquals(key, locVal.getEntryKey());
		TraceObject loc = locVal.getChild();
		TraceObject spec = loc;
		assertEquals(new AddressRangeImpl(addr, len), loc.getValue(0, "_range").getValue());
		assertEquals(TraceBreakpointKindSet.encode(kinds), spec.getValue(0, "_kinds").getValue());
		assertTrue(spec.getValue(0, "_expression").getValue().toString().contains(expression));
	}

	protected void assertWatchLoc(TraceObjectValue locVal, String key, Address addr, int len,
			Set<TraceBreakpointKind> kinds, String expression) throws Exception {
		assertEquals(key, locVal.getEntryKey());
		TraceObject loc = locVal.getChild();
		assertEquals(new AddressRangeImpl(addr, len), loc.getValue(0, "_range").getValue());
		assertEquals(TraceBreakpointKindSet.encode(kinds), loc.getValue(0, "_kinds").getValue());
	}

	protected void waitTxDone() {
		waitFor(() -> tb.trace.getCurrentTransactionInfo() == null);
	}

	public static void waitForPass(Runnable runnable, long timeoutMs, long retryDelayMs) {
		long start = System.currentTimeMillis();
		AssertionError lastError = null;
		while (System.currentTimeMillis() - start < timeoutMs) {
			try {
				runnable.run();
				return;
			}
			catch (AssertionError e) {
				lastError = e;
			}
			try {
				Thread.sleep(retryDelayMs);
			}
			catch (InterruptedException e) {
				// Retry sooner, I guess.
			}
		}
		if (lastError == null) {
			throw new AssertionError("Timed out before first try?");
		}
		throw lastError;
	}
}
