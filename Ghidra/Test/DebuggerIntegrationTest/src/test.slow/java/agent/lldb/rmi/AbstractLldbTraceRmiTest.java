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
package agent.lldb.rmi;

import static org.hamcrest.Matchers.startsWith;
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
import java.util.stream.Collectors;

import org.apache.commons.io.output.TeeOutputStream;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.BeforeClass;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.app.services.TraceRmiService;
import ghidra.dbg.testutil.DummyProc;
import ghidra.debug.api.tracermi.*;
import ghidra.framework.*;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginsConfiguration;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.pty.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

public abstract class AbstractLldbTraceRmiTest extends AbstractGhidraHeadedDebuggerTest {

	record PlatDep(String name, String endian, String lang, String cSpec, String callMne,
			String intReg, String floatReg) {
		static final PlatDep ARM64 =
			new PlatDep("arm64", "little", "AARCH64:LE:64:v8A", "default", "bl", "x0", "s0");
		static final PlatDep X8664 = // Note AT&T callq
			new PlatDep("x86_64", "little", "x86:LE:64:default", "gcc", "callq", "rax", "st0");
	}

	public static final PlatDep PLAT = computePlat();

	static PlatDep computePlat() {
		return switch (System.getProperty("os.arch")) {
			case "aarch64" -> PlatDep.ARM64;
			case "x86" -> PlatDep.X8664;
			case "amd64" -> PlatDep.X8664;
			default -> throw new AssertionError(
				"Unrecognized arch: " + System.getProperty("os.arch"));
		};
	}

	static String getSpecimenClone() {
		return DummyProc.which("expCloneExit");
	}

	static String getSpecimenPrint() {
		return DummyProc.which("expPrint");
	}

	static String getSpecimenRead() {
		return DummyProc.which("expRead");
	}

	/**
	 * Some features have to be disabled to avoid permissions issues in the test container. Namely,
	 * don't try to disable ASLR.
	 * 
	 * Color codes mess up the address parsing.
	 */
	public static final String PREAMBLE = """
			script import ghidralldb
			settings set use-color false
			settings set target.disable-aslr false
			""";
	// Connecting should be the first thing the script does, so use a tight timeout.
	protected static final int CONNECT_TIMEOUT_MS = 3000;
	protected static final int TIMEOUT_SECONDS = 300;
	protected static final int QUIT_TIMEOUT_MS = 1000;

	protected TraceRmiService traceRmi;
	private Path lldbPath;

	// @BeforeClass
	public static void setupPython() throws Throwable {
		new ProcessBuilder("gradle",
			"Debugger-rmi-trace:assemblePyPackage",
			"Debugger-agent-lldb:assemblePyPackage")
					.directory(TestApplicationUtils.getInstallationDirectory())
					.inheritIO()
					.start()
					.waitFor();
	}

	protected void setPythonPath(Map<String, String> env) throws IOException {
		String sep =
			OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS ? ";" : ":";
		String rmiPyPkg = Application.getModuleSubDirectory("Debugger-rmi-trace",
			"build/pypkg/src").getAbsolutePath();
		String gdbPyPkg = Application.getModuleSubDirectory("Debugger-agent-lldb",
			"build/pypkg/src").getAbsolutePath();
		String add = rmiPyPkg + sep + gdbPyPkg;
		env.compute("PYTHONPATH", (k, v) -> v == null ? add : (v + sep + add));
	}

	@Before
	public void setupTraceRmi() throws Throwable {
		traceRmi = addPlugin(tool, TraceRmiPlugin.class);

		try {
			lldbPath = Paths.get(DummyProc.which("lldb-16"));
		}
		catch (RuntimeException e) {
			lldbPath = Paths.get(DummyProc.which("lldb"));
		}
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

	protected static String addrToStringForLldb(InetAddress address) {
		if (address.isAnyLocalAddress()) {
			return "127.0.0.1"; // Can't connect to 0.0.0.0 as such. Choose localhost.
		}
		return address.getHostAddress();
	}

	protected static String sockToStringForLldb(SocketAddress address) {
		if (address instanceof InetSocketAddress tcp) {
			return addrToStringForLldb(tcp.getAddress()) + ":" + tcp.getPort();
		}
		throw new AssertionError("Unhandled address type " + address);
	}

	protected record LldbResult(boolean timedOut, int exitCode, String out) {
		protected String handle() {
			if (0 != exitCode && 143 != exitCode) {
				throw new LldbError(exitCode, out);
			}
			return out;
		}
	}

	protected record ExecInLldb(Pty pty, PtySession lldb, CompletableFuture<LldbResult> future,
			Thread pumper) {}

	@SuppressWarnings("resource") // Do not close stdin 
	protected ExecInLldb execInLldb(String script) throws IOException {
		Pty pty = PtyFactory.local().openpty();
		Map<String, String> env = new HashMap<>(System.getenv());
		setPythonPath(env);
		env.put("TERM", "xterm-256color");
		ByteArrayOutputStream capture = new ByteArrayOutputStream();
		OutputStream tee = new TeeOutputStream(System.out, capture);
		Thread pumper = new StreamPumper(pty.getParent().getInputStream(), tee);
		pumper.start();
		PtySession lldbSession = pty.getChild().session(new String[] { lldbPath.toString() }, env);

		OutputStream stdin = pty.getParent().getOutputStream();
		stdin.write(script.getBytes());
		stdin.flush();
		return new ExecInLldb(pty, lldbSession, CompletableFuture.supplyAsync(() -> {
			try {
				int exitVal = lldbSession.waitExited(TIMEOUT_SECONDS, TimeUnit.SECONDS);
				Msg.info(this, "LLDB exited with code " + exitVal);
				return new LldbResult(false, exitVal, capture.toString());
			}
			catch (TimeoutException e) {
				return new LldbResult(true, -1, capture.toString());
			}
			catch (Exception e) {
				return ExceptionUtils.rethrow(e);
			}
			finally {
				try {
					pty.close();
				}
				catch (IOException e) {
					Msg.warn(this, "Couldn't close pty: " + e);
				}
				lldbSession.destroyForcibly();
				pumper.interrupt();
			}
		}), pumper);
	}

	public static class LldbError extends RuntimeException {
		public final int exitCode;
		public final String out;

		public LldbError(int exitCode, String out) {
			super("""
					exitCode=%d:
					----out----
					%s
					""".formatted(exitCode, out));
			this.exitCode = exitCode;
			this.out = out;
		}
	}

	protected String runThrowError(String script) throws Exception {
		CompletableFuture<LldbResult> result = execInLldb(script).future;
		return result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
	}

	protected record LldbAndConnection(ExecInLldb exec, TraceRmiConnection connection)
			implements AutoCloseable {
		protected RemoteMethod getMethod(String name) {
			return Objects.requireNonNull(connection.getMethods().get(name));
		}

		public void execute(String cmd) {
			RemoteMethod execute = getMethod("execute");
			execute.invoke(Map.of("cmd", cmd));
		}

		public RemoteAsyncResult executeAsync(String cmd) {
			RemoteMethod execute = getMethod("execute");
			return execute.invokeAsync(Map.of("cmd", cmd));
		}

		public String executeCapture(String cmd) {
			RemoteMethod execute = getMethod("execute");
			return (String) execute.invoke(Map.of("cmd", cmd, "to_string", true));
		}

		public Object evaluate(String expr) {
			RemoteMethod evaluate = getMethod("evaluate");
			return evaluate.invoke(Map.of("expr", expr));
		}

		public Object pyeval(String expr) {
			RemoteMethod pyeval = getMethod("pyeval");
			return pyeval.invoke(Map.of("expr", expr));
		}

		@Override
		public void close() throws Exception {
			Msg.info(this, "Cleaning up lldb");
			execute("settings set auto-confirm true");
			exec.pty.getParent().getOutputStream().write("""
					quit
					""".getBytes());
			try {
				LldbResult r = exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
				r.handle();
				waitForPass(() -> assertTrue(connection.isClosed()));
			}
			finally {
				exec.pty.close();
				exec.lldb.destroyForcibly();
				exec.pumper.interrupt();
			}
		}
	}

	protected LldbAndConnection startAndConnectLldb(Function<String, String> scriptSupplier)
			throws Exception {
		TraceRmiAcceptor acceptor = traceRmi.acceptOne(null);
		ExecInLldb exec =
			execInLldb(scriptSupplier.apply(sockToStringForLldb(acceptor.getAddress())));
		acceptor.setTimeout(CONNECT_TIMEOUT_MS);
		try {
			TraceRmiConnection connection = acceptor.accept();
			return new LldbAndConnection(exec, connection);
		}
		catch (SocketTimeoutException e) {
			exec.pty.close();
			exec.lldb.destroyForcibly();
			exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
			exec.pumper.interrupt();
			throw e;
		}
	}

	protected LldbAndConnection startAndConnectLldb() throws Exception {
		return startAndConnectLldb(addr -> """
				%s
				ghidra trace connect %s
				""".formatted(PREAMBLE, addr));
	}

	@SuppressWarnings("resource")
	protected String runThrowError(Function<String, String> scriptSupplier)
			throws Exception {
		LldbAndConnection conn = startAndConnectLldb(scriptSupplier);
		LldbResult r = conn.exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
		conn.exec.pty.close();
		conn.exec.pumper.interrupt();
		String stdout = r.handle();
		waitForPass(() -> assertTrue(conn.connection.isClosed()));
		return stdout;
	}

	protected void waitState(String state) {
		TraceObject proc = Objects.requireNonNull(tb.objAny("Processes[]", Lifespan.at(0)));
		for (int i = 0; i < 5; i++) {
			try {
				waitForPass(() -> {
					Long snap = tb.trace.getTimeManager().getMaxSnap();
					assertEquals(state, tb.objValue(proc, snap != null ? snap : 0, "_state"));
				});
				break;
			}
			catch (AssertionError e) {
				if (i == 4) {
					throw e;
				}
			}
		}
		waitTxDone();
	}

	protected void waitStopped(LldbAndConnection conn) {
		waitForPass(() -> assertEquals(Boolean.TRUE,
			conn.pyeval("util.get_debugger().GetTargetAtIndex(0).GetProcess().is_stopped")));
		// waitState("STOPPED");
	}

	protected void waitRunning(LldbAndConnection conn) {
		waitForPass(() -> assertEquals(Boolean.TRUE,
			conn.pyeval("util.get_debugger().GetTargetAtIndex(0).GetProcess().is_running")));
		// waitState("RUNNING");
	}

	protected String extractOutSection(String out, String head) {
		String[] split = out.replace("\r", "").split("\n");
		String xout = "";
		for (String s : split) {
			if (!s.startsWith("(lldb)") && !s.contains("script print(") && !s.equals("")) {
				xout += s + "\n";
			}
		}
		return xout.split(head)[1].split("---")[0].replace("(lldb)", "").trim();
	}

	record MemDump(long address, byte[] data) {}

	protected MemDump parseHexDump(String dump) throws IOException {
		// First, get the address. Assume contiguous, so only need top line.
		List<String> lines = List.of(dump.split("\n"));
		List<String> toksLine0 = List.of(lines.get(0).split("\\s+"));
		assertThat(toksLine0.get(0), startsWith("0x"));
		String addrstr = toksLine0.get(0);
		if (addrstr.contains(":")) {
			addrstr = addrstr.substring(0, addrstr.indexOf(":"));
		}
		long address = Long.decode(addrstr);

		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		for (String l : lines) {
			List<String> parts = List.of(l.split(":"));
			assertEquals(2, parts.size());
			String hex = parts.get(1).replaceAll("\\s*0x", "");
			byte[] lineData = NumericUtilities.convertStringToBytes(hex);
			assertNotNull("Converted to null: " + hex, parts.get(1));
			buf.write(lineData);
		}
		return new MemDump(address, buf.toByteArray());
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

	protected void assertLocalOs(String actual) {
		assertThat(actual, Matchers.startsWith(switch (OperatingSystem.CURRENT_OPERATING_SYSTEM) {
			case LINUX -> "linux";
			case MAC_OS_X -> "macos";
			default -> throw new AssertionError("What OS?");
		}));
	}

	protected void assertBreakLoc(TraceObjectValue locVal, String key, Address addr, int len,
			Set<TraceBreakpointKind> kinds, String expression) throws Exception {
		assertEquals(key, locVal.getEntryKey());
		TraceObject loc = locVal.getChild();
		TraceObject spec = loc.getCanonicalParent(0).getParent();
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

	private record Cut(String head, int begin, int end) {
		String parseCell(String line) {
			int begin = Math.min(line.length(), this.begin);
			int end = Math.min(line.length(), this.end);
			/**
			 * NOTE: Do not assert previous char is space.
			 * 
			 * When breakpoints table spells out locations, Address and What cells are indented and
			 * no longer align with their column headers.
			 */
			return line.substring(begin, end).trim();
		}
	}

	protected record Row(Map<String, String> cells) {
		private static Row parse(List<Cut> cuts, String line) {
			return new Row(
				cuts.stream().collect(Collectors.toMap(Cut::head, c -> c.parseCell(line))));
		}

		public String getCell(String head) {
			return cells.get(head);
		}
	}

	protected record Tabular(List<String> headings, List<Row> rows) {

		static final Pattern SPACES = Pattern.compile(" *");
		static final Pattern WORDS = Pattern.compile("\\w+");

		private static List<Cut> findCuts(String header) {
			List<Cut> result = new ArrayList<>();
			Matcher spaceMatcher = SPACES.matcher(header);
			Matcher wordMatcher = WORDS.matcher(header);
			int start = 0;
			while (start < header.length()) {
				if (!spaceMatcher.find(start)) {
					throw new AssertionError();
				}
				start = spaceMatcher.end();
				if (start >= header.length()) {
					break;
				}
				if (!wordMatcher.find(start)) {
					throw new AssertionError();
				}
				result.add(new Cut(wordMatcher.group(), wordMatcher.start(), wordMatcher.end()));
				start = wordMatcher.end();
			}
			return result;
		}

		private static List<Cut> adjustCuts(List<Cut> cuts) {
			List<Cut> result = new ArrayList<>();
			for (int i = 0; i < cuts.size(); i++) {
				Cut cut = cuts.get(i);
				int j = i + 1;
				int end = j < cuts.size() ? cuts.get(j).begin : Integer.MAX_VALUE;
				result.add(new Cut(cut.head, cut.begin, end));
			}
			return result;
		}

		/**
		 * Parse a table.
		 * 
		 * <p>
		 * This is far from perfect, but good enough for making assertions in tests. For example, in
		 * the breakpoints table, lldb may insert an extra informational line under a breakpoint
		 * row. This line will get mangled and parsed as if it were an entry. However, it's "Num"
		 * cell will be empty, so they will not likely interfere.
		 * 
		 * @param out the output in tabular form
		 * @return the table object, more or less
		 */
		public static Tabular parse(String out) {
			List<String> lines = List.of(out.split("\n"));
			if (lines.isEmpty()) {
				throw new AssertionError("Output is not tabular");
			}
			List<Cut> cuts = adjustCuts(findCuts(lines.get(0)));
			return new Tabular(cuts.stream().map(Cut::head).toList(),
				lines.stream().skip(1).map(l -> Row.parse(cuts, l)).toList());
		}

		public Row findRow(String head, String contents) {
			return rows.stream()
					.filter(r -> Objects.equals(contents, r.getCell(head)))
					.findFirst()
					.orElse(null);
		}
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
