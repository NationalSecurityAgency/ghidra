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
package agent.gdb.rmi;

import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.*;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Before;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.app.services.TraceRmiService;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
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
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.target.*;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

public abstract class AbstractGdbTraceRmiTest extends AbstractGhidraHeadedDebuggerTest {
	/**
	 * The tests are touchy about anything being printed on stderr, because that's usually where
	 * Python stack traces go that otherwise are ignored. Unfortunately, GDB also emits some
	 * warnings there, and these are more common in containers where permissions and resources are
	 * more restricted. Thus, we add some commands here to disable the features that commonly cause
	 * these warnings: Leave ASLR alone, and don't try to display source code.
	 */
	public static final String PREAMBLE = """
			set python print-stack full
			python import ghidragdb
			set disable-randomization off
			set source open off
			""";
	// Connecting should be the first thing the script does, so use a tight timeout.
	protected static final int CONNECT_TIMEOUT_MS = 3000;
	protected static final int TIMEOUT_SECONDS = 300;
	protected static final int QUIT_TIMEOUT_MS = 1000;
	public static final String INSTRUMENT_STOPPED = """
			ghidra trace tx-open "Fake" 'ghidra trace create-obj Inferiors[1]'
			define do-set-stopped
			  ghidra trace set-value Inferiors[1] _state '"STOPPED"'
			end
			define set-stopped
			  ghidra trace tx-open Stopped do-set-stopped
			end
			python gdb.events.stop.connect(lambda e: gdb.execute("set-stopped"))""";
	public static final String INSTRUMENT_RUNNING = """
			ghidra trace tx-open "Fake" 'ghidra trace create-obj Inferiors[1]'
			define do-set-running
			  ghidra trace set-value Inferiors[1] _state '"RUNNING"'
			end
			define set-running
			  ghidra trace tx-open Running do-set-running
			end
			python gdb.events.cont.connect(lambda e: gdb.execute("set-running"))""";

	protected TraceRmiService traceRmi;
	private Path gdbPath;
	private Path outFile;
	private Path errFile;

	// @BeforeClass
	public static void setupPython() throws Throwable {
		new ProcessBuilder("gradle", "Debugger-agent-gdb:assemblePyPackage")
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
		String gdbPyPkg = Application.getModuleSubDirectory("Debugger-agent-gdb",
			"build/pypkg/src").getAbsolutePath();
		String add = rmiPyPkg + sep + gdbPyPkg;
		pb.environment().compute("PYTHONPATH", (k, v) -> v == null ? add : (v + sep + add));
	}

	protected Path getGdbPath() {
		return Paths.get(DummyProc.which("gdb"));
	}

	@Before
	public void setupTraceRmi() throws Throwable {
		traceRmi = addPlugin(tool, TraceRmiPlugin.class);

		gdbPath = getGdbPath();
		outFile = Files.createTempFile("gdbout", null);
		errFile = Files.createTempFile("gdberr", null);
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

	protected static String addrToStringForGdb(InetAddress address) {
		if (address.isAnyLocalAddress()) {
			return "127.0.0.1"; // Can't connect to 0.0.0.0 as such. Choose localhost.
		}
		return address.getHostAddress();
	}

	protected static String sockToStringForGdb(SocketAddress address) {
		if (address instanceof InetSocketAddress tcp) {
			return addrToStringForGdb(tcp.getAddress()) + ":" + tcp.getPort();
		}
		throw new AssertionError("Unhandled address type " + address);
	}

	protected record GdbResult(boolean timedOut, int exitCode, String stdout, String stderr) {
		protected String handle() {
			if (!"".equals(stderr) | 0 != exitCode) {
				throw new GdbError(exitCode, stdout, stderr);
			}
			return stdout;
		}
	}

	protected record ExecInGdb(Process gdb, CompletableFuture<GdbResult> future) {
	}

	@SuppressWarnings("resource") // Do not close stdin 
	protected ExecInGdb execInGdb(String script) throws IOException {
		ProcessBuilder pb = new ProcessBuilder(gdbPath.toString());
		setPythonPath(pb);

		// If commands come from file, GDB will quit after EOF.
		Msg.info(this, "outFile: " + outFile);
		Msg.info(this, "errFile: " + errFile);
		pb.redirectInput(ProcessBuilder.Redirect.PIPE);
		pb.redirectOutput(outFile.toFile());
		pb.redirectError(errFile.toFile());
		Process gdbProc = pb.start();
		OutputStream stdin = gdbProc.getOutputStream();
		stdin.write(script.getBytes());
		stdin.flush();
		return new ExecInGdb(gdbProc, CompletableFuture.supplyAsync(() -> {
			try {
				if (!gdbProc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
					Msg.error(this, "Timed out waiting for GDB");
					gdbProc.destroyForcibly();
					gdbProc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
					return new GdbResult(true, -1, Files.readString(outFile),
						Files.readString(errFile));
				}
				Msg.info(this, "GDB exited with code " + gdbProc.exitValue());
				return new GdbResult(false, gdbProc.exitValue(), Files.readString(outFile),
					Files.readString(errFile));
			}
			catch (Exception e) {
				return ExceptionUtils.rethrow(e);
			}
			finally {
				gdbProc.destroyForcibly();
			}
		}));
	}

	protected static class GdbError extends RuntimeException {
		public final int exitCode;
		public final String stdout;
		public final String stderr;

		public GdbError(int exitCode, String stdout, String stderr) {
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
		CompletableFuture<GdbResult> result = execInGdb(script).future;
		return result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
	}

	protected record GdbAndConnection(ExecInGdb exec, TraceRmiConnection connection)
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

		@Override
		public void close() throws Exception {
			Msg.info(this, "Cleaning up gdb");
			try {
				try {
					RemoteAsyncResult asyncQuit = executeAsync("quit");
					try {
						asyncQuit.get(QUIT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
					}
					catch (TimeoutException e) {
						/**
						 * This seems like a bug in gdb. AFAICT, it's a rehash or regression of
						 * https://sourceware.org/bugzilla/show_bug.cgi?id=17247. If I attach to the
						 * hung gdb, I get a similar stack trace, but with Python frames on the
						 * stack. The workaround given in the comments works here, too. I hesitate
						 * to point fingers, though, because I'm testing with a modern gdb-13.1
						 * compiled from source on a rather un-modern distro.
						 */
						Msg.warn(this, "gdb hung on quit. Sending SIGCONT.");
						Runtime.getRuntime().exec("kill -SIGCONT %d".formatted(exec.gdb.pid()));
						asyncQuit.get(QUIT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
					}
				}
				catch (TraceRmiError e) {
					// expected
				}
				catch (ExecutionException e) {
					if (!(e.getCause() instanceof TraceRmiError)) {
						throw e;
					}
				}
				GdbResult r = exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
				r.handle();
				waitForPass(() -> assertTrue(connection.isClosed()));
			}
			finally {
				exec.gdb.destroyForcibly();
			}
		}
	}

	protected GdbAndConnection startAndConnectGdb(Function<String, String> scriptSupplier)
			throws Exception {
		TraceRmiAcceptor acceptor = traceRmi.acceptOne(null);
		ExecInGdb exec = execInGdb(scriptSupplier.apply(sockToStringForGdb(acceptor.getAddress())));
		acceptor.setTimeout(CONNECT_TIMEOUT_MS);
		try {
			TraceRmiConnection connection = acceptor.accept();
			return new GdbAndConnection(exec, connection);
		}
		catch (SocketTimeoutException e) {
			exec.gdb.destroyForcibly();
			exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
			throw e;
		}
	}

	protected GdbAndConnection startAndConnectGdb() throws Exception {
		return startAndConnectGdb(addr -> """
				%s
				ghidra trace connect %s
				""".formatted(PREAMBLE, addr));
	}

	@SuppressWarnings("resource")
	protected String runThrowError(Function<String, String> scriptSupplier)
			throws Exception {
		GdbAndConnection conn = startAndConnectGdb(scriptSupplier);
		GdbResult r = conn.exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
		String stdout = r.handle();
		waitForPass(() -> assertTrue(conn.connection.isClosed()));
		return stdout;
	}

	protected void waitState(int infnum, Supplier<Long> snapSupplier, TargetExecutionState state) {
		TraceObjectKeyPath infPath = TraceObjectKeyPath.parse("Inferiors").index(infnum);
		TraceObject inf =
			Objects.requireNonNull(tb.trace.getObjectManager().getObjectByCanonicalPath(infPath));
		waitForPass(
			() -> assertEquals(state.name(), tb.objValue(inf, snapSupplier.get(), "_state")));
		waitTxDone();
	}

	protected void waitStopped() {
		waitState(1, () -> 0L, TargetExecutionState.STOPPED);
	}

	protected void waitRunning() {
		waitState(1, () -> 0L, TargetExecutionState.RUNNING);
	}

	protected String extractOutSection(String out, String head) {
		return out.split(head)[1].split("---")[0].replace("(gdb)", "").trim();
	}

	record MemDump(long address, byte[] data) {
	}

	protected MemDump parseHexDump(String dump) throws IOException {
		// First, get the address. Assume contiguous, so only need top line.
		List<String> lines = List.of(dump.split("\n"));
		List<String> toksLine0 = List.of(lines.get(0).split("\\s+"));
		assertThat(toksLine0.get(0), startsWith("0x"));
		long address = Long.decode(toksLine0.get(0));

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

	protected void assertBreakLoc(TraceObjectValue locVal, String key, Address addr, int len,
			Set<TraceBreakpointKind> kinds, String expression) throws Exception {
		assertEquals(key, locVal.getEntryKey());
		TraceObject loc = locVal.getChild();
		TraceObject spec = loc.getCanonicalParent(0).getParent();
		assertEquals(new AddressRangeImpl(addr, len), loc.getValue(0, "_range").getValue());
		assertEquals(TraceBreakpointKindSet.encode(kinds), spec.getValue(0, "_kinds").getValue());
		assertEquals(expression, spec.getValue(0, "_expression").getValue());
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
		 * the breakpoints table, gdb may insert an extra informational line under a breakpoint row.
		 * This line will get mangled and parsed as if it were an entry. However, it's "Num" cell
		 * will be empty, so they will not likely interfere.
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
