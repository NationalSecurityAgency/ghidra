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
package agent.java.rmi;

import static org.junit.Assert.*;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Before;

import generic.Unique;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin;
import ghidra.app.plugin.core.debug.utils.ManagedDomainObject;
import ghidra.app.plugin.core.misc.RecoverySnapshotMgrPlugin;
import ghidra.app.services.TraceRmiService;
import ghidra.dbg.util.PathPredicates;
import ghidra.debug.api.tracermi.*;
import ghidra.framework.Application;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginsConfiguration;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.Msg;
import junit.framework.AssertionFailedError;

public abstract class AbstractJavaTraceRmiTest extends AbstractGhidraHeadedDebuggerTest {

	/**
	 * TODO: It would be nice if we didn't have to initialize a "Ghidra application" in order to use
	 * the RmiClient; however, I'm not sure that's worth it.
	 */
	public static final String PREAMBLE = """
			import java.io.*;
			import java.util.*;
			import com.sun.jdi.*;
			import com.sun.jdi.request.*;
			import ghidra.dbg.jdi.rmi.jpda.*;
			import ghidra.dbg.jdi.manager.impl.*;
			import ghidra.framework.Application;
			import ghidra.framework.GhidraApplicationConfiguration;
			import ghidra.GhidraApplicationLayout;
			import ghidra.program.model.address.*;
			import ghidra.app.plugin.core.debug.client.tracermi.*;
			import ghidra.rmi.trace.TraceRmi.MemoryState;

			GhidraApplicationLayout layout = new GhidraApplicationLayout();
			GhidraApplicationConfiguration config = new GhidraApplicationConfiguration();
			config.setShowSplashScreen(false);
			Application.initializeApplication(layout, config);

			JdiManagerImpl manager = new JdiManagerImpl();
			JdiManager jdiManager = new JdiManager(manager);
			JdiCommands cmds = jdiManager.getCommands();
			JdiMethods meths = jdiManager.getMethods();
			JdiHooks hooks   = jdiManager.getHooks();
			hooks.installHooks();
			""";
	// Connecting should be the first thing the script does, so use a tight timeout.
	protected static final int CONNECT_TIMEOUT_MS = 3000;
	protected static final int TIMEOUT_SECONDS = 300;
	protected static final int QUIT_TIMEOUT_MS = 1000;
	protected static final long EXT_TIMEOUT_MS = 5000;
	protected static final long EXT_RETRY_MS = 500;

	protected TraceRmiService traceRmi;
	private Path jshellPath;
	private Path outFile;
	private Path errFile;

	@Before
	public void setupTraceRmi() throws Throwable {
		traceRmi = addPlugin(tool, TraceRmiPlugin.class);

		traceManager.setSaveTracesByDefault(false);

		jshellPath = Paths.get(System.getProperty("java.home")).resolve("bin/jshell");
		outFile = Files.createTempFile("jshout", null);
		errFile = Files.createTempFile("jsherr", null);

		FrontEndTool frontEndTool = env.getFrontEndTool();
		Plugin recoveryPlugin = frontEndTool.getManagedPlugins()
				.stream()
				.filter(p -> p instanceof RecoverySnapshotMgrPlugin)
				.findAny()
				.get();
		frontEndTool.removePlugins(List.of(recoveryPlugin));
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

	protected static String addrToStringForJshell(InetAddress address) {
		if (address.isAnyLocalAddress()) {
			return "127.0.0.1"; // Can't connect to 0.0.0.0 as such. Choose localhost.
		}
		return address.getHostAddress();
	}

	protected static String sockToStringForJshell(SocketAddress address) {
		if (address instanceof InetSocketAddress tcp) {
			return addrToStringForJshell(tcp.getAddress()) + ":" + tcp.getPort();
		}
		throw new AssertionError("Unhandled address type " + address);
	}

	protected record JshellResult(boolean timedOut, int exitCode, String stdout, String stderr) {
		protected String handle() {
			if (stderr.contains("Error:") || (0 != exitCode)) {
				throw new JshellError(exitCode, stdout, stderr);
			}
			System.out.println("--stdout--");
			System.out.println(stdout);
			System.out.println("--stderr--");
			System.out.println(stderr);
			return stdout;
		}
	}

	protected record ExecInJshell(Process jshell, AbstractJavaTraceRmiTest test,
			CompletableFuture<JshellResult> future) {}

	private String parseClassPath() {
		String classPath = System.getProperty("java.class.path");
		String[] split = classPath.split(":");
		String newClassPath = "";
		for (String p : split) {
			File file = new File(p);
			if (file.exists()) {
				newClassPath += p + ":";
			}
		}
		return newClassPath;
	}

	@SuppressWarnings("resource") // Do not close stdin 
	protected ExecInJshell execInJshell(String script) throws IOException {
		String classPath = parseClassPath();
		ProcessBuilder pb = new ProcessBuilder(jshellPath.toString(), "--class-path=" + classPath);

		// If commands come from file, jshell will quit after EOF.
		Msg.info(this, "outFile: " + outFile);
		Msg.info(this, "errFile: " + errFile);

		ResourceFile rf = Application.getModuleDataFile("TestResources", "HelloWorld.class");
		pb.environment().put("OPT_TARGET_CLASSPATH", rf.getParentFile().getAbsolutePath());
		pb.environment().put("OPT_TARGET_CLASS", "HelloWorld");
		pb.environment().put("OPT_SUSPEND", "true");
		pb.environment().put("OPT_INCLUDE", "n");
		//pb.inheritIO();
		pb.redirectInput(ProcessBuilder.Redirect.PIPE);
		pb.redirectOutput(outFile.toFile());
		pb.redirectError(errFile.toFile());
		Process proc = pb.start();
		OutputStream stdin = proc.getOutputStream();
		stdin.write(script.getBytes());
		stdin.flush();
		//stdin.close();
		return new ExecInJshell(proc, this, CompletableFuture.supplyAsync(() -> {
			try {
				if (!proc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
					Msg.error(this, "Timed out waiting for jshell");
					proc.destroyForcibly();
					proc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
					return new JshellResult(true, -1, Files.readString(outFile),
						Files.readString(errFile));
				}
				Msg.info(this, "jshell exited with code " + proc.exitValue());
				return new JshellResult(false, proc.exitValue(), Files.readString(outFile),
					Files.readString(errFile));
			}
			catch (Exception e) {
				return ExceptionUtils.rethrow(e);
			}
			finally {
				proc.destroyForcibly();
			}
		}));
	}

	public static class JshellError extends RuntimeException {
		public final int exitCode;
		public final String stdout;
		public final String stderr;

		public JshellError(int exitCode, String stdout, String stderr) {
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
		CompletableFuture<JshellResult> result = execInJshell(script).future;
		return result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
	}

	protected record JshellAndConnection(ExecInJshell exec, TraceRmiConnection connection)
			implements AutoCloseable {
		private static BufferedReader reader = null;

		protected RemoteMethod getMethod(String name) {
			return Objects.requireNonNull(connection.getMethods().get(name));
		}

		public void execute(String cmd) {
			try {
				cmd += "\n";
				exec.jshell.getOutputStream().write(cmd.getBytes());
				exec.jshell.getOutputStream().flush();
			}
			catch (IOException e) {
				throw new AssertionError(e.getMessage());
			}
		}

		public RemoteAsyncResult executeAsync(String cmd) {
			RemoteMethod execute = getMethod("execute");
			return execute.invokeAsync(Map.of("cmd", cmd));
		}

		public List<String> executeCapture(String cmd) {
			try {
				if (reader == null) {
					reader = Files.newBufferedReader(exec.test.outFile);
				}
				if (cmd != null) {
					execute(cmd);
				}
				List<String> collect = waitForPass(() -> {
					List<String> list = reader.lines().collect(Collectors.toList());
					assertFalse(list.isEmpty());
					return list;
				});
				return collect;
			}
			catch (IOException e) {
				throw new AssertionError(e.getMessage());
			}
		}

		@Override
		public void close() throws Exception {
			Msg.info(this, "Cleaning up jshell");
			execute("/exit");
			try {
				JshellResult r = exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
				r.handle();
				connection.close();
			}
			finally {
				exec.jshell.destroyForcibly();
			}
		}

		public void waitOnClosed() {
			waitForPass(() -> assertTrue(connection.isClosed()));
		}
	}

	protected JshellAndConnection startAndConnectJshell(Function<String, String> scriptSupplier)
			throws Exception {
		TraceRmiAcceptor acceptor = traceRmi.acceptOne(null);
		ExecInJshell exec =
			execInJshell(scriptSupplier.apply(sockToStringForJshell(acceptor.getAddress())));
		acceptor.setTimeout(TIMEOUT_SECONDS * 1000);
		try {
			TraceRmiConnection connection = acceptor.accept();
			return new JshellAndConnection(exec, connection);
		}
		catch (SocketTimeoutException e) {
			exec.jshell.destroyForcibly();
			exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
			throw e;
		}
	}

	protected JshellAndConnection startAndConnectJshell() throws Exception {
		return startAndConnectJshell(addr -> """
				%s
				cmds.ghidraTraceConnect("%s");
				""".formatted(PREAMBLE, addr));
	}

	@SuppressWarnings("resource")
	protected String runThrowError(Function<String, String> scriptSupplier)
			throws Exception {
		JshellAndConnection conn = startAndConnectJshell(scriptSupplier);
		JshellResult r = conn.exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
		String stdout = r.handle();
		/**
		 * We know at this point the process should be terminated. Depending on how cleanly that
		 * happened, the socket may or may not be closed. Do not assert/wait for it to close. Just
		 * clean up by closing our end
		 */
		conn.connection.close();
		assertFalse(stdout.contains("Error:"));
		return stdout;
	}

	protected void waitStopped(String message, Long snap) {
		TraceObject proc = Objects.requireNonNull(tb.objAny("VMs[]", Lifespan.at(snap)));
		waitForPass(() -> assertEquals(message, "STOPPED", tb.objValue(proc, 0, "_state")));
		waitTxDone();
	}

	protected void waitRunning(String message, Long snap) {
		TraceObject proc = Objects.requireNonNull(tb.objAny("VMs[]", Lifespan.at(snap)));
		waitForPass(() -> assertEquals(message, "RUNNING", tb.objValue(proc, 0, "_state")));
		waitTxDone();
	}

	protected void waitAny(String message, Long snap) {
		TraceObject proc = Objects.requireNonNull(tb.objAny("VMs[]", Lifespan.at(snap)));
		waitForPass(() -> assertNotNull(message, tb.objValue(proc, 0, "_state")));
		waitTxDone();
	}

	protected String extractOutSection(String out, String head) {
		String[] split = out.split("\n");
		String xout = "";
		for (String s : split) {
			if (!s.startsWith("jshell>") && !s.equals("")) {
				if (s.startsWith("INFO") || s.startsWith("ERROR") || s.startsWith("WARN")) {
					if (s.indexOf("(") > 0) {
						s = s.substring(0, s.lastIndexOf("(")).trim();
					}
				}
				xout += s + "\n";
			}
		}
		return xout.split(head)[1].split("---")[0].replace("jshell>", "").trim();
	}

	record MemDump(long address, byte[] data) {}

	protected MemDump parseHexDump(String dump) throws IOException {
		// First, get the address. Assume contiguous, so only need top line.
		List<String> lines = List.of(dump.split("\n"));
		String bytes = lines.get(0);
		bytes = bytes.substring(bytes.indexOf("{") + 1, bytes.indexOf("}"));
		List<String> toks = List.of(bytes.split(",\\s+"));
		String addrstr = lines.get(1);
		long address = Long.parseLong(addrstr, 16);

		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		byte[] lineData = new byte[toks.size()];
		int i = 0;
		for (String t : toks) {
			lineData[i++] = Byte.parseByte(t.trim());
		}
		buf.write(lineData);
		return new MemDump(address, buf.toByteArray());
	}

	protected ManagedDomainObject openDomainObject(String path) throws Exception {
		DomainFile dfx = waitForPass(() -> {
			DomainFile df = env.getProject().getProjectData().getFile(path);
			assertNotNull(df);
			return df;
		}, TIMEOUT_SECONDS * 1000, 500);
		return new ManagedDomainObject(dfx, false, false, monitor);
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
		waitForCondition(() -> tb.trace.getCurrentTransactionInfo() == null,
			() -> "Error waiting for transaction to finish");
	}

	public static <T> T waitForPass(Supplier<T> supplier) {
		var locals = new Object() {
			AssertionError lastError;
			T value;
		};
		waitForCondition(() -> {
			try {
				locals.value = supplier.get();
				return true;
			}
			catch (AssertionError e) {
				locals.lastError = e;
				return false;
			}
		}, () -> locals.lastError.getMessage());
		return locals.value;
	}

	public static void waitForCondition(BooleanSupplier condition,
			Supplier<String> failureMessageSupplier) throws AssertionFailedError {

		int totalTime = 0;
		while (totalTime <= DEFAULT_WAIT_TIMEOUT * 10) {

			if (condition.getAsBoolean()) {
				return; // success
			}

			totalTime += sleep(DEFAULT_WAIT_DELAY * 10);
		}

		String failureMessage = "Timed-out waiting for condition";
		if (failureMessageSupplier != null) {
			failureMessage = failureMessageSupplier.get();
		}

		throw new AssertionFailedError(failureMessage);
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

	public static <T> T waitForPass(Supplier<T> supplier, long timeoutMs, long retryDelayMs) {
		var locals = new Object() {
			T value;
		};
		waitForPass(() -> {
			locals.value = supplier.get();
		}, timeoutMs, retryDelayMs);
		return locals.value;
	}

	protected long getMaxSnap() {
		Long maxSnap = tb.trace.getTimeManager().getMaxSnap();
		return maxSnap == null ? 0 : maxSnap;
	}

	protected TraceObject waitForObject(String path) {
		return waitForPass(() -> {
			TraceObject obj = tb.objAny(path, Lifespan.at(getMaxSnap()));
			assertNotNull("Object " + path + " never appeared.", obj);
			return obj;
		});
	}

	protected List<TraceObjectValue> getValues(String path) {
		return tb.trace.getObjectManager()
				.getValuePaths(Lifespan.at(getMaxSnap()), PathPredicates.parse(path))
				.map(p -> p.getLastEntry())
				.sorted(Comparator.comparing(TraceObjectValue::getEntryKey))
				.toList();
	}

	protected List<TraceObjectValue> waitForValuesPass(String path,
			Consumer<List<TraceObjectValue>> asserter) {
		return waitForPass(() -> {
			List<TraceObjectValue> vals = getValues(path);
			asserter.accept(vals);
			return vals;
		});
	}

	protected List<TraceObjectValue> waitForValues(String path) {
		return waitForValuesPass(path, vals -> assertFalse(vals.isEmpty()));
	}

	protected Address getPC() {
		return (Address) Unique
				.assertOne(tb.objValues(getMaxSnap(), "VMs[].Threads[main].Stack[0].PC"));
	}

	protected Address waitForPC(Consumer<Address> asserter) {
		return waitForPass(() -> {
			Address pc = getPC();
			asserter.accept(pc);
			return pc;
		});
	}

	public static void assertMatches(String expectedPattern, TraceObject object) {
		assertTrue("Expected matches " + expectedPattern + " but was " +
			object.getCanonicalPath().toString(),
			PathPredicates.parse(expectedPattern).matches(object.getCanonicalPath().getKeyList()));
	}

	protected void waitForLocation(String clsName, String methodName, long codeIndex) {
		try {
			waitForValuesPass("VMs[].Threads[main].Stack[0].Location.Method", methods -> {
				assertMatches("VMs[].Classes[" + clsName + "].Methods[" + methodName + "]",
					Unique.assertOne(methods).getChild());
			});
			waitForValuesPass("VMs[].Threads[main].Stack[0].Location.Index", indices -> {
				assertEquals(codeIndex, Unique.assertOne(indices).getValue());
			});
		}
		catch (AssertionError e) {
			TraceObjectValue locVal = Unique.assertAtMostOne(
				getValues("VMs[].Threads[main].Stack[0].Location"));
			if (locVal == null) {
				throw new AssertionError("Wrong location. Expected %s.%s:%d but was null"
						.formatted(clsName, methodName, codeIndex));
			}
			TraceObject loc = locVal.getChild();
			long snap = getMaxSnap();
			throw new AssertionError("Wrong location. Expected %s.%s:%d but was %s:%d"
					.formatted(clsName, methodName, codeIndex,
						loc.getAttribute(snap, "Method").getValue(),
						loc.getAttribute(snap, "Index").getValue()));
		}
	}
}
