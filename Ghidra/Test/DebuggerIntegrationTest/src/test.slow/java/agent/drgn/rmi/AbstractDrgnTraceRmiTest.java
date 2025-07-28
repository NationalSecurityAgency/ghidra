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
package agent.drgn.rmi;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.FileWriter;
import java.io.IOException;
import java.net.*;
import java.nio.file.*;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.*;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.junit.Before;
import org.junit.BeforeClass;

import generic.jar.ResourceFile;
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
import ghidra.pty.testutil.DummyProc;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import junit.framework.AssertionFailedError;

public abstract class AbstractDrgnTraceRmiTest extends AbstractGhidraHeadedDebuggerTest {

	protected static final String CORE = "core.12137";
	protected static final String MDO = "/New Traces/" + CORE;
	public static final String PREAMBLE = """
			import os
			import drgn
			import drgn.cli
			os.environ['OPT_TARGET_KIND'] = 'coredump'
			os.environ['OPT_TARGET_IMG'] = '$CORE'
			from ghidradrgn.commands import *
			""";

	// Connecting should be the first thing the script does, so use a tight timeout.
	protected static final int CONNECT_TIMEOUT_MS = 3000;
	protected static final int TIMEOUT_SECONDS = 30000;
	protected static final int QUIT_TIMEOUT_MS = 1000;

	/** Some snapshot likely to exceed the latest */
	protected static final long SNAP = 100;

	protected static boolean didSetupPython = false;

	protected TraceRmiService traceRmi;
	private Path pythonPath;
	private Path outFile;
	private Path errFile;

	@Before
	public void assertOS() {
		assumeTrue(OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.LINUX);
	}

	@BeforeClass
	public static void setupPython() throws Throwable {
		if (didSetupPython) {
			// Only do this once when running the full suite.
			return;
		}
		if (SystemUtilities.isInTestingBatchMode()) {
			// Don't run gradle in gradle. It already did this task.
			return;
		}
		String gradle = DummyProc.which("gradle");
		new ProcessBuilder(gradle, "assemblePyPackage")
				.directory(TestApplicationUtils.getInstallationDirectory())
				.inheritIO()
				.start()
				.waitFor();
		didSetupPython = true;
	}

	protected void setPythonPath(ProcessBuilder pb) throws IOException {
		String sep =
			OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.LINUX ? ":" : ";";
		String rmiPyPkg = Application.getModuleSubDirectory("Debugger-rmi-trace",
			"build/pypkg/src").getAbsolutePath();
		String drgnPyPkg = Application.getModuleSubDirectory("Debugger-agent-drgn",
			"build/pypkg/src").getAbsolutePath();
		String add = rmiPyPkg + sep + drgnPyPkg;
		pb.environment().compute("PYTHONPATH", (k, v) -> v == null ? add : (v + sep + add));
	}

	@Before
	public void setupTraceRmi() throws Throwable {
		traceRmi = addPlugin(tool, TraceRmiPlugin.class);

		try {
			pythonPath = Paths.get(DummyProc.which("drgn"));
		}
		catch (RuntimeException e) {
			Msg.error(this, e);
		}
		outFile = Files.createTempFile("drgnout", null);
		errFile = Files.createTempFile("drgnerr", null);
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
			if (stderr.contains("RuntimeError") || stderr.contains(" Error") ||
				(0 != exitCode && 1 != exitCode && 143 != exitCode)) {
				throw new PythonError(exitCode, stdout, stderr);
			}
			System.out.println("--stdout--");
			System.out.println(stdout);
			System.out.println("--stderr--");
			System.out.println(stderr);
			return stdout;
		}
	}

	protected record ExecInDrgn(Process python, CompletableFuture<PythonResult> future) {}

	@SuppressWarnings("resource") // Do not close stdin 
	protected ExecInDrgn execInDrgn(String script) throws IOException {
		ResourceFile rf = Application.getModuleDataFile("TestResources", CORE);
		script = script.replace("$CORE", rf.getAbsolutePath());
		Path fp = Files.createTempFile("test", ".py");
		FileWriter fw = new FileWriter(fp.toFile());
		fw.write(script);
		fw.close();
		ProcessBuilder pb = new ProcessBuilder(pythonPath.toString(), "-c",
			rf.getAbsolutePath(), fp.toFile().getAbsolutePath());
		setPythonPath(pb);

		// If commands come from file, Python will quit after EOF.
		Msg.info(this, "outFile: " + outFile);
		Msg.info(this, "errFile: " + errFile);

		//pb.inheritIO();
		pb.redirectInput(ProcessBuilder.Redirect.PIPE);
		pb.redirectOutput(outFile.toFile());
		pb.redirectError(errFile.toFile());
		Process pyproc = pb.start();
		return new ExecInDrgn(pyproc, CompletableFuture.supplyAsync(() -> {
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
		CompletableFuture<PythonResult> result = execInDrgn(script).future;
		return result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
	}

	protected record PythonAndConnection(ExecInDrgn exec, TraceRmiConnection connection)
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
			Msg.info(this, "Cleaning up python");
			exec.python().destroy();
			try {
				PythonResult r = exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
				r.handle();
				waitForPass(() -> assertTrue(connection.isClosed()));
			}
			finally {
				exec.python.destroyForcibly();
			}
		}
	}

	protected PythonAndConnection startAndConnectDrgn(Function<String, String> scriptSupplier)
			throws Exception {
		TraceRmiAcceptor acceptor = traceRmi.acceptOne(null);
		ExecInDrgn exec =
			execInDrgn(scriptSupplier.apply(sockToStringForPython(acceptor.getAddress())));
		acceptor.setTimeout(CONNECT_TIMEOUT_MS);
		try {
			TraceRmiConnection connection = acceptor.accept();
			return new PythonAndConnection(exec, connection);
		}
		catch (SocketTimeoutException e) {
			exec.python.destroyForcibly();
			exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS).handle();
			throw e;
		}
	}

	protected PythonAndConnection startAndConnectDrgn() throws Exception {
		return startAndConnectDrgn(addr -> """
				%s
				ghidra_trace_connect('%s')
				drgn.cli.run_interactive(prog)
				""".formatted(PREAMBLE, addr));
	}

	@SuppressWarnings("resource")
	protected String runThrowError(Function<String, String> scriptSupplier)
			throws Exception {
		PythonAndConnection conn = startAndConnectDrgn(scriptSupplier);
		PythonResult r = conn.exec.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
		String stdout = r.handle();
		//waitForPass(() -> assertTrue(conn.connection.isClosed()));
		return stdout;
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

	protected long getMaxSnap() {
		Long maxSnap = tb.trace.getTimeManager().getMaxSnap();
		return maxSnap == null ? 0 : maxSnap;
	}

	protected void waitTxDone() {
		waitFor(() -> tb.trace.getCurrentTransactionInfo() == null);
	}

	public static void waitForPass(Runnable runnable) {
		AtomicReference<AssertionError> lastError = new AtomicReference<>();
		waitForCondition(() -> {
			try {
				runnable.run();
				return true;
			}
			catch (AssertionError e) {
				lastError.set(e);
				return false;
			}
		}, () -> lastError.get().getMessage());
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

}
