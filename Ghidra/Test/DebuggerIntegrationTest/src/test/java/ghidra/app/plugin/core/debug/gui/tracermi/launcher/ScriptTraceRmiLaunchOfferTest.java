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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import static org.junit.Assert.*;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.AbstractTraceRmiLaunchOffer.NullPtyTerminalSession;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.AbstractTraceRmiLaunchOffer.PtyTerminalSession;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.ScriptAttributesParser.ParseException;
import ghidra.app.plugin.core.debug.gui.tracermi.launcher.ScriptAttributesParser.ScriptAttributes;
import ghidra.app.plugin.core.debug.service.target.DebuggerTargetServicePlugin;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiHandler;
import ghidra.app.plugin.core.terminal.TerminalListener;
import ghidra.app.services.Terminal;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.TerminalSession;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.*;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.model.listing.Program;
import ghidra.pty.*;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

public class ScriptTraceRmiLaunchOfferTest extends AbstractGhidraHeadedDebuggerTest {

	static class TestScriptAttributesParser extends ScriptAttributesParser {
		List<String> errors = new ArrayList<>();

		@Override
		protected boolean ignoreLine(int lineNo, String line) {
			return false;
		}

		@Override
		protected String removeDelimiter(String line) {
			return line;
		}

		@Override
		protected void reportError(String message) {
			super.reportError(message);
			errors.add(message);
		}
	}

	static ScriptAttributes parse(String header, String name) throws ParseException {
		try {
			TestScriptAttributesParser parser = new TestScriptAttributesParser();
			ScriptAttributes attributes =
				parser.parseStream(new ByteArrayInputStream(header.getBytes()), name);
			if (!parser.errors.isEmpty()) {
				throw new ParseException(null, parser.errors.toString());
			}
			return attributes;
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	record Config(Map<String, ValStr<?>> args) implements LaunchConfigurator {
		public static final Config DEFAULTS = new Config(Map.of());

		@Override
		public PromptMode getPromptMode() {
			return PromptMode.NEVER;
		}

		@Override
		public Map<String, ValStr<?>> configureLauncher(TraceRmiLaunchOffer offer,
				Map<String, ValStr<?>> arguments, RelPrompt relPrompt) {
			Map<String, ValStr<?>> mod = new HashMap<>(arguments);
			mod.putAll(args);
			return mod;
		}
	}

	record MockTerminal() implements Terminal {
		@Override
		public void addTerminalListener(TerminalListener listener) {
		}

		@Override
		public void removeTerminalListener(TerminalListener listener) {
		}

		@Override
		public void injectDisplayOutput(ByteBuffer bb) {
		}

		@Override
		public void setSubTitle(String title) {
		}

		@Override
		public String getSubTitle() {
			return null;
		}

		@Override
		public void setFixedSize(short cols, short rows) {
		}

		@Override
		public void setDynamicSize() {
		}

		@Override
		public void setMaxScrollBackRows(int rows) {
		}

		@Override
		public int getColumns() {
			return 0;
		}

		@Override
		public int getRows() {
			return 0;
		}

		@Override
		public int getScrollBackRows() {
			return 0;
		}

		@Override
		public String getFullText() {
			return null;
		}

		@Override
		public String getDisplayText() {
			return null;
		}

		@Override
		public String getLineText(int line) {
			return null;
		}

		@Override
		public String getRangeText(int startCol, int startLine, int endCol, int endLine) {
			return null;
		}

		@Override
		public int getCursorRow() {
			return 0;
		}

		@Override
		public int getCursorColumn() {
			return 0;
		}

		@Override
		public void close() {
		}

		@Override
		public void terminated(int exitcode) {
		}

		@Override
		public void setTerminateAction(Runnable action) {
		}

		@Override
		public boolean isTerminated() {
			return false;
		}

		@Override
		public void toFront() {
		}
	}

	record MockPtySession() implements PtySession {
		@Override
		public int waitExited() throws InterruptedException {
			return 0;
		}

		@Override
		public int waitExited(long timeout, TimeUnit unit)
				throws InterruptedException, TimeoutException {
			return 0;
		}

		@Override
		public void destroyForcibly() {
		}

		@Override
		public String description() {
			return null;
		}
	}

	record MockPty() implements Pty {
		@Override
		public String toString() {
			return getClass().getSimpleName();
		}

		@Override
		public PtyParent getParent() {
			return null;
		}

		@Override
		public PtyChild getChild() {
			return null;
		}

		@Override
		public void close() throws IOException {
		}
	}

	File nameTempFile() {
		return Paths.get(getTestDirectoryPath(), name.getMethodName()).toFile();
	}

	static class MockClient extends Thread implements AutoCloseable {
		private static final DomObjId TRACE_ID = DomObjId.newBuilder().setId(0).build();
		private final SocketAddress addr;
		private final String name;

		private Throwable exc;

		Socket s;
		OutputStream out;
		InputStream in;

		public MockClient(SocketAddress addr, String name) {
			setDaemon(true);
			this.addr = addr;
			this.name = name;
		}

		void send(RootMessage msg) throws IOException {
			ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES);
			buf.putInt(msg.getSerializedSize());
			out.write(buf.array());
			msg.writeTo(out);
			out.flush();
		}

		RootMessage recv() throws IOException {
			int len = ByteBuffer.wrap(in.readNBytes(Integer.BYTES)).getInt();
			return RootMessage.parseFrom(in.readNBytes(len));
		}

		void completeNegotiation() throws IOException {
			send(RootMessage.newBuilder()
					.setRequestNegotiate(RequestNegotiate.newBuilder()
							.setVersion(TraceRmiHandler.VERSION)
							.setDescription("Mock Client"))
					.build());
			Msg.debug(this, "Sent negotation request");
			RootMessage reply = recv();
			Msg.debug(this, "Received: " + reply);
			assertNotNull(reply.getReplyNegotiate());
		}

		void createTrace() throws IOException {
			send(RootMessage.newBuilder()
					.setRequestCreateTrace(RequestCreateTrace.newBuilder()
							.setOid(TRACE_ID)
							.setLanguage(Language.newBuilder().setId("Toy:BE:64:default"))
							.setCompiler(Compiler.newBuilder().setId("default"))
							.setPath(FilePath.newBuilder().setPath(name)))
					.build());
			Msg.debug(this, "Sent createTrace request");
			RootMessage reply = recv();
			Msg.debug(this, "Received: " + reply);
			assertNotNull(reply.getReplyCreateTrace());
		}

		protected void doRun() throws Throwable {
			s = new Socket();
			s.connect(addr);
			out = s.getOutputStream();
			in = s.getInputStream();

			completeNegotiation();

			createTrace();

			s.close();
		}

		@Override
		public void run() {
			try {
				doRun();
			}
			catch (Throwable e) {
				Msg.error(this, "Mock client crashed", e);
				this.exc = e;
			}
		}

		@Override
		public void close() throws Exception {
			join(1000);
			if (exc != null) {
				throw new RuntimeException("Exception in mock client", exc);
			}
			assertFalse(isAlive());
		}
	}

	class TestScriptTraceRmiLaunchOffer extends AbstractScriptTraceRmiLaunchOffer {
		int nextNullId = 0;

		public TestScriptTraceRmiLaunchOffer(Program program, String header) throws ParseException {
			super(launchPlugin, program, nameTempFile(), name.getMethodName(),
				parse(header, name.getMethodName()));
		}

		@Override
		protected NullPtyTerminalSession nullPtyTerminal() throws IOException {
			return new NullPtyTerminalSession(new MockTerminal(), new MockPty(),
				"null-" + (++nextNullId));
		}

		@Override
		protected PtyTerminalSession runInTerminal(List<String> commandLine,
				Map<String, String> env, File workingDirectory,
				Collection<TerminalSession> subordinates) throws IOException {
			String host = env.get(ScriptAttributesParser.ENV_GHIDRA_TRACE_RMI_HOST);
			int port = Integer.parseInt(env.get(ScriptAttributesParser.ENV_GHIDRA_TRACE_RMI_PORT));
			// The plugin is waiting for a connection. Have to satisfy it to move on.
			client = new MockClient(new InetSocketAddress(host, port), name.getMethodName());
			client.start();
			return new PtyTerminalSession(new MockTerminal(), new MockPty(), new MockPtySession(),
				client);
		}
	}

	TraceRmiLauncherServicePlugin launchPlugin;

	MockClient client;

	record ResultAndClient(LaunchResult result, MockClient client) implements AutoCloseable {
		@Override
		public void close() throws Exception {
			client.close();
			result.close();
		}

		public PtyTerminalSession mockSession() {
			return new PtyTerminalSession(new MockTerminal(), new MockPty(), new MockPtySession(),
				client);
		}

		public NullPtyTerminalSession mockNull(String name) {
			return new NullPtyTerminalSession(new MockTerminal(), new MockPty(), name);
		}
	}

	ResultAndClient launchNoErr(TraceRmiLaunchOffer offer, Map<String, ValStr<?>> args)
			throws Throwable {
		LaunchResult result = offer.launchProgram(new ConsoleTaskMonitor(), new Config(args));
		if (result.exception() != null) {
			throw (result.exception());
		}
		return new ResultAndClient(result, client);
	}

	ResultAndClient launchNoErr(TraceRmiLaunchOffer offer) throws Throwable {
		return launchNoErr(offer, Map.of());
	}

	@Before
	public void setupOfferTest() throws PluginException {
		// BUG: Seems I shouldn't have to do this. It's in servicesRequired (transitive)
		addPlugin(tool, DebuggerTargetServicePlugin.class);
		launchPlugin = addPlugin(tool, TraceRmiLauncherServicePlugin.class);
	}

	@Test
	public void testTitleOnly() throws Throwable {
		createProgram();
		TraceRmiLaunchOffer offer = new TestScriptTraceRmiLaunchOffer(program, """
				@title Test
				""");

		try (ResultAndClient rac = launchNoErr(offer)) {
			assertEquals(Map.ofEntries(
				Map.entry("Shell", rac.mockSession())),
				rac.result.sessions());
		}
	}

	@Test
	public void testTtyAlways() throws Throwable {
		TraceRmiLaunchOffer offer = new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@tty TTY_TARGET
				""");
		try (ResultAndClient rac = launchNoErr(offer)) {
			assertEquals(Map.ofEntries(
				Map.entry("Shell", rac.mockSession()),
				Map.entry("TTY_TARGET", rac.mockNull("null-1"))),
				rac.result.sessions());
		}
	}

	@Test
	public void testTtyCondBoolFalse() throws Throwable {
		TraceRmiLaunchOffer offer = new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@env OPT_EXTRA_TTY:bool=false "Extra TTY" "Provide a separate tty."
				@tty TTY_TARGET if env:OPT_EXTRA_TTY
				""");
		try (ResultAndClient rac = launchNoErr(offer)) {
			assertEquals(Map.ofEntries(
				Map.entry("Shell", rac.mockSession())),
				rac.result.sessions());
		}
	}

	@Test
	public void testTtyCondBoolTrue() throws Throwable {
		TraceRmiLaunchOffer offer = new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@env OPT_EXTRA_TTY:bool=false "Extra TTY" "Provide a separate tty."
				@tty TTY_TARGET if env:OPT_EXTRA_TTY
				""");
		try (ResultAndClient rac = launchNoErr(offer, Map.of(
			"env:OPT_EXTRA_TTY", ValStr.from(true)))) {
			assertEquals(Map.ofEntries(
				Map.entry("Shell", rac.mockSession()),
				Map.entry("TTY_TARGET", rac.mockNull("null-1"))),
				rac.result.sessions());
		}
	}

	@Test(expected = ParseException.class)
	public void testTtyCondBoolTypeMismatch() throws Throwable {
		new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@env OPT_SOME_INT:int=0 "An integer" "Just an option for testing."
				@tty TTY_TARGET if env:OPT_SOME_INT
				""");
	}

	@Test(expected = ParseException.class)
	public void testTtyCondBoolNoSuch() throws Throwable {
		new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@tty TTY_TARGET if env:NO_SUCH
				""");
	}

	@Test
	public void testTtyCondStrEqFalse() throws Throwable {
		TraceRmiLaunchOffer offer = new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@env OPT_EXTRA_TTY:str="No" "Extra TTY" "Provide a separate tty."
				@tty TTY_TARGET if env:OPT_EXTRA_TTY == "Yes"
				""");
		try (ResultAndClient rac = launchNoErr(offer)) {
			assertEquals(Map.ofEntries(
				Map.entry("Shell", rac.mockSession())),
				rac.result.sessions());
		}
	}

	@Test
	public void testTtyCondStrEqTrue() throws Throwable {
		TraceRmiLaunchOffer offer = new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@env OPT_EXTRA_TTY:str="No" "Extra TTY" "Provide a separate tty."
				@tty TTY_TARGET if env:OPT_EXTRA_TTY == "Yes"
				""");
		try (ResultAndClient rac = launchNoErr(offer, Map.of(
			"env:OPT_EXTRA_TTY", ValStr.str("Yes")))) {
			assertEquals(Map.ofEntries(
				Map.entry("Shell", rac.mockSession()),
				Map.entry("TTY_TARGET", rac.mockNull("null-1"))),
				rac.result.sessions());
		}
	}

	@Test(expected = ParseException.class)
	public void testTtyCondStrEqNoSuch() throws Throwable {
		new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@tty TTY_TARGET if env:NO_SUCH == "Yes"
				""");
	}

	@Test
	public void testTtyCondIntEqFalse() throws Throwable {
		TraceRmiLaunchOffer offer = new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@env OPT_EXTRA_TTY:int=0 "Extra TTY" "Provide a separate tty."
				@tty TTY_TARGET if env:OPT_EXTRA_TTY == 6
				""");
		try (ResultAndClient rac = launchNoErr(offer)) {
			assertEquals(Map.ofEntries(
				Map.entry("Shell", rac.mockSession())),
				rac.result.sessions());
		}
	}

	@Test
	public void testTtyCondIntEqTrue() throws Throwable {
		TraceRmiLaunchOffer offer = new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@env OPT_EXTRA_TTY:int=0 "Extra TTY" "Provide a separate tty."
				@tty TTY_TARGET if env:OPT_EXTRA_TTY == 0b110
				""");
		try (ResultAndClient rac = launchNoErr(offer, Map.of(
			"env:OPT_EXTRA_TTY", ValStr.from(BigInteger.valueOf(6))))) {
			assertEquals(Map.ofEntries(
				Map.entry("Shell", rac.mockSession()),
				Map.entry("TTY_TARGET", rac.mockNull("null-1"))),
				rac.result.sessions());
		}
	}

	@Test(expected = ParseException.class)
	public void testTtyCondIntEqParseErr() throws Throwable {
		new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@env OPT_SOME_INT:int=0 "An integer" "Just an option for testing."
				@tty TTY_TARGET if env:OPT_SOME_INT == "Yes"
				""");
	}

	@Test(expected = ParseException.class)
	public void testTtyCondIntEqNoSuch() throws Throwable {
		new TestScriptTraceRmiLaunchOffer(null, """
				@title Test
				@no-image
				@tty TTY_TARGET if env:NO_SUCH == 6
				""");
	}
}
