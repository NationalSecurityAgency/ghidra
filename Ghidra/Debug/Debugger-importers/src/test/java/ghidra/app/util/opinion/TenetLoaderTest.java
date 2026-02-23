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
package ghidra.app.util.opinion;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.util.List;

import org.junit.Ignore;
import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.model.DebuggerModelPlugin;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersPlugin;
import ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPlugin;
import ghidra.app.plugin.core.debug.gui.time.DebuggerTimePlugin;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.trace.model.thread.TraceThread;

public class TenetLoaderTest extends AbstractGhidraHeadedDebuggerTest {

	/**
	 * Create a byte array
	 *
	 * <p>
	 * This is basically syntactic sugar, since expressing a byte array literal can get obtuse in
	 * Java. {@code new byte[] {0, 1, 2, (byte) 0x80, (byte) 0xff}} vs
	 * {@code arr(0, 1, 2, 0x80, 0xff)}.
	 *
	 * @param e the bytes' values
	 * @return the array
	 */
	private byte[] arr(final int... e) {
		final byte[] result = new byte[e.length];
		for (int i = 0; i < e.length; i++) {
			result[i] = (byte) e[i];
		}
		return result;
	}

	private Trace createTraceWithLoader(final String testFile) throws Exception {
		this.createProgram();
		this.intoProject(this.program);

		final TenetLoader loader = new TenetLoader();
		final ByteProvider provider =
			new ByteArrayProvider("test.tenet", testFile.getBytes("utf8"));
		final LoadSpec loadSpec = Unique.assertOne(loader.findSupportedLoadSpecs(provider));

		final List<Option> options =
			loader.getDefaultOptions(provider, loadSpec, null, false, false);
		final Option programOption = Unique.assertOne(
			options.stream().filter(o -> o.getName().equals(TenetLoader.DOMAIN_FILE_OPTION_NAME)));
		programOption.setValue(this.program.getDomainFile().getPathname());

		final MessageLog log = new MessageLog();
		final ImporterSettings settings = new ImporterSettings(provider, "test",
			this.env.getProject(), "/", false, loadSpec, options, this, log, this.monitor);

		final LoadResults<? extends DomainObject> results = loader.load(settings);
		if (!(results.getPrimary().domainObject instanceof final Trace trace)) {
			fail("Import result was not a trace");
			return null;
		}

		return trace;

	}

	/*
	 * Test that the loader continues on a bad register name
	 */
	@Test
	public void testBadRegisterNames() throws Exception {
		final String testFile = """
				pc=0x1,rax=0x1234
				""";
		final Trace trace = this.createTraceWithLoader(testFile);
		assertNotNull(trace);
	}

	/*
	 * Test the filename check for the loader
	 */
	@Test
	public void testFileName() throws Exception {
		final String testFile = """
				slide=0x0
				pc=0x1,r0=0x1234
				pc=0x2,r1=0x4321
				""";

		this.createProgram();
		this.intoProject(this.program);

		final TenetLoader loader = new TenetLoader();

		ByteProvider provider = new ByteArrayProvider("test.tenet", testFile.getBytes("utf8"));
		Unique.assertOne(loader.findSupportedLoadSpecs(provider));

		provider = new ByteArrayProvider("test.trace", testFile.getBytes("utf8"));
		Unique.assertOne(loader.findSupportedLoadSpecs(provider));

		provider = new ByteArrayProvider("test.anythingelse", testFile.getBytes("utf8"));
		assertEquals(0, loader.findSupportedLoadSpecs(provider).size());
	}

	/*
	 * Automate loading a trace for manual testing purposes
	 */
	@Ignore
	public void testManual() throws Exception {
		final String testFile = """
				slide=0x0
				pc=0x1,r0=0x1234
				pc=0x2,r1=0x4321
				""";

		addPlugin(this.tool, DebuggerRegistersPlugin.class);
		addPlugin(this.tool, DebuggerModelPlugin.class);
		addPlugin(this.tool, DebuggerThreadsPlugin.class);
		addPlugin(this.tool, DebuggerListingPlugin.class);
		addPlugin(this.tool, DebuggerTimePlugin.class);

		final Trace trace = this.createTraceWithLoader(testFile);

		this.traceManager.openTrace(trace);
		this.traceManager.activateTrace(trace);

		Thread.sleep(1000);
	}

	/*
	 * Test that the loader after more than {@link TenetLoader.ERROR_THRESHOLD}
	 * lines with bad register names
	 */
	@Test
	public void testManyLinesBadRegisterNames() throws Exception {
		// Should fail after 10 lines with bad registers
		final String badTestFile = "pc=0x1,rax=0x1234\n".repeat(TenetLoader.ERROR_THRESHOLD + 1);
		assertThrows(LoadException.class, () -> this.createTraceWithLoader(badTestFile));
	}

	/*
	 * Test that the loader fails after {@TenetLoader.ERROR_THRESHOLD} lines
	 * without a PC
	 */
	@Test
	public void testManyLinesNoPc() throws Exception {
		// Should fail after {@TenetLoader.ERROR_THRESHOLD} lines with no PC
		final String badTestFile = "r1=0x1234\n".repeat(TenetLoader.ERROR_THRESHOLD + 1);
		assertThrows(LoadException.class, () -> this.createTraceWithLoader(badTestFile));
	}

	/*
	 * Test how the loader handles overlapping memory reads/writes
	 */
	@Test
	public void testMemoryValueOverlap() throws Exception {
		final String testFile = """
				pc=0x1,r0=0x1234,mr=0x1000:0000000000001337
				pc=0x2,r1=0x4321,mw=0x2000:deadbeefdeadbeef
				pc=0x3,mw=0x1000:87654321,mr=0x2000:c0ffee
				""";

		final Trace trace = this.createTraceWithLoader(testFile);

		final AddressSpace addrSpace =
			trace.getBaseLanguage().getAddressFactory().getDefaultAddressSpace();
		final ByteBuffer buffer =
			ByteBuffer.allocate(trace.getBaseLanguage().getProgramCounter().getNumBytes());

		trace.getMemoryManager().getBytes(0, addrSpace.getAddress(0x1000), buffer);
		assertArrayEquals(this.arr(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x13, 0x37), buffer.array());

		buffer.clear();
		trace.getMemoryManager().getBytes(1, addrSpace.getAddress(0x2000), buffer);
		assertArrayEquals(this.arr(0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef), buffer.array());

		buffer.clear();
		trace.getMemoryManager().getBytes(2, addrSpace.getAddress(0x1000), buffer);
		assertArrayEquals(this.arr(0x87, 0x65, 0x43, 0x21, 0x00, 0x00, 0x13, 0x37), buffer.array());

		buffer.clear();
		trace.getMemoryManager().getBytes(2, addrSpace.getAddress(0x2000), buffer);
		assertArrayEquals(this.arr(0xc0, 0xff, 0xee, 0xef, 0xde, 0xad, 0xbe, 0xef), buffer.array());
	}

	/*
	 * Test that the loader continues after a line with no PC
	 */
	@Test
	public void testNoPc() throws Exception {
		final String testFile = """
				pc=0x1,r1=0x1234
				r2=0x1234
				""";
		final Trace trace = this.createTraceWithLoader(testFile);
		assertNotNull(trace);
	}

	/*
	 * Test that the loader handles no slide value properly
	 */
	@Test
	public void testNoSlideValue() throws Exception {
		final String testFile = """
				pc=0x1,r0=0x1234
				pc=0x2,r1=0x4321
				""";

		final Trace trace = this.createTraceWithLoader(testFile);

		final TraceStaticMapping staticMapping =
			Unique.assertOne(trace.getStaticMappingManager().getAllEntries());
		assertEquals(this.program.getImageBase().getUnsignedOffset(),
			staticMapping.getMinTraceAddress().getUnsignedOffset());
	}

	/*
	 * Test that the loader parses register values properly
	 */
	@Test
	public void testRegisterValues() throws Exception {
		final String testFile = """
				slide=0x0
				pc=0x1,r0=0x1234
				pc=0x2,r1=0x4321
				""";

		final Trace trace = this.createTraceWithLoader(testFile);

		final TraceThread thread = Unique.assertOne(trace.getThreadManager().getAllThreads());
		final TraceMemorySpace regs =
			trace.getMemoryManager().getMemoryRegisterSpace(thread, false);

		assertNotNull(regs);
		assertEquals("1",
			regs.getValue(0, this.program.getLanguage().getProgramCounter())
					.getUnsignedValue()
					.toString(16));

		assertEquals("2",
			regs.getValue(1, this.program.getLanguage().getProgramCounter())
					.getUnsignedValue()
					.toString(16));

	}

	/*
	 * Test that the loader handles a slide value properly
	 */
	@Test
	public void testWithSlideValue() throws Exception {
		final String testFile = """
				slide=0x10000
				pc=0x1,r0=0x1234
				pc=0x2,r1=0x4321
				""";

		final Trace trace = this.createTraceWithLoader(testFile);

		final TraceStaticMapping staticMapping =
			Unique.assertOne(trace.getStaticMappingManager().getAllEntries());
		assertEquals(this.program.getImageBase().getUnsignedOffset() + 0x10000,
			staticMapping.getMinTraceAddress().getUnsignedOffset());
	}
}
