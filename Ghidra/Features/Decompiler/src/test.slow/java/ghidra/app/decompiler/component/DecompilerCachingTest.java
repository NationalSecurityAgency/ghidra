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
package ghidra.app.decompiler.component;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

import org.junit.*;

import com.google.common.cache.*;

import docking.ComponentProvider;
import generic.test.TestUtils;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;
import mockit.Mock;
import mockit.MockUp;

public class DecompilerCachingTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private DecompilePlugin decompilePlugin;
	private CodeBrowserPlugin codeBrowser;
	private ProgramDB program;
	private List<Address> functionAddrs = new ArrayList<>();
	private DecompilerProvider decompilerProvider;
	public Cache<Function, DecompileResults> cache;
	private ToyProgramBuilder builder;

	// partial fake of DecompilerController to take control of the buildCache() method.
	public class FakeDecompilerController extends MockUp<DecompilerController> {
		@Mock
		public Cache<Function, DecompileResults> buildCache() {
			//@formatter:off
			cache = CacheBuilder
				.newBuilder()
				.maximumSize(3)
				.recordStats()
				.build()
				;
			//@formatter:on
			return cache;
		}
	}

	@Before
	public void setUp() throws Exception {
		// the magic of JMockit will cause our FakeDecompilerController to get used instead
		// of the real one, regardless of where it gets constructed.
		new FakeDecompilerController();

		setErrorGUIEnabled(false);

		env = new TestEnv();
		tool = env.getTool();

		initializeTool();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testNewFunctionIsCacheMiss() {
		goTo(functionAddrs.get(0));
		CacheStats stats1 = cache.stats();

		goTo(functionAddrs.get(1));
		CacheStats stats2 = cache.stats();

		assertEquals("Expected hitCount to stay the same", stats1.hitCount(), stats2.hitCount());
		assertEquals("Expected missCount to increment", stats1.missCount() + 1, stats2.missCount());
	}

	@Test
	public void testReturnToPreviousFunctionIsCacheHit() {
		goTo(functionAddrs.get(0));
		goTo(functionAddrs.get(1));
		CacheStats stats1 = cache.stats();

		goTo(functionAddrs.get(0));
		CacheStats stats2 = cache.stats();

		assertEquals("Expected hitCount to increment", stats1.hitCount() + 1, stats2.hitCount());
		assertEquals("Expected missCount to stay the same", stats1.missCount(), stats2.missCount());
	}

	@Test
	public void testCacheRemovesEntryWhenSizeIsExceeded() {
		// cache size was set to 3 for this test
		goTo(functionAddrs.get(0));
		goTo(functionAddrs.get(1));
		goTo(functionAddrs.get(2));
		goTo(functionAddrs.get(3));
		CacheStats stats1 = cache.stats();

		goTo(functionAddrs.get(2));
		goTo(functionAddrs.get(1));

		CacheStats stats2 = cache.stats();

		assertEquals("Expected hitCount to increment by 2", stats1.hitCount() + 2,
			stats2.hitCount());
		assertEquals("Expected missCount to stay the same", stats1.missCount(), stats2.missCount());

		goTo(functionAddrs.get(0));
		CacheStats stats3 = cache.stats();

		assertEquals("Expected hitCount to stay the same", stats2.hitCount(), stats3.hitCount());
		assertEquals("Expected missCount to stay to increment by 1", stats2.missCount() + 1,
			stats3.missCount());

	}

	@Test
	public void testDomainChangeClearsTheCache() {
		goTo(functionAddrs.get(0));
		goTo(functionAddrs.get(1));
		goTo(functionAddrs.get(2));

		CacheStats stats1 = cache.stats();

		generateDomainObjectChange();

		goTo(functionAddrs.get(0));
		goTo(functionAddrs.get(1));

		CacheStats stats2 = cache.stats();

		assertEquals("Expected hitCount to not change", stats1.hitCount(), stats2.hitCount());
		assertEquals("Expected missCount to increment by 2", stats1.missCount() + 2,
			stats2.missCount());
	}

	@Test
	public void testCacheIsClearedWhenProgramIsClosed() {
		goTo(functionAddrs.get(0));
		goTo(functionAddrs.get(1));
		goTo(functionAddrs.get(2));
		assertCacheSize(3);

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram(program, true);
		waitForSwing();
		assertCacheSize(0);
	}

	@Test
	public void testCacheIsClearedWhenOptionsChange() {
		goTo(functionAddrs.get(0));
		goTo(functionAddrs.get(1));
		goTo(functionAddrs.get(2));
		assertCacheSize(3);

		decompilerProvider.optionsChanged(new ToolOptions("Decompiler"), "Anything", null, null);
		assertCacheSize(0);
	}

	private void initializeTool() throws Exception {
		installPlugins();

		openProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		showTool(tool);
		showDecompilerProvider();
	}

	private void showDecompilerProvider() {
		ComponentProvider decompiler = tool.getComponentProvider("Decompiler");
		tool.showComponentProvider(decompiler, true);
		decompilerProvider = waitForComponentProvider(DecompilerProvider.class);
	}

	private void openProgram() throws Exception {

		builder = new ToyProgramBuilder("notepad", true);
		builder.createMemory(".text", "0x1004000", 0x1000);
		buildDummyFunction(builder, "fun1", "0x1004000");
		buildDummyFunction(builder, "fun2", "0x1004002");
		buildDummyFunction(builder, "fun3", "0x1004004");
		buildDummyFunction(builder, "fun4", "0x1004006");
		buildDummyFunction(builder, "fun5", "0x1004008");
		buildDummyFunction(builder, "fun6", "0x100400a");
		buildDummyFunction(builder, "fun7", "0x100400c");
		buildDummyFunction(builder, "fun8", "0x100400e");
		program = builder.getProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	private void assertCacheSize(int expected) {
		Supplier<String> supplier = () -> getCacheSizeFailureMessage(expected);
		waitForCondition(() -> cache.size() == expected, supplier);
	}

	private String getCacheSizeFailureMessage(int expected) {
		StringBuilder buffy = new StringBuilder("Cache size is not as expected - expected " +
			expected + "; found " + cache.size() + "\nEntries in cache:\n");
		ConcurrentMap<Function, DecompileResults> map = cache.asMap();
		Set<Entry<Function, DecompileResults>> entries = map.entrySet();
		for (Entry<Function, DecompileResults> entry : entries) {
			Function key = entry.getKey();
			buffy.append('\t').append(key.getName()).append('\n');
		}
		return buffy.toString();
	}

	private void buildDummyFunction(ToyProgramBuilder programBuilder, String functionName,
			String address) throws MemoryAccessException {
		programBuilder.addBytesReturn(address);
		programBuilder.disassemble(address, 2, true);
		programBuilder.createFunction(address);
		programBuilder.createLabel(address, functionName);// function label
		functionAddrs.add(programBuilder.addr(address));

	}

	private void generateDomainObjectChange() {
		builder.createFunctionComment("0x1004000", "Hey There");
	}

	private void installPlugins() throws PluginException {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(DecompilePlugin.class.getName());

		decompilePlugin = env.getPlugin(DecompilePlugin.class);
		codeBrowser = env.getPlugin(CodeBrowserPlugin.class);
	}

	private void goTo(Address addr) {
		ProgramLocation location = new ProgramLocation(program, addr);
		assertTrue(codeBrowser.goTo(location, true));

		waitForSwing();
		waitForBusyDecompile();
	}

	private void waitForBusyDecompile() {
		DecompilerController controller =
			(DecompilerController) TestUtils.getInstanceField("controller", decompilerProvider);
		waitForCondition(() -> !controller.isDecompiling());
	}

}
