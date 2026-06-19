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
package ghidra.app.plugin.core.debug.service.modules;

import static org.junit.Assert.*;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectManager;
import ghidra.trace.model.target.path.PathFilter;
import ghidra.trace.model.target.path.PathPattern;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.trace.model.target.schema.XmlSchemaContext;

/**
 * Regression test for GitHub issue #8145: opening a file with the Emulator tool enumerates
 * every file in a shared project.
 *
 * Root cause: ProgramModuleIndexer.indexFolder() was called eagerly in the constructor,
 * scanning every DomainFile in the project (and calling getMetadata() on each) the moment
 * the Debugger tool was opened. On a large shared project this caused hundreds of server
 * round-trips before any actual work was done.
 *
 * Fix: indexFolder() is now deferred until the first call to getBestEntries().
 */
public class ProgramModuleIndexerTest extends AbstractGhidraHeadedDebuggerTest {

	private static final String CTX_XML = """
			<context>
			    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
			        <attribute name='Processes' schema='ProcessContainer' />
			    </schema>
			    <schema name='ProcessContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <element index='1' schema='Process' />
			    </schema>
			    <schema name='Process' elementResync='NEVER' attributeResync='ONCE'>
			        <attribute name='Modules' schema='ModuleContainer' />
			    </schema>
			    <schema name='ModuleContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <element schema='Module' />
			    </schema>
			    <schema name='Module' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Module' />
			    </schema>
			</context>""";

	/**
	 * Static counter used by TrackingIndexer to record indexFolder invocations.
	 *
	 * Must be static (not an instance field on TrackingIndexer) because the super-constructor
	 * calls the overridden indexFolder() before Java runs subclass field initializers, which
	 * would leave an instance AtomicInteger null and cause a NPE in the RED state.
	 */
	private static AtomicInteger folderScanCount;

	private static class TrackingIndexer extends ProgramModuleIndexer {
		TrackingIndexer(ghidra.framework.plugintool.PluginTool tool) {
			super(tool);
		}

		@Override
		protected void indexFolder(DomainFolder folder) {
			if (folderScanCount != null) {
				folderScanCount.incrementAndGet();
			}
			super.indexFolder(folder);
		}
	}

	/**
	 * Populate the project with {@code count} uniquely-named program files to make any
	 * eager project scan observable. Each call uses a distinct name to avoid duplicate-file
	 * errors across loop iterations.
	 */
	private void populateProject(int count) throws Exception {
		Language lang = getToyBE64Language();
		for (int i = 0; i < count; i++) {
			program = new ProgramDB("dummy_prog_" + i, lang, lang.getDefaultCompilerSpec(), this);
			intoProject(program);
			program.release(this);
			program = null;
		}
	}

	private TraceModule addModule(String moduleName) throws Exception {
		SchemaContext ctx = XmlSchemaContext.deserialize(CTX_XML);
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager()
					.createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
		PathPattern modulePattern = PathFilter.parse("Processes[1].Modules[]");
		TraceObjectManager om = tb.trace.getObjectManager();
		Lifespan span = Lifespan.nowOn(0);
		try (Transaction tx = tb.startTransaction()) {
			TraceModule module = Objects.requireNonNull(
				om.createObject(modulePattern.applyKeys(moduleName).getSingletonPath())
						.insert(span, ConflictResolution.TRUNCATE)
						.getDestination(null)
						.queryInterface(TraceModule.class));
			module.getObject().setAttribute(span, TraceModule.KEY_MODULE_NAME, moduleName);
			module.getObject()
					.setAttribute(span, TraceModule.KEY_RANGE, tb.range(0x55550000, 0x5554ffff));
			return module;
		}
	}

	/**
	 * RED before fix: indexFolder is called inside the ProgramModuleIndexer constructor,
	 * so folderScanCount > 0 immediately after construction.
	 *
	 * GREEN after fix: construction completes with folderScanCount == 0.
	 */
	@Test
	public void testConstructorDoesNotScanProject() throws Exception {
		populateProject(5);

		folderScanCount = new AtomicInteger();
		TrackingIndexer indexer = new TrackingIndexer(tool);
		try {
			assertEquals(
				"indexFolder must not be called during construction (eager scan causes " +
					"server round-trips on every project file for shared projects)",
				0, folderScanCount.get());
		}
		finally {
			indexer.dispose();
		}
	}

	/**
	 * Verifies the other side of the contract: the scan does happen on the first
	 * getBestEntries() call, so module-mapping proposals still work correctly.
	 */
	@Test
	public void testFirstQueryTriggersLazyScan() throws Exception {
		populateProject(3);
		createTrace();
		TraceModule module = addModule("target_firmware");

		folderScanCount = new AtomicInteger();
		TrackingIndexer indexer = new TrackingIndexer(tool);
		try {
			assertEquals("no scan should have occurred yet", 0, folderScanCount.get());

			indexer.getBestEntries(module, 0);

			assertTrue("getBestEntries must trigger the deferred project scan",
				folderScanCount.get() > 0);
		}
		finally {
			indexer.dispose();
		}
	}

	/**
	 * Verifies that subsequent queries do not re-trigger the scan.
	 */
	@Test
	public void testSubsequentQueriesDoNotRescan() throws Exception {
		createTrace();
		TraceModule module = addModule("target_firmware");

		folderScanCount = new AtomicInteger();
		TrackingIndexer indexer = new TrackingIndexer(tool);
		try {
			indexer.getBestEntries(module, 0); // triggers scan
			int countAfterFirst = folderScanCount.get();
			assertTrue(countAfterFirst > 0);

			indexer.getBestEntries(module, 0); // must not re-scan
			assertEquals("subsequent queries must not re-trigger the project scan",
				countAfterFirst, folderScanCount.get());
		}
		finally {
			indexer.dispose();
		}
	}
}
