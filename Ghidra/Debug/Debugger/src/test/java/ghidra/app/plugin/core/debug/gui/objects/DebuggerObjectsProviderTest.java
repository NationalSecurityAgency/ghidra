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
package ghidra.app.plugin.core.debug.gui.objects;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.util.database.UndoableTransaction;

public class DebuggerObjectsProviderTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected DebuggerObjectsPlugin objectsPlugin;
	protected DebuggerObjectsProvider objectsProvider;

	protected DebuggerStaticMappingService mappingService;
	protected CodeViewerService codeViewer;

	@Before
	public void setUpListingProviderTest() throws Exception {
		objectsPlugin = addPlugin(tool, DebuggerObjectsPlugin.class);
		objectsProvider = waitForComponentProvider(DebuggerObjectsProvider.class);

		mappingService = tool.getService(DebuggerStaticMappingService.class);
		codeViewer = tool.getService(CodeViewerService.class);
	}

	@Test
	public void testBasic() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		try (UndoableTransaction tid = tb.startTransaction()) {
			//objectsProvider.importFromXMLAction.run();
		}
		waitForDomainObject(tb.trace);
	}
}
