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
package ghidra.app.plugin.core.decompile;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.junit.Before;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.actions.AbstractFindReferencesDataTypeAction;
import ghidra.app.actions.AbstractFindReferencesToAddressAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.decompile.actions.FindReferencesToHighSymbolAction;
import ghidra.app.plugin.core.navigation.FindAppliedDataTypesService;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesProvider;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService;
import ghidra.app.services.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDecompilerFindReferencesActionTest extends AbstractDecompilerTest {

	protected DockingActionIf findReferencesAction;
	protected DockingActionIf findReferencesToSymbolAction;
	protected DockingActionIf findReferencesToAddressAction;

	protected SpyLocationReferencesService spyLocationReferenceService;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		findReferencesAction = getAction(decompiler, AbstractFindReferencesDataTypeAction.NAME);
		findReferencesToSymbolAction = getAction(decompiler, FindReferencesToHighSymbolAction.NAME);
		findReferencesToAddressAction =
			getAction(decompiler, AbstractFindReferencesToAddressAction.NAME);

		installSpyDataTypeReferenceFinder();
	}

	private void installSpyDataTypeReferenceFinder() {

		//
		// We replace services in order for us to spy on system internals.   This gets tricky
		// because the LocationReferencesPlugin installs 2 services. So, when we replace it, we
		// lose both of it services.  We only want to replace one of the services, so we have to
		// re-install the plugin to be the service provider for the service we still need.
		//
		FindAppliedDataTypesService fadService = tool.getService(FindAppliedDataTypesService.class);
		replaceService(tool, DataTypeReferenceFinder.class, new SpyDataTypeReferenceFinder());

		LocationReferencesService lrService = tool.getService(LocationReferencesService.class);
		spyLocationReferenceService = new SpyLocationReferencesService(lrService);
		replaceService(tool, LocationReferencesService.class, spyLocationReferenceService);

		// as noted above, put back this service implementation
		replaceService(tool, FindAppliedDataTypesService.class, fadService);
	}

	protected void assertFindAllReferencesToCompositeFieldWasCalled() {

		int last = SpyDataTypeReferenceFinder.instances.size() - 1;
		SpyDataTypeReferenceFinder spyReferenceFinder =
			SpyDataTypeReferenceFinder.instances.get(last);
		assertEquals(1, spyReferenceFinder.getFindCompositeFieldReferencesCallCount());
		assertEquals(0, spyReferenceFinder.getFindDataTypeReferencesCallCount());
	}

	protected void assertFindAllReferencesToDataTypeWasCalled() {

		int last = SpyDataTypeReferenceFinder.instances.size() - 1;
		SpyDataTypeReferenceFinder spyReferenceFinder =
			SpyDataTypeReferenceFinder.instances.get(last);
		assertEquals(0, spyReferenceFinder.getFindCompositeFieldReferencesCallCount());
		assertEquals(1, spyReferenceFinder.getFindDataTypeReferencesCallCount());
	}

	protected void assertFindAllReferencesToSymbolWasCalled() {
		assertEquals(1, spyLocationReferenceService.getShowReferencesCallCount());
	}

	protected void assertFindAllReferencesToAddressWasCalled() {
		assertEquals(1, spyLocationReferenceService.getShowReferencesCallCount());
	}

	protected ThreadedTableModel<?, ?> performFindDataTypes() {
		// tricky business - the 'finder' is being run in a thread pool, so we must wait for that
		//                   model to finish loading

		DecompilerActionContext context =
			new DecompilerActionContext(provider, addr(0x0), false);
		performAction(findReferencesAction, context, true);

		ThreadedTableModel<?, ?> model = waitForSearchProvider();
		return model;
	}

	protected ThreadedTableModel<?, ?> performFindReferencesToAddress() {
		// tricky business - the 'finder' is being run in a thread pool, so we must wait for that
		//                   model to finish loading

		DecompilerActionContext context =
			new DecompilerActionContext(provider, addr(0x0), false);
		performAction(findReferencesToAddressAction, context, true);

		ThreadedTableModel<?, ?> model = waitForSearchProvider();
		return model;
	}

	protected ThreadedTableModel<?, ?> performFindReferencesToSymbol() {
		// tricky business - the 'finder' is being run in a thread pool, so we must wait for that
		//                   model to finish loading

		DecompilerActionContext context =
			new DecompilerActionContext(provider, addr(0x0), false);
		performAction(findReferencesToSymbolAction, context, true);

		ThreadedTableModel<?, ?> model = waitForSearchProvider();
		return model;
	}

	protected ThreadedTableModel<?, ?> waitForSearchProvider() {

		LocationReferencesProvider searchProvider =
			(LocationReferencesProvider) tool.getComponentProvider(LocationReferencesProvider.NAME);

		assertNotNull("Could not find the Location References Provider", searchProvider);
		ThreadedTableModel<?, ?> model = getTableModel(searchProvider);
		waitForTableModel(model);

		return model;
	}

	protected ThreadedTableModel<?, ?> getTableModel(
			LocationReferencesProvider referencesProvider) {
		Object referencesPanel = getInstanceField("referencesPanel", referencesProvider);
		return (ThreadedTableModel<?, ?>) getInstanceField("tableModel", referencesPanel);
	}

	protected void assertActionInPopup() {
		ActionContext context = provider.getActionContext(null);
		assertTrue("'Find References to' action should be enabled; currently selected token: " +
			provider.currentTokenToString(), findReferencesAction.isAddToPopup(context));
	}

	protected void assertActionNotInPopup() {
		ActionContext context = provider.getActionContext(null);
		assertFalse(
			"'Find References to' action should not be enabled; currently selected token: " +
				provider.currentTokenToString(),
			findReferencesAction.isAddToPopup(context));
	}

	public static class SpyDataTypeReferenceFinder implements DataTypeReferenceFinder {

		private static List<SpyDataTypeReferenceFinder> instances = new ArrayList<>();

		private AtomicInteger dataTypeReferencesCallCount = new AtomicInteger();
		private AtomicInteger compositeFieldReferencesCallCount = new AtomicInteger();

		public SpyDataTypeReferenceFinder() {

			// Instances of this class are created by ReferenceUtils via the ClassSearcher. Save
			// the instances so we can use the spy in the test
			instances.add(this);
		}

		@Override
		public void findReferences(Program p, DataType dataType,
				Consumer<DataTypeReference> callback, TaskMonitor monitor) {

			dataTypeReferencesCallCount.incrementAndGet();
		}

		@Override
		public void findReferences(Program p, DataType dt, String fieldName,
				Consumer<DataTypeReference> callback, TaskMonitor monitor) {

			compositeFieldReferencesCallCount.incrementAndGet();
		}

		@Override
		public void findReferences(Program p, FieldMatcher fieldMatcher,
				Consumer<DataTypeReference> callback, TaskMonitor monitor) {

			if (fieldMatcher.isIgnored()) {
				// an empty field matcher signals a data type search
				dataTypeReferencesCallCount.incrementAndGet();
			}
			else {
				compositeFieldReferencesCallCount.incrementAndGet();
			}
		}

		public int getFindDataTypeReferencesCallCount() {
			return dataTypeReferencesCallCount.get();
		}

		public int getFindCompositeFieldReferencesCallCount() {
			return compositeFieldReferencesCallCount.get();
		}
	}

	public class SpyLocationReferencesService implements LocationReferencesService {

		private AtomicInteger showReferencesCallCount = new AtomicInteger();
		private LocationReferencesService lrService;

		public SpyLocationReferencesService(LocationReferencesService lrService) {
			this.lrService = lrService;
		}

		@Override
		public void showReferencesToLocation(ProgramLocation location, Navigatable navigatable) {
			showReferencesCallCount.incrementAndGet();
			lrService.showReferencesToLocation(location, navigatable);
		}

		public int getShowReferencesCallCount() {
			return showReferencesCallCount.get();
		}

		@Override
		public HelpLocation getHelpLocation() {
			return null;
		}

	}

}
