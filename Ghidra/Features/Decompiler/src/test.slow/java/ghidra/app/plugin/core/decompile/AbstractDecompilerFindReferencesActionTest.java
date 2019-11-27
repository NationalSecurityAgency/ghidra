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

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.junit.Before;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.actions.AbstractFindReferencesDataTypeAction;
import ghidra.app.actions.AbstractFindReferencesToAddressAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.decompile.actions.FindReferencesToSymbolAction;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesProvider;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService;
import ghidra.app.services.DataTypeReference;
import ghidra.app.services.DataTypeReferenceFinder;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;
import mockit.*;

public abstract class AbstractDecompilerFindReferencesActionTest extends AbstractDecompilerTest {

	protected DockingActionIf findReferencesAction;
	protected DockingActionIf findReferencesToSymbolAction;
	protected DockingActionIf findReferencesToAddressAction;

	protected SpyDataTypeReferenceFinder<DataTypeReferenceFinder> spyReferenceFinder;
	protected SpyLocationReferencesService<LocationReferencesService> spyLocationReferenceService;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		findReferencesAction = getAction(decompiler, AbstractFindReferencesDataTypeAction.NAME);
		findReferencesToSymbolAction = getAction(decompiler, FindReferencesToSymbolAction.NAME);
		findReferencesToAddressAction =
			getAction(decompiler, AbstractFindReferencesToAddressAction.NAME);

		installSpyDataTypeReferenceFinder();
	}

	private void installSpyDataTypeReferenceFinder() {

		spyReferenceFinder = new SpyDataTypeReferenceFinder<>();
		replaceService(tool, DataTypeReferenceFinder.class, new StubDataTypeReferenceFinder());

		spyLocationReferenceService = new SpyLocationReferencesService<>();
	}

	protected void assertFindAllReferencesToCompositeFieldWasCalled() {
		assertEquals(1, spyReferenceFinder.getFindCompositeFieldReferencesCallCount());
		assertEquals(0, spyReferenceFinder.getFindDataTypeReferencesCallCount());
	}

	protected void assertFindAllReferencesToDataTypeWasCalled() {
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

		DecompilerActionContext context = new DecompilerActionContext(provider, addr(0x0), false);
		performAction(findReferencesAction, context, true);

		ThreadedTableModel<?, ?> model = waitForSearchProvider();
		return model;
	}

	protected ThreadedTableModel<?, ?> performFindReferencesToAddress() {
		// tricky business - the 'finder' is being run in a thread pool, so we must wait for that
		//                   model to finish loading

		DecompilerActionContext context = new DecompilerActionContext(provider, addr(0x0), false);
		performAction(findReferencesToAddressAction, context, true);

		ThreadedTableModel<?, ?> model = waitForSearchProvider();
		return model;
	}

	protected ThreadedTableModel<?, ?> performFindReferencesToSymbol() {
		// tricky business - the 'finder' is being run in a thread pool, so we must wait for that
		//                   model to finish loading

		DecompilerActionContext context = new DecompilerActionContext(provider, addr(0x0), false);
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

	public class SpyDataTypeReferenceFinder<T extends DataTypeReferenceFinder> extends MockUp<T> {

		private AtomicInteger dataTypeReferencesCallCount = new AtomicInteger();
		private AtomicInteger compositeFieldReferencesCallCount = new AtomicInteger();

		@Mock
		public void findReferences(Program p, DataType dataType,
				Consumer<DataTypeReference> callback, TaskMonitor monitor) {

			dataTypeReferencesCallCount.incrementAndGet();
		}

		@Mock
		public void findReferences(Program p, Composite composite, String fieldName,
				Consumer<DataTypeReference> callback, TaskMonitor monitor) {

			compositeFieldReferencesCallCount.incrementAndGet();
		}

		public int getFindDataTypeReferencesCallCount() {
			return dataTypeReferencesCallCount.get();
		}

		public int getFindCompositeFieldReferencesCallCount() {
			return compositeFieldReferencesCallCount.get();
		}
	}

	public class SpyLocationReferencesService<T extends LocationReferencesService>
			extends MockUp<T> {

		private AtomicInteger showReferencesCallCount = new AtomicInteger();

		@Mock
		public void showReferencesToLocation(Invocation invocation, ProgramLocation location,
				Navigatable navigatable) {
			showReferencesCallCount.incrementAndGet();
			invocation.proceed(location, navigatable);
		}

		public int getShowReferencesCallCount() {
			return showReferencesCallCount.get();
		}
	}
}
