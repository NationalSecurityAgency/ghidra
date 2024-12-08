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
package ghidra.features.bsim.gui;

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.Test;

import docking.widgets.OkDialog;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.features.bsim.gui.overview.BSimOverviewTestHelper;
import ghidra.features.bsim.gui.search.dialog.BSimSearchDialogTestHelper;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.facade.*;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.ResponseNearestVector;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.util.ProgramSelection;

public class BSimSearchPluginTest extends AbstractBSimPluginTest {

	@Test
	public void testNoFunctionSelected() {
		performAction(searchAction, false);
		OkDialog dialog = waitForDialogComponent(OkDialog.class);
		assertNotNull(dialog);
	}

	@Test
	public void testSingleFunctionQuery() {
		goTo(FUN1_ADDR);
		invokeBSimSearchAction();
		Set<FunctionSymbol> functions =
			BSimSearchDialogTestHelper.getSelectedFunctions(searchDialog);
		assertEquals(1, functions.size());
		assertEquals("FUN_01001100", functions.iterator().next().getName());

		assertNull(getServer());
		FunctionDatabaseTestDouble database = createTestDoubleWithDataForSingleFunction();
		BSimSearchDialogTestHelper.setBSimSearchTestServer(searchPlugin, searchDialog, database);

		doSearch();

		assertEquals(4, getMatchesModel().getRowCount());
		assertEquals(2, getExecutablesModel().getRowCount());
	}

	@Test
	public void testRepeatedQueryRemembersSettings() {
		goTo(FUN1_ADDR);
		invokeBSimSearchAction();
		assertNull(getServer());
		FunctionDatabaseTestDouble database = createTestDoubleWithDataForSingleFunction();
		BSimSearchDialogTestHelper.setBSimSearchTestServer(searchPlugin, searchDialog, database);

		doSearch();

		invokeBSimSearchAction();
		assertNotNull(getServer());

	}

	@Test
	public void testQueryWithSelection() {
		createMultiFunctionSelection();
		invokeBSimSearchAction();

		Set<FunctionSymbol> functions =
			BSimSearchDialogTestHelper.getSelectedFunctions(searchDialog);
		assertEquals(3, functions.size());

		FunctionDatabaseTestDouble database = createTestDoubleWithDataForSingleFunction();
		BSimSearchDialogTestHelper.setBSimSearchTestServer(searchPlugin, searchDialog, database);

		doSearch();
		assertEquals(4, getMatchesModel().getRowCount());
		assertEquals(2, getExecutablesModel().getRowCount());
	}

	@Test
	public void testOverviewQuery() {
		invokeBSimOverviewAction();
		FunctionDatabaseTestDouble database = createTestDoubleWithOverviewResults();
		BSimOverviewTestHelper.setBSimOVerviewTestServer(searchPlugin, overviewDialog, database);

		doOverview();
		assertEquals(4, getOverviewModel().getRowCount());
	}

//	private void setBSimTestServer() {
//		runSwing(() -> {
//			FunctionDatabaseTestDouble database =
//				createTestDoubleWithDataForSingleFunction(TEST_URL);
//			searchPlugin.setQueryServiceFactory(new TestSFQueryServiceFactory(database));
//			BSimServerInfo info = new TestBSimServerInfo(database);
//			BSimServerManager serverManager = searchPlugin.getServerManager();
//			serverManager.addServer(info);
//			BSimSearchDialogTestHelper.setSelectedServer(dialog, server);
//		});
//	}

//	private void setBSimOVerviewTestServer() {
//		runSwing(() -> {
//			FunctionDatabaseTestDouble database = createTestDoubleWithOverviewResults(TEST_URL);
//			searchPlugin.setQueryServiceFactory(new TestSFQueryServiceFactory(database));
//			BSimServerInfo info = new TestBSimServerInfo(database);
//			BSimServerManager serverManager = searchPlugin.getServerManager();
//			serverManager.addServer(info);
//			BSimSearchDialogTestHelper.setSelectedServer(dialog, server);
//		});
//	}

	private FunctionDatabaseTestDouble createTestDoubleWithDataForSingleFunction() {
		FunctionDatabaseTestDouble database = new FunctionDatabaseTestDouble();

		// create some canned data
		ResponseNearest response = new ResponseNearest(null);
		response.result.add(new TestSimilarityResult("queryFunction", "exec1", "matchFunction1",
			01001100, 0.9d, 15.0d));
		response.result.add(new TestSimilarityResult("queryFunction", "exec2", "matchFunction2",
			01001100, 0.9d, 15.0d));
		response.result.add(new TestSimilarityResult("queryFunction", "exec1", "matchFunction3",
			01001100, 0.9d, 15.0d));
		response.result.add(new TestSimilarityResult("queryFunction", "exec1", "matchFunction4",
			01001100, 0.9d, 15.0d));

		database.setQueryResponse(response); // set a valid response to be returned on query
		database.setCanInitialize(true); // initialize may be called--this is OK

		return database;
	}

	private FunctionDatabaseTestDouble createTestDoubleWithOverviewResults() {
		FunctionDatabaseTestDouble database = new FunctionDatabaseTestDouble();
		// create some canned data
		ResponseNearestVector response = new ResponseNearestVector(null);
		response.result.add(new TestNearestVectorResult("function1", "exec1", 12, 0.9d));
		response.result.add(new TestNearestVectorResult("function1", "exec2", 8, .9d));
		response.result.add(new TestNearestVectorResult("function2", "exec3", 32, .9d));
		response.result.add(new TestNearestVectorResult("function3", "exec4", 4, 9d));

		database.setQueryResponse(response); // set a valid response to be returned on query
		database.setCanInitialize(true); // initialize may be called--this is OK

		return database;
	}

	protected void createMultiFunctionSelection() {
		ProgramSelection selection = new ProgramSelection(addr(FUN1_ADDR), addr(FUN3_ADDR));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", selection, program));
		waitForSwing();
		program.flushEvents();
		waitForSwing();
	}

	private BSimServerInfo getServer() {
		return BSimSearchDialogTestHelper.getSelectedServer(searchDialog);
	}

	class TestBSimServerInfo extends BSimServerInfo {

		private FunctionDatabase database;

		public TestBSimServerInfo(FunctionDatabase database) {
			super(DBType.postgres, "0.0.0.0", 123, "testDB");
			this.database = database;
		}

		@Override
		public FunctionDatabase getFunctionDatabase(boolean async) {
			return database;
		}
	}

}
