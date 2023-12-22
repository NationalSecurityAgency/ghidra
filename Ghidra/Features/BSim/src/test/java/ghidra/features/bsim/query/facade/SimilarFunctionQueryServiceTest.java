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
package ghidra.features.bsim.query.facade;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.*;

import ghidra.features.bsim.gui.search.results.BSimMatchResult;
import ghidra.features.bsim.query.protocol.QueryResponseRecord;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class SimilarFunctionQueryServiceTest extends AbstractGhidraHeadlessIntegrationTest {

	private TestEnv env;
	private Program program;
	SimilarFunctionQueryService queryService;

	public SimilarFunctionQueryServiceTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = env.getProgram("notepad_w2k");
	}

	@After
	public void tearDown() throws Exception {
		if (queryService != null) {
			queryService.dispose();
		}
		env.release(program);
		env.dispose();
	}

	@Test
	public void testBuildQueryWithEmptyFunctions() throws Exception {
		Set<FunctionSymbol> functions = new HashSet<>();
		try {
			new SFQueryInfo(functions);
			Assert.fail("Did not get expected exception passing an empty functions list");
		}
		catch (IllegalArgumentException iae) {
			// good!
		}
	}

	@Test
	public void testQueryValidServerWithFunctions() throws Exception {
		createQueryService();

		Set<FunctionSymbol> functions = createKnownFunctionsSet();
		SFQueryInfo queryInfo = new SFQueryInfo(functions);
		String serverURL = "ghidra://localhost/repo";

		queryService.initializeDatabase(serverURL);
		SFQueryResult result =
			queryService.querySimilarFunctions(queryInfo, null, TaskMonitor.DUMMY);
		assertNotNull(result);

		List<BSimMatchResult> similarFunctions =
			BSimMatchResult.generate(result.getSimilarityResults(), program);
		assertTrue(similarFunctions.isEmpty());
	}

	@Test
	public void testQueryWithStagingOn() throws Exception {
		createQueryService();

		Set<FunctionSymbol> functions = createKnownFunctionsSet();
		SFQueryInfo queryInfo = new SFQueryInfo(functions);
		queryService.setNumberOfStages(2);
		String serverURL = "ghidra://localhost/repo";

		queryService.initializeDatabase(serverURL);
		SFQueryResult result =
			queryService.querySimilarFunctions(queryInfo, null, TaskMonitor.DUMMY);
		assertNotNull(result);

		List<BSimMatchResult> similarFunctions =
			BSimMatchResult.generate(result.getSimilarityResults(), program);
		assertTrue(similarFunctions.isEmpty());
	}

	@Test
	public void testResultsListener() throws Exception {
		createQueryService();

		Set<FunctionSymbol> functions = createKnownFunctionsSet();
		SFQueryInfo queryInfo = new SFQueryInfo(functions);

		ResultsListener resultsListener = new ResultsListener();
		String serverURL = "ghidra://localhost/repo";

		queryService.initializeDatabase(serverURL);
		queryService.querySimilarFunctions(queryInfo, resultsListener, TaskMonitor.DUMMY);

		assertTrue("Did not receive a resultsAdded() callback",
			resultsListener.resultsAddedCount >= 1);
		assertTrue("Did not complete", resultsListener.operationComplete);
		assertNotNull("Did not receive a final result", resultsListener.finalResult);
	}

	@Test
	public void testResultsListenerWithMultipleStagesGetsMultipleCallbacks() throws Exception {
		createQueryService();

		Set<FunctionSymbol> functions = createKnownFunctionsSet();
		SFQueryInfo queryInfo = new SFQueryInfo(functions);

		ResultsListener resultsListener = new ResultsListener();

		int stageCount = 2;
		queryService.setNumberOfStages(stageCount);

		String serverURL = "ghidra://localhost/repo";

		queryService.initializeDatabase(serverURL);
		queryService.querySimilarFunctions(queryInfo, resultsListener, TaskMonitor.DUMMY);

		assertEquals("Did not receive a resultsAdded() callback", stageCount,
			resultsListener.resultsAddedCount);
		assertTrue("Did not complete", resultsListener.operationComplete);
		assertNotNull("Did not receive a final result", resultsListener.finalResult);

		resultsListener = new ResultsListener();

		stageCount = 3;

		// Note: the staging code will not allow the number of stages to go past the number of functions
		int actualStageCount = 2;
		queryService.setNumberOfStages(stageCount);

		queryService.querySimilarFunctions(queryInfo, resultsListener, TaskMonitor.DUMMY);

		assertEquals("Did not receive a resultsAdded() callback", actualStageCount,
			resultsListener.resultsAddedCount);
		assertTrue("Did not complete", resultsListener.operationComplete);
		assertNotNull("Did not receive a final result", resultsListener.finalResult);
	}

	@Test
	public void testMultipleQueriesToSameDatabaseGeneratesMultipleConnectedCallbacks()
			throws Exception {
		createQueryService();

		Set<FunctionSymbol> functions = createKnownFunctionsSet();
		SFQueryInfo queryInfo = new SFQueryInfo(functions);

		ResultsListener resultsListener = new ResultsListener();
		String serverURL = "ghidra://localhost/repo";

		queryService.initializeDatabase(serverURL);

		queryService.querySimilarFunctions(queryInfo, resultsListener, TaskMonitor.DUMMY);
		assertTrue("Did not complete", resultsListener.operationComplete);
		assertNotNull("Did not receive a final result", resultsListener.finalResult);

		resultsListener.reset();

		queryService.querySimilarFunctions(queryInfo, resultsListener, TaskMonitor.DUMMY);
		assertTrue("Did not complete", resultsListener.operationComplete);
		assertNotNull("Did not receive a final result", resultsListener.finalResult);
	}

	@Test
	public void testQueryInvalidServer() {
		//
		// Make sure we get a connection error when attempting to connect when a server is not
		// running.  For this test, all we need to do is not supply a database test double.
		//

		queryService = new SimilarFunctionQueryService(program);
		Set<FunctionSymbol> functions = createKnownFunctionsSet();
		SFQueryInfo queryInfo = new SFQueryInfo(functions);
		String serverURL = "ghidra://localhost/repo";

		try {
			queryService.initializeDatabase(serverURL);
			queryService.querySimilarFunctions(queryInfo, null, TaskMonitor.DUMMY);
			Assert.fail("Did not receive an exception for failing to connect to the database: " +
				serverURL);
		}
		catch (CancelledException ce) {
			// shouldn't happen
		}
		catch (QueryDatabaseException qde) {
			// good!
		}
	}

	@Test
	public void testCreatingQueryInfo() {
		try {
			new SFQueryInfo(null);
			Assert.fail("Did not get exception passing null for function list");
		}
		catch (Exception e) {
			// good!
		}

		try {
			new SFQueryInfo(new HashSet<FunctionSymbol>());
			Assert.fail("Did not get exception passing null for function list");
		}
		catch (Exception e) {
			// good!
		}
	}

	@Test
	public void testInvalidUserMadeQuery() throws QueryDatabaseException {
		createQueryService();

		Set<FunctionSymbol> functions = createKnownFunctionsSet();
		SFQueryInfo queryInfo = new BadQueryInfo(functions);
		String serverURL = "ghidra://localhost/repo";

		queryService.initializeDatabase(serverURL);
		try {
			queryService.querySimilarFunctions(queryInfo, null, TaskMonitor.DUMMY);
			Assert.fail(
				"Did not get an exception with a user-defined query that returns a null function list");
		}
		catch (Exception e) {
			// good!
		}
	}

	@Test
	public void testCancelQuery() throws Exception {
		//
		// Rather than start multiple threads to test cancelling, we will just start the monitor
		// in the cancelled state to simulate the user cancelling.
		//
		createQueryService();

		Set<FunctionSymbol> functions = createKnownFunctionsSet();
		SFQueryInfo queryInfo = new SFQueryInfo(functions);

		ResultsListener resultsListener = new ResultsListener();
		String serverURL = "ghidra://localhost/repo";

		TaskMonitorAdapter monitor = new TaskMonitorAdapter();
		monitor.setCancelEnabled(true);
		monitor.cancel();

		queryService.initializeDatabase(serverURL);

		try {
			queryService.querySimilarFunctions(queryInfo, resultsListener, monitor);
			Assert.fail("Did not get a cancelled exception as expected");
		}
		catch (CancelledException ce) {
			// good!
		}

		assertEquals("Received a callback when the work should have been cancelled", 0,
			resultsListener.resultsAddedCount);
		assertTrue("Did not complete", resultsListener.operationComplete);
		assertNull("Did not receive a final result", resultsListener.finalResult);
	}

	@Test
	public void testChangeDatabase() throws Exception {
		//
		// Test that passing a different database URL doesn't blow up (the database is cached, but
		// should change when the user changes URLs)
		//
		createQueryService();

		Set<FunctionSymbol> functions = createKnownFunctionsSet();
		SFQueryInfo queryInfo = new SFQueryInfo(functions);
		String serverURL = "ghidra://localhost/repo";

		queryService.initializeDatabase(serverURL);
		SFQueryResult result =
			queryService.querySimilarFunctions(queryInfo, null, TaskMonitor.DUMMY);
		assertNotNull(result);

		List<BSimMatchResult> similarFunctions =
			BSimMatchResult.generate(result.getSimilarityResults(), program);
		assertTrue(similarFunctions.isEmpty());

		serverURL = "ghidra://localhost/otherrepo";

		try {
			queryService.initializeDatabase(serverURL);
			queryService.querySimilarFunctions(queryInfo, null, TaskMonitor.DUMMY);
		}
		catch (Exception e) {
			// Expected--we can't connect to the newly supplied URL, as there is no server 
			// running on that port.  However, the exception means that the code tried to change
			// databases, which is what we wanted.
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void createQueryService() {
		assertNull(queryService);
		String serverURL = "ghidra://localhost/repo";
		FunctionDatabaseTestDouble db = new FunctionDatabaseTestDouble(serverURL);

		// response
		ResponseNearest response = new ResponseNearest(null);
		db.setQueryResponse(response);

		queryService = new SimilarFunctionQueryService(program, db);
	}

	private Set<FunctionSymbol> createKnownFunctionsSet() {
		Set<FunctionSymbol> functions = new HashSet<>();
		FunctionManager functionManager = program.getFunctionManager();
		Function ghidra = functionManager.getFunctionAt(addr("010018a0"));
		functions.add((FunctionSymbol) ghidra.getSymbol());
		Function sscanf = functionManager.getFunctionAt(addr("0100219c"));
		functions.add((FunctionSymbol) sscanf.getSymbol());
		return functions;
	}

	private Address addr(String addressString) {
		AddressFactory factory = program.getAddressFactory();
		return factory.getAddress(addressString);
	}

//==================================================================================================
// Private Classes
//==================================================================================================

	private class ResultsListener implements SFResultsUpdateListener<SFQueryResult> {

		private int resultsAddedCount;
		private boolean operationComplete;
		private SFQueryResult finalResult;
		private List<String> messages = new ArrayList<>();

		@Override
		public void resultAdded(QueryResponseRecord result) {
			resultsAddedCount++;
			assertNotNull(result);
		}

		public void reset() {
			resultsAddedCount = 0;
			operationComplete = false;
			finalResult = null;
			messages.clear();
		}

//		@Override
//		public void updateStatus(String message, MessageType type) {
//			String msg = "Message(" + type + "): " + message;
//			System.out.println(msg);
//			messages.add(msg);
//		}

		@Override
		public void setFinalResult(SFQueryResult result) {
			finalResult = result;
			assertFalse("Operation previously completed", this.operationComplete);
			this.operationComplete = true;
		}
	}

	private class BadQueryInfo extends SFQueryInfo {

		public BadQueryInfo(Set<FunctionSymbol> functions) {
			super(functions);
		}

		@Override
		public Set<FunctionSymbol> getFunctions() {
			return null;
		}
	}
}
