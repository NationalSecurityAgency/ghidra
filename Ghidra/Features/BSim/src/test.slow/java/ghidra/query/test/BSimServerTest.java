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
package ghidra.query.test;

import static org.junit.Assert.*;

import java.io.*;
import java.net.URL;
import java.sql.Date;
import java.time.Instant;
import java.util.*;

import org.junit.*;
import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import generic.lsh.vector.*;
import generic.util.Path;
import ghidra.GhidraTestApplicationLayout;
import ghidra.app.util.headless.HeadlessAnalyzer;
import ghidra.app.util.headless.HeadlessOptions;
import ghidra.features.bsim.gui.filters.ExecutableCategoryBSimFilterType;
import ghidra.features.bsim.gui.filters.HasNamedChildBSimFilterType;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.FunctionDatabase.Error;
import ghidra.features.bsim.query.client.tables.ExeTable.ExeTableOrderColumn;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.ingest.BSimLaunchable;
import ghidra.features.bsim.query.protocol.*;
import ghidra.framework.*;
import ghidra.framework.client.HeadlessClientAuthenticator;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

// These tests require specific data files and paths to be set up.  See BSimServerTestUtil.
// The "ignore" directive is to prevent these from running as part of the automated nightly tests.
@Ignore
public class BSimServerTest {
	private static final String PROPERTIES_FILE = "RegressionSignatures.properties";

	private static BSimServerTestUtil util;
	private static LSHVectorFactory vectorFactory;
	private static FunctionDatabase client;
	private static BSimLaunchable bulk;
	private static ResourceFile dumpFile;
	private static DescriptionManager originalBash;

	private static XmlPullParser getParser(ResourceFile file) {
		XmlPullParser parser;
		try {
			InputStream input = file.getInputStream();
			parser = new NonThreadedXmlPullParserImpl(input, "BSim test parser",
				SpecXmlUtils.getXmlHandler(), false);
		}
		catch (SAXException e) {
			return null;
		}
		catch (IOException e) {
			return null;
		}
		return parser;
	}

	@BeforeClass
	public static void setUp() throws Exception {
		util = new BSimServerTestUtil();
		util.verifyDirectories();
		GhidraTestApplicationLayout layout =
			new GhidraTestApplicationLayout(new File(util.ghidraDir));
		ApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
		Application.initializeApplication(layout, config);
		ghidra.framework.protocol.ghidra.Handler.registerHandler();	/// Register ghidra: protocol
		ghidra.features.bsim.query.postgresql.Handler.registerHandler();			// Register postgresql: protocol
		HeadlessClientAuthenticator.installHeadlessClientAuthenticator(null, null, true);
		bulk = new BSimLaunchable();

		util.verifyRaw();
		File propFile = new File(util.xmlDir, PROPERTIES_FILE);
		if (!propFile.isFile()) {
			createPropertiesFile();
			runHeadless();
		}

		util.startServer();
		doIngest();
		BSimServerInfo bsimServerInfo;
		try {
			bsimServerInfo = new BSimServerInfo(new URL(util.bsimURLString));
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
		client = BSimClientFactory.buildClient(bsimServerInfo, false);
		if (!client.initialize()) {
			throw new IOException("Unable to connect to server");
		}
		vectorFactory = client.getLSHVectorFactory();

		ResourceFile xmlFile =
			new ResourceFile(new ResourceFile(util.xmlDir), "sigs_" + BSimServerTestUtil.BASH_MD5);
		if (!xmlFile.isFile()) {
			throw new IOException("Basic signature generation did not happen");
		}
		XmlPullParser parser = getParser(xmlFile);
		originalBash = new DescriptionManager();
		originalBash.restoreXml(parser, vectorFactory);
		parser.dispose();
	}

	@AfterClass
	public static void shutdown() throws Exception {
		if (client != null) {
			client.close();
		}
		util.shutdownServer();
		if (dumpFile != null && dumpFile.exists()) {
			dumpFile.delete();
		}
	}

	@Test
	public void testLibHistoryXml() {
		ResourceFile xmlFile = new ResourceFile(new ResourceFile(util.xmlDir),
			"sigs_" + BSimServerTestUtil.LIBHISTORY_MD5);
		assertTrue(xmlFile.isFile());
		XmlPullParser parser = getParser(xmlFile);
		DescriptionManager manager = new DescriptionManager();
		try {
			manager.restoreXml(parser, vectorFactory);
			assertTrue(manager.getExecutableRecordSet().size() == 2);
			ExecutableRecord eRec = manager.findExecutable(BSimServerTestUtil.LIBHISTORY_MD5);
			// make sure basic meta-data comes through
			assertTrue(eRec.getNameExec().equals("libhistory.so.7.0"));
			assertTrue(eRec.getNameCompiler().equals("gcc"));
			assertTrue(eRec.getPath().equals("raw"));
			assertTrue(eRec.getRepository().equals("ghidra://localhost/repo"));
			assertTrue(eRec.hasCategory("Test Category", "shared"));
			ExecutableRecord libRec = manager.findExecutable("unknown", "x86:LE:64:default", "");
			assertTrue(libRec.isLibrary());
			FunctionDescription fDesc = manager.findFunctionByName("close", libRec);
			assertNotNull(fDesc);
			assertEquals(fDesc.getAddress(), -1);
			fDesc = manager.findFunctionByName("read_history_range", eRec);
			assertNotNull(fDesc);
			assertEquals(fDesc.getAddress(), 0x105f60);
			FunctionDescription addHistory = null;
			FunctionDescription malloc = null;
			for (CallgraphEntry entry : fDesc.getCallgraphRecord()) {
				String name = entry.getFunctionDescription().getFunctionName();
				if (name.equals("add_history")) {
					addHistory = entry.getFunctionDescription();
				}
				else if (name.equals("malloc")) {
					malloc = entry.getFunctionDescription();
				}
			}
			assertNotNull(addHistory);
			assertNotNull(malloc);
			assertEquals(addHistory.getAddress(), 0x102770);
			assertEquals(malloc.getAddress(), -1);
			assertTrue(addHistory.getExecutableRecord() == eRec);		// Should be same object
			assertTrue(malloc.getExecutableRecord() == libRec);
		}
		catch (LSHException e) {
			Assert.fail("Failure processing libhistory");
		}
	}

	@Test
	public void testBashLibReadline() {
		try {
			ResourceFile xmlFile = new ResourceFile(new ResourceFile(util.xmlDir),
				"sigs_" + BSimServerTestUtil.LIBREADLINE_MD5);
			XmlPullParser parser = getParser(xmlFile);
			DescriptionManager manager = new DescriptionManager();
			manager.restoreXml(parser, vectorFactory);
			parser.dispose();
			assertEquals(manager.getExecutableRecordSet().size(), 2);
			ExecutableRecord bashRec = originalBash.findExecutable(BSimServerTestUtil.BASH_MD5);
			assertTrue(bashRec.hasCategory("Test Category", "static"));
			ExecutableRecord readRec = manager.findExecutable(BSimServerTestUtil.LIBREADLINE_MD5);
			assertTrue(readRec.hasCategory("Test Category", "shared"));
			// Comparing function "history_filename"
			FunctionDescription bashFunc =
				originalBash.findFunction("FUN_001cc840", 0x1cc840, bashRec);
			FunctionDescription readFunc = manager.findFunction("FUN_00134a70", 0x134a70, readRec);
			VectorCompare compareData = new VectorCompare();
			double sig = bashFunc.getSignatureRecord()
					.getLSHVector()
					.compare(readFunc.getSignatureRecord().getLSHVector(), compareData);
			assertTrue(sig > 0.99999);
		}
		catch (LSHException e) {
			Assert.fail("Failure processing bash and libreadline");
		}
	}

	private static void compareExe(DescriptionManager manager1, DescriptionManager manager2,
			String md5) throws Exception {
		ExecutableRecord eRec1 = manager1.findExecutable(md5);
		ExecutableRecord eRec2 = manager2.findExecutable(md5);
		Iterator<FunctionDescription> iter = manager1.listFunctions(eRec1);
		while (iter.hasNext()) {
			FunctionDescription func1 = iter.next();
			FunctionDescription func2 =
				manager2.findFunction(func1.getFunctionName(), func1.getAddress(), eRec2);
			assertEquals(func1.getFlags(), func2.getFlags());
			if (func1.getSignatureRecord() == null) {
				assertTrue(func2.getSignatureRecord() == null);
			}
			else {
				assertNotNull(func2.getSignatureRecord());
				assertTrue(func1.getSignatureRecord()
						.getLSHVector()
						.equals(func2.getSignatureRecord().getLSHVector()));
			}
			if (func1.getCallgraphRecord() == null) {
				assertTrue(func2.getCallgraphRecord() == null);
				continue;
			}
			assertNotNull(func2.getCallgraphRecord());
			func1.sortCallgraph();
			func2.sortCallgraph();
			Iterator<CallgraphEntry> iter1 = func1.getCallgraphRecord().iterator();
			Iterator<CallgraphEntry> iter2 = func2.getCallgraphRecord().iterator();
			while (iter1.hasNext()) {
				assertTrue(iter2.hasNext());
				FunctionDescription call1 = iter1.next().getFunctionDescription();
				FunctionDescription call2 = iter2.next().getFunctionDescription();
				assertTrue(call1.equals(call2));
			}
		}
	}

	@Test
	public void testDumpFile() {
		try {
			assertNotNull(dumpFile);
			assertTrue(dumpFile.exists());
			XmlPullParser parser = getParser(dumpFile);
			DescriptionManager manager1 = new DescriptionManager();
			manager1.restoreXml(parser, vectorFactory);
			parser.dispose();
			compareExe(manager1, originalBash, BSimServerTestUtil.BASH_MD5);
		}
		catch (Exception e) {
			Assert.fail("Failed to perform dumpexexml: " + e.getMessage());
		}
	}

	private static void testForError(QueryResponseRecord response) throws LSHException {
		if (response == null) {
			Error lastError = client.getLastError();
			if (lastError == null) {
				throw new LSHException("Unknown error");
			}
			throw new LSHException(lastError.message);
		}
	}

	@Test
	public void testQueryInfo() throws LSHException {
		QueryInfo queryInfo = new QueryInfo();
		ResponseInfo response = queryInfo.execute(client);
		testForError(response);
		DatabaseInformation info = response.info;
		assertTrue(info.databasename.equals("TestName"));
		assertTrue(info.owner.equals("TestOwner"));
		assertTrue(info.description.equals("TestDescription"));
		assertEquals(info.settings, 0x49);
		assertTrue(info.trackcallgraph);
		assertNotNull(info.execats);
		assertEquals(info.execats.size(), 1);
		assertTrue(info.execats.get(0).equals("Test Category"));
	}

	private void compareExecutableRecords(ExecutableRecord exe1, ExecutableRecord exe2) {
		assertEquals(exe1.getMd5(), exe2.getMd5());
		assertEquals(exe1.getNameExec(), exe2.getNameExec());
		assertEquals(exe1.getArchitecture(), exe2.getArchitecture());
		assertEquals(exe1.getNameCompiler(), exe2.getNameCompiler());
		assertEquals(exe1.getPath(), exe2.getPath());
	}

	@Test
	public void testQueryExeInfo() throws LSHException {
		ExecutableRecord libHistory = new ExecutableRecord(BSimServerTestUtil.LIBHISTORY_MD5,
			"libhistory.so.7.0", "gcc", "x86:LE:64:default", null, null, null, "raw");
		ExecutableRecord libReadline = new ExecutableRecord(BSimServerTestUtil.LIBREADLINE_MD5,
			"libreadline.so.7.0", "gcc", "x86:LE:64:default", null, null, null, "raw");
		QueryExeInfo queryExeInfo = new QueryExeInfo();
		queryExeInfo.includeFakes = true;
		ResponseExe responseExe = queryExeInfo.execute(client);
		testForError(responseExe);
		assertEquals(responseExe.recordCount, 3);
		ExecutableRecord exe1 = responseExe.records.get(0);
		compareExecutableRecords(exe1, libHistory);
		assertEquals(exe1.getExeCategoryAlphabetic("Test Category"), "shared");
		ExecutableRecord exe2 = responseExe.records.get(1);
		compareExecutableRecords(exe2, libReadline);
		assertEquals(exe2.getExeCategoryAlphabetic("Test Category"), "shared");
		ExecutableRecord exe3 = responseExe.records.get(2);
		assertEquals(exe3.getMd5(), "bbbbbbbbaaaaaaaa4b13cd7905584d9f");
		assertEquals(exe3.getNameExec(), "unknown");

		queryExeInfo = new QueryExeInfo();
		queryExeInfo.filterMd5 = BSimServerTestUtil.LIBREADLINE_MD5;
		responseExe = queryExeInfo.execute(client);
		testForError(responseExe);
		assertEquals(responseExe.recordCount, 1);
		exe1 = responseExe.records.get(0);
		compareExecutableRecords(exe1, libReadline);

		queryExeInfo = new QueryExeInfo();
		queryExeInfo.filterMd5 = "0a860";			// Partial md5
		responseExe = queryExeInfo.execute(client);
		testForError(responseExe);
		assertEquals(responseExe.recordCount, 1);
		exe1 = responseExe.getDescriptionManager().findExecutable("libhistory.so.7.0", null, null);
		compareExecutableRecords(exe1, libHistory);

		queryExeInfo = new QueryExeInfo();
		queryExeInfo.filterExeName = "lib";
		queryExeInfo.sortColumn = ExeTableOrderColumn.NAME;
		responseExe = queryExeInfo.execute(client);
		testForError(responseExe);
		assertEquals(responseExe.records.size(), 2);
		exe1 = responseExe.records.get(0);
		exe2 = responseExe.records.get(1);
		compareExecutableRecords(exe1, libHistory);
		compareExecutableRecords(exe2, libReadline);

		QueryExeCount queryExeCount = new QueryExeCount();
		responseExe = queryExeCount.execute(client);
		testForError(responseExe);
		assertEquals(responseExe.recordCount, 2);
	}

	@Test
	public void testQueryName() throws LSHException {
		QueryName queryName = new QueryName();
		queryName.spec.exename = "libhistory.so.7.0";
		queryName.funcname = "history_arg_extract";
		ResponseName responseName = queryName.execute(client);
		testForError(responseName);
		assertTrue(responseName.uniqueexecutable);
		ExecutableRecord eRec =
			responseName.manage.findExecutable(BSimServerTestUtil.LIBHISTORY_MD5);
		assertTrue(eRec.getNameExec().equals("libhistory.so.7.0"));
		assertTrue(eRec.getMd5().equals(BSimServerTestUtil.LIBHISTORY_MD5));
		assertTrue(eRec.getNameCompiler().equals("gcc"));
		assertTrue(eRec.getPath().equals("raw"));
		Iterator<FunctionDescription> iter = responseName.manage.listAllFunctions();
		assertTrue(iter.hasNext());
		FunctionDescription func = iter.next();
		assertFalse(iter.hasNext());				// Should be exactly one function
		assertTrue(func.getFunctionName().equals("history_arg_extract"));
		assertEquals(func.getAddress(), 0x103d40);
		SignatureRecord sigRec = func.getSignatureRecord();
		assertNotNull(sigRec);
		assertEquals(sigRec.getCount(), 2);
		ExecutableRecord bashRec = originalBash.findExecutable(BSimServerTestUtil.BASH_MD5);
		FunctionDescription bashFunc =
			originalBash.findFunctionByName("history_arg_extract", bashRec);
		assertNotNull(bashFunc);
		VectorCompare vectorCompare = new VectorCompare();
		double sim = sigRec.getLSHVector()
				.compare(bashFunc.getSignatureRecord().getLSHVector(), vectorCompare);
		assertTrue(sim > 0.8);
		assertTrue(sim < 0.999);
	}

	private static QueryResponseRecord doStagedQuery(BSimQuery<?> query,
			StagingManager stagingManager) throws LSHException {

		boolean haveMore = stagingManager.initialize(query);
		query.buildResponseTemplate();

		QueryResponseRecord globalResponse = query.getResponse();

		while (haveMore) {
			// Get the current staged form of the query
			BSimQuery<?> stagedQuery = stagingManager.getQuery();
			QueryResponseRecord response = stagedQuery.execute(client);
			if (response != null) {
				if (globalResponse != response) {
					globalResponse.mergeResults(response);	// Merge the staged response with the global response
				}

				haveMore = stagingManager.nextStage();
				if (haveMore) {
					stagedQuery.clearResponse(); // Make space for next stage
				}
			}
			else {
				throw new LSHException(client.getLastError().message);
			}
		}

		return globalResponse;
	}

	private static void testSimilarityResult(SimilarityResult simRes) {
		assertEquals(simRes.getTotalCount(), 2);
		Iterator<SimilarityNote> iter = simRes.iterator();
		SimilarityNote note1 = iter.next();
		SimilarityNote note2 = iter.next();
		FunctionDescription func1 = note1.getFunctionDescription();
		FunctionDescription func2 = note2.getFunctionDescription();
		assertTrue(func1.getExecutableRecord().getNameExec().equals("libhistory.so.7.0"));
		assertTrue(func2.getExecutableRecord().getNameExec().equals("libreadline.so.7.0"));
		assertNotNull(func1.getSignatureRecord());
		assertNotNull(func2.getSignatureRecord());
		assertNotNull(simRes.getBase().getSignatureRecord());
		LSHVector baseVector = simRes.getBase().getSignatureRecord().getLSHVector();
		VectorCompare vectorCompare = new VectorCompare();
		double sim1 = func1.getSignatureRecord().getLSHVector().compare(baseVector, vectorCompare);
		assertEquals(note1.getSimilarity(), sim1, 0.0001);
		double sim2 = func2.getSignatureRecord().getLSHVector().compare(baseVector, vectorCompare);
		assertEquals(note2.getSimilarity(), sim2, 0.0001);
	}

	@Test
	public void testQueryNearest() throws LSHException {
		QueryNearest queryNearest = new QueryNearest();
		ExecutableRecord bashRec = originalBash.findExecutable(BSimServerTestUtil.BASH_MD5);
		FunctionDescription func1 = originalBash.findFunctionByName("_rl_adjust_point", bashRec);
		FunctionDescription func2 = originalBash.findFunctionByName("_rl_compare_chars", bashRec);
		FunctionDescription func3 = originalBash.findFunctionByName("add_history", bashRec);
		FunctionDescription func4 = originalBash.findFunctionByName("get_history_event", bashRec);
		queryNearest.manage.transferSettings(originalBash);
		queryNearest.manage.transferFunction(func1, true);
		queryNearest.manage.transferFunction(func2, true);
		queryNearest.manage.transferFunction(func3, true);
		queryNearest.manage.transferFunction(func4, true);
		StagingManager functionStage = new FunctionStaging(2);
		QueryResponseRecord response = doStagedQuery(queryNearest, functionStage);
		testForError(response);
		ResponseNearest respNearest = (ResponseNearest) response;
		respNearest.sort();
		int matchCount = 0;
		for (SimilarityResult simRes : respNearest.result) {
			if (simRes.getBase().getAddress() == func1.getAddress()) {
				assertTrue(func1.equals(simRes.getBase()));
				matchCount += 1;
			}
			else if (simRes.getBase().getAddress() == func2.getAddress()) {
				assertTrue(func2.equals(simRes.getBase()));
				matchCount += 1;
			}
			else if (simRes.getBase().getAddress() == func3.getAddress()) {
				assertTrue(func3.equals(simRes.getBase()));
				matchCount += 1;
			}
			else if (simRes.getBase().getAddress() == func4.getAddress()) {
				assertTrue(func4.equals(simRes.getBase()));
				matchCount += 1;
			}
			testSimilarityResult(simRes);
		}
		assertEquals(matchCount, 4);		// Make sure we hit all functions
	}

	@Test
	public void testQueryVector() throws LSHException {
		QueryNearestVector queryVector = new QueryNearestVector();
		ExecutableRecord bashRec = originalBash.findExecutable(BSimServerTestUtil.BASH_MD5);
		FunctionDescription func = originalBash.findFunctionByName("_rl_kill_kbd_macro", bashRec);
		queryVector.manage.transferSettings(originalBash);
		queryVector.manage.transferFunction(func, true);
		ResponseNearestVector respVector = queryVector.execute(client);
		testForError(respVector);
		respVector.sort();
		assertEquals(respVector.totalvec, 1);
		assertEquals(respVector.totalmatch, 2);
		assertEquals(respVector.uniquematch, 0);		// 1 vector matches 2 functions
		Iterator<SimilarityVectorResult> iter = respVector.result.iterator();
		SimilarityVectorResult simVecRes = iter.next();
		assertFalse(iter.hasNext());
		assertTrue(simVecRes.getBase().equals(func));
		assertEquals(simVecRes.getTotalCount(), 2);
		Iterator<VectorResult> iter2 = simVecRes.iterator();
		VectorResult vec1 = iter2.next();
		VectorResult vec2 = iter2.next();
		assertFalse(iter2.hasNext());
		if (vec1.sim > vec2.sim) {
			VectorResult tmp = vec1;
			vec1 = vec2;
			vec2 = tmp;
		}
		VectorCompare vectorCompare = new VectorCompare();
		LSHVector baseVector = func.getSignatureRecord().getLSHVector();
		double sim1 = baseVector.compare(vec1.vec, vectorCompare);
		assertEquals(sim1, vec1.sim, 0.0001);
		assertEquals(vec1.hitcount, 1);
		double sim2 = baseVector.compare(vec2.vec, vectorCompare);
		assertEquals(sim2, vec2.sim, 0.0001);
		assertEquals(vec1.hitcount, 1);
		assertTrue(vec2.sim > 0.999);		// Second vector should be 1.0 match
	}

	@Test
	public void testChildFilter() throws LSHException {
		QueryNearest query = new QueryNearest();
		query.manage.transferSettings(originalBash);
		ExecutableRecord bashRec = originalBash.findExecutable(BSimServerTestUtil.BASH_MD5);
		FunctionDescription funcDesc = originalBash.findFunctionByName("_rl_errmsg", bashRec);
		query.manage.transferFunction(funcDesc, true);
		query.bsimFilter = new BSimFilter();
		query.bsimFilter.addAtom(new HasNamedChildBSimFilterType(), "[unknown]__fprintf_chk");
		ResponseNearest respNearest = query.execute(client);
		testForError(respNearest);
		assertEquals(respNearest.totalfunc, 1);
		assertEquals(respNearest.totalmatch, 1);		// Filtered all but one response
		assertEquals(respNearest.uniquematch, 1);
		ExecutableRecord eRec = respNearest.manage.getExecutableRecordSet().first();
		assertTrue(eRec.getNameExec().equals("libreadline.so.7.0"));
		assertTrue(eRec.getMd5().equals(BSimServerTestUtil.LIBREADLINE_MD5));
		assertEquals(respNearest.result.size(), 1);
		SimilarityResult simRes = respNearest.result.get(0);
		assertEquals(simRes.size(), 1);			// Only one function returned
		assertEquals(simRes.getTotalCount(), 3);	// 3 functions similar to vector
		SimilarityNote note = simRes.iterator().next();
		assertTrue(note.getSimilarity() > 0.800);
		FunctionDescription resFunc = note.getFunctionDescription();
		assertTrue(resFunc.getFunctionName().equals("FUN_0011ece0"));
		assertEquals(resFunc.getAddress(), 0x11ece0);
		assertEquals(resFunc.getSignatureRecord().getCount(), 1);		// only function with this exact vector
	}

	@Test
	public void testUpdate() throws Exception {
		QueryUpdate update = new QueryUpdate();

		Date dt = new Date(Instant.parse("2010-12-25T10:15:30.00Z").toEpochMilli());
		ExecutableRecord exerec = update.manage.newExecutableRecord(
			BSimServerTestUtil.LIBREADLINE_MD5, "libreadline.so.7.0", "gcc", "x86:LE:64:default",
			dt, "ghidra://localhost/repo", "/raw", null);
		List<CategoryRecord> catrec = new ArrayList<>();
		catrec.add(new CategoryRecord("Test Category", "SHARED!"));
		update.manage.setExeCategories(exerec, catrec);
		update.manage.newFunctionDescription("my_remove_history", 0x131c00, exerec);
		ResponseUpdate respUpdate = update.execute(client);
		testForError(respUpdate);
		assertEquals(respUpdate.exeupdate, 1);
		assertEquals(respUpdate.funcupdate, 1);
		assertTrue(respUpdate.badexe.isEmpty());
		assertTrue(respUpdate.badfunc.isEmpty());
		if (util.isElasticSearch) {
			Thread.sleep(2000);		// Give chance for refresh timer to expire
		}
		QueryNearest nearest = new QueryNearest();
		nearest.manage.transferSettings(originalBash);

		ExecutableRecord bash = originalBash.findExecutable(BSimServerTestUtil.BASH_MD5);
		FunctionDescription desc = originalBash.findFunctionByName("remove_history", bash);
		nearest.manage.transferFunction(desc, true);
		nearest.bsimFilter = new BSimFilter();
		nearest.bsimFilter.addAtom(new ExecutableCategoryBSimFilterType("Test Category"),
			"SHARED!");
		ResponseNearest respNearest = nearest.execute(client);
		testForError(respNearest);
		assertEquals(respNearest.totalfunc, 1);
		assertEquals(respNearest.totalmatch, 1);
		assertEquals(respNearest.uniquematch, 1);
		SimilarityResult simRes = respNearest.result.get(0);
		assertTrue(simRes.getBase().equals(desc));		// base should match original function
		assertEquals(simRes.size(), 1);
		assertEquals(simRes.getTotalCount(), 2);		// The filtered libhistory version is also counted here
		SimilarityNote note = simRes.iterator().next();
		FunctionDescription resFunc = note.getFunctionDescription();
		assertTrue(resFunc.getFunctionName().equals("my_remove_history"));
		ExecutableRecord resRec = resFunc.getExecutableRecord();
		assertTrue(resRec.getDate().equals(dt));

		// Restore the original records
		update = new QueryUpdate();
		exerec = update.manage.newExecutableRecord(BSimServerTestUtil.LIBREADLINE_MD5,
			"libreadline.so.7.0", "gcc", "x86:LE:64:default", bash.getDate(),
			"ghidra://localhost/repo", "/raw", null);
		catrec = new ArrayList<>();
		catrec.add(new CategoryRecord("Test Category", "shared"));
		update.manage.setExeCategories(exerec, catrec);
		update.manage.newFunctionDescription("remove_history", 0x131c00, exerec);
		testForError(update.execute(client));
		if (util.isElasticSearch) {
			Thread.sleep(2000);		// Give chance for refresh timer to expire
		}
	}

	private static void doIngest() throws Exception {
		if (dumpFile != null && dumpFile.exists()) {
			return;
		}
		runCreateDatabase();
		if (util.isElasticSearch) {
			Thread.sleep(2000);		// Give chance for refresh timer to expire
		}
		runSetMetaData();
		runSetExeCategory();
		runDropIndex();
		if (util.isElasticSearch) {
			Thread.sleep(2000);		// Give chance for refresh timer to expire
		}
		runCommitSigs();
		runRebuildIndex();
		if (util.isElasticSearch) {
			Thread.sleep(2000);		// Give chance for refresh timer to expire
		}
		runDumpFile(BSimServerTestUtil.BASH_MD5);
		dumpFile =
			new ResourceFile(new ResourceFile(util.testDir), "sigs_" + BSimServerTestUtil.BASH_MD5);
		runDelete();
		if (util.isElasticSearch) {
			Thread.sleep(2000);		// Give chance for refresh timer to expire
		}
	}

	private static void createPropertiesFile() throws IOException {
		File props = new File(util.xmlDir, PROPERTIES_FILE);
		FileWriter writer = new FileWriter(props);
		writer.write("RegressionSignatures: Working directory = " + util.xmlDir + '\n');
		writer.close();
	}

	private static void runHeadless() throws IOException {
		HeadlessAnalyzer analyzer = HeadlessAnalyzer.getInstance();
		HeadlessOptions options = analyzer.getOptions();
		List<String> preScripts = new ArrayList<>();
		List<String> postScripts = new ArrayList<>();
		List<File> inputFiles = new ArrayList<>();

		options.setPropertiesFileDirectories(util.xmlDir);
		Path scriptPath = new Path(Path.GHIDRA_HOME + "/Features/BSim/other/testscripts");
		options.setScriptDirectories(scriptPath.getPath().getAbsolutePath());

		inputFiles.add(new File(util.rawDir));
		preScripts.add("TailoredAnalysis.java");
		preScripts.add("InstallMetadataTest.java");
		postScripts.add("RegressionSignatures.java");

		options.setPreScripts(preScripts);
		options.setPostScripts(postScripts);

		analyzer.processLocal(util.projectDir, util.repoName, "/", inputFiles);
	}

	private static void runCreateDatabase() throws Exception {
		String params[] = new String[3];
		params[0] = "createdatabase";
		params[1] = util.bsimURLString;
		params[2] = "medium_64";
		bulk.run(params);
	}

	private static void runSetMetaData() throws Exception {
		String params[] = new String[5];
		params[0] = "setmetadata";
		params[1] = util.bsimURLString;
		params[2] = "name=TestName";
		params[3] = "owner=TestOwner";
		params[4] = "description=TestDescription";
		bulk.run(params);
	}

	private static void runSetExeCategory() throws Exception {
		String params[] = new String[3];
		params[0] = "addexecategory";
		params[1] = util.bsimURLString;
		params[2] = "Test Category";
		bulk.run(params);
	}

	private static void runDropIndex() throws Exception {
		if (util.isH2Database) {
			return;
		}
		String params[] = new String[2];
		params[0] = "dropindex";
		params[1] = util.bsimURLString;
		bulk.run(params);
	}

	private static void runCommitSigs() throws Exception {
		String params[] = new String[3];
		params[0] = "commitsigs";
		params[1] = util.bsimURLString;
		params[2] = util.xmlDir;
		bulk.run(params);
	}

	private static void runRebuildIndex() throws Exception {
		if (util.isH2Database) {
			return;
		}
		String params[] = new String[2];
		params[0] = "rebuildindex";
		params[1] = util.bsimURLString;
		bulk.run(params);
	}

	private static void runDelete() throws Exception {
		String params[] = new String[3];
		params[0] = "delete";
		params[1] = util.bsimURLString;
		params[2] = "md5=" + BSimServerTestUtil.BASH_MD5;
		bulk.run(params);
	}

	private static void runDumpFile(String md5) throws Exception {
		String params[] = new String[4];
		params[0] = "dumpsigs";
		params[1] = util.bsimURLString;
		params[2] = util.testDir;
		params[3] = "md5=" + BSimServerTestUtil.BASH_MD5;
		bulk.run(params);
	}
}
