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
package ghidra.query.inmemory;

import static org.junit.Assert.*;

import java.io.File;
import java.util.*;

import org.junit.*;

import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.Error;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.features.bsim.query.protocol.CreateDatabase;
import ghidra.features.bsim.query.protocol.ResponseInfo;
import ghidra.framework.Application;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;
import utilities.util.FileUtilities;

public class BSimH2DatabaseManagerTest extends AbstractGhidraHeadedIntegrationTest {
	public static final String MEDIUM_NOSIZE = "medium_nosize";

	//private static final String XML_SOURCE_DIR = System.getProperty("user.home") + "/sigs/postgres_test";

	//private static final String TEST_DIR_NO_XML = System.getProperty("user.home") + "/sigs/empty";

	@Before
	public void setUp() {
		cleanup();
		getTempDbDir().mkdir();
	}

	@After
	public void tearDown() {
		//cleanup();
	}

	private File getTempDbDir() {
		return new File(Application.getUserTempDirectory(), "BSimH2Test");
	}

	private void cleanup() {
		for (BSimH2FileDataSource ds : BSimH2FileDBConnectionManager.getAllDataSources()) {
			ds.delete();
		}
		FileUtilities.deleteDir(getTempDbDir());
	}

	private String getDbName(String name) {
		return (new File(getTempDbDir(), name)).getAbsolutePath();
	}

	private BSimServerInfo getBsimServerInfo(String name) {
		return new BSimServerInfo(DBType.file, null, -1, getDbName(name));
	}

	private BSimServerInfo createDatabase(String databaseName) {
		return createDatabase(databaseName, null, null, null);
	}

	private BSimServerInfo createDatabase(String databaseName, List<String> tags,
		List<String> execats, String expectedError) {

		BSimServerInfo h2DbInfo = getBsimServerInfo(databaseName);
		Msg.debug(this, "Creating H2 File DB: " + h2DbInfo);

		try (FunctionDatabase h2Database = BSimClientFactory.buildClient(h2DbInfo, false)) {
			BSimH2FileDataSource bds =
				BSimH2FileDBConnectionManager.getDataSource(h2Database.getServerInfo());
			assertEquals("Expected no connections", 0, bds.getActiveConnections());
			assertFalse(bds.exists());

			CreateDatabase command = new CreateDatabase();
			command.info = new DatabaseInformation();
			// Put in fields provided on the command line
			// If they are null, the template will fill them in
			command.info.databasename = databaseName; // TODO: Unclear how this relates to full dbPath
			command.config_template = MEDIUM_NOSIZE;
			command.info.trackcallgraph = true;
			if (tags != null) {
				command.info.functionTags = tags;
			}
			if (execats != null) {
				command.info.execats = execats;
			}
			ResponseInfo response = command.execute(h2Database);
			if (response == null) {
				if (expectedError != null) {
					Error lastError = h2Database.getLastError();
					assertNotNull(lastError);
					assertTrue(lastError.message.contains(expectedError));
				}
				else {
					fail("Create failed: " + h2Database.getLastError().message);
				}
			}
			else {
				assertNull(h2Database.getLastError());
			}
		}
		return h2DbInfo;
	}

	@Test
	public void testCreateDatabase() {

		BSimServerInfo h2DbInfo = getBsimServerInfo("test");
		BSimH2FileDataSource ds = BSimH2FileDBConnectionManager.getDataSourceIfExists(h2DbInfo);
		assertNull(ds);
		ds = BSimH2FileDBConnectionManager.getDataSource(h2DbInfo);
		assertFalse(ds.exists());

		createDatabase("test");

		assertTrue(ds.exists());
	}

	@Test
	public void testListingDatabases() {

		List<BSimServerInfo> dbList = new ArrayList<BSimServerInfo>();
		for (int i = 1; i <= 3; i++) {
			// Create data source without creating database
			BSimServerInfo h2DbInfo = getBsimServerInfo("test" + i);
			BSimH2FileDataSource bds = BSimH2FileDBConnectionManager.getDataSource(h2DbInfo);
			dbList.add(h2DbInfo);
			assertFalse(bds.exists());
		}

		List<BSimServerInfo> actualDbList = new ArrayList<BSimServerInfo>();
		for (BSimH2FileDataSource bds : BSimH2FileDBConnectionManager.getAllDataSources()) {
			actualDbList.add(bds.getServerInfo());
		}
		Collections.sort(actualDbList);

		assertEquals(dbList, actualDbList);
	}

	@Test
	public void testDatabaseConfiguration() {

		List<String> tags = new ArrayList<>();
		tags.add("tag1");
		tags.add("tag2");

		List<String> cats = new ArrayList<>();
		cats.add("cat1");
		cats.add("cat2");
		cats.add("cat3");

		BSimServerInfo serverInfo = createDatabase("test1", tags, cats, null);

		try (FunctionDatabase fdb = serverInfo.getFunctionDatabase(false)) {
			assertTrue(fdb.initialize());
			DatabaseInformation info = fdb.getInfo();
			assertEquals(2, info.functionTags.size());
			assertTrue(info.functionTags.contains("tag1"));
			assertTrue(info.functionTags.contains("tag2"));
			assertEquals(3, info.execats.size());
			assertTrue(info.execats.contains("cat1"));
			assertTrue(info.execats.contains("cat2"));
			assertTrue(info.execats.contains("cat3"));
		}
	}

	@Test
	public void testCreateClientForNonExistentDB() {

		BSimServerInfo serverInfo = getBsimServerInfo("test");
		try (FunctionDatabase fdb = serverInfo.getFunctionDatabase(false)) {
			assertFalse(fdb.initialize());
			Error lastError = fdb.getLastError();
			assertNotNull(lastError);
			assertTrue(lastError.message.startsWith("Database does not exist: "));
		}
	}

//
//	@Test
//	public void testCreateDBandConnectClient() {
//		List<String> exeCats = new ArrayList<>();
//		exeCats.add("cat1");
//		exeCats.add("cat2");
//		List<String> funcTags = new ArrayList<>();
//		funcTags.add("tag1");
//		funcTags.add("tag2");
//		funcTags.add("tag3");
//		BSimH2DatabaseManager.createDatabase("test", new File(XML_SOURCE_DIR), MEDIUM_NOSIZE,
//			funcTags, exeCats);
//		URL url = null;
//		H2FunctionDatabase db = null;
//		try {
//			url = BSimClientFactory.deriveBSimURL(Handler.BSIM_IM_MEM_PROTOCOL + "://test");
//			db = (H2FunctionDatabase) BSimClientFactory.buildClient(url, false);
//			if (!db.initialize()) {
//				fail();
//			}
//		}
//		catch (MalformedURLException e) {
//			fail();
//		}
//		QueryInfo queryInfo = new QueryInfo();
//		ResponseInfo responseInfo = (ResponseInfo) db.query(queryInfo);
//		assertEquals("test", responseInfo.info.databasename);
//
//		List<String> dbCats = responseInfo.info.execats;
//		assertEquals(2, dbCats.size());
//		assertEquals("cat1", dbCats.get(0));
//		assertEquals("cat2", dbCats.get(1));
//
//		List<String> dbTags = responseInfo.info.functionTags;
//		assertEquals(3, dbTags.size());
//		assertEquals("tag1", dbTags.get(0));
//		assertEquals("tag2", dbTags.get(1));
//		assertEquals("tag3", dbTags.get(2));
//
//		assertTrue(responseInfo.info.trackcallgraph);
//
//		QueryExeCount queryCount = new QueryExeCount();
//		queryCount.includeFakes = false;
//		ResponseExe h2CountResponse = (ResponseExe) db.query(queryCount);
//		File xmlSourceDir = new File(XML_SOURCE_DIR);
//		File[] xmlFiles = xmlSourceDir.listFiles((d, n) -> n.startsWith("sigs_"));
//		assertEquals(xmlFiles.length, h2CountResponse.recordCount);
//
//		db.close();
//		assertTrue(BSimH2DatabaseManager.exists("test"));
//		BSimH2DatabaseManager.closeDatabase("test");
//		assertFalse(BSimH2DatabaseManager.exists("test"));
//	}
//
//	@Test(expected = IllegalArgumentException.class)
//	public void testBadFunctionTag() {
//		List<String> funcTags = new ArrayList<>();
//		funcTags.add("tag%1");
//		BSimH2DatabaseManager.createDatabase("test", new File(XML_SOURCE_DIR), MEDIUM_NOSIZE,
//			funcTags, Collections.emptyList());
//	}
//
//	@Test(expected = IllegalArgumentException.class)
//	public void testBadExecutableCategory() {
//		List<String> exeCats = new ArrayList<>();
//		exeCats.add("cat%1");
//		BSimH2DatabaseManager.createDatabase("test", new File(XML_SOURCE_DIR), MEDIUM_NOSIZE,
//			Collections.emptyList(), exeCats);
//	}
//
//	@Test(expected = IllegalArgumentException.class)
//	public void testDuplicateFunctionTags() {
//		List<String> funcTags = new ArrayList<>();
//		funcTags.add("tag1");
//		funcTags.add("tag1");
//		BSimH2DatabaseManager.createDatabase("test", new File(XML_SOURCE_DIR), MEDIUM_NOSIZE,
//			funcTags, Collections.emptyList());
//	}
//
//	@Test(expected = IllegalArgumentException.class)
//	public void testDuplicateExecutableCategories() {
//		List<String> exeCats = new ArrayList<>();
//		exeCats.add("cat1");
//		exeCats.add("cat1");
//		BSimH2DatabaseManager.createDatabase("test", new File(XML_SOURCE_DIR), MEDIUM_NOSIZE,
//			Collections.emptyList(), exeCats);
//	}
//
//	@Test
//	public void testPing() {
//		String name = "ping_test";
//		assertFalse(BSimH2DatabaseManager.exists(name));
//		BSimH2DatabaseManager.createDatabase(name, new File(XML_SOURCE_DIR), MEDIUM_NOSIZE,
//			Collections.emptyList(), Collections.emptyList());
//		assertTrue(BSimH2DatabaseManager.exists(name));
//		BSimH2DatabaseManager.closeDatabase(name);
//		assertFalse(BSimH2DatabaseManager.exists(name));
//	}
//
//	@Test
//	public void testNoSigFilesInDir() {
//		String name = "test";
//		assertFalse(BSimH2DatabaseManager.exists(name));
//		BSimH2DatabaseManager.createDatabase(name, new File(TEST_DIR_NO_XML), MEDIUM_NOSIZE,
//			Collections.emptyList(), Collections.emptyList());
//		assertFalse(BSimH2DatabaseManager.exists(name));
//	}

}
