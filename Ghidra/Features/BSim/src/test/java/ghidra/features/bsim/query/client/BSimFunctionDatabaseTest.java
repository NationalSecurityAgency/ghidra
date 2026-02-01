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
package ghidra.features.bsim.query.client;

import static org.junit.Assert.*;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.facade.FunctionDatabaseTestDouble;
import ghidra.features.bsim.query.file.H2FileFunctionDatabase;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.Msg;

public class BSimFunctionDatabaseTest extends AbstractGhidraHeadlessIntegrationTest {

	public BSimFunctionDatabaseTest() {
		super();
	}

	/**
	 * Tests that we can recognize when a feature vector has already been used to query
	 * the db, so we don't query it again.
	 * 
	 * To test, we create 5 of {@link FunctionDescription} instances, and populate each of them
	 * with one of two {@link LSHVector} instances. This should result in only 2 database queries,
	 * since we only have 2 unique vectors; the other 3 should be processed but NOT result in 
	 * db queries.  
	 * @throws Exception if an unexpected exception occurs
	 */
	@Test
	public void testDupes() throws Exception {

		String dbPath = getTestDirectoryPath() + "/bsimTest" + BSimServerInfo.H2_FILE_EXTENSION;
		URL dbUrl = new File(dbPath).toURI().toURL();

		Msg.error(this, ">>>>>>>>>> Expected 2 Error Messages: \"...Database does not exist...\"");

		// First set up some objects we'll need to populate for the queries.
		try (H2FileFunctionDatabase dbClient = new H2FileFunctionDatabase(dbUrl)) {
			LSHVectorFactory vectorFactory = dbClient.getLSHVectorFactory();
			FunctionDatabaseTestDouble.loadWeightsFile(vectorFactory);
			QueryNearest query = new QueryNearest();
			BSimSqlClause filter = null;
			ResponseNearest response = new ResponseNearest(query);
			DescriptionManager descMgr = new DescriptionManager();

			//create a fake ExecutableRecord to avoid NPE 
			ExecutableRecord erec = new ExecutableRecord("name", "arch", new RowKeySQL(0));
			// Create a list of function descriptions; we'll loop over all of these, 
			// trying to query each one in turn.
			List<FunctionDescription> descs = new ArrayList<>();
			FunctionDescription desc1 = new FunctionDescription(erec, "d1", 0x10100);
			FunctionDescription desc2 = new FunctionDescription(erec, "d2", 0x10200);
			FunctionDescription desc3 = new FunctionDescription(erec, "d3", 0x10300);
			FunctionDescription desc4 = new FunctionDescription(erec, "d4", 0x10400);
			FunctionDescription desc5 = new FunctionDescription(erec, "d5", 0x10500);

			// Now create 2 different LSH vectors. Make them slightly different so 
			// we should treat them as distinct vectors. (Note that we already have tests
			// that check vector equality in LSHVectorEqualityTest).
			LSHVector vec1 = vectorFactory.buildVector(new int[] { 1, 2, 3 });
			LSHVector vec2 = vectorFactory.buildVector(new int[] { 1, 2, 4 });

			// And now put those LSH vectors into SignatureRecords, which will be stored
			// in the FunctionDescriptions.
			SignatureRecord sigrec1 = new SignatureRecord(vec1);
			SignatureRecord sigrec2 = new SignatureRecord(vec2);

			desc1.setSignatureRecord(sigrec1);
			desc2.setSignatureRecord(sigrec1);
			desc3.setSignatureRecord(sigrec2);
			desc4.setSignatureRecord(sigrec1);
			desc5.setSignatureRecord(sigrec2);

			descs.add(desc1);
			descs.add(desc2);
			descs.add(desc3);
			descs.add(desc4);
			descs.add(desc5);

			// Perform the query, which returns the number of unique vectors used to query
			// the db. In this test it should have 2 entries.
			int results =
				dbClient.queryFunctions(query, filter, response, descMgr, descs.iterator());
			assertEquals(results, 2);
		}
		finally {
			Msg.error(this, ">>>>>>>>>> End Expected Error Messages");
			File dbFile = new File(dbPath);
			dbFile.delete();
		}
	}

}
