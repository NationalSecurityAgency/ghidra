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
package ghidra.feature.vt.db;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.*;

import ghidra.feature.vt.api.impl.VTProgramCorrelatorInfo;
import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTProgramCorrelator;

public class VTSessionDBTest extends VTBaseTestCase {

	private int testTransactionID;

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		testTransactionID = db.startTransaction("Test");
	}

	@Override
	@After
	public void tearDown() throws Exception {
		db.endTransaction(testTransactionID, false);
	}

	@Test
	public void testCreateAndGetMatchSet() throws Exception {
		VTProgramCorrelator correlator = VTTestUtils.createProgramCorrelator(null,
			db.getSourceProgram(), db.getDestinationProgram());
		VTMatchSet matchSet = db.createMatchSet(correlator);
		assertNotNull(matchSet);

		List<VTMatchSet> matchSets = db.getMatchSets();
		assertEquals(3, matchSets.size());
		assertEquals(matchSet, matchSets.get(2));

		VTProgramCorrelatorInfo info = matchSet.getProgramCorrelatorInfo();
		String programCorrelatorClassName = info.getCorrelatorClassName();
		assertEquals(correlator.getClass().getName(), programCorrelatorClassName);
	}

	//
	// This methods allows us to test that we can create/save/and restore version tracking 
	// managers...it takes a while, so we don't wanna do it all the time...plus this code is
	// ultimately tested during usage...we did it here for TDD purposes.
	//
//	public void testGetName() throws Exception {
//		assertEquals( "Untitled", db.getName() );
//
//		db.endTransaction( testTransactionID, false );
//		
//		GhidraProject project = GhidraProject.createProject( "C:\\Temp\\", "GhidrProject", true );
//		DomainFolder rootFolder = project.getRootFolder();
//		DomainFile file = rootFolder.createFile( "foop", db, TaskMonitorAdapter.DUMMY_MONITOR );
//		
//		Program sourceProgram = db.getSourceProgram();
//		Program destinationProgram = db.getDestinationProgram();
//		
//		db.close();
//		
//		DomainObject domainObject = file.getDomainObject( null, false, false, 
//			TaskMonitorAdapter.DUMMY_MONITOR );
//		assertTrue( domainObject instanceof VTSessionDB );
//		assertEquals( "foop", domainObject.getName() );
//		
//		db = (VTSessionDB) domainObject;
//		
//		Program unrelatedProgram = createProgram( "TEST" );
//		try {
//			db.setPrograms( unrelatedProgram, unrelatedProgram);
//			Assert.fail("Should not have been able to set the wrong program");
//		}
//		catch (IllegalArgumentException e) {
//			// expected case
//		}
//		
//		db.setPrograms(sourceProgram, destinationProgram );
//		
//		testTransactionID = db.startTransaction( "Test" ); // for cleanup
//	}
}
