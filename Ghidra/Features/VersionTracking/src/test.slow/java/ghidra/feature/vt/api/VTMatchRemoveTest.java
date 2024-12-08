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
package ghidra.feature.vt.api;

import static ghidra.feature.vt.db.VTTestUtils.*;
import static org.junit.Assert.*;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.*;

import docking.DialogComponentProvider;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.db.DummyTestProgramCorrelator;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.task.*;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.*;

public class VTMatchRemoveTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private VTController controller;
	private VTPlugin plugin;
	private VTSessionDB session;
	private ProgramDB srcProgram;
	private ProgramDB destProgram;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		ClassicSampleX86ProgramBuilder sourceBuilder = new ClassicSampleX86ProgramBuilder();
		srcProgram = sourceBuilder.getProgram();

		ClassicSampleX86ProgramBuilder destinationBuilder = new ClassicSampleX86ProgramBuilder();
		destProgram = destinationBuilder.getProgram();

		tool = env.getTool();
		tool.addPlugin(VTPlugin.class.getName());
		plugin = getPlugin(tool, VTPlugin.class);
		controller = new VTControllerImpl(plugin);

		session = new VTSessionDB(testName.getMethodName() + " - Test Match Set Manager",
			srcProgram, destProgram, this);

		runSwing(() -> controller.openVersionTrackingSession(session));
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testRemoveMatch_UnaccpetedMatch() throws Exception {

		Address srcAddr = addr("0x0100808c", srcProgram);
		Address destAddr = addr("0x0100808c", destProgram);

		setDataOnPrograms(srcAddr, destAddr);
		String labelName = "Bob";
		addLabel(labelName, srcAddr, srcProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, srcAddr, destAddr);

		VTMatchSet matchSet = match.getMatchSet();
		remove(match, false);
		assertMatchRemoved(matchSet, srcAddr, destAddr);
		assertNoLabelApplied(labelName, destAddr);
	}

	@Test
	public void testRemoveMatch_AccpetedMatch() throws Exception {

		/*
		 	Test:
		 		- create and apply a match
		 		- remove the match
		 		- leave the applied markup after match removal
		 */

		Address srcAddr = addr("0x0100808c", srcProgram);
		Address destAddr = addr("0x0100808c", destProgram);

		setDataOnPrograms(srcAddr, destAddr);
		String labelName = "Bob";
		addLabel(labelName, srcAddr, srcProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, srcAddr, destAddr);
		setApplyDataLabelOnAccept();
		accept(match);
		assertAcceptedAndLabelApplied(match, labelName, destAddr);

		VTMatchSet matchSet = match.getMatchSet();
		remove(match);
		assertMatchRemoved(matchSet, srcAddr, destAddr);
		assertLabelApplied(labelName, destAddr);
	}

	@Test
	public void testRemoveMatch_Accepted_MultipleMatchesForAssociation() throws Exception {

		/*
		 	Test:
		 		- create multiple matches for the same association
		 		- apply one match
		 		- remove the applied match
		 		- leave the applied markup after match removal
		 		
		 	*This tests control flow that avoids execution when the match being removed is the last
		 	 match for an association.
		 	
		 */

		Address srcAddr = addr("0x0100808c", srcProgram);
		Address destAddr = addr("0x0100808c", destProgram);

		setDataOnPrograms(srcAddr, destAddr);
		String labelName = "Bob";
		addLabel(labelName, srcAddr, srcProgram);

		VTMatch match = createMatchSetWithMultipleMatchesToSameAssociation(srcAddr, destAddr);
		setApplyDataLabelOnAccept();
		accept(match);
		assertAcceptedAndLabelApplied(match, labelName, destAddr);

		VTMatchSet matchSet = match.getMatchSet();
		remove(match, false);
		assertMatchRemoved(matchSet, srcAddr, destAddr);
		assertLabelApplied(labelName, destAddr);
	}

	@Test
	public void testRemoveMatch_RejectedMatch() throws Exception {

		Address srcAddr = addr("0x0100808c", srcProgram);
		Address destAddr = addr("0x0100808c", destProgram);

		setDataOnPrograms(srcAddr, destAddr);
		String labelName = "Bob";
		addLabel(labelName, srcAddr, srcProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, srcAddr, destAddr);
		setApplyDataLabelOnAccept();
		reject(match);
		assertNoLabelApplied(labelName, destAddr);

		VTMatchSet matchSet = match.getMatchSet();
		remove(match, false);
		assertMatchRemoved(matchSet, srcAddr, destAddr);
		assertNoLabelApplied(labelName, destAddr);
	}

	@Test
	public void testRemoveMatch_AccpetedMatch_ChooseNotToDelete() throws Exception {

		/*
		 	Test:
		 		- create and apply a match
		 		- remove the match, but cancel at dialog prompt
		 		- match should still be valid; markup should still be applied
		 */

		Address srcAddr = addr("0x0100808c", srcProgram);
		Address destAddr = addr("0x0100808c", destProgram);

		setDataOnPrograms(srcAddr, destAddr);
		String labelName = "Bob";
		addLabel(labelName, srcAddr, srcProgram);

		VTMatch match = createMatchSetWithOneDataMatch(session, srcAddr, destAddr);
		setApplyDataLabelOnAccept();
		accept(match);
		assertAcceptedAndLabelApplied(match, labelName, destAddr);

		VTMatchSet matchSet = match.getMatchSet();
		startRemoveThenCancel(match);
		assertMatchNotRemoved(matchSet, srcAddr, destAddr);
		assertLabelApplied(labelName, destAddr);
	}

//=================================================================================================
// Private Methods
//=================================================================================================	

	private void remove(VTMatch match) {
		remove(match, true);
	}

	private void remove(VTMatch match, boolean expectPrompt) {
		RemoveMatchTask task = new RemoveMatchTask(session, List.of(match));

		AtomicBoolean finished = runTaskLater(task); // this task is blocking, so run later and wait

		if (expectPrompt) {
			DialogComponentProvider removeDialog =
				waitForDialogComponent("Delete ACCEPTED Matches?");
			pressButtonByText(removeDialog, "Delete Accepted Matches");
		}

		// let the task finish processing after pressing the button
		waitFor(finished);
		waitForProgram(destProgram);
	}

	private void startRemoveThenCancel(VTMatch match) {
		RemoveMatchTask task = new RemoveMatchTask(session, List.of(match));

		AtomicBoolean finished = runTaskLater(task); // this task is blocking, so run later and wait

		DialogComponentProvider removeDialog = waitForDialogComponent("Delete ACCEPTED Matches?");
		pressButtonByText(removeDialog, "Finish");

		// let the task finish processing after pressing the button
		waitFor(finished);
		waitForProgram(destProgram);
	}

	private void assertLabelApplied(String labelName, Address addr) {
		assertEquals(labelName, getSymbol(destProgram, addr).getName());
	}

	private void assertNoLabelApplied(String labelName, Address addr) {
		Symbol symbol = getSymbol(destProgram, addr);
		if (symbol == null) {
			return; // no label; expected
		}
		assertNotEquals(labelName, symbol.getName());
	}

	private void assertMatchRemoved(VTMatchSet matchSet, Address srcAddr, Address destAddr) {
		Collection<VTMatch> matches = matchSet.getMatches(srcAddr, destAddr);
		assertTrue(matches.isEmpty());
	}

	private void assertMatchNotRemoved(VTMatchSet matchSet, Address srcAddr, Address destAddr) {
		Collection<VTMatch> matches = matchSet.getMatches(srcAddr, destAddr);
		assertFalse(matches.isEmpty());
	}

	private void assertAcceptedAndLabelApplied(VTMatch match, String labelName, Address addr) {
		VTAssociationStatus status = match.getAssociation().getStatus();
		assertEquals(VTAssociationStatus.ACCEPTED, status);
		assertEquals(labelName, getSymbol(destProgram, addr).getName());
	}

	private Symbol getSymbol(Program p, Address addr) {
		return p.getSymbolTable().getPrimarySymbol(addr);
	}

	private void setApplyDataLabelOnAccept() {
		ToolOptions options = controller.getOptions();
		options.setBoolean(VTOptionDefines.APPLY_DATA_NAME_ON_ACCEPT, true);
	}

	private void accept(VTMatch match) throws Exception {
		AcceptMatchTask task = new AcceptMatchTask(controller, List.of(match));
		runTask(task);
	}

	private void reject(VTMatch match) throws Exception {
		RejectMatchTask task = new RejectMatchTask(session, List.of(match));
		runTask(task);
	}

	private void setDataOnPrograms(Address srcAddr, Address destAddr) {
		DataType srcDt = new DWordDataType();
		DataType destDt1 = new StringDataType();
		DataType destDt2 = new WordDataType();
		setData(srcDt, 4, srcAddr, srcProgram);
		setData(destDt1, 2, destAddr, destProgram);
		setData(destDt2, 2, destAddr.add(2), destProgram);
	}

	private Symbol addLabel(String name, Address address, Program program) {
		return tx(program, () -> {
			SymbolTable symbolTable = program.getSymbolTable();
			return symbolTable.createLabel(address, name, SourceType.USER_DEFINED);
		});
	}

	private Data setData(DataType dataType, int length, Address address, Program program) {
		return tx(program, () -> {
			Listing listing = program.getListing();
			return listing.createData(address, dataType, length);
		});
	}

	private AtomicBoolean runTaskLater(VtTask task) {
		AtomicBoolean finishedFlag = new AtomicBoolean();
		runSwingLater(() -> {
			controller.runVTTask(task);
			finishedFlag.set(true);
		});
		waitForSwing();
		return finishedFlag;
	}

	private void runTask(VtTask task) {
		controller.runVTTask(task);
		waitForProgram(destProgram);
	}

	private VTMatch createMatchSetWithMultipleMatchesToSameAssociation(Address srcAddr,
			Address destAddr) throws Exception {
		int txId = 0;
		try {
			txId = session.startTransaction("Test Create Data Match Set");
			VTMatchInfo info = createRandomMatch(srcAddr, destAddr, session);
			info.setAssociationType(VTAssociationType.DATA);
			VTMatchSet matchSet =
				session.createMatchSet(createProgramCorrelator(srcProgram, destProgram));
			VTMatch firstMatch = matchSet.addMatch(info);

			// create a second match, match set and correlator, all tied to the given association
			DummyTestProgramCorrelator pc2 =
				(DummyTestProgramCorrelator) createProgramCorrelator(srcProgram, destProgram);
			pc2.setName("Correlator Two");
			VTMatchSet ms2 = session.createMatchSet(pc2);
			ms2.addMatch(createRandomMatch(srcAddr, destAddr, session));

			return firstMatch;
		}
		finally {
			session.endTransaction(txId, true);
		}
	}
}
