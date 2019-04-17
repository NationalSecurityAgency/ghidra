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
package ghidra.app.merge.listing;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.awt.Window;
import java.math.BigInteger;

import javax.swing.JLabel;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.ProgramContext;

public class ProgramContextMergeManagerTest extends AbstractListingMergeManagerTest {

	final String regNameDR0 = "DR0";
	final String regNameTR2 = "TR2";
	final String regNameAx = "AX";
	final String regNameEbp = "EBP";
	final String regNameHbp = "HBP";
	final String regNameBp = "BP";

	// The following is an instruction context register.
	final String regNameContextBit = "bit64"; // any bit field will due

	@Test
	public void testAddRegValueAutoMerge() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					// Initially Direction was 0x1e240
					setRegValue(pc, addr("1002085"), addr("1002100"), regDR0, 0x5L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("1002000"), addr("1002074"), regDR0, 0x22L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		// Neither set it
		for (Address a = addr("1001fff"); a.compareTo(addr("1001fff")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
		// From MY
		for (Address a = addr("1002000"); a.compareTo(addr("1002074")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x22L);
		}
		// Neither set it
		for (Address a = addr("1002075"); a.compareTo(addr("1002084")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
		// From LATEST
		for (Address a = addr("1002085"); a.compareTo(addr("1002100")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x5L);
		}
		// Neither set it
		for (Address a = addr("1002101"); a.compareTo(addr("1002150")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
	}

	@Test
	public void testChangeRegValueAutoMerge() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					// Initially Direction was 0x1e240
					setRegValue(pc, addr("10022d4"), addr("10022d9"), regDR0, 0x66L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("10022e0"), addr("10022e5"), regDR0, 0x44L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		// Neither set it
		for (Address a = addr("1001fff"); a.compareTo(addr("10022d3")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
		// From MY
		for (Address a = addr("10022d4"); a.compareTo(addr("10022d9")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x66L);
		}
		// Neither set it
		for (Address a = addr("10022da"); a.compareTo(addr("10022df")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x1010101L);
		}
		// From LATEST
		for (Address a = addr("10022e0"); a.compareTo(addr("10022e5")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x44L);
		}
		// Neither set it
		for (Address a = addr("10022fc"); a.compareTo(addr("100230a")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
		// Was already set
		for (Address a = addr("100230b"); a.compareTo(addr("100231c")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0xa4561427L);
		}
	}

	@Test
	public void testRemoveRegValueAutoMerge() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					pc.remove(addr("1002312"), addr("1002317"), regDR0);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					pc.remove(addr("100230c"), addr("1002311"), regDR0);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		// Neither set it
		for (Address a = addr("1002306"); a.compareTo(addr("100230a")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
		// Was already set
		for (Address a = addr("100230b"); a.compareTo(addr("100230b")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0xa4561427L);
		}
		// From MY
		for (Address a = addr("100230c"); a.compareTo(addr("1002311")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
		// From LATEST
		for (Address a = addr("1002312"); a.compareTo(addr("1002317")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
		// Was already set
		for (Address a = addr("1002318"); a.compareTo(addr("100231c")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0xa4561427L);
		}
		// Neither set it
		for (Address a = addr("100231d"); a.compareTo(addr("1002320")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
	}

	@Test
	public void testChangeLatestRemoveMyPickCancel() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					// Initially Direction was 0x1e240
					setRegValue(pc, addr("1002329"), addr("100233b"), regDR0, 0x5L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					pc.remove(addr("1002329"), addr("100233b"), regDR0);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		checkDisplayValues(new Long(0x5L), (Long) null, new Long(0x40e20100L));

		chooseCancel(); // 1002085 - 1002100
		Thread.sleep(250);
		Window cancelWindow = waitForMergeCancelWindow(5000);
		assertNotNull(cancelWindow);
		pressButtonByText(cancelWindow, "No");
		Thread.sleep(250);
		chooseCancel(); // 1002085 - 1002100
		Thread.sleep(250);
		cancelWindow = waitForMergeCancelWindow(5000);
		assertNotNull(cancelWindow);
		pressButtonByText(cancelWindow, "Yes");

		waitForMergeCompletion();
		Thread.sleep(1000);

		for (Address a = addr("1002329"); a.compareTo(addr("100233b")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x5L);
		}
	}

	@Test
	public void testChangeLatestRemoveMyPickLatest() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					// Initially Direction was 0x1e240
					setRegValue(pc, addr("1002329"), addr("100233b"), regDR0, 0x5L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					pc.remove(addr("1002329"), addr("100233b"), regDR0);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		checkDisplayValues(new Long(0x5L), (Long) null, new Long(0x40e20100L));
		chooseRadioButton(LATEST_BUTTON_NAME);
		waitForMergeCompletion();

		for (Address a = addr("1002329"); a.compareTo(addr("100233b")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x5L);
		}
	}

	@Test
	public void testChangeLatestRemoveMyPickMy() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					// Initially Direction was 0x1e240
					setRegValue(pc, addr("1002329"), addr("100233b"), regDR0, 0x5L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					pc.remove(addr("1002329"), addr("100233b"), regDR0);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		checkDisplayValues(new Long(0x5L), (Long) null, new Long(0x40e20100L));
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1002050 - 1002074
		waitForMergeCompletion();

		for (Address a = addr("1002329"); a.compareTo(addr("100233b")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
	}

	@Test
	public void testChangeLatestRemoveMyPickOriginal() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					// Initially Direction was 0x1e240
					setRegValue(pc, addr("1002329"), addr("100233b"), regDR0, 0x5L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					pc.remove(addr("1002329"), addr("100233b"), regDR0);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		checkDisplayValues(new Long(0x5L), (Long) null, new Long(0x40e20100L));
		chooseRadioButton(ORIGINAL_BUTTON_NAME);
		waitForMergeCompletion();

		for (Address a = addr("1002329"); a.compareTo(addr("100233b")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x40e20100L);
		}
	}

	@Test
	public void testRemoveLatestChangeMy() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					// Initially Direction was 0x1e240
					pc.remove(addr("1002329"), addr("100233b"), regDR0);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("1002329"), addr("100233b"), regDR0, 0x5L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		checkDisplayValues((Long) null, new Long(0x5L), new Long(0x40e20100L));
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		for (Address a = addr("1002329"); a.compareTo(addr("100233b")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x5L);
		}
	}

	@Test
	public void testSingleRegConflictsCancel() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDir = pc.getRegister(regNameTR2);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					setRegValue(pc, addr("1002000"), addr("1002074"), regDir, 0x5L);
					setRegValue(pc, addr("1002075"), addr("1002100"), regDir, 0x7L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regDR0 = pc.getRegister(regNameTR2);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("1002050"), addr("1002084"), regDR0, 0x1L);
					setRegValue(pc, addr("1002085"), addr("1002150"), regDR0, 0x3L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1002050 - 1002074
		chooseRadioButton(LATEST_BUTTON_NAME); // 1002075 - 1002084

		for (Address a = addr("1002000"); a.compareTo(addr("1002049")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x5L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002074")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x1L);
		}
		chooseCancel(); // 1002085 - 1002100
		Window cancelWindow = waitForMergeCancelWindow(5000);
		assertNotNull(cancelWindow);
		pressButtonByText(cancelWindow, "Yes");
		waitForMergeCompletion();
		Thread.sleep(1000);

		for (Address a = addr("1002000"); a.compareTo(addr("1002049")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x5L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002074")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x5L);
		}
		for (Address a = addr("1002075"); a.compareTo(addr("1002084")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x7L);
		}
		for (Address a = addr("1002085"); a.compareTo(addr("1002100")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x7L);
		}
		for (Address a = addr("1002101"); a.compareTo(addr("1002150")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue(regNameTR2, a);
		}
	}

	@Test
	public void testSingleRegConflictsPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameTR2);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					setRegValue(pc, addr("1002000"), addr("1002074"), reg1, 0x5L);
					setRegValue(pc, addr("1002075"), addr("1002100"), reg1, 0x7L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameTR2);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("1002050"), addr("1002084"), reg1, 0x1L);
					setRegValue(pc, addr("1002085"), addr("1002150"), reg1, 0x3L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1002050 - 1002074
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1002075 - 1002084
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1002085 - 1002100
		waitForMergeCompletion();

		for (Address a = addr("1002000"); a.compareTo(addr("1002049")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x5L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002074")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x1L);
		}
		for (Address a = addr("1002075"); a.compareTo(addr("1002084")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x1L);
		}
		for (Address a = addr("1002085"); a.compareTo(addr("1002100")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
		for (Address a = addr("1002101"); a.compareTo(addr("1002150")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
	}

	@Test
	public void testSingleRegConflictsPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameTR2);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					setRegValue(pc, addr("1002000"), addr("1002074"), reg1, 0x5L);
					setRegValue(pc, addr("1002075"), addr("1002100"), reg1, 0x7L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameTR2);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("1002050"), addr("1002084"), reg1, 0x1L);
					setRegValue(pc, addr("1002085"), addr("1002150"), reg1, 0x3L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME); // 1002050 - 1002074
		chooseRadioButton(LATEST_BUTTON_NAME); // 1002075 - 1002084
		chooseRadioButton(LATEST_BUTTON_NAME); // 1002085 - 1002100
		waitForMergeCompletion();

		for (Address a = addr("1002000"); a.compareTo(addr("1002049")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x5L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002074")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x5L);
		}
		for (Address a = addr("1002075"); a.compareTo(addr("1002084")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x7L);
		}
		for (Address a = addr("1002085"); a.compareTo(addr("1002100")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x7L);
		}
		for (Address a = addr("1002101"); a.compareTo(addr("1002150")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
	}

	@Test
	public void testSingleRegConflictsPickVarious() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameTR2);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					setRegValue(pc, addr("1002000"), addr("1002074"), reg1, 0x5L);
					setRegValue(pc, addr("1002075"), addr("1002100"), reg1, 0x7L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameTR2);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("1002050"), addr("1002084"), reg1, 0x1L);
					setRegValue(pc, addr("1002085"), addr("1002150"), reg1, 0x3L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1002050 - 1002074
		chooseRadioButton(LATEST_BUTTON_NAME); // 1002075 - 1002084
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1002085 - 1002100
		waitForMergeCompletion();

		for (Address a = addr("1002000"); a.compareTo(addr("1002049")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x5L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002074")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x1L);
		}
		for (Address a = addr("1002075"); a.compareTo(addr("1002084")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x7L);
		}
		for (Address a = addr("1002085"); a.compareTo(addr("1002100")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
		for (Address a = addr("1002101"); a.compareTo(addr("1002150")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
	}

	@Test
	public void testMultipleRegConflictsPickVarious() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regTR2 = pc.getRegister(regNameTR2);
				Register regAx = pc.getRegister(regNameAx);
				Register regEbp = pc.getRegister(regNameEbp);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					setRegValue(pc, addr("1002000"), addr("1002074"), regTR2, 0x5L);
					setRegValue(pc, addr("1002075"), addr("1002100"), regTR2, 0x7L);
					setRegValue(pc, addr("1006420"), addr("1006440"), regAx, 0x123bL);
					setRegValue(pc, addr("1001007"), addr("1001010"), regEbp, 0x22334455L);
					setRegValue(pc, addr("1002050"), addr("1002060"), regEbp, 0x22334455L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regTR2 = pc.getRegister(regNameTR2);
				Register regAx = pc.getRegister(regNameAx);
				Register regEbp = pc.getRegister(regNameEbp);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("1001300"), addr("1001320"), regAx, 0x7788L);
					setRegValue(pc, addr("1002050"), addr("1002084"), regTR2, 0x1L);
					setRegValue(pc, addr("1002085"), addr("1002150"), regTR2, 0x3L);
					setRegValue(pc, addr("1006422"), addr("1006424"), regAx, 0x123bL);
					setRegValue(pc, addr("1006428"), addr("1006430"), regAx, 0xabcdL);
					setRegValue(pc, addr("1006432"), addr("1006434"), regAx, 0x1255L);
					setRegValue(pc, addr("1001007"), addr("1001008"), regEbp, 0xaa33cc55L);
					setRegValue(pc, addr("1002054"), addr("1002054"), regEbp, 0x22334455L);
					setRegValue(pc, addr("1002055"), addr("1002060"), regEbp, 0x99887766L);
					setRegValue(pc, addr("1002080"), addr("1002090"), regEbp, 0x12345678L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);

		// EBP register conflicts
		checkDisplayValues(new Long(0x22334455L), new Long(0xaa33cc55L), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1001007 - 1001008
		checkDisplayValues(new Long(0x22334455L), new Long(0x99887766L), (Long) null);
		chooseRadioButton(ORIGINAL_BUTTON_NAME); // 1002055 - 1002060

		// TR2 register conflicts
		checkDisplayValues(new Long(0x5L), new Long(0x1L), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1002050 - 1002074
		checkDisplayValues(new Long(0x7L), new Long(0x1L), (Long) null);
		chooseRadioButton(LATEST_BUTTON_NAME); // 1002075 - 1002084
		checkDisplayValues(new Long(0x7L), new Long(0x3L), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1002085 - 1002100

		// AX register conflicts
		checkDisplayValues(new Long(0x123bL), new Long(0xabcdL), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1006428 - 1006430
		checkDisplayValues(new Long(0x123bL), new Long(0x1255L), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1006432 - 1006434

		// BP register conflicts
		checkDisplayValues(new Long(0x4455L), new Long(0xcc55L), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1001007 - 1001008
		checkDisplayValues(new Long(0x4455L), new Long(0x7766L), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1002055 - 1002060

		// AL register conflicts
		checkDisplayValues(new Long(0x3bL), new Long(0xcdL), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1006428 - 1006430
		checkDisplayValues(new Long(0x3bL), new Long(0x55L), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1006432 - 1006434

		// AH register conflicts
		checkDisplayValues(new Long(0x12L), new Long(0xabL), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 1006428 - 100106430

		waitForMergeCompletion();

		for (Address a = addr("1002000"); a.compareTo(addr("1002049")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x5L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002074")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x1L);
		}
		for (Address a = addr("1002075"); a.compareTo(addr("1002084")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x7L);
		}
		for (Address a = addr("1002085"); a.compareTo(addr("1002100")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
		for (Address a = addr("1002101"); a.compareTo(addr("1002150")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
		for (Address a = addr("1006420"); a.compareTo(addr("1006421")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x123bL);
		}
		for (Address a = addr("1006422"); a.compareTo(addr("1006424")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x123bL);
		}
		for (Address a = addr("1006425"); a.compareTo(addr("1006427")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x123bL);
		}
		for (Address a = addr("1006428"); a.compareTo(addr("1006430")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0xabcdL);
		}
		assertRegValue(regNameAx, addr("1006431"), 0x123bL);
		for (Address a = addr("1006432"); a.compareTo(addr("1006434")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x1255L);
		}
		// EBP
		for (Address a = addr("1001007"); a.compareTo(addr("1001008")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0xaa33cc55L);
		}
		for (Address a = addr("1001009"); a.compareTo(addr("1001010")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x22334455L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002054")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x22334455L);
		}
		for (Address a = addr("1002055"); a.compareTo(addr("1002060")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue(regNameEbp, a);
		}
		for (Address a = addr("1002080"); a.compareTo(addr("1002090")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x12345678L);
		}
		// BP
		for (Address a = addr("1001007"); a.compareTo(addr("1001008")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0xcc55L);
		}
		for (Address a = addr("1001009"); a.compareTo(addr("1001010")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x4455L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002054")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x4455L);
		}
		for (Address a = addr("1002055"); a.compareTo(addr("1002060")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x7766L);
		}
		for (Address a = addr("1002080"); a.compareTo(addr("1002090")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x5678L);
		}
	}

	@Test
	public void testInstructionContextChangedPickVarious() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {

				ProgramContext pc = program.getProgramContext();
				Register regSsType = pc.getRegister(regNameContextBit);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					clear(program, "0x1006436", "0x1006436");

					setRegValue(pc, addr("1006436"), addr("1006436"), regSsType, 0x1L);
					setRegValue(pc, addr("1001000"), addr("1001010"), regSsType, 0x1L);

					disassemble(program, "0x1006436", "0x1006436");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {

				ProgramContext pc = program.getProgramContext();
				Register regSsType = pc.getRegister(regNameContextBit);

				int transactionID = program.startTransaction("Setup my version");
				try {
					clear(program, "0x1006432", "0x1006434");

					setRegValue(pc, addr("1006432"), addr("1006434"), regSsType, 0x1L);
					setRegValue(pc, addr("1001000"), addr("1001004"), regSsType, 0x1L);
					setRegValue(pc, addr("1001005"), addr("1001010"), regSsType, 0x0L);

					disassemble(program, "0x1006432", "0x1006434");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);

		// SSTYPE register causes 4 code unit conflicts
		chooseCodeUnit("0x1001004", "0x1001007", KEEP_MY);
		chooseCodeUnit("0x1001008", "0x100100b", KEEP_LATEST);
		chooseCodeUnit("0x100100c", "0x100100f", KEEP_ORIGINAL);
		chooseCodeUnit("0x1001010", "0x1001013", KEEP_MY);

		waitForMergeCompletion();

		for (Address a = addr("1006432"); a.compareTo(addr("1006434")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameContextBit, a, 0x1L);
		}
		for (Address a = addr("1006436"); a.compareTo(addr("1006436")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameContextBit, a, 0x1L);
		}
		for (Address a = addr("1001000"); a.compareTo(addr("1001004")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameContextBit, a, 0x1L);
		}
		for (Address a = addr("1001005"); a.compareTo(addr("1001007")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameContextBit, a, 0x0L);
		}
		for (Address a = addr("1001008"); a.compareTo(addr("100100b")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameContextBit, a, 0x1L);
		}
		for (Address a = addr("100100c"); a.compareTo(addr("10010f")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameContextBit, a, 0x0L);
		}
		for (Address a = addr("1001010"); a.compareTo(addr("1001010")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameContextBit, a, 0x0L);
		}
	}

	@Test
	public void testA() throws Exception {

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				int transactionID = program.startTransaction("Setup latest version");
				try {
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regEbp = pc.getRegister(regNameEbp);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("1002080"), addr("1002090"), regEbp, 0x12345678L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		for (Address a = addr("1002080"); a.compareTo(addr("1002090")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x12345678L);
		}
	}

	@Test
	public void testChangeRegConflictsPickMy() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					setRegValue(pc, addr("10022d4"), addr("10022e5"), reg1, 0x66L);
					setRegValue(pc, addr("10022ee"), addr("10022fc"), reg1, 0x44L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("10022d4"), addr("10022e5"), reg1, 0x7L);
					setRegValue(pc, addr("10022ee"), addr("10022fc"), reg1, 0x5L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		checkDisplayValues(new Long(0x66L), new Long(0x7L), new Long(0x1010101L));
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		checkDisplayValues(new Long(0x44L), new Long(0x5L), (Long) null);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		for (Address a = addr("10022d4"); a.compareTo(addr("10022e5")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x7L);
		}
		for (Address a = addr("10022ee"); a.compareTo(addr("10022fc")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x5L);
		}
	}

	@Test
	public void testChangeRegConflictsPickLatest() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					setRegValue(pc, addr("10022d4"), addr("10022e5"), reg1, 0x66L);
					setRegValue(pc, addr("10022ee"), addr("10022fc"), reg1, 0x44L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("10022d4"), addr("10022e5"), reg1, 0x7L);
					setRegValue(pc, addr("10022ee"), addr("10022fc"), reg1, 0x5L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		checkDisplayValues(new Long(0x66L), new Long(0x7L), new Long(0x1010101L));
		chooseRadioButton(LATEST_BUTTON_NAME);
		checkDisplayValues(new Long(0x44L), new Long(0x5L), (Long) null);
		chooseRadioButton(LATEST_BUTTON_NAME);
		waitForMergeCompletion();

		for (Address a = addr("10022d4"); a.compareTo(addr("10022e5")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x66L);
		}
		for (Address a = addr("10022ee"); a.compareTo(addr("10022fc")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x44L);
		}
	}

	@Test
	public void testChangeRegConflictsPickOriginal() throws Exception {

		mtf.initialize("DiffTestPgm1_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					setRegValue(pc, addr("10022d4"), addr("10022e5"), reg1, 0x66L);
					setRegValue(pc, addr("10022ee"), addr("10022fc"), reg1, 0x44L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register reg1 = pc.getRegister(regNameDR0);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("10022d4"), addr("10022e5"), reg1, 0x7L);
					setRegValue(pc, addr("10022ee"), addr("10022fc"), reg1, 0x5L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		checkDisplayValues(new Long(0x66L), new Long(0x7L), new Long(0x1010101L));
		chooseRadioButton(ORIGINAL_BUTTON_NAME);
		checkDisplayValues(new Long(0x44L), new Long(0x5L), (Long) null);
		chooseRadioButton(ORIGINAL_BUTTON_NAME);
		waitForMergeCompletion();

		for (Address a = addr("10022d4"); a.compareTo(addr("10022e5")) <= 0; a = a.add(0x1L)) {
			assertRegValue("DR0", a, 0x1010101L);
		}
		for (Address a = addr("10022ee"); a.compareTo(addr("10022fc")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue("DR0", a);
		}
	}

	private void chooseCancel() throws Exception {
		waitForPrompting();
		Window window = windowForComponent(getMergePanel());
		pressButtonByText(window, "Cancel", false);
	}

	private void checkDisplayValues(Long latest, Long my, Long original) throws Exception {
		waitForPrompting();
		String latestExpected = getValueString(latest);
		String myExpected = getValueString(my);
		String originalExpected = getValueString(original);
		waitForPostedSwingRunnables();
		Window window = windowForComponent(getMergePanel());
		final VerticalChoicesPanel comp = findComponent(window, VerticalChoicesPanel.class);
		JLabel latestLabel = (JLabel) findComponentByName(comp, comp.getComponentName(1, 1));
		JLabel myLabel = (JLabel) findComponentByName(comp, comp.getComponentName(2, 1));
		JLabel originalLabel = (JLabel) findComponentByName(comp, comp.getComponentName(3, 1));
		String latestValue = latestLabel.getText();
		String myValue = myLabel.getText();
		String originalValue = originalLabel.getText();
		assertEquals(latestExpected, latestValue);
		assertEquals(myExpected, myValue);
		assertEquals(originalExpected, originalValue);
	}

	private String getValueString(Long value) {
		if (value == null) {
			return "-- No Value --";
		}
		return "0x" + Long.toHexString(value.longValue());
	}

	/**
	 * Gets an Address that is indicated by the string.
	 * @param address a string representing the address
	 * @return the address
	 */
	@Override
	public Address addr(String address) {
		return mtf.getResultProgram().getAddressFactory().getAddress(address);
	}

	private void setRegValue(ProgramContext pc, Address start, Address end, Register reg,
			long value) throws ContextChangeException {
		BigInteger bi = BigInteger.valueOf(value);
		pc.setValue(reg, start, end, bi);
	}

	/**
	 * Fails test if the register doesn't have the specified value at the indicated address.
	 * @param registerName name of the register
	 * @param address the address to check
	 * @param expectedValue the expected value
	 */
	private void assertRegValue(String registerName, Address address, long expectedValue) {
		ProgramContext pc = resultProgram.getProgramContext();
		Register reg = pc.getRegister(registerName);
		BigInteger actualValue = pc.getValue(reg, address, false);
		if (actualValue == null) {
			Assert.fail("No register value defined for " + registerName + " at " +
				address.toString() + ".");
			return;
		}
		assertEquals(
			"Register " + registerName + " at " + address.toString() + " expected 0x" +
				Long.toHexString(expectedValue) + " but was 0x" + actualValue.toString(16),
			expectedValue, actualValue.longValue());
	}

	/**
	 * Fails test if the register does not have an undefined value at the indicated address.
	 * @param registerName name of the register
	 * @param address the address to check
	 */
	private void assertUndefinedRegValue(String registerName, Address address) {
		ProgramContext pc = resultProgram.getProgramContext();
		Register reg = pc.getRegister(registerName);
		BigInteger actualValue = pc.getValue(reg, address, false);
		if (actualValue != null) {
			Assert.fail("Register value of 0x" + actualValue.toString(16) +
				" was unexpectedly defined for " + registerName + " at " + address.toString() +
				".");
		}
	}

	private void setupUseForAll() throws Exception {
		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regTR2 = pc.getRegister(regNameTR2);
				Register regAx = pc.getRegister(regNameAx);
				Register regEbp = pc.getRegister(regNameEbp);

				int transactionID = program.startTransaction("Setup latest version");
				try {
					setRegValue(pc, addr("1002000"), addr("1002074"), regTR2, 0x5L);
					setRegValue(pc, addr("1002075"), addr("1002100"), regTR2, 0x7L);
					setRegValue(pc, addr("1006420"), addr("1006440"), regAx, 0x123bL);
					setRegValue(pc, addr("1001007"), addr("1001010"), regEbp, 0x22334455L);
					setRegValue(pc, addr("1002050"), addr("1002060"), regEbp, 0x22334455L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws ContextChangeException {
				ProgramContext pc = program.getProgramContext();
				Register regTR2 = pc.getRegister(regNameTR2);
				Register regAx = pc.getRegister(regNameAx);
				Register regEbp = pc.getRegister(regNameEbp);

				int transactionID = program.startTransaction("Setup my version");
				try {
					setRegValue(pc, addr("1001300"), addr("1001320"), regAx, 0x7788L);
					setRegValue(pc, addr("1002050"), addr("1002084"), regTR2, 0x1L);
					setRegValue(pc, addr("1002085"), addr("1002150"), regTR2, 0x3L);
					setRegValue(pc, addr("1006422"), addr("1006424"), regAx, 0x123bL);
					setRegValue(pc, addr("1006428"), addr("1006430"), regAx, 0xabcdL);
					setRegValue(pc, addr("1006432"), addr("1006434"), regAx, 0x1255L);
					setRegValue(pc, addr("1001007"), addr("1001008"), regEbp, 0xaa33cc55L);
					setRegValue(pc, addr("1002054"), addr("1002054"), regEbp, 0x22334455L);
					setRegValue(pc, addr("1002055"), addr("1002060"), regEbp, 0x99887766L);
					setRegValue(pc, addr("1002080"), addr("1002090"), regEbp, 0x12345678L);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});
	}

	@Test
	public void testDontUseForAll() throws Exception {

		setupUseForAll();

		executeMerge(ASK_USER);

		// EBP register conflicts
		checkDisplayValues(new Long(0x22334455L), new Long(0xaa33cc55L), (Long) null);
		chooseProgramContext("EBP", KEEP_MY, false); // 1001007 - 1001008
		checkDisplayValues(new Long(0x22334455L), new Long(0x99887766L), (Long) null);
		chooseProgramContext("EBP", KEEP_ORIGINAL, false); // 1002055 - 1002060

		// TR2 register conflicts
		checkDisplayValues(new Long(0x5L), new Long(0x1L), (Long) null);
		chooseProgramContext("TR2", KEEP_MY, false); // 1002050 - 1002074
		checkDisplayValues(new Long(0x7L), new Long(0x1L), (Long) null);
		chooseProgramContext("TR2", KEEP_LATEST, false); // 1002075 - 1002084
		checkDisplayValues(new Long(0x7L), new Long(0x3L), (Long) null);
		chooseProgramContext("TR2", KEEP_MY, false); // 1002085 - 1002100

		// AX register conflicts
		checkDisplayValues(new Long(0x123bL), new Long(0xabcdL), (Long) null);
		chooseProgramContext("AX", KEEP_MY, false); // 1006428 - 1006430
		checkDisplayValues(new Long(0x123bL), new Long(0x1255L), (Long) null);
		chooseProgramContext("AX", KEEP_MY, false); // 1006432 - 1006434

		// BP register conflicts
		checkDisplayValues(new Long(0x4455L), new Long(0xcc55L), (Long) null);
		chooseProgramContext("BP", KEEP_MY, false); // 1001007 - 1001008
		checkDisplayValues(new Long(0x4455L), new Long(0x7766L), (Long) null);
		chooseProgramContext("BP", KEEP_MY, false); // 1002055 - 1002060

		// AL register conflicts
		checkDisplayValues(new Long(0x3bL), new Long(0xcdL), (Long) null);
		chooseProgramContext("AL", KEEP_MY, false); // 1006428 - 1006430
		checkDisplayValues(new Long(0x3bL), new Long(0x55L), (Long) null);
		chooseProgramContext("AL", KEEP_MY, false); // 1006432 - 1006434

		// AH register conflicts
		checkDisplayValues(new Long(0x12L), new Long(0xabL), (Long) null);
		chooseProgramContext("AH", KEEP_MY, false); // 1006428 - 100106430

		waitForMergeCompletion();

		for (Address a = addr("1002000"); a.compareTo(addr("1002049")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x5L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002074")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x1L);
		}
		for (Address a = addr("1002075"); a.compareTo(addr("1002084")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x7L);
		}
		for (Address a = addr("1002085"); a.compareTo(addr("1002100")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
		for (Address a = addr("1002101"); a.compareTo(addr("1002150")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
		for (Address a = addr("1006420"); a.compareTo(addr("1006421")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x123bL);
		}
		for (Address a = addr("1006422"); a.compareTo(addr("1006424")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x123bL);
		}
		for (Address a = addr("1006425"); a.compareTo(addr("1006427")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x123bL);
		}
		for (Address a = addr("1006428"); a.compareTo(addr("1006430")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0xabcdL);
		}
		assertRegValue(regNameAx, addr("1006431"), 0x123bL);
		for (Address a = addr("1006432"); a.compareTo(addr("1006434")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x1255L);
		}
		// EBP
		for (Address a = addr("1001007"); a.compareTo(addr("1001008")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0xaa33cc55L);
		}
		for (Address a = addr("1001009"); a.compareTo(addr("1001010")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x22334455L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002054")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x22334455L);
		}
		for (Address a = addr("1002055"); a.compareTo(addr("1002060")) <= 0; a = a.add(0x1L)) {
			assertUndefinedRegValue(regNameEbp, a);
		}
		for (Address a = addr("1002080"); a.compareTo(addr("1002090")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x12345678L);
		}
		// BP
		for (Address a = addr("1001007"); a.compareTo(addr("1001008")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0xcc55L);
		}
		for (Address a = addr("1001009"); a.compareTo(addr("1001010")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x4455L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002054")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x4455L);
		}
		for (Address a = addr("1002055"); a.compareTo(addr("1002060")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x7766L);
		}
		for (Address a = addr("1002080"); a.compareTo(addr("1002090")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x5678L);
		}
	}

	@Test
	public void testUseForAll() throws Exception {

		setupUseForAll();

		executeMerge(ASK_USER);

		// EBP register conflicts
		checkDisplayValues(new Long(0x22334455L), new Long(0xaa33cc55L), (Long) null);
		chooseProgramContext("EBP", KEEP_MY, true); // 1001007 - 1001008
//		checkDisplayValues(new Long(0x22334455L), new Long(0x99887766L), (Long) null);
//		chooseProgramContext("EBP", KEEP_ORIGINAL, false); // 1002055 - 1002060

		// TR2 register conflicts
		checkDisplayValues(new Long(0x5L), new Long(0x1L), (Long) null);
		chooseProgramContext("TR2", KEEP_MY, true); // 1002050 - 1002074
//		checkDisplayValues(new Long(0x7L), new Long(0x1L), (Long) null);
//		chooseProgramContext("TR2", KEEP_LATEST, false); // 1002075 - 1002084
//		checkDisplayValues(new Long(0x7L), new Long(0x3L), (Long) null);
//		chooseProgramContext("TR2", KEEP_MY, false); // 1002085 - 1002100

		// AX register conflicts
		checkDisplayValues(new Long(0x123bL), new Long(0xabcdL), (Long) null);
		chooseProgramContext("AX", KEEP_MY, false); // 1006428 - 1006430
		checkDisplayValues(new Long(0x123bL), new Long(0x1255L), (Long) null);
		chooseProgramContext("AX", KEEP_MY, false); // 1006432 - 1006434

		// BP register conflicts
		checkDisplayValues(new Long(0x4455L), new Long(0xcc55L), (Long) null);
		chooseProgramContext("BP", KEEP_MY, true); // 1001007 - 1001008
//		checkDisplayValues(new Long(0x4455L), new Long(0x7766L), (Long) null);
//		chooseProgramContext("BP", KEEP_MY, false); // 1002055 - 1002060

		// AL register conflicts
		checkDisplayValues(new Long(0x3bL), new Long(0xcdL), (Long) null);
		chooseProgramContext("AL", KEEP_MY, false); // 1006428 - 1006430
		checkDisplayValues(new Long(0x3bL), new Long(0x55L), (Long) null);
		chooseProgramContext("AL", KEEP_MY, false); // 1006432 - 1006434

		// AH register conflicts
		checkDisplayValues(new Long(0x12L), new Long(0xabL), (Long) null);
		chooseProgramContext("AH", KEEP_MY, true); // 1006428 - 100106430

		waitForMergeCompletion();

		for (Address a = addr("1002000"); a.compareTo(addr("1002049")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x5L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002074")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x1L);
		}
		for (Address a = addr("1002075"); a.compareTo(addr("1002084")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x1L);
		}
		for (Address a = addr("1002085"); a.compareTo(addr("1002100")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
		for (Address a = addr("1002101"); a.compareTo(addr("1002150")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameTR2, a, 0x3L);
		}
		for (Address a = addr("1006420"); a.compareTo(addr("1006421")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x123bL);
		}
		for (Address a = addr("1006422"); a.compareTo(addr("1006424")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x123bL);
		}
		for (Address a = addr("1006425"); a.compareTo(addr("1006427")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x123bL);
		}
		for (Address a = addr("1006428"); a.compareTo(addr("1006430")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0xabcdL);
		}
		assertRegValue(regNameAx, addr("1006431"), 0x123bL);
		for (Address a = addr("1006432"); a.compareTo(addr("1006434")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameAx, a, 0x1255L);
		}
		// EBP
		for (Address a = addr("1001007"); a.compareTo(addr("1001008")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0xaa33cc55L);
		}
		for (Address a = addr("1001009"); a.compareTo(addr("1001010")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x22334455L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002054")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x22334455L);
		}
		for (Address a = addr("1002055"); a.compareTo(addr("1002060")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x99887766L);
		}
		for (Address a = addr("1002080"); a.compareTo(addr("1002090")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameEbp, a, 0x12345678L);
		}
		// BP
		for (Address a = addr("1001007"); a.compareTo(addr("1001008")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0xcc55L);
		}
		for (Address a = addr("1001009"); a.compareTo(addr("1001010")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x4455L);
		}
		for (Address a = addr("1002050"); a.compareTo(addr("1002054")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x4455L);
		}
		for (Address a = addr("1002055"); a.compareTo(addr("1002060")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x7766L);
		}
		for (Address a = addr("1002080"); a.compareTo(addr("1002090")) <= 0; a = a.add(0x1L)) {
			assertRegValue(regNameBp, a, 0x5678L);
		}
	}
}
