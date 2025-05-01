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
package ghidra.app.util.pdb.classtype;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.gclass.ClassID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Unit tests for the {@link MsVxtManager}.
 * <p>
 * See {@link MsVxtManager} for a description of what tests need to work
 */
public class MsVxtManagerTest extends AbstractGenericTest {

	private static MessageLog log = new MessageLog();
	private static TaskMonitor monitor = TaskMonitor.DUMMY;

	private static DataOrganizationImpl dataOrg32;
	private static DataOrganizationImpl dataOrg64;
	static {
		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl();
		bitFieldPacking.setUseMSConvention(true);
		// DataOrganization based on x86win.cspec
		// The DataOrganizationImpl currently has defaults of a 32-bit windows cspec, but could
		// change in the future.
		dataOrg32 = DataOrganizationImpl.getDefaultOrganization(null);
		dataOrg32.setBitFieldPacking(bitFieldPacking);
		// DataOrganization based on x86-64-win.cspec
		dataOrg64 = DataOrganizationImpl.getDefaultOrganization(null);
		DataOrganizationTestUtils.initDataOrganizationWindows64BitX86(dataOrg64);
		dataOrg64.setBitFieldPacking(bitFieldPacking);
	}

	private static ClassID A1 = Cfb432ProgramCreator.A1;
	private static ClassID A2 = Cfb432ProgramCreator.A2;
	private static ClassID A = Cfb432ProgramCreator.A;
	private static ClassID B1 = Cfb432ProgramCreator.B1;
	private static ClassID B2 = Cfb432ProgramCreator.B2;
	private static ClassID B = Cfb432ProgramCreator.B;
	private static ClassID C = Cfb432ProgramCreator.C;
	private static ClassID D = Cfb432ProgramCreator.D;
	private static ClassID E = Cfb432ProgramCreator.E;
	private static ClassID F = Cfb432ProgramCreator.F;
	private static ClassID G = Cfb432ProgramCreator.G;
	private static ClassID H = Cfb432ProgramCreator.H;
	private static ClassID I = Cfb432ProgramCreator.I;
	private static ClassID J = Cfb432ProgramCreator.J;
	private static ClassID K = Cfb432ProgramCreator.K;
	private static ClassID L = Cfb432ProgramCreator.L;
	private static ClassID N1 = Cfb432ProgramCreator.N1;
	private static ClassID N2 = Cfb432ProgramCreator.N2;
	private static ClassID M = Cfb432ProgramCreator.M;
	private static ClassID O1 = Cfb432ProgramCreator.O1;
	private static ClassID O2 = Cfb432ProgramCreator.O2;
	private static ClassID O3 = Cfb432ProgramCreator.O3;
	private static ClassID O4 = Cfb432ProgramCreator.O4;
	private static ClassID O = Cfb432ProgramCreator.O;

	private static ClassID P1 = Vftm32ProgramCreator.P1;
	private static ClassID P2 = Vftm32ProgramCreator.P2;
	private static ClassID Q1 = Vftm32ProgramCreator.Q1;
	private static ClassID Q2 = Vftm32ProgramCreator.Q2;
	private static ClassID Q3 = Vftm32ProgramCreator.Q3;
	private static ClassID Q4 = Vftm32ProgramCreator.Q4;
	private static ClassID Q5 = Vftm32ProgramCreator.Q5;
	private static ClassID Q6 = Vftm32ProgramCreator.Q6;
	private static ClassID Q7 = Vftm32ProgramCreator.Q7;
	private static ClassID R1 = Vftm32ProgramCreator.R1;

	private static ClassID E_G = Egray832ProgramCreator.G;
	private static ClassID E_H = Egray832ProgramCreator.H;
	private static ClassID E_G1 = Egray832ProgramCreator.G1;
	private static ClassID E_H1 = Egray832ProgramCreator.H1;
	private static ClassID E_GX1 = Egray832ProgramCreator.GX1;
	private static ClassID E_HX1 = Egray832ProgramCreator.HX1;
	private static ClassID E_IX1 = Egray832ProgramCreator.IX1;
	private static ClassID E_GG1 = Egray832ProgramCreator.GG1;
	private static ClassID E_GG2 = Egray832ProgramCreator.GG2;
	private static ClassID E_GG3 = Egray832ProgramCreator.GG3;
	private static ClassID E_GG4 = Egray832ProgramCreator.GG4;
	private static ClassID E_I = Egray832ProgramCreator.I;
	private static ClassID E_I1 = Egray832ProgramCreator.I1;
	private static ClassID E_I2 = Egray832ProgramCreator.I2;
	private static ClassID E_I3 = Egray832ProgramCreator.I3;
	private static ClassID E_I4 = Egray832ProgramCreator.I4;
	private static ClassID E_I5 = Egray832ProgramCreator.I5;
	private static ClassID E_J1 = Egray832ProgramCreator.J1;
	private static ClassID E_J2 = Egray832ProgramCreator.J2;
	private static ClassID E_J3 = Egray832ProgramCreator.J3;
	private static ClassID E_J4 = Egray832ProgramCreator.J4;
	private static ClassID E_J5 = Egray832ProgramCreator.J5;
	private static ClassID E_J6 = Egray832ProgramCreator.J6;

	private static ClassID E_P = Egray832ProgramCreator.P;
	private static ClassID E_Q = Egray832ProgramCreator.Q;
	private static ClassID E_R = Egray832ProgramCreator.R;
	private static ClassID E_S = Egray832ProgramCreator.S;
	private static ClassID E_T = Egray832ProgramCreator.T;
	private static ClassID E_U = Egray832ProgramCreator.U;
	private static ClassID E_V = Egray832ProgramCreator.V;
	private static ClassID E_W = Egray832ProgramCreator.W;
	private static ClassID E_WW = Egray832ProgramCreator.WW;

	private static ClassID E_AA3a = Egray832ProgramCreator.AA3a;
	private static ClassID E_AA3b = Egray832ProgramCreator.AA3b;
	private static ClassID E_AA3c = Egray832ProgramCreator.AA3c;
	private static ClassID E_AA3d = Egray832ProgramCreator.AA3d;
	private static ClassID E_AA3g = Egray832ProgramCreator.AA3g;

	private static ClassID E_AA4a = Egray832ProgramCreator.AA4a;
	private static ClassID E_AA4b = Egray832ProgramCreator.AA4b;
	private static ClassID E_AA4c = Egray832ProgramCreator.AA4c;
	private static ClassID E_AA4d = Egray832ProgramCreator.AA4d;
	private static ClassID E_AA4e = Egray832ProgramCreator.AA4e;
	private static ClassID E_AA4f = Egray832ProgramCreator.AA4f;
	private static ClassID E_AA4g = Egray832ProgramCreator.AA4g;
	private static ClassID E_AA4j = Egray832ProgramCreator.AA4j;
	private static ClassID E_AA4k = Egray832ProgramCreator.AA4k;
	private static ClassID E_AA4m = Egray832ProgramCreator.AA4m;
	private static ClassID E_AA4n = Egray832ProgramCreator.AA4n;
	private static ClassID E_AA4p = Egray832ProgramCreator.AA4p;
	private static ClassID E_AA4q = Egray832ProgramCreator.AA4q;

	private static ClassID E_AA5e = Egray832ProgramCreator.AA5e;
	private static ClassID E_AA5f = Egray832ProgramCreator.AA5f;
	private static ClassID E_AA5g = Egray832ProgramCreator.AA5g;
	private static ClassID E_AA5h = Egray832ProgramCreator.AA5h;
	private static ClassID E_AA5j = Egray832ProgramCreator.AA5j;

	private static ClassID E_AA6c = Egray832ProgramCreator.AA6c;
	private static ClassID E_AA6g = Egray832ProgramCreator.AA6g;
	private static ClassID E_AA6h = Egray832ProgramCreator.AA6h;
	private static ClassID E_AA6j = Egray832ProgramCreator.AA6j;

	private static ClassID E_AA7a = Egray832ProgramCreator.AA7a;
	private static ClassID E_AA7b = Egray832ProgramCreator.AA7b;
	private static ClassID E_AA7c = Egray832ProgramCreator.AA7c;
	private static ClassID E_AA7d = Egray832ProgramCreator.AA7d;

	private static ClassID E_BB1c = Egray832ProgramCreator.BB1c;
	private static ClassID E_BB1d = Egray832ProgramCreator.BB1d;

	private static ClassID E_BB2a = Egray832ProgramCreator.BB2a;
	private static ClassID E_BB2b = Egray832ProgramCreator.BB2b;
	private static ClassID E_BB2c = Egray832ProgramCreator.BB2c;
	private static ClassID E_BB2d = Egray832ProgramCreator.BB2d;
	private static ClassID E_BB2e = Egray832ProgramCreator.BB2e;

	private static ClassID E_BB3d = Egray832ProgramCreator.BB3d;
	private static ClassID E_BB3e = Egray832ProgramCreator.BB3e;
	private static ClassID E_BB3f = Egray832ProgramCreator.BB3f;
	private static ClassID E_BB3g = Egray832ProgramCreator.BB3g;

	private static ClassID E_CC1h = Egray832ProgramCreator.CC1h;

	private static ClassID E_DD1b = Egray832ProgramCreator.DD1b;
	private static ClassID E_DD1c = Egray832ProgramCreator.DD1c;
	private static ClassID E_DD1d = Egray832ProgramCreator.DD1d;

	private Program cfb432Program;
	private MockPdb cfb432Pdb;
	private Map<String, Address> cfb432AddressesByMangled;
	private MsVxtManager cfb432VxtManager;

	private Program vftm32Program;
	private MockPdb vftm32Pdb;
	private Map<String, Address> vftm32AddressesByMangled;
	private MsVxtManager vftm32VxtManager;

	private Program egray832Program;
	private MockPdb egray832Pdb;
	private Map<String, Address> egray832AddressesByMangled;
	private MsVxtManager egray832VxtManager;

	@Before
	public void setUp() throws Exception {
		ProgramTestArtifacts programTestArtifacts;
		ClassTypeManager ctm;

		Cfb432ProgramCreator cb432Creator = new Cfb432ProgramCreator();
		programTestArtifacts = cb432Creator.create();
		cfb432Program = programTestArtifacts.program();
		cfb432Pdb = programTestArtifacts.pdb();
		cfb432AddressesByMangled = programTestArtifacts.addressesByMangled();
		ctm = new ClassTypeManager(cfb432Program.getDataTypeManager());
		int txID = cfb432Program.startTransaction("Processing data.");
		boolean commit = false;
		try {
			cfb432Pdb.applySymbols(cfb432Program);
			commit = true;
		}
		finally {
			cfb432Program.endTransaction(txID, commit);
		}
		cfb432VxtManager = new MsVxtManager(ctm, cfb432Program);
		cfb432VxtManager.createVirtualTables(CategoryPath.ROOT, cfb432AddressesByMangled, log,
			monitor);

		//=====

		Vftm32ProgramCreator vftm32Creator = new Vftm32ProgramCreator();
		programTestArtifacts = vftm32Creator.create();
		vftm32Program = programTestArtifacts.program();
		vftm32Pdb = programTestArtifacts.pdb();
		vftm32AddressesByMangled = programTestArtifacts.addressesByMangled();
		ctm = new ClassTypeManager(vftm32Program.getDataTypeManager());
		txID = vftm32Program.startTransaction("Setting vxt symbols.");
		commit = false;
		try {
			vftm32Pdb.applySymbols(vftm32Program);
			commit = true;
		}
		finally {
			vftm32Program.endTransaction(txID, commit);
		}
		vftm32VxtManager = new MsVxtManager(ctm, vftm32Program);
		vftm32VxtManager.createVirtualTables(CategoryPath.ROOT, vftm32AddressesByMangled, log,
			monitor);

		//=====

		Egray832ProgramCreator egray832Creator = new Egray832ProgramCreator();
		programTestArtifacts = egray832Creator.create();
		egray832Program = programTestArtifacts.program();
		egray832Pdb = programTestArtifacts.pdb();
		egray832AddressesByMangled = programTestArtifacts.addressesByMangled();
		ctm = new ClassTypeManager(egray832Program.getDataTypeManager());
		txID = egray832Program.startTransaction("Setting vxt symbols.");
		commit = false;
		try {
			egray832Pdb.applySymbols(egray832Program);
			commit = true;
		}
		finally {
			egray832Program.endTransaction(txID, commit);
		}
		egray832VxtManager = new MsVxtManager(ctm, egray832Program);
		egray832VxtManager.createVirtualTables(CategoryPath.ROOT, egray832AddressesByMangled, log,
			monitor);

	}

	//==============================================================================================
	//==============================================================================================

	// Note that if a query is malformed (owner/parentage), bad results can be returned from
	// the manager (whether null or wrong table).  The algorithm needs improved, and we
	// might want to hone the algorithm to cause null returns on bad queries
	/**
	 * For vbts in the egray8 program...
	 * Performs the check of finding the vxt based on inheritance parentage and symbol parentage.
	 *  Note that the symbol parentage queries are based on our still-flawed understanding of
	 *  how the vxt labels are simplified.  We are using those understandings to create the
	 *  queries, but we know that they do not necessarily match the real symbol.  So that needs
	 *  fixed.  The "find" mechanism might likely also need fixed when it is all figured out.
	 * For now, the caller should set the symbol parentage to null to skip that query and notate
	 *  in a comment in the calling code what the query was intended to be (even if flawed)
	 * @param owner the class owner
	 * @param parentage the inheritance parentage
	 * @param symParentage the symbol (as we constructed) parentage
	 * @throws Exception upon check failure
	 */
	private void checkEgray8Vbt(ClassID owner, List<ClassID> parentage, List<ClassID> symParentage)
			throws Exception {
		// vbt obtained by querying on parentage
		ProgramVirtualBaseTable pvbt =
			(ProgramVirtualBaseTable) egray832VxtManager.findVbt(owner, parentage, null);
		assertEquals(egray832AddressesByMangled.get(pvbt.getMangledName()), pvbt.getAddress());
		if (symParentage == null) {
			Msg.warn(this,
				"TESTING:  Due to needed improvement, skipping vbt symParentage lookup for " +
					owner.toString() + " " + parentage.toString());
			return;
		}
		// vbt obtained by querying on msft symbol info
		ProgramVirtualBaseTable mvbt =
			(ProgramVirtualBaseTable) egray832VxtManager.findVbt(owner, symParentage, null);
		// Check if exact same table; not just equivalence
		assertTrue(mvbt == pvbt);
	}

	// Note that if a query is malformed (owner/parentage), bad results can be returned from
	// the manager (whether null or wrong table).  The algorithm needs improved, and we
	// might want to hone the algorithm to cause null returns on bad queries
	/**
	 * For vfts in the egray8 program...
	 * Performs the check of finding the vxt based on inheritance parentage and symbol parentage.
	 *  Note that the symbol parentage queries are based on our still-flawed understanding of
	 *  how the vxt labels are simplified.  We are using those understandings to create the
	 *  queries, but we know that they do not necessarily match the real symbol.  So that needs
	 *  fixed.  The "find" mechanism might likely also need fixed when it is all figured out.
	 * For now, the caller should set the symbol parentage to null to skip that query and notate
	 *  in a comment in the calling code what the query was intended to be (even if flawed)
	 * @param owner the class owner
	 * @param parentage the inheritance parentage
	 * @param symParentage the symbol (as we constructed) parentage
	 * @throws Exception upon check failure
	 */
	private void checkEgray8Vft(ClassID owner, List<ClassID> parentage, List<ClassID> symParentage)
			throws Exception {
		// vbt obtained by querying on parentage
		ProgramVirtualFunctionTable pvft =
			(ProgramVirtualFunctionTable) egray832VxtManager.findVft(owner, parentage, null);
		assertEquals(egray832AddressesByMangled.get(pvft.getMangledName()), pvft.getAddress());
		if (symParentage == null) {
			Msg.warn(this,
				"TESTING:  Due to needed improvement, skipping vft symParentage lookup for " +
					owner.toString() + " " + parentage.toString());
			return;
		}
		// vbt obtained by querying on msft symbol info
		ProgramVirtualFunctionTable mvft =
			(ProgramVirtualFunctionTable) egray832VxtManager.findVft(owner, symParentage, null);
		// Check if exact same table; not just equivalence
		assertTrue(mvft == pvft);
	}

	// Note that if a query is malformed (owner/parentage), bad results can be returned from
	// the manager (whether null or wrong table).  The algorithm needs improved, and we
	// might want to hone the algorithm to cause null returns on bad queries
	/**
	 * For vbts in the cfb4 program...
	 * Performs the check of finding the vxt based on inheritance parentage and symbol parentage.
	 *  Note that the symbol parentage queries are based on our still-flawed understanding of
	 *  how the vxt labels are simplified.  We are using those understandings to create the
	 *  queries, but we know that they do not necessarily match the real symbol.  So that needs
	 *  fixed.  The "find" mechanism might likely also need fixed when it is all figured out.
	 * For now, the caller should set the symbol parentage to null to skip that query and notate
	 *  in a comment in the calling code what the query was intended to be (even if flawed)
	 * @param owner the class owner
	 * @param parentage the inheritance parentage
	 * @param symParentage the symbol (as we constructed) parentage
	 * @throws Exception upon check failure
	 */
	private void checkCfb4Vbt(ClassID owner, List<ClassID> parentage, List<ClassID> symParentage)
			throws Exception {
		// vbt obtained by querying on parentage
		ProgramVirtualBaseTable pvbt =
			(ProgramVirtualBaseTable) cfb432VxtManager.findVbt(owner, parentage, null);
		assertEquals(cfb432AddressesByMangled.get(pvbt.getMangledName()), pvbt.getAddress());
		if (symParentage == null) {
			Msg.warn(this,
				"TESTING:  Due to needed improvement, skipping vbt symParentage lookup for " +
					owner.toString() + " " + parentage.toString());
			return;
		}
		// vbt obtained by querying on msft symbol info
		ProgramVirtualBaseTable mvbt =
			(ProgramVirtualBaseTable) cfb432VxtManager.findVbt(owner, symParentage, null);
		// Check if exact same table; not just equivalence
		assertTrue(mvbt == pvbt);
	}

	// Note that if a query is malformed (owner/parentage), bad results can be returned from
	// the manager (whether null or wrong table).  The algorithm needs improved, and we
	// might want to hone the algorithm to cause null returns on bad queries
	/**
	 * For vfts in the cfb4 program...
	 * Performs the check of finding the vxt based on inheritance parentage and symbol parentage.
	 *  Note that the symbol parentage queries are based on our still-flawed understanding of
	 *  how the vxt labels are simplified.  We are using those understandings to create the
	 *  queries, but we know that they do not necessarily match the real symbol.  So that needs
	 *  fixed.  The "find" mechanism might likely also need fixed when it is all figured out.
	 * For now, the caller should set the symbol parentage to null to skip that query and notate
	 *  in a comment in the calling code what the query was intended to be (even if flawed)
	 * @param owner the class owner
	 * @param parentage the inheritance parentage
	 * @param symParentage the symbol (as we constructed) parentage
	 * @throws Exception upon check failure
	 */
	private void checkCfb4Vft(ClassID owner, List<ClassID> parentage, List<ClassID> symParentage)
			throws Exception {
		// vbt obtained by querying on parentage
		ProgramVirtualFunctionTable pvft =
			(ProgramVirtualFunctionTable) cfb432VxtManager.findVft(owner, parentage, null);
		assertEquals(cfb432AddressesByMangled.get(pvft.getMangledName()), pvft.getAddress());
		if (symParentage == null) {
			Msg.warn(this,
				"TESTING:  Due to needed improvement, skipping vft symParentage lookup for " +
					owner.toString() + " " + parentage.toString());
			return;
		}
		// vbt obtained by querying on msft symbol info
		ProgramVirtualFunctionTable mvft =
			(ProgramVirtualFunctionTable) cfb432VxtManager.findVft(owner, symParentage, null);
		// Check if exact same table; not just equivalence
		assertTrue(mvft == pvft);
	}

	// Note that if a query is malformed (owner/parentage), bad results can be returned from
	// the manager (whether null or wrong table).  The algorithm needs improved, and we
	// might want to hone the algorithm to cause null returns on bad queries
	/**
	 * For vbts in the vftm program...
	 * Performs the check of finding the vxt based on inheritance parentage and symbol parentage.
	 *  Note that the symbol parentage queries are based on our still-flawed understanding of
	 *  how the vxt labels are simplified.  We are using those understandings to create the
	 *  queries, but we know that they do not necessarily match the real symbol.  So that needs
	 *  fixed.  The "find" mechanism might likely also need fixed when it is all figured out.
	 * For now, the caller should set the symbol parentage to null to skip that query and notate
	 *  in a comment in the calling code what the query was intended to be (even if flawed)
	 * @param owner the class owner
	 * @param parentage the inheritance parentage
	 * @param symParentage the symbol (as we constructed) parentage
	 * @throws Exception upon check failure
	 */
	private void checkVftmVbt(ClassID owner, List<ClassID> parentage, List<ClassID> symParentage)
			throws Exception {
		// vbt obtained by querying on parentage
		ProgramVirtualBaseTable pvbt =
			(ProgramVirtualBaseTable) vftm32VxtManager.findVbt(owner, parentage, null);
		assertEquals(vftm32AddressesByMangled.get(pvbt.getMangledName()), pvbt.getAddress());
		if (symParentage == null) {
			Msg.warn(this,
				"TESTING:  Due to needed improvement, skipping vbt symParentage lookup for " +
					owner.toString() + " " + parentage.toString());
			return;
		}
		// vbt obtained by querying on msft symbol info
		ProgramVirtualBaseTable mvbt =
			(ProgramVirtualBaseTable) vftm32VxtManager.findVbt(owner, symParentage, null);
		// Check if exact same table; not just equivalence
		assertTrue(mvbt == pvbt);
	}

	// Note that if a query is malformed (owner/parentage), bad results can be returned from
	// the manager (whether null or wrong table).  The algorithm needs improved, and we
	// might want to hone the algorithm to cause null returns on bad queries
	/**
	 * For vfts in the vftm program...
	 * Performs the check of finding the vxt based on inheritance parentage and symbol parentage.
	 *  Note that the symbol parentage queries are based on our still-flawed understanding of
	 *  how the vxt labels are simplified.  We are using those understandings to create the
	 *  queries, but we know that they do not necessarily match the real symbol.  So that needs
	 *  fixed.  The "find" mechanism might likely also need fixed when it is all figured out.
	 * For now, the caller should set the symbol parentage to null to skip that query and notate
	 *  in a comment in the calling code what the query was intended to be (even if flawed)
	 * @param owner the class owner
	 * @param parentage the inheritance parentage
	 * @param symParentage the symbol (as we constructed) parentage
	 * @throws Exception upon check failure
	 */
	private void checkVftmVft(ClassID owner, List<ClassID> parentage, List<ClassID> symParentage)
			throws Exception {
		// vbt obtained by querying on parentage
		ProgramVirtualFunctionTable pvft =
			(ProgramVirtualFunctionTable) vftm32VxtManager.findVft(owner, parentage, null);
		assertEquals(vftm32AddressesByMangled.get(pvft.getMangledName()), pvft.getAddress());
		if (symParentage == null) {
			Msg.warn(this,
				"TESTING:  Due to needed improvement, skipping vft symParentage lookup for " +
					owner.toString() + " " + parentage.toString());
			return;
		}
		// vbt obtained by querying on msft symbol info
		ProgramVirtualFunctionTable mvft =
			(ProgramVirtualFunctionTable) vftm32VxtManager.findVft(owner, symParentage, null);
		// Check if exact same table; not just equivalence
		assertTrue(mvft == pvft);
	}

	//==============================================================================================
	//==============================================================================================
	@Test
	public void testEgray8MVbt() throws Exception {

		checkEgray8Vbt(E_G, List.of(E_G), List.of());

		checkEgray8Vbt(E_H, List.of(E_H), List.of());

		checkEgray8Vbt(E_GG1, List.of(E_GG1), List.of());

		checkEgray8Vbt(E_GG2, List.of(E_GG2), List.of());

		checkEgray8Vbt(E_GG3, List.of(E_GG3), List.of());

		checkEgray8Vbt(E_GG4, List.of(E_GG4), List.of());

		checkEgray8Vbt(E_I, List.of(E_G, E_I), List.of(E_G));
		checkEgray8Vbt(E_I, List.of(E_H, E_I), List.of(E_H));

		checkEgray8Vbt(E_GX1, List.of(E_GX1), List.of());

		checkEgray8Vbt(E_HX1, List.of(E_HX1), List.of());

		checkEgray8Vbt(E_IX1, List.of(E_GX1, E_IX1), List.of(E_GX1));
		checkEgray8Vbt(E_IX1, List.of(E_HX1, E_IX1), List.of(E_HX1));

		checkEgray8Vbt(E_G1, List.of(E_G1), List.of());

		checkEgray8Vbt(E_H1, List.of(E_H1), List.of());

		checkEgray8Vbt(E_I1, List.of(E_G1, E_I1), List.of(E_G1));
		checkEgray8Vbt(E_I1, List.of(E_H, E_I1), List.of(E_H));

		checkEgray8Vbt(E_I2, List.of(E_G, E_I2), List.of(E_G));
		checkEgray8Vbt(E_I2, List.of(E_H1, E_I2), List.of(E_H1));

		checkEgray8Vbt(E_I3, List.of(E_G1, E_I3), List.of(E_G1));
		checkEgray8Vbt(E_I3, List.of(E_H1, E_I3), List.of(E_H1));

		checkEgray8Vbt(E_I4, List.of(E_G1, E_I4), List.of());

		checkEgray8Vbt(E_I5, List.of(E_G1, E_I5), List.of());

		checkEgray8Vbt(E_J1, List.of(E_G1, E_I1, E_J1), List.of(E_G1));
		checkEgray8Vbt(E_J1, List.of(E_H, E_I1, E_J1), List.of(E_H));
		checkEgray8Vbt(E_J1, List.of(E_G, E_I2, E_J1), List.of(E_G));
		checkEgray8Vbt(E_J1, List.of(E_H1, E_I2, E_J1), List.of(E_H1));

		checkEgray8Vbt(E_J2, List.of(E_G, E_I2, E_J2), List.of(E_G));
		checkEgray8Vbt(E_J2, List.of(E_H1, E_I2, E_J2), List.of(E_H1));
		checkEgray8Vbt(E_J2, List.of(E_G1, E_I1, E_J2), List.of(E_G1));
		checkEgray8Vbt(E_J2, List.of(E_H, E_I1, E_J2), List.of(E_H));

		checkEgray8Vbt(E_J3, List.of(E_G, E_I2, E_J3), List.of(E_G));
		checkEgray8Vbt(E_J3, List.of(E_H1, E_I2, E_J3), List.of(E_H1));
		checkEgray8Vbt(E_J3, List.of(E_G1, E_I1, E_J3), List.of(E_G1));
		checkEgray8Vbt(E_J3, List.of(E_H, E_I1, E_J3), List.of(E_H));

		checkEgray8Vbt(E_J4, List.of(E_G1, E_I3, E_J4), List.of(E_G1));
		checkEgray8Vbt(E_J4, List.of(E_H1, E_I3, E_J4), List.of(E_H1));
		checkEgray8Vbt(E_J4, List.of(E_GG1, E_J4), List.of(E_GG1));
		checkEgray8Vbt(E_J4, List.of(E_G, E_I, E_J4), List.of(E_G));
		checkEgray8Vbt(E_J4, List.of(E_H, E_I, E_J4), List.of(E_H));
		checkEgray8Vbt(E_J4, List.of(E_GG2, E_J4), List.of(E_GG2));
		checkEgray8Vbt(E_J4, List.of(E_GG3, E_J4), List.of(E_GG3));

		checkEgray8Vbt(E_J5, List.of(E_G1, E_I3, E_J5), List.of(E_G1));
		checkEgray8Vbt(E_J5, List.of(E_H1, E_I3, E_J5), List.of(E_H1));
		checkEgray8Vbt(E_J5, List.of(E_GG1, E_J5), List.of(E_GG1));
		checkEgray8Vbt(E_J5, List.of(E_G, E_I, E_J5), List.of(E_G));
		checkEgray8Vbt(E_J5, List.of(E_H, E_I, E_J5), List.of(E_H));
		checkEgray8Vbt(E_J5, List.of(E_GG2, E_J5), List.of(E_GG2));
		checkEgray8Vbt(E_J5, List.of(E_GG3, E_J5), List.of(E_GG3));

		// msft symbol query is same as regular query
		checkEgray8Vbt(E_J6, List.of(E_J6), List.of(E_J6));
		checkEgray8Vbt(E_J6, List.of(E_GG4, E_J6), List.of(E_GG4));
		checkEgray8Vbt(E_J6, List.of(E_GG3, E_J6), List.of(E_GG3));

		checkEgray8Vbt(E_T, List.of(E_T), List.of());
		checkEgray8Vbt(E_U, List.of(E_T, E_U), List.of());

		checkEgray8Vbt(E_AA3a, List.of(E_AA3a), List.of());

		checkEgray8Vbt(E_AA3b, List.of(E_AA3b), List.of());

		checkEgray8Vbt(E_AA3c, List.of(E_AA3a, E_AA3c), List.of(E_AA3a));
		checkEgray8Vbt(E_AA3c, List.of(E_AA3b, E_AA3c), List.of(E_AA3b));

		// msft symbol query is same as regular query
		checkEgray8Vbt(E_AA3d, List.of(E_AA3d), List.of(E_AA3d));
		checkEgray8Vbt(E_AA3d, List.of(E_AA3a, E_AA3d), List.of(E_AA3a));
		checkEgray8Vbt(E_AA3d, List.of(E_AA3b, E_AA3d), List.of(E_AA3b));

		checkEgray8Vbt(E_AA3g, List.of(E_AA3g), List.of());

		checkEgray8Vbt(E_AA4a, List.of(E_AA4a), List.of());

		checkEgray8Vbt(E_AA4b, List.of(E_AA4b), List.of());

		checkEgray8Vbt(E_AA4c, List.of(E_AA4a, E_AA4c), List.of(E_AA4a));
		checkEgray8Vbt(E_AA4c, List.of(E_AA4b, E_AA4c), List.of(E_AA4b));

		checkEgray8Vbt(E_AA4d, List.of(E_AA4b, E_AA4d), List.of(E_AA4b));
		checkEgray8Vbt(E_AA4d, List.of(E_AA4a, E_AA4d), List.of(E_AA4a));

		checkEgray8Vbt(E_AA4e, List.of(E_AA4a, E_AA4e), List.of(E_AA4a));
		checkEgray8Vbt(E_AA4e, List.of(E_AA4b, E_AA4e), List.of(E_AA4b));

		// msft symbol query is same as regular query
		checkEgray8Vbt(E_AA4f, List.of(E_AA4f), List.of(E_AA4f));
		checkEgray8Vbt(E_AA4f, List.of(E_AA4a, E_AA4f), List.of(E_AA4a));
		checkEgray8Vbt(E_AA4f, List.of(E_AA4b, E_AA4f), List.of(E_AA4b));

		checkEgray8Vbt(E_AA4g, List.of(E_AA4b, E_AA4g), List.of());

		checkEgray8Vbt(E_AA4j, List.of(E_AA4j), List.of());

		checkEgray8Vbt(E_AA4k, List.of(E_AA4k), List.of());

		checkEgray8Vbt(E_AA4m, List.of(E_AA4j, E_AA4m), List.of());

		checkEgray8Vbt(E_AA4n, List.of(E_AA4k, E_AA4n), List.of());

		checkEgray8Vbt(E_AA4p, List.of(E_AA4j, E_AA4m, E_AA4p), List.of());

		// "List.of()" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_AA4q, List.of(E_AA4k, E_AA4n, E_AA4q), List.of());
		checkEgray8Vbt(E_AA4q, List.of(E_AA4k, E_AA4n, E_AA4q), null);
		// "List.of()" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_AA4q, List.of(E_AA4j, E_AA4m, E_AA4q), List.of());
		checkEgray8Vbt(E_AA4q, List.of(E_AA4j, E_AA4m, E_AA4q), null);

		checkEgray8Vbt(E_AA5e, List.of(E_AA5e), List.of());

		checkEgray8Vbt(E_AA5f, List.of(E_AA5f), List.of());

		// msft symbol query is same as regular query
		checkEgray8Vbt(E_AA5g, List.of(E_AA5g), List.of(E_AA5g));
		// "List.of()" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_AA5g, List.of(E_AA5e, E_AA5g), List.of());
		checkEgray8Vbt(E_AA5g, List.of(E_AA5e, E_AA5g), null);

		// msft symbol query is same as regular query
		checkEgray8Vbt(E_AA5h, List.of(E_AA5h), List.of(E_AA5h));
		// "List.of()" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_AA5h, List.of(E_AA5f, E_AA5h), List.of());
		checkEgray8Vbt(E_AA5h, List.of(E_AA5f, E_AA5h), null);

		checkEgray8Vbt(E_AA5j, List.of(E_AA5g, E_AA5j), List.of(E_AA5g));
		checkEgray8Vbt(E_AA5j, List.of(E_AA5h, E_AA5j), List.of(E_AA5h));
		// "List.of()" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_AA5j, List.of(E_AA5e, E_AA5g, E_AA5j), List.of());
		checkEgray8Vbt(E_AA5j, List.of(E_AA5e, E_AA5g, E_AA5j), null);
		// "List.of()" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_AA5j, List.of(E_AA5f, E_AA5h, E_AA5j), List.of());
		checkEgray8Vbt(E_AA5j, List.of(E_AA5f, E_AA5h, E_AA5j), null);

		checkEgray8Vbt(E_AA6c, List.of(E_AA6c), List.of());

		checkEgray8Vbt(E_AA6g, List.of(E_AA6c, E_AA6g), List.of(E_AA6g));

		// msft symbol query is same as regular query
		checkEgray8Vbt(E_AA6h, List.of(E_AA6h), List.of(E_AA6h));
		// "List.of()" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_AA6h, List.of(E_AA6c, E_AA6h), List.of());
		checkEgray8Vbt(E_AA6h, List.of(E_AA6c, E_AA6h), null);

		// msft symbol query is same as regular query
		checkEgray8Vbt(E_AA6j, List.of(E_AA6j), List.of(E_AA6j));
		// "List.of()" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_AA6j, List.of(E_AA6c, E_AA6j), List.of());
		checkEgray8Vbt(E_AA6j, List.of(E_AA6c, E_AA6j), null);

		checkEgray8Vbt(E_AA7d, List.of(E_AA7d), List.of());

		checkEgray8Vbt(E_BB1c, List.of(E_BB1c), List.of());

		checkEgray8Vbt(E_BB1d, List.of(E_BB1c, E_BB1d), List.of());

		checkEgray8Vbt(E_BB2a, List.of(E_BB2a), List.of());

		checkEgray8Vbt(E_BB2b, List.of(E_BB2a, E_BB2b), List.of());

		// msft symbol query is same as regular query
		checkEgray8Vbt(E_BB2c, List.of(E_BB2c), List.of(E_BB2c));
		// "List.of()" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_BB2c, List.of(E_BB2a, E_BB2c), List.of());
		checkEgray8Vbt(E_BB2c, List.of(E_BB2a, E_BB2c), null);

		// "List.of(E_BB2b)" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_BB2d, List.of(E_BB2a, E_BB2b, E_BB2d), List.of(E_BB2b));
		checkEgray8Vbt(E_BB2d, List.of(E_BB2a, E_BB2b, E_BB2d), null);
		checkEgray8Vbt(E_BB2d, List.of(E_BB2c, E_BB2d), List.of(E_BB2c));
		// "List.of(E_BB2c)" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vbt(E_BB2d, List.of(E_BB2a, E_BB2c, E_BB2d), List.of(E_BB2c));
		checkEgray8Vbt(E_BB2d, List.of(E_BB2a, E_BB2c, E_BB2d), null);

		checkEgray8Vbt(E_BB2e, List.of(E_BB2a, E_BB2b, E_BB2e), List.of());

		checkEgray8Vbt(E_BB3d, List.of(E_BB3d), List.of());

		checkEgray8Vbt(E_BB3e, List.of(E_BB3e), List.of());

		checkEgray8Vbt(E_BB3f, List.of(E_BB3d, E_BB3f), List.of(E_BB3d));
		checkEgray8Vbt(E_BB3f, List.of(E_BB3e, E_BB3f), List.of(E_BB3e));

		checkEgray8Vbt(E_BB3g, List.of(E_BB3e, E_BB3g), List.of(E_BB3e));
		checkEgray8Vbt(E_BB3g, List.of(E_BB3d, E_BB3g), List.of(E_BB3d));

		checkEgray8Vbt(E_CC1h, List.of(E_CC1h), List.of());

		checkEgray8Vbt(E_DD1b, List.of(E_DD1b), List.of());

		checkEgray8Vbt(E_DD1c, List.of(E_DD1b, E_DD1c), List.of());

		checkEgray8Vbt(E_DD1d, List.of(E_DD1b, E_DD1d), List.of());

	}

	//==============================================================================================
	@Test
	public void testEgray8MVft() throws Exception {

		checkEgray8Vft(E_P, List.of(), List.of(E_P));

		checkEgray8Vft(E_Q, List.of(), List.of(E_P, E_Q));

		checkEgray8Vft(E_R, List.of(), List.of(E_R));

		checkEgray8Vft(E_S, List.of(E_P), List.of(E_P, E_S));
		checkEgray8Vft(E_S, List.of(E_R), List.of(E_R, E_S));

		// msft symbol query is same as regular query
		checkEgray8Vft(E_T, List.of(E_T), List.of(E_T));
		// "List.of(E_P, E_T)" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vft(E_T, List.of(), List.of(E_P, E_T));
		checkEgray8Vft(E_T, List.of(), null);

		checkEgray8Vft(E_U, List.of(E_T), List.of(E_T, E_U));
		// "List.of()" is wrong here, but until we can get the algorithm in
		//   CppCompositeType correct for generating the query (and understanding of the
		//   simplification), we are commenting this part out.
		//checkEgray8Vft(E_U, List.of(E_P, E_T, E_U), List.of());
		checkEgray8Vft(E_U, List.of(E_P, E_T, E_U), null);

		checkEgray8Vft(E_V, List.of(), List.of(E_V));

		checkEgray8Vft(E_W, List.of(), List.of(E_V, E_W));

		checkEgray8Vft(E_WW, List.of(), List.of(E_V, E_W, E_WW));

		checkEgray8Vft(E_AA7a, List.of(), List.of(E_AA7a));

		checkEgray8Vft(E_AA7b, List.of(), List.of(E_AA7b));

		checkEgray8Vft(E_AA7c, List.of(E_AA7a), List.of(E_AA7a, E_AA7c));
		checkEgray8Vft(E_AA7c, List.of(E_AA7b), List.of(E_AA7b, E_AA7c));

		// msft symbol query is same as regular query
		checkEgray8Vft(E_AA7d, List.of(E_AA7d), List.of(E_AA7d));
		checkEgray8Vft(E_AA7d, List.of(E_AA7a), List.of(E_AA7a, E_AA7d));
		checkEgray8Vft(E_AA7d, List.of(E_AA7b), List.of(E_AA7b, E_AA7d));

	}

	//==============================================================================================
	//==============================================================================================
	@Test
	public void testVftmMVbt() throws Exception {

		checkVftmVbt(Q4, List.of(), List.of(Q4));

		checkVftmVbt(Q5, List.of(), List.of(Q5));

		checkVftmVbt(Q6, List.of(), List.of(Q6));

		checkVftmVbt(Q7, List.of(), List.of(Q7));

		checkVftmVbt(R1, List.of(), List.of(R1));

	}

	//==============================================================================================
	@Test
	public void testVftmMVft() throws Exception {

		checkVftmVft(P1, List.of(), List.of(P1));

		checkVftmVft(P2, List.of(), List.of(P2));

		checkVftmVft(Q1, List.of(P1), List.of(P1, Q1));
		checkVftmVft(Q1, List.of(P2), List.of(P2, Q1));

		checkVftmVft(Q2, List.of(P1), List.of(P1, Q2));
		checkVftmVft(Q2, List.of(P2), List.of(P2, Q2));

		checkVftmVft(Q3, List.of(P1), List.of(P1, Q3));
		checkVftmVft(Q3, List.of(P2), List.of(P2, Q3));

		checkVftmVft(Q4, List.of(P2), List.of(P2, Q4));
		checkVftmVft(Q4, List.of(P1), List.of(P1, Q4));

		checkVftmVft(Q5, List.of(P1), List.of(P1, Q5));
		checkVftmVft(Q5, List.of(P2), List.of(P2, Q5));

		checkVftmVft(Q6, List.of(P1), List.of(P1, Q6));
		checkVftmVft(Q6, List.of(P2), List.of(P2, Q6));

		// msft symbol query is same as regular query
		checkVftmVft(Q7, List.of(Q7), List.of(Q7));
		checkVftmVft(Q7, List.of(P1), List.of(P1, Q7));
		checkVftmVft(Q7, List.of(P2), List.of(P2, Q7));

		// msft symbol query is same as regular query
		checkVftmVft(R1, List.of(R1), List.of(R1));
		checkVftmVft(R1, List.of(P1, Q1), List.of(P1, Q1, R1));
		checkVftmVft(R1, List.of(P2, Q1), List.of(P2, Q1, R1));
		checkVftmVft(R1, List.of(P1, Q2), List.of(P1, Q2, R1));
		checkVftmVft(R1, List.of(P2, Q2), List.of(P2, Q2, R1));

	}

	//==============================================================================================
	//==============================================================================================
	@Test
	public void testCfb4MVbt() throws Exception {

		checkCfb4Vbt(A, List.of(), List.of(A));

		checkCfb4Vbt(B, List.of(), List.of(B));

		checkCfb4Vbt(C, List.of(), List.of(C));

		checkCfb4Vbt(D, List.of(C), List.of(C, D));
		checkCfb4Vbt(D, List.of(A), List.of(A, D));
		checkCfb4Vbt(D, List.of(B), List.of(B, D));

		checkCfb4Vbt(E, List.of(A), List.of(A, E));
		checkCfb4Vbt(E, List.of(B), List.of(B, E));

		checkCfb4Vbt(F, List.of(), List.of(F));

		checkCfb4Vbt(G, List.of(), List.of(F, G));

		checkCfb4Vbt(H, List.of(), List.of(F, H));

		checkCfb4Vbt(I, List.of(G), List.of(F, G, I));
		checkCfb4Vbt(I, List.of(H), List.of(F, H, I));

		checkCfb4Vbt(J, List.of(H), List.of(J));

		checkCfb4Vbt(K, List.of(), List.of(J, K));

		checkCfb4Vbt(L, List.of(), List.of(J, K, L));

		checkCfb4Vbt(M, List.of(A, E), List.of(A, E, M));
		checkCfb4Vbt(M, List.of(C), List.of(C, D, M));
		checkCfb4Vbt(M, List.of(A, D), List.of(A, D, M));
		checkCfb4Vbt(M, List.of(B, D), List.of(B, D, M));
		checkCfb4Vbt(M, List.of(G), List.of(F, G, I, M));
		checkCfb4Vbt(M, List.of(H), List.of(F, H, I, M));
		checkCfb4Vbt(M, List.of(), List.of(J, K, L, M));
		checkCfb4Vbt(M, List.of(B, E), List.of(B, E, M));

		checkCfb4Vbt(O1, List.of(A), List.of(A, O1));
		checkCfb4Vbt(O1, List.of(B), List.of(B, O1));

		checkCfb4Vbt(O2, List.of(A), List.of(A, O2));
		checkCfb4Vbt(O2, List.of(B), List.of(B, O2));

		checkCfb4Vbt(O3, List.of(A), List.of(A, O3));
		checkCfb4Vbt(O3, List.of(B), List.of(B, O3));

		checkCfb4Vbt(O4, List.of(A), List.of(A, O4));
		checkCfb4Vbt(O4, List.of(B), List.of(B, O4));

		checkCfb4Vbt(O, List.of(A, O1), List.of(A, O1, O));
		checkCfb4Vbt(O, List.of(B, O1), List.of(B, O1, O));
		checkCfb4Vbt(O, List.of(A, O2), List.of(A, O2, O));
		checkCfb4Vbt(O, List.of(B, O2), List.of(B, O2, O));
		checkCfb4Vbt(O, List.of(A, O3), List.of(A, O3, O));
		checkCfb4Vbt(O, List.of(B, O3), List.of(B, O3, O));
		checkCfb4Vbt(O, List.of(A, O4), List.of(A, O4, O));

	}

	//==============================================================================================
	@Test
	public void testCfb4MVft() throws Exception {

		checkCfb4Vft(A1, List.of(), List.of(A1));

		checkCfb4Vft(A2, List.of(), List.of(A2));

		checkCfb4Vft(A, List.of(), List.of(A));

		// Spot-check a function from the table
		ProgramVirtualFunctionTable vft =
			(ProgramVirtualFunctionTable) cfb432VxtManager.findVft(A, List.of(), null);
		assertEquals(cfb432AddressesByMangled.get(vft.getMangledName()), vft.getAddress());
		Address address = vft.getAddress(0);
		Symbol s = cfb432Program.getSymbolTable().getPrimarySymbol(address);
		assertEquals("ANS::A::fa_1", s.getName(true));

		checkCfb4Vft(A, List.of(A1), List.of(A1, A));
		checkCfb4Vft(A, List.of(A2), List.of(A2, A));

		checkCfb4Vft(B1, List.of(), List.of(B1));

		checkCfb4Vft(B2, List.of(), List.of(B2));

		checkCfb4Vft(B, List.of(), List.of(B));
		checkCfb4Vft(B, List.of(B1), List.of(B1, B));
		checkCfb4Vft(B, List.of(B2), List.of(B2, B));

		// msft symbol query is same as regular query
		checkCfb4Vft(C, List.of(C), List.of(C));
		checkCfb4Vft(C, List.of(A1), List.of(A1, C));
		checkCfb4Vft(C, List.of(A2), List.of(A2, C));
		checkCfb4Vft(C, List.of(B1), List.of(B1, C));
		checkCfb4Vft(C, List.of(B2), List.of(B2, C));

		checkCfb4Vft(D, List.of(C), List.of(C, D));
		checkCfb4Vft(D, List.of(A), List.of(A, D));
		checkCfb4Vft(D, List.of(B), List.of(B, D));
		checkCfb4Vft(D, List.of(A1), List.of(A1, A, D));
		checkCfb4Vft(D, List.of(A2), List.of(A2, A, D));
		checkCfb4Vft(D, List.of(B1), List.of(B1, B, D));
		checkCfb4Vft(D, List.of(B2), List.of(B2, B, D));

		checkCfb4Vft(E, List.of(A), List.of(A, E));
		checkCfb4Vft(E, List.of(A1), List.of(A1, A, E));
		checkCfb4Vft(E, List.of(A2), List.of(A2, A, E));
		checkCfb4Vft(E, List.of(B1), List.of(B1, B, E));
		checkCfb4Vft(E, List.of(B2), List.of(B2, B, E));
		checkCfb4Vft(E, List.of(B), List.of(B, E));

		checkCfb4Vft(F, List.of(), List.of(A1, F));

		checkCfb4Vft(G, List.of(), List.of(A1, F, G));

		checkCfb4Vft(H, List.of(), List.of(A1, F, H));

		checkCfb4Vft(I, List.of(), List.of(A1, F, G, I));

		checkCfb4Vft(J, List.of(), List.of(A1, J));

		checkCfb4Vft(K, List.of(), List.of(A1, J, K));

		checkCfb4Vft(L, List.of(), List.of(A1, J, K, L));

		checkCfb4Vft(N1, List.of(), List.of(A1, F));

		checkCfb4Vft(N2, List.of(), List.of(A1, F));

		checkCfb4Vft(M, List.of(A, E), List.of(A, E, M));
		checkCfb4Vft(M, List.of(C), List.of(C, D, M));
		checkCfb4Vft(M, List.of(A, D), List.of(A, D, M));
		checkCfb4Vft(M, List.of(B, D), List.of(B, D, M));
		checkCfb4Vft(M, List.of(N1), List.of(N1, M));
		checkCfb4Vft(M, List.of(A1), List.of(A1, A, E, M));
		checkCfb4Vft(M, List.of(A2), List.of(A2, A, E, M));
		checkCfb4Vft(M, List.of(B1), List.of(B1, B, E, M));
		checkCfb4Vft(M, List.of(B2), List.of(B2, B, E, M));
		checkCfb4Vft(M, List.of(B, E), List.of(B, E, M));
		checkCfb4Vft(M, List.of(N2), List.of(N2, M));

		checkCfb4Vft(O1, List.of(A), List.of(A, O1));
		checkCfb4Vft(O1, List.of(B), List.of(B, O1));
		checkCfb4Vft(O1, List.of(A1), List.of(A1, A, O1));
		checkCfb4Vft(O1, List.of(A2), List.of(A2, A, O1));
		checkCfb4Vft(O1, List.of(B1), List.of(B1, B, O1));
		checkCfb4Vft(O1, List.of(B2), List.of(B2, B, O1));

		checkCfb4Vft(O2, List.of(A), List.of(A, O2));
		checkCfb4Vft(O2, List.of(A1), List.of(A1, A, O2));
		checkCfb4Vft(O2, List.of(A2), List.of(A2, A, O2));
		checkCfb4Vft(O2, List.of(B1), List.of(B1, B, O2));
		checkCfb4Vft(O2, List.of(B2), List.of(B2, B, O2));
		checkCfb4Vft(O2, List.of(B), List.of(B, O2));

		checkCfb4Vft(O3, List.of(A), List.of(A, O3));
		checkCfb4Vft(O3, List.of(B), List.of(B, O3));
		checkCfb4Vft(O3, List.of(A1), List.of(A1, A, O3));
		checkCfb4Vft(O3, List.of(A2), List.of(A2, A, O3));
		checkCfb4Vft(O3, List.of(B1), List.of(B1, B, O3));
		checkCfb4Vft(O3, List.of(B2), List.of(B2, B, O3));

		checkCfb4Vft(O4, List.of(A), List.of(A, O4));
		checkCfb4Vft(O4, List.of(A1), List.of(A1, A, O4));
		checkCfb4Vft(O4, List.of(A2), List.of(A2, A, O4));
		checkCfb4Vft(O4, List.of(B1), List.of(B1, B, O4));
		checkCfb4Vft(O4, List.of(B2), List.of(B2, B, O4));
		checkCfb4Vft(O4, List.of(B), List.of(B, O4));

		checkCfb4Vft(O, List.of(A, O1), List.of(A, O1, O));
		checkCfb4Vft(O, List.of(B, O1), List.of(B, O1, O));
		checkCfb4Vft(O, List.of(A, O2), List.of(A, O2, O));
		checkCfb4Vft(O, List.of(A1), List.of(A1, A, O1, O));
		checkCfb4Vft(O, List.of(A2), List.of(A2, A, O1, O));
		checkCfb4Vft(O, List.of(B1), List.of(B1, B, O1, O));
		checkCfb4Vft(O, List.of(B2), List.of(B2, B, O1, O));
		checkCfb4Vft(O, List.of(B, O2), List.of(B, O2, O));
		checkCfb4Vft(O, List.of(A, O3), List.of(A, O3, O));
		checkCfb4Vft(O, List.of(B, O3), List.of(B, O3, O));
		checkCfb4Vft(O, List.of(A, O4), List.of(A, O4, O));

	}

}
