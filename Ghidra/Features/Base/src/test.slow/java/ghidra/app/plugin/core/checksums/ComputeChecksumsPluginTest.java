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
package ghidra.app.plugin.core.checksums;

import static org.junit.Assert.*;

import java.util.Random;

import org.junit.*;

import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.blockmodel.BlockModelServicePlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ComputeChecksumsPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private ComputeChecksumsPlugin plugin;
	private Program program;
	private DockingAction showProviderAction;
	private DockingAction computeAction;
	private ToggleDockingAction hexAction;
	private ToggleDockingAction selectionAction;
	private ToggleDockingAction onesCompAction;
	private ToggleDockingAction twosCompAction;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		tool = env.getTool();
		configureTool(tool);

		plugin = env.getPlugin(ComputeChecksumsPlugin.class);

		showProviderAction = (DockingAction) getAction(plugin, "GenerateChecksum");
		computeAction = (DockingAction) getAction(plugin, "Compute Checksum");
		hexAction = (ToggleDockingAction) getAction(plugin, "Show Hex Values");
		selectionAction = (ToggleDockingAction) getAction(plugin, "On Selection");
		onesCompAction = (ToggleDockingAction) getAction(plugin, "Ones Complement");
		onesCompAction = (ToggleDockingAction) getAction(plugin, "Ones Complement");
		twosCompAction = (ToggleDockingAction) getAction(plugin, "Twos Complement");

		openProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	private void openProgram() throws Exception {
		program = buildProgram("sample");
		env.showTool(program);
		waitForSwing();
	}

	private Program buildProgram(String name) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, ProgramBuilder._TOY, this);
		builder.createMemory("test1", "0x1001000", 0x2000);
		builder.createUninitializedMemory("test2", "0x1008000", 0x1000);
		builder.setBytes("0x1001000", genBytes(0x2000));
		return builder.getProgram();
	}

	private byte[] genBytes(int size) {
		byte[] bytes = new byte[size];

		Random generator = new Random(0);// always generate the same sequence for testing
		generator.nextBytes(bytes);
		return bytes;
	}

	private void closeProgram() throws Exception {
		if (program != null) {
			env.close(program);
			program = null;
		}
	}

	private Address addr(String addr) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		try {
			return space.getAddress(addr);
		}
		catch (AddressFormatException e) {
			failWithException("No such address: " + addr, e);
			return null; // can't get there
		}
	}

	private void configureTool(PluginTool toolToConfigure) throws Exception {
		toolToConfigure.addPlugin(BlockModelServicePlugin.class.getName());
		toolToConfigure.addPlugin(NextPrevAddressPlugin.class.getName());
		toolToConfigure.addPlugin(CodeBrowserPlugin.class.getName());
		toolToConfigure.addPlugin(GoToAddressLabelPlugin.class.getName());
		toolToConfigure.addPlugin(ComputeChecksumsPlugin.class.getName());
	}

	@Test
	public void testActionEnablement() throws Exception {
		assertTrue(showProviderAction.isEnabled());
		performAction(showProviderAction, true);
		assertTrue(showProviderAction.isEnabled());

		ComputeChecksumsProvider provider =
			waitForComponentProvider(ComputeChecksumsProvider.class);
		assertNotNull(provider);
		assertTrue(provider.isVisible());
		closeProgram();
		assertTrue(showProviderAction.isEnabled());
		assertTrue(provider.isVisible());
	}

	@Test
	public void testBasicChecksums() throws Exception {
		ChecksumTableModel model = setupModelForEntireProgram();
		toggleHex(false);

		ChecksumAlgorithm checksum8 = model.getChecksumFor("Checksum-8");
		ChecksumAlgorithm checksum16 = model.getChecksumFor("Checksum-16");
		ChecksumAlgorithm checksum32 = model.getChecksumFor("Checksum-32");

		assertNotNull("Could not find Checksum-8 algorithm", checksum8);
		assertNotNull("Could not find Checksum-16 algorithm", checksum16);
		assertNotNull("Could not find Checksum-32 algorithm", checksum32);

		assertEquals("37", getChecksumResult(model, checksum8));
		assertEquals("20938", getChecksumResult(model, checksum16));
		assertEquals("1711145936", getChecksumResult(model, checksum32));

		toggleHex(true);
		assertEquals("25", getChecksumResult(model, checksum8));
		assertEquals("51ca", getChecksumResult(model, checksum16));
		assertEquals("65fe03d0", getChecksumResult(model, checksum32));

		toggleHex(false);
		assertEquals("37", getChecksumResult(model, checksum8));
		assertEquals("20938", getChecksumResult(model, checksum16));
		assertEquals("1711145936", getChecksumResult(model, checksum32));

		toggleHex(true);
		selectOnesComplement(true);
		assertEquals("da", getChecksumResult(model, checksum8));
		assertEquals("ae35", getChecksumResult(model, checksum16));
		assertEquals("9a01fc2f", getChecksumResult(model, checksum32));

		selectTwosComplement(true);
		assertEquals("db", getChecksumResult(model, checksum8));
		assertEquals("af35", getChecksumResult(model, checksum16));
		assertEquals("9b01fc2f", getChecksumResult(model, checksum32));
	}

	@Test
	public void testCrcAndAdler() throws Exception {
		ChecksumTableModel model = setupModelForEntireProgram();
		toggleHex(false);

		ChecksumAlgorithm adler32 = model.getChecksumFor("Adler-32");
		ChecksumAlgorithm crc16 = model.getChecksumFor("CRC-16");
		ChecksumAlgorithm ccitt = model.getChecksumFor("CRC-16-CCITT");
		ChecksumAlgorithm crc32 = model.getChecksumFor("CRC-32");

		assertNotNull("Could not find Adler-32 checksum algorithm", adler32);
		assertNotNull("Could not find CRC-16 checksum algorithm", crc16);
		assertNotNull("Could not find CRC-CCITT checksum algorithm", ccitt);
		assertNotNull("Could not find CRC-32 checksum algorithm", crc32);

		assertEquals("370021660", getChecksumResult(model, adler32));
		assertEquals("62064", getChecksumResult(model, crc16));
		assertEquals("14727", getChecksumResult(model, ccitt));

		toggleHex(true);
		assertEquals("160e151c", getChecksumResult(model, adler32));
		assertEquals("f270", getChecksumResult(model, crc16));
		assertEquals("3987", getChecksumResult(model, ccitt));
		assertEquals("4e9736a5", getChecksumResult(model, crc32));

		toggleHex(false);
		assertEquals("370021660", getChecksumResult(model, adler32));
		assertEquals("62064", getChecksumResult(model, crc16));
		assertEquals("14727", getChecksumResult(model, ccitt));
		assertEquals("1318532773", getChecksumResult(model, crc32));

		toggleHex(true);
		selectOnesComplement(true);
		assertEquals("e9f1eae3", getChecksumResult(model, adler32));
		assertEquals("0d8f", getChecksumResult(model, crc16));
		assertEquals("c678", getChecksumResult(model, ccitt));
		assertEquals("b168c95a", getChecksumResult(model, crc32));

		selectTwosComplement(true);
		assertEquals("eaf1eae3", getChecksumResult(model, adler32));
		assertEquals("0e8f", getChecksumResult(model, crc16));
		assertEquals("c778", getChecksumResult(model, ccitt));
		assertEquals("b268c95a", getChecksumResult(model, crc32));
	}

	@Test
	public void testShaAndMd() throws Exception {
		ChecksumTableModel model = setupModelForEntireProgram();
		toggleHex(false);

		ChecksumAlgorithm md2 = model.getChecksumFor("MD2");
		ChecksumAlgorithm md5 = model.getChecksumFor("MD5");
		ChecksumAlgorithm sha1 = model.getChecksumFor("SHA-1");
		ChecksumAlgorithm sha256 = model.getChecksumFor("SHA-256");
		ChecksumAlgorithm sha384 = model.getChecksumFor("SHA-384");
		ChecksumAlgorithm sha512 = model.getChecksumFor("SHA-512");

		assertNotNull("Could not find MD-2 checksum algorithm", md2);
		assertNotNull("Could not find MD-5 checksum algorithm", md5);
		assertNotNull("Could not find SHA-1 checksum algorithm", sha1);
		assertNotNull("Could not find SHA-256 checksum algorithm", sha256);
		assertNotNull("Could not find SHA-384 checksum algorithm", sha384);
		assertNotNull("Could not find SHA-512 checksum algorithm", sha512);

		// md's and sha's have no options; Their values should never change when options change.
		String expectedMD2 = "67f3849f3330bce51ae5b7bb1946a695";
		String expectedMD5 = "baa018c4f5f618a51828c4a0c0a80658";
		String expectedSHA1 = "3f43da8834eaceead0ecbbfb76acccc9ed5dc9f4";
		String expectedSHA256 = "81bdf8b0e7adbd071f395adcd5a669d3ae8c79e6981e1c52e6f80054cb4642d8";
		String expectedSHA384 = "1dfcdf95347a1741af4e9549abbcfe3cd8b9050b3c18043e0668c289274df1f9" +
			"e6b0566d71ce37e69403ec341aedfeb5";
		String expectedSHA512 =
			"3c657c0bf046f9358e1a41a84c1f5bd033b2ac2a83d25ae36ea85cd0107bfb7d9" +
				"1e6a6cdf0a63dba57b5ac67af16f8417e17d62d239be184390b2042c6a720c5";

		assertEquals(expectedMD2, getChecksumResult(model, md2));
		assertEquals(expectedMD5, getChecksumResult(model, md5));
		assertEquals(expectedSHA1, getChecksumResult(model, sha1));
		assertEquals(expectedSHA256, getChecksumResult(model, sha256));
		assertEquals(expectedSHA384, getChecksumResult(model, sha384));
		assertEquals(expectedSHA512, getChecksumResult(model, sha512));

		toggleHex(false);
		assertEquals(expectedMD2, getChecksumResult(model, md2));
		assertEquals(expectedMD5, getChecksumResult(model, md5));
		assertEquals(expectedSHA1, getChecksumResult(model, sha1));
		assertEquals(expectedSHA256, getChecksumResult(model, sha256));
		assertEquals(expectedSHA384, getChecksumResult(model, sha384));
		assertEquals(expectedSHA512, getChecksumResult(model, sha512));

		toggleHex(true);
		selectOnesComplement(true);
		assertEquals(expectedMD2, getChecksumResult(model, md2));
		assertEquals(expectedMD5, getChecksumResult(model, md5));
		assertEquals(expectedSHA1, getChecksumResult(model, sha1));
		assertEquals(expectedSHA256, getChecksumResult(model, sha256));
		assertEquals(expectedSHA384, getChecksumResult(model, sha384));
		assertEquals(expectedSHA512, getChecksumResult(model, sha512));

		selectTwosComplement(true);
		assertEquals(expectedMD2, getChecksumResult(model, md2));
		assertEquals(expectedMD5, getChecksumResult(model, md5));
		assertEquals(expectedSHA1, getChecksumResult(model, sha1));
		assertEquals(expectedSHA256, getChecksumResult(model, sha256));
		assertEquals(expectedSHA384, getChecksumResult(model, sha384));
		assertEquals(expectedSHA512, getChecksumResult(model, sha512));
	}

	@Test
	public void testToggleSelection() throws Exception {

		ChecksumTableModel model = setupModelForSelection("0x1006420", "0x1006440");

		ChecksumAlgorithm checksum8 = model.getChecksumFor("Checksum-8");
		ChecksumAlgorithm checksum16 = model.getChecksumFor("Checksum-16");
		ChecksumAlgorithm checksum32 = model.getChecksumFor("Checksum-32");
		ChecksumAlgorithm adler32 = model.getChecksumFor("Adler-32");
		ChecksumAlgorithm crc16 = model.getChecksumFor("CRC-16");
		ChecksumAlgorithm crc32 = model.getChecksumFor("CRC-32");
		ChecksumAlgorithm ccitt = model.getChecksumFor("CRC-16-CCITT");
		ChecksumAlgorithm md2 = model.getChecksumFor("MD2");
		ChecksumAlgorithm md5 = model.getChecksumFor("MD5");
		ChecksumAlgorithm sha1 = model.getChecksumFor("SHA-1");
		ChecksumAlgorithm sha256 = model.getChecksumFor("SHA-256");
		ChecksumAlgorithm sha384 = model.getChecksumFor("SHA-384");
		ChecksumAlgorithm sha512 = model.getChecksumFor("SHA-512");

		// Results from only over the selection.
		String checksum8Selection = getChecksumResult(model, checksum8);
		String checksum16Selection = getChecksumResult(model, checksum16);
		String checksum32Selection = getChecksumResult(model, checksum32);
		String adler32Selection = getChecksumResult(model, adler32);
		String crc16Selection = getChecksumResult(model, crc16);
		String crc32Selection = getChecksumResult(model, crc32);
		String ccittSelection = getChecksumResult(model, ccitt);
		String md2Selection = getChecksumResult(model, md2);
		String md5Selection = getChecksumResult(model, md5);
		String sha1Selection = getChecksumResult(model, sha1);
		String sha256Selection = getChecksumResult(model, sha256);
		String sha384Selection = getChecksumResult(model, sha384);
		String sha512Selection = getChecksumResult(model, sha512);

		// Switches from compute over selection to compute over entire program.
		setSelected(selectionAction, false);
		waitForTasks();

		// Results from over the entire program.
		String checksum8Entire = getChecksumResult(model, checksum8);
		String checksum16Entire = getChecksumResult(model, checksum16);
		String checksum32Entire = getChecksumResult(model, checksum32);
		String adler32Entire = getChecksumResult(model, adler32);
		String crc16Entire = getChecksumResult(model, crc16);
		String crc32Entire = getChecksumResult(model, crc32);
		String ccittEntire = getChecksumResult(model, ccitt);
		String md2Entire = getChecksumResult(model, md2);
		String md5Entire = getChecksumResult(model, md5);
		String sha1Entire = getChecksumResult(model, sha1);
		String sha256Entire = getChecksumResult(model, sha256);
		String sha384Entire = getChecksumResult(model, sha384);
		String sha512Entire = getChecksumResult(model, sha512);

		assertFalse(checksum8Selection.equals(checksum8Entire));
		assertFalse(checksum16Selection.equals(checksum16Entire));
		assertFalse(checksum32Selection.equals(checksum32Entire));
		assertFalse(adler32Selection.equals(adler32Entire));
		assertFalse(crc16Selection.equals(crc16Entire));
		assertFalse(crc32Selection.equals(crc32Entire));
		assertFalse(ccittSelection.equals(ccittEntire));
		assertFalse(md2Selection.equals(md2Entire));
		assertFalse(md5Selection.equals(md5Entire));
		assertFalse(sha1Selection.equals(sha1Entire));
		assertFalse(sha256Selection.equals(sha256Entire));
		assertFalse(sha384Selection.equals(sha384Entire));
		assertFalse(sha512Selection.equals(sha512Entire));
	}

	@Test
	public void testUninitialized() throws Exception {

		setupModelForSelection("0x01002ffc", "0x01008003");

		ComputeChecksumsProvider provider = getProvider();
		String error = provider.getErrorStatus();
		assertTrue(error.contains("contains uninitialized memory"));

		String addr = "0x01001000";
		goTo(addr);
		select(addr, addr);
		error = provider.getErrorStatus();
		assertTrue(error.isEmpty());
	}

	private void goTo(String addr) {
		Address a = addr(addr);
		GoToService goTo = tool.getService(GoToService.class);
		goTo.goTo(a);
	}

	private String getChecksumResult(ChecksumTableModel model, ChecksumAlgorithm alg) {
		return (String) model.getColumnValueForRow(alg, ChecksumTableModel.VALUE_COL);
	}

	private void selectOnesComplement(boolean selected) {
		setSelected(onesCompAction, selected);
	}

	private void selectTwosComplement(boolean selected) {
		setSelected(twosCompAction, selected);
	}

	private void toggleHex(boolean selected) {
		setSelected(hexAction, selected);
	}

	private void setSelected(ToggleDockingAction action, boolean selected) {
		runSwing(() -> {

			if (action.isSelected() != selected) {
				performAction(action, false);
			}

		});

		waitForSwing();
	}

	private ComputeChecksumsProvider getProvider() {
		ComputeChecksumsProvider provider =
			waitForComponentProvider(ComputeChecksumsProvider.class);
		return provider;
	}

	private ChecksumTableModel setupModelForSelection(String from, String to) throws Exception {

		performAction(showProviderAction, true);
		waitForTasks(); // allow the provider to compute the checksums

		ComputeChecksumsProvider provider = getProvider();
		ChecksumTableModel model = provider.getModel();

		select(from, to);

		return model;
	}

	private void select(String from, String to) {
		runSwing(() -> {
			ProgramSelection selection = new ProgramSelection(addr(from), addr(to));
			tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));
		}, false);
		waitForSwing();
	}

	private ChecksumTableModel setupModelForEntireProgram() throws Exception {

		performAction(showProviderAction, true);
		performAction(computeAction, false);
		waitForTasks(); // allow the provider to compute the checksums

		ComputeChecksumsProvider provider = getProvider();
		ChecksumTableModel model = provider.getModel();
		return model;
	}
}
