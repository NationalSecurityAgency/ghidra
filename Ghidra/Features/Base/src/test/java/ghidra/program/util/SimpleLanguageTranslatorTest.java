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
package ghidra.program.util;

import static org.junit.Assert.*;

import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.util.Arrays;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import generic.test.TestUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

public class SimpleLanguageTranslatorTest extends AbstractGenericTest {

	private OldLanguage lang1;
	private OldLanguage lang3;
	private LanguageTranslator trans13;

	public SimpleLanguageTranslatorTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		lang1 = getLang1();
		lang3 = getLang3();
		trans13 = getTrans13();
	}

	private SimpleLanguageTranslator readSimpleLanguageTranslator(String translatorXML)
			throws Exception {
		Reader r = new StringReader(translatorXML);
		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
		Document document = sax.build(r);
		Element root = document.getRootElement();
		return SimpleLanguageTranslator.getSimpleLanguageTranslator("test-XML", root);
	}

	// A new instance should be created for each invocation of the LanguageTranslator.fixupInstructions method
	public static class DummyPostUpgradeHandler extends LanguagePostUpgradeInstructionHandler {

		public static volatile int dummyCalled;
		public static volatile int lastInstanceNum;

		private int instanceNum;

		public DummyPostUpgradeHandler(Program program) {
			super(program);
			instanceNum = ++lastInstanceNum;
		}

		@Override
		public void fixupInstructions(Language oldLanguage, TaskMonitor monitor)
				throws CancelledException {
			dummyCalled = instanceNum;
		}

	}

	private SimpleLanguageTranslator getTrans13() throws Exception {
		SimpleLanguageTranslator trans = readSimpleLanguageTranslator(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "<language_translation>" +
				"    <from_language version=\"1\">x86:LE:32:test</from_language>" +
				"    <to_language version=\"3\">x86:LE:32:test</to_language>" +
				"    <map_register from=\"AL\" to=\"AL2\" />" +
				"    <map_register from=\"AH\" to=\"AH2\" />" +
				"    <map_register from=\"AX\" to=\"AX2\" />" +
				"    <map_register from=\"EAX\" to=\"EAX2\" />" +
				"    <map_register from=\"XX\" to=\"XX2\" />" +
				"    <map_register from=\"XL\" to=\"XL2\" />" +
				"    <post_upgrade_handler class=\"" + DummyPostUpgradeHandler.class.getName() +
				"\" />" + "</language_translation>");
		// avoid validation issues with fictitious test languages
		TestUtils.setInstanceField("oldLanguage", trans, lang1);
		TestUtils.setInstanceField("newLanguage", trans, lang3);
		assertTrue(trans.isValid());
		int expectedInstanceNum = DummyPostUpgradeHandler.lastInstanceNum + 1;
		trans.fixupInstructions(null, null, TaskMonitor.DUMMY);
		assertEquals(expectedInstanceNum, DummyPostUpgradeHandler.dummyCalled);
		trans.fixupInstructions(null, null, TaskMonitor.DUMMY);
		assertEquals(expectedInstanceNum + 1, DummyPostUpgradeHandler.dummyCalled);
		return trans;
	}

	private OldLanguage readOldLanguage(String oldLanguageXML) throws Exception {
		Reader r = new StringReader(oldLanguageXML);
		SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
		Document document = sax.build(r);
		Element root = document.getRootElement();
		return new OldLanguage(root);
	}

	private OldLanguage getLang1() throws Exception {
		return readOldLanguage("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
			"<language version=\"1\" endian=\"little\">" + "   <description>" +
			"       <id>x86:LE:32:test</id>" + "       <processor>x86</processor>" +
			"       <variant>test</variant>" + "       <size>32</size>" + "   </description>" +
			"   <compiler name=\"abc\" id=\"abc\" />" + "   <compiler name=\"xyz\" id=\"xyz\" />" +
			"   <compiler name=\"123\" id=\"123\" />" + "   <spaces>" +
			"       <space name=\"ram\" type=\"ram\" size=\"4\" default=\"yes\" />" +
			"       <space name=\"register\" type=\"register\" size=\"4\" />" + "   </spaces>" +
			"   <registers>" +
			"       <context_register name=\"contextreg\" offset=\"0x2000\" bitsize=\"32\">" +
			"           <field name=\"a\" range=\"0,0\" />" +
			"           <field name=\"b\" range=\"1,1\" />" +
			"           <field name=\"c\" range=\"2,3\" />" + "       </context_register>" +
			"       <register name=\"EAX\" offset=\"0x0\" bitsize=\"32\" />" +
			"       <register name=\"AX\" offset=\"0x0\" bitsize=\"16\" />" +
			"       <register name=\"AL\" offset=\"0x0\" bitsize=\"8\" />" +
			"       <register name=\"AH\" offset=\"0x1\" bitsize=\"8\" />" +
			"       <register name=\"XX\" offset=\"0x10\" bitsize=\"16\" />" +
			"       <register name=\"XL\" offset=\"0x10\" bitsize=\"8\" />" + "   </registers>" +
			"</language>");
	}

	/**
	 * Return language which has modified context field offsets/sizes, register
	 * offsets, and compiler-spec ID's
	 * 
	 * NOTES: 1. Translation can not be handled by DefaultLanguageTransaltor 2.
	 * SimpleLanguageTransaltor should handle it
	 */
	private OldLanguage getLang3() throws Exception {
		return readOldLanguage("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
			"<language version=\"3\" endian=\"little\">" + "    <description>" +
			"       <id>x86:LE:32:test</id>" + "       <processor>x86</processor>" +
			"       <variant>test</variant>" + "       <size>32</size>" + "   </description>" +
			"   <compiler name=\"abc\" id=\"abc\" />" + "   <compiler name=\"xyz\" id=\"xyz\" />" +
			"   <spaces>" +
			"       <space name=\"ram\" type=\"ram\" size=\"4\" default=\"yes\" />" +
			"       <space name=\"register\" type=\"register\" size=\"4\" />" + "   </spaces>" +
			"   <registers>" +
			"       <context_register name=\"contextreg\" offset=\"0x3000\" bitsize=\"32\">" +
			"           <field name=\"a\" range=\"0,3\" />" +
			"           <field name=\"b\" range=\"4,4\" />" +
			"           <field name=\"c\" range=\"5,5\" />" + "       </context_register>" +
			"       <register name=\"RAX2\" offset=\"0x8\" bitsize=\"64\" />" +
			"       <register name=\"EAX2\" offset=\"0x8\" bitsize=\"32\" />" +
			"       <register name=\"AX2\" offset=\"0x8\" bitsize=\"16\" />" +
			"       <register name=\"AL2\" offset=\"0x8\" bitsize=\"8\" />" +
			"       <register name=\"AH2\" offset=\"0x9\" bitsize=\"8\" />" +
			"       <register name=\"XX2\" offset=\"0x20\" bitsize=\"16\" />" +
			"       <register name=\"XL2\" offset=\"0x21\" bitsize=\"8\" />" + "   </registers>" +
			"</language>");
	}

	private Address lang1Addr(String spaceName, long offset) {
		return lang1.getAddressFactory().getAddressSpace(spaceName).getAddress(offset);
	}

	@Test
	public void testGetOldRegister() {

		Register reg = trans13.getOldRegister(lang1Addr("register", 0), 4);
		assertNotNull(reg);
		assert (!reg.isProcessorContext());
		assertEquals("EAX", reg.getName());

		reg = trans13.getOldRegister(lang1Addr("register", 0), 2);
		assertNotNull(reg);
		assert (!reg.isProcessorContext());
		assertEquals("AX", reg.getName());

		reg = trans13.getOldRegister(lang1Addr("register", 0), 1);
		assertNotNull(reg);
		assert (!reg.isProcessorContext());
		assertEquals("AL", reg.getName());

		reg = trans13.getOldRegister(lang1Addr("register", 1), 1);
		assertNotNull(reg);
		assert (!reg.isProcessorContext());
		assertEquals("AH", reg.getName());
	}

	@Test
	public void testGetNewRegister() {

		Register reg = trans13.getOldRegister(lang1Addr("register", 0), 4);
		assertNotNull(reg);
		reg = trans13.getNewRegister(reg);
		assert (!reg.isProcessorContext());
		assertEquals("EAX2", reg.getName());
		assertEquals(8, reg.getAddress().getOffset());

		reg = trans13.getOldRegister(lang1Addr("register", 0), 2);
		assertNotNull(reg);
		reg = trans13.getNewRegister(reg);
		assert (!reg.isProcessorContext());
		assertEquals("AX2", reg.getName());
		assertEquals(8, reg.getAddress().getOffset());

		reg = trans13.getOldRegister(lang1Addr("register", 0), 1);
		assertNotNull(reg);
		reg = trans13.getNewRegister(reg);
		assert (!reg.isProcessorContext());
		assertEquals("AL2", reg.getName());
		assertEquals(8, reg.getAddress().getOffset());

		reg = trans13.getOldRegister(lang1Addr("register", 1), 1);
		assertNotNull(reg);
		reg = trans13.getNewRegister(reg);
		assert (!reg.isProcessorContext());
		assertEquals("AH2", reg.getName());
		assertEquals(9, reg.getAddress().getOffset());
	}

	@Test
	public void testGetOldContextRegister() {
		Register reg = trans13.getOldContextRegister();
		assertNotNull(reg);
		assert (reg.isProcessorContext());
		assertEquals(0x2000, reg.getAddress().getOffset());
	}

	@Test
	public void testGetNewContextRegister() {
		Register reg = trans13.getNewContextRegister();
		assertNotNull(reg);
		assert (reg.isProcessorContext());
		assertEquals(0x3000, reg.getAddress().getOffset());
	}

	@Test
	public void testGetNewAddressSpace() {
		AddressSpace space = trans13.getNewAddressSpace("ram");
		assertNotNull(space);
		assertEquals("ram", space.getName());
	}

	@Test
	public void testIsValueTranslationRequired() {

		Register ctx1 = trans13.getOldContextRegister();
		assertTrue(trans13.isValueTranslationRequired(ctx1));

		Register oldXX = trans13.getOldRegister(lang1Addr("register", 0x10), 2);
		assertTrue(trans13.isValueTranslationRequired(oldXX));
	}

	@Test
	public void testGetNewRegisterValue() {

		Register oldRegEAX = trans13.getOldRegister(lang1Addr("register", 0), 4);
		assertNull(oldRegEAX.getParentRegister());

		RegisterValue oldValue = new RegisterValue(oldRegEAX,
			new byte[] { (byte) 0xff, 0, (byte) 0xff, 0, 0x78, 0, 0x34, 0 });
		RegisterValue newValue = trans13.getNewRegisterValue(oldValue);
		assertNotNull(newValue);
		Register newReg = newValue.getRegister();
		assertEquals("EAX2", newReg.getName());
		assertEquals(8, newReg.getAddress().getOffset());
		assertNotNull(newReg.getParentRegister());
		assertEquals("RAX2", newReg.getParentRegister().getBaseRegister().getName());

		assertTrue(Arrays.equals(
			new byte[] { 0, 0, 0, 0, (byte) 0xff, 0, (byte) 0xff, 0, 0, 0, 0, 0, 0x78, 0, 0x34, 0 },
			newValue.toBytes()));// reflects RAX base register
	}

	@Test
	public void testGetNewContextRegisterValue() {

		RegisterValue oldValue = (new RegisterValue(lang1.getRegister("a"),
			BigInteger.valueOf(1))).getBaseRegisterValue();
		oldValue = (new RegisterValue(lang1.getRegister("c"),
			BigInteger.valueOf(3))).getBaseRegisterValue().combineValues(oldValue);
		RegisterValue newValue = trans13.getNewRegisterValue(oldValue);
		assertNotNull(newValue);
		Register newReg = newValue.getRegister();
		assertTrue(newReg.isProcessorContext());

		// field a grows from 1-bit to 4-bits, field c is truncated from 2-bit to 1-bit
		byte[] expectedBytes = new byte[] { (byte) 0xf4, 0, 0, 0, (byte) 0x14, 0, 0, 0 };
		assertTrue("context value/mask translation failed",
			Arrays.equals(expectedBytes, newValue.toBytes()));
	}

	@Test
	public void testGetNewCompilerSpecID() {

		// direct name mapping
		assertEquals(new CompilerSpecID("abc"),
			trans13.getNewCompilerSpecID(new CompilerSpecID("abc")));
		assertEquals(new CompilerSpecID("xyz"),
			trans13.getNewCompilerSpecID(new CompilerSpecID("xyz")));

		// 123 replaced by default spec abc
		assertEquals(new CompilerSpecID("abc"),
			trans13.getNewCompilerSpecID(new CompilerSpecID("123")));
	}

}
