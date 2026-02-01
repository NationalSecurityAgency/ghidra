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
package ghidra.app.plugin.processors.sleigh;

import java.io.*;

import org.junit.Assert;
import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageID;

public class SleighLanguageVolatilityTest extends AbstractGenericTest {
	protected SleighLanguage lang;
	protected String PORTFAddressString = "mem:0x31";
	protected String PORTGAddressString = "mem:0x34";
	protected boolean isPORTFVolatile;
	protected boolean isPORTGVolatile;

	/**
	 * Constructs a string based on parameters, and uses that as the content of a custom pspec file.
	 * Parameters effect the volatility of the symbol "PORTF". 
	 * The pspec file is read by the SleighLanguage object which tracks volatile addresses.
	 * @param symbolVolatile Nullable boolean value that specifies the symbol PORTF volatility setting.
	 * @param symbolSize Nullable integer value specifying the symbol PORTF size in bytes.
	 * @param memoryVolatile Nullable boolean value that specifies the volatility setting of the 
	 * 			memory location that includes PORTF.
	 * @param reverseOrder boolean, reverseOrder refers to the order that 'volatile' and 
	 * 			'default_symbols' elements appear in the pspec file.
	 * @throws Exception if an error occurred
	 */
	public void setUp(Boolean symbolVolatile, Integer symbolSize, Boolean memoryVolatile,
			boolean reverseOrder) throws Exception {
		//symbolVolatile and symbolSize are in reference to the symbol PORTF. However, setting a
		//size that is too large will overwrite other symbols such as PING, DDRG or PORTG.
		String defaultSymbolsElement =
			"  <default_symbols>\r\n" +
				"    <symbol name=\"RESET\" address=\"code:0x0000\" entry=\"true\"/>\r\n" +
				"    <symbol name=\"INT0\" address=\"code:0x0002\" entry=\"true\"/>\r\n" +
				"    <symbol name=\"INT1\" address=\"code:0x0004\" entry=\"true\"/>\r\n" +
				"    <symbol name=\"PORTE\" address=\"mem:0x2e\"/>\r\n" +
				"    <symbol name=\"PINF\" address=\"mem:0x2f\"/>\r\n" +
				"    <symbol name=\"DDRF\" address=\"mem:0x30\"/>\r\n" +
				"    <symbol name=\"PORTF\" address=\"mem:0x31\"";
		defaultSymbolsElement +=
			symbolVolatile == null ? "" : " volatile=\"" + symbolVolatile.toString() + "\"";
		defaultSymbolsElement +=
			symbolSize == null ? "" : " size=\"" + symbolSize.toString() + "\"";
		defaultSymbolsElement += " />\r\n" +
			"    <symbol name=\"PING\" address=\"mem:0x32\"/>\r\n" +
			"    <symbol name=\"DDRG\" address=\"mem:0x33\"/>\r\n" +
			"    <symbol name=\"PORTG\" address=\"mem:0x34\"/>\r\n" +
			"    <symbol name=\"TIFR0\" address=\"mem:0x35\"/>\r\n" + "  </default_symbols>\r\n";

		//memoryVolatile null will not set the memory range 0x20 to 0x57 as volatile. 
		//memoryVolatile true will set the memory range 0x20 to 0x57 to volatile.
		//memoryVolatile false will exclude the address of PORTF (0x31) from the volatility setting. 
		//Example:
		//	"<range space=\"mem\" first=\"0x20\" last=\"0x30\"/>"
		//	"<range space=\"mem\" first=\"0x32\" last=\"0x57\"/>"
		String volatileElement =
			"  <volatile outputop=\"write_volatile\" inputop=\"read_volatile\">\r\n";
		volatileElement += memoryVolatile == null ? ""
				: memoryVolatile ? "<range space=\"mem\" first=\"0x20\" last=\"0x57\"/>\r\n"
						: "<range space=\"mem\" first=\"0x20\" last=\"0x30\"/>\r\n" +
							"<range space=\"mem\" first=\"0x32\" last=\"0x57\"/>\r\n";

		volatileElement +=
			"    <range space=\"mem\" first=\"0x60\" last=\"0xff\"/>\r\n" + "  </volatile>\r\n";

		//This variable represents the content of a pspec file.
		//The original pspec file this is based on is the avr8 atmega256.pspec.
		String pspecContentString =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" + "\r\n" + "<processor_spec>\r\n" +
				"\r\n" + "  <programcounter register=\"PC\"/> \r\n" +
				"  <data_space space=\"mem\"/>\r\n";
		pspecContentString += reverseOrder ? volatileElement : defaultSymbolsElement;
		pspecContentString += "  \r\n" + "  <context_data>\r\n" +
			"    <tracked_set space=\"code\">\r\n" + "      <set name=\"R1\" val=\"0\"/>\r\n" +
			"    </tracked_set>\r\n" + "  </context_data>\r\n" + "  \r\n";
		pspecContentString += reverseOrder ? defaultSymbolsElement : volatileElement;
		pspecContentString += "\r\n" + "  <default_memory_blocks>\r\n" +
			"    <memory_block name=\"regalias\" start_address=\"mem:0x00\" length=\"0x20\" initialized=\"false\"/>\r\n" +
			"    <memory_block name=\"iospace\" start_address=\"mem:0x20\" length=\"0x1e0\" initialized=\"false\"/>\r\n" +
			"    <memory_block name=\"sram\" start_address=\"mem:0x200\" length=\"0x4000\" initialized=\"false\"/>\r\n" +
			"    <memory_block name=\"codebyte\" start_address=\"codebyte:0x0\" length=\"0x40000\" byte_mapped_address=\"code:0x0\"/>\r\n" +
			"  </default_memory_blocks>\r\n" + "\r\n" + "\r\n" + "</processor_spec>\r\n" + "";

		String languageIDString = "avr8:LE:16:atmega256Test";
		LanguageID langId = new LanguageID(languageIDString);

		ResourceFile pspecFile = createCustomPspecFile("atmega256", pspecContentString);
		ResourceFile ldefFile = createTempLdefsFile("avr8", pspecFile);
		SleighLanguageProvider provider = new SleighLanguageProvider(ldefFile);
		lang = (SleighLanguage) provider.getLanguage(langId);

		Address PORTFAddress = lang.getAddressFactory().getAddress(PORTFAddressString);
		Address PORTGAddress = lang.getAddressFactory().getAddress(PORTGAddressString);

		isPORTFVolatile = lang.isVolatile(PORTFAddress);
		isPORTGVolatile = lang.isVolatile(PORTGAddress);
	}

	@Test
	public void testPORTFWithSymbolVolatility() throws Exception {
		setUp(null, null, null, false);

		Assert.assertFalse(isPORTFVolatile);

		setUp(false, null, null, false);

		Assert.assertFalse(isPORTFVolatile);

		setUp(true, null, null, false);

		Assert.assertTrue(isPORTFVolatile);
	}

	@Test
	public void testPORTFWithSize() throws Exception {
		setUp(null, 1, null, false);

		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTGVolatile);

		setUp(false, 1, null, false);

		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTGVolatile);

		setUp(true, 1, null, false);

		Assert.assertTrue(isPORTFVolatile);
		Assert.assertFalse(isPORTGVolatile);

		setUp(null, 4, null, false);

		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTGVolatile);

		setUp(false, 4, null, false);

		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTGVolatile);

		setUp(true, 4, null, false); // setting portf to size 4 overwrites portg as well

		Assert.assertTrue(isPORTFVolatile);
		Assert.assertTrue(isPORTGVolatile);
	}

	@Test
	public void testPORTFNoSizeOrSymbolVolatility() throws Exception {
		setUp(null, null, null, false);

		Assert.assertFalse(isPORTFVolatile);

		setUp(null, null, false, false);

		Assert.assertFalse(isPORTFVolatile);

		setUp(null, null, true, false);

		Assert.assertTrue(isPORTFVolatile);
	}

	@Test
	public void testPORTFNoSize() throws Exception {
		setUp(true, null, true, false);

		Assert.assertTrue(isPORTFVolatile);

		setUp(false, null, true, false);

		Assert.assertFalse(isPORTFVolatile);

		setUp(true, null, false, false);

		Assert.assertTrue(isPORTFVolatile);

		setUp(false, null, false, false);

		Assert.assertFalse(isPORTFVolatile);
	}

	@Test
	public void testReverseSettingPORTFVolatile() throws Exception {
		setUp(false, null, null, true);
		Assert.assertFalse(isPORTFVolatile);
		setUp(true, null, null, true);
		Assert.assertTrue(isPORTFVolatile);
	}

	private ResourceFile createTempLdefsFile(String name, ResourceFile pspecFile) {
		String pspecFilename = pspecFile.getName();
		return createCustomLdefFile("avr8", pspecFilename);
	}

	public ResourceFile createCustomPspecFile(String name, String content) {
		File newPspecFile = null;
		try {
			newPspecFile = Application.createTempFile(name, ".pspec");
			BufferedWriter bw = new BufferedWriter(new FileWriter(newPspecFile));
			bw.write(content);
			bw.close();

		}
		catch (IOException e) {
			System.err.println("Error creating test pspec file.");
		}
		newPspecFile.deleteOnExit();
		return new ResourceFile(newPspecFile);
	}

	public ResourceFile createCustomLdefFile(String name, String pspecFilename) {
		Iterable<ResourceFile> files = Application.findFilesByExtensionInApplication(".ldefs");
		ResourceFile originalLdefFile = null;
		for (ResourceFile file : files) {
			if (file.getName().equals(name + ".ldefs")) {
				originalLdefFile = file;
				break;
			}
		}

		try {
			File editedPspecFile = Application.createTempFile(name, ".ldefs");
			BufferedReader br = new BufferedReader(new FileReader(originalLdefFile.getFile(false)));
			BufferedWriter bw = new BufferedWriter(new FileWriter(editedPspecFile));
			String s;
			while ((s = br.readLine()) != null) {
				//if the string is defining a filename, edit that line
				String originalPspecFilename = "atmega256.pspec";

				if (s.contains(originalPspecFilename)) {
					s = s.replace(originalPspecFilename, pspecFilename);
				}

				if (s.contains("avr8:LE:16:atmega256")) {
					s = s.replace("avr8:LE:16:atmega256", "avr8:LE:16:atmega256Test");
				}
				bw.write(s);
				bw.newLine();
			}
			bw.close();
			br.close();
			editedPspecFile.deleteOnExit();
			return new ResourceFile(editedPspecFile);
		}
		catch (IOException e) {
			System.err.println("Error creating test pspec file.");
		}

		return null;
	}

}
