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
//
// Parses AVR8 header files and extracts special memory definitions for each processor variant
//
//  Defined enums can be applied to the program and the enum value is interpreted as an address, and the
//  name of the enum the label at that addres.
//
//@category Data Types

import java.io.File;
import java.io.IOException;
import java.util.Iterator;

import org.bouncycastle.util.Arrays;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.CParserUtils.CParseResults;
import ghidra.app.util.cparser.CPP.DefineTable;
import ghidra.app.util.cparser.CPP.ParseException;
import ghidra.app.util.cparser.CPP.PreProcessor;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.util.AddressEvaluator;
import ghidra.util.Msg;

public class CreateAVR8GDTArchiveScript extends GhidraScript {

	private File outputDirectory;
	
	private static String headerFilePath = "/data/HeaderFiles";

	private static String filenames[] = {
			"stdint.h",
			"avr/io.h",
	};
	
	private static String orig_args[] = {
			"-I"+headerFilePath+"/avr/include",
			"-I"+headerFilePath+"/avr/include/avr",
			"-D__STDC",
			"-D_GNU_SOURCE",
			"-D__GLIBC_HAVE_LONG_LONG=1",
			"-D__DOXYGEN__=true",  // header files have special __attributes__ if not defined
	};
	
	private static String processorVariants[] = {
			"AT94K", 
			"AT43USB320",
			"AT43USB355",
			"AT76C711",
			"AT86RF401",
			"AT90PWM1",
			"AT90PWM2",
			"AT90PWM2B",
			"AT90PWM3",
			"AT90PWM3B",
			"AT90PWM216",
			"AT90PWM316",
			"AT90PWM161",
			"AT90PWM81",
			"ATmega8U2",
			"ATmega16M1",
			"ATmega16U2",
			"ATmega16U4",
			"ATmega32C1",
			"ATmega32M1",
			"ATmega32U2",
			"ATmega32U4",
			"ATmega32U6",
			"ATmega64C1",
			"ATmega64M1",
			"ATmega128",
			"ATmega128A",
			"ATmega1280",
			"ATmega1281",
			"ATmega1284",
			"ATmega1284P",
			"ATmega128RFA1",
			"ATmega1284RFR2",
			"ATmega128RFR2",
			"ATmega2564RFR2",
			"ATmega256RFR2",
			"ATmega2560",
			"ATmega2561",
			"AT90CAN32",
			"AT90CAN64",
			"AT90CAN128",
			"AT90USB82",
			"AT90USB162",
			"AT90USB646",
			"AT90USB647",
			"AT90USB1286",
			"AT90USB1287",
			"ATmega644RFR2",
			"ATmega64RFR2",
			"ATmega64",
			"ATmega64A",
			"ATmega640",
			"ATmega644",
			"ATmega644A",
			"ATmega644P",
			"ATmega644PA",
			"ATmega645",
			"ATmega645A",
			"ATmega645P",
			"ATmega6450",
			"ATmega6450A",
			"ATmega6450P",
			"ATmega649",
			"ATmega649A",
			"ATmega6490",
			"ATmega6490A",
			"ATmega6490P",
			"ATmega649P",
			"ATmega64HVE",
			"ATmega64HVE2",
			"ATmega103",
			"ATmega32",
			"ATmega32A",
			"ATmega323",
			"ATmega324P",
			"ATmega324A",
			"ATmega324PA",
			"ATmega325",
			"ATmega325A",
			"ATmega325P",
			"ATmega325PA",
			"ATmega3250",
			"ATmega3250A",
			"ATmega3250P",
			"ATmega3250PA",
			"ATmega328P",
			"ATmega328",
			"ATmega329",
			"ATmega329A",
			"ATmega329P", 
			"ATmega329PA",
			"ATmega3290PA",
			"ATmega3290",
			"ATmega3290A",
			"ATmega3290P",
			"ATmega32HVB",
			"ATmega32HVBREVB",
			"ATmega406",
			"ATmega16",
			"ATmega16A",
			"ATmega161",
			"ATmega162",
			"ATmega163",
			"ATmega164P",
			"ATmega164A",
			"ATmega164PA",
			"ATmega165",
			"ATmega165A",
			"ATmega165P",
			"ATmega165PA",
			"ATmega168",
			"ATmega168A",
			"ATmega168P",
			"ATmega168PA",
			"ATmega168PB",
			"ATmega169",
			"ATmega169A",
			"ATmega169P",
			"ATmega169PA",
			"ATmega8HVA",
			"ATmega16HVA",
			"ATmega16HVA2",
			"ATmega16HVB",
			"ATmega16HVBREVB",
			"ATmega8",
			"ATmega8A",
			"ATmega48",
			"ATmega48A",
			"ATmega48PA",
			"ATmega48PB",
			"ATmega48P",
			"ATmega88",
			"ATmega88A",
			"ATmega88P",
			"ATmega88PA",
			"ATmega88PB",
			"ATmega8515",
			"ATmega8535",
			"AT90S8535",
			"AT90C8534",
			"AT90S8515",
			"AT90S4434",
			"AT90S4433",
			"AT90S4414",
			"ATtiny22",
			"ATtiny26",
			"AT90S2343",
			"AT90S2333",
			"AT90S2323",
			"AT90S2313",
			"ATtiny4",
			"ATtiny5",
			"ATtiny9",
			"ATtiny10",
			"ATtiny20",
			"ATtiny40",
			"ATtiny2313",
			"ATtiny2313A",
			"ATtiny13",
			"ATtiny13A",
			"ATtiny25",
			"ATtiny4313",
			"ATtiny45",
			"ATtiny85",
			"ATtiny24",
			"ATtiny24A",
			"ATtiny44",
			"ATtiny44A",
			"ATtiny441",
			"ATtiny84",
			"ATtiny84A",
			"ATtiny841",
			"ATtiny261",
			"ATtiny261A",
			"ATtiny461",
			"ATtiny461A",
			"ATtiny861",
			"ATtiny861A",
			"ATtiny43U",
			"ATtiny48",
			"ATtiny88",
			"ATtiny828",
			"ATtiny87",
			"ATtiny167",
			"ATtiny1634",
			"AT90SCR100",
			"ATxmega8E5",
			"ATxmega16A4",
			"ATxmega16A4U",
			"ATxmega16C4",
			"ATxmega16D4",
			"ATxmega16E5",
			"ATxmega32A4",
			"ATxmega32A4U",
			"ATxmega32C3",
			"ATxmega32C4",
			"ATxmega32D3",
			"ATxmega32D4",
			"ATxmega32E5",
			"ATxmega64A1",
			"ATxmega64A1U",
			"ATxmega64A3",
			"ATxmega64A3U",
			"ATxmega64A4U",
			"ATxmega64B1",
			"ATxmega64B3",
			"ATxmega64C3",
			"ATxmega64D3",
			"ATxmega64D4",
			"ATxmega128A1",
			"ATxmega128A1U",
			"ATxmega128A4U",
			"ATxmega128A3",
			"ATxmega128A3U",
			"ATxmega128B1",
			"ATxmega128B3",
			"ATxmega128C3",
			"ATxmega128D3",
			"ATxmega128D4",
			"ATxmega192A3",
			"ATxmega192A3U",
			"ATxmega192C3",
			"ATxmega192D3",
			"ATxmega256A3",
			"ATxmega256A3U",
			"ATxmega256A3B",
			"ATxmega256A3BU",
			"ATxmega256C3",
			"ATxmega256D3",
			"ATxmega384C3",
			"ATxmega384D3",
			"ATA5702M322",
			"ATA5782",
			"ATA5790",
			"ATA5790N",
			"ATA5791",
			"ATA5831",
			"ATA5272",
			"ATA5505",
			"ATA5795",
			"ATA6285",
			"ATA6286",
			"ATA6289",
			"ATA6612C",
			"ATA6613C",
			"ATA6614Q",
			"ATA6616C",
			"ATA6617C",
			"ATA664251",
			"ATA8210",
			"ATA8510",
			"ATtiny28",
			"AT90S1200",
			"ATtiny15",
			"ATtiny12",
			"ATtiny11",
			"M3000",
	};
	
	@Override
	protected void run() throws Exception {
		outputDirectory = askDirectory("Select Directory for GDT files", "Select GDT Output Dir");
		
		parseGDT_AVR8();
	}
	
	public void parseGDT_AVR8() throws Exception {	
		// If need data types from other archives can add other archives
		
		// Using another archive while parsing will cause:
		//  - a dependence on the other archive
		//  - any missing data types while parsing are supplied if present from existingDTMgr
		//  - after parsing all data types parsed that have an equivalent data type will be
		//    replaced by the data type from the existingDTMgr
		//
		// NOTE: This will only occur if the data type from the exisitngDTMgr is equivalent.
		//
		ResourceFile clib64ArchiveFile = DataTypeArchiveUtility.findArchiveFile("generic_clib.gdt");
		File file = new File(clib64ArchiveFile.getAbsolutePath());
		DataTypeManager vsDTMgr = FileDataTypeManager.openFileArchive(file, false);
		DataTypeManager openTypes[] = { vsDTMgr };
		// by defaults, don't want to be dependent on other archives if have all necessary definitions
		// comment out if missing data types
		openTypes = null;
		
		String dataTypeFile = outputDirectory + File.separator + "avr8.gdt";

		File f = getArchiveFile(dataTypeFile);
		
        FileDataTypeManager dtMgr = FileDataTypeManager.createFileArchive(f);
        
        // Parse each processor variant as an individual parse that gets added to the data
        // type manager.  If all header files were parsed at once, there are conflicting
        // macro definitions that will cause the parse to fail.
        //
        for (String variantName : processorVariants) {
        	parseProcessorDefs(variantName, dtMgr, openTypes);
        }
		
		dtMgr.save();
		dtMgr.close();
	}

	/**
	 * Turn string into a file, delete old archive if it exists
	 * 
	 * @param dataTypeFile
	 * 
	 * @return file
	 */
	private File getArchiveFile(String dataTypeFile) {
		File f = new File(dataTypeFile);
		if (f.exists()) {
			f.delete();
		}
		String lockFile = dataTypeFile + ".ulock";
		File lf = new File(lockFile);
		if (lf.exists()) {
			lf.delete();
		}
		return f;
	}

	/**
	 * parse a single AVR8 variant
	 * 
	 * @param procName name of processor
	 * @param dtMgr open data type manager to add types to
	 * @param openTypes any open archives for missing data types
	 * @throws ParseException something happened
	 * @throws ghidra.app.util.cparser.C.ParseException
	 * @throws IOException io exception
	 */
	private void parseProcessorDefs(String procName, FileDataTypeManager dtMgr, DataTypeManager[] openTypes)
			throws ParseException, ghidra.app.util.cparser.C.ParseException, IOException {
		
		String args[] = Arrays.append(orig_args, "-D__AVR_"+procName+"__");
        
		CParseResults results = CParserUtils.parseHeaderFiles(openTypes, filenames, args, dtMgr, "avr8:LE:16:atmega256", "gcc", monitor);
		
		Msg.info(this, results.getFormattedParseMessage(null));
		
		storeExtraDefinitions(procName, dtMgr, openTypes, results.preProcessor());
	}

	/**
	 * get extra defines special for the AVR8 that describe memory locations per variant
	 * 
	 * @param procName processor variant
	 * @param dtMgr add data types to dtMgr
	 * @param cpp pre-processor holds macros/defines from parsing
	 */
	private void storeExtraDefinitions(String procName, FileDataTypeManager dtMgr, DataTypeManager[] openTypes, PreProcessor cpp) {
		int transactionID = dtMgr.startTransaction("Add Extra Equates");
		
		DefineTable definitions = cpp.getDefinitions();
		Iterator<String> defineNames = definitions.getDefineNames();
		while (defineNames.hasNext()) {
			String defName = defineNames.next();
			String rawDefValue = definitions.getValue(defName);
			String expandValue = definitions.expandDefine(defName);
			
			if (expandValue == null || expandValue.length()==0) {
				// can't expand, must be a macro
				continue;
			}
			
			// look at string and see if if the definition of an SFR, register
			String PTR_PREFIX_16 = "(*(volatile uint16_t *)";
			String PTR_PREFIX_8  = "(*(volatile uint8_t *)";
			
			Long lvalue = null;
			if (expandValue.startsWith(PTR_PREFIX_16)) {
				// ptr to 16 bit address in SFR
				expandValue = expandValue.replace(PTR_PREFIX_16, "");
				expandValue = expandValue.substring(0,expandValue.lastIndexOf(')'));
			} else if (expandValue.startsWith(PTR_PREFIX_8) ) {
				// ptr to 8 bit address in SFR
				expandValue = expandValue.replace(PTR_PREFIX_8, "");
				expandValue = expandValue.substring(0,expandValue.lastIndexOf(')'));
			} else {
				continue;
			}
		
			if (expandValue == null || expandValue.length() == 0) {
				continue;
			}
			
			lvalue = AddressEvaluator.evaluateToLong(expandValue);
			if (lvalue == null) {
				continue;
			}
			definitions.populateDefineEquate(openTypes, dtMgr, "memory", "", defName, lvalue);
		}
		dtMgr.endTransaction(transactionID, true);
	}
}
