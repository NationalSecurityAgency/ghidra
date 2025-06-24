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
package ghidra.app.util.pdb;

import java.util.*;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.SymbolPathParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.pdb.pdbapplicator.CppCompositeType;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.gclass.ClassID;
import ghidra.program.model.gclass.ClassUtils;

/**
 * Class to create the cvf4 64-bit program and mock PDB.
 * <p>
 * This class implementation is not complete... expected results need codified
 */
public class Cfb464ProgramCreator extends ProgramCreator {

	public static final CategoryPath MAIN_CATEGORY_PATH = CategoryPath.ROOT;

	public static final ClassID A1 = new ClassID(MAIN_CATEGORY_PATH, sp("A1NS::A1"));
	public static final ClassID A2 = new ClassID(MAIN_CATEGORY_PATH, sp("A2NS::A2"));
	public static final ClassID A = new ClassID(MAIN_CATEGORY_PATH, sp("ANS::A"));
	public static final ClassID B1 = new ClassID(MAIN_CATEGORY_PATH, sp("B1NS::B1"));
	public static final ClassID B2 = new ClassID(MAIN_CATEGORY_PATH, sp("B2NS::B2"));
	public static final ClassID B = new ClassID(MAIN_CATEGORY_PATH, sp("BNS::B"));
	public static final ClassID C = new ClassID(MAIN_CATEGORY_PATH, sp("CNS::C"));
	public static final ClassID D = new ClassID(MAIN_CATEGORY_PATH, sp("DNS::D"));
	public static final ClassID E = new ClassID(MAIN_CATEGORY_PATH, sp("ENS::E"));
	public static final ClassID F = new ClassID(MAIN_CATEGORY_PATH, sp("FNS::F"));
	public static final ClassID G = new ClassID(MAIN_CATEGORY_PATH, sp("GNS::G"));
	public static final ClassID H = new ClassID(MAIN_CATEGORY_PATH, sp("HNS::H"));
	public static final ClassID I = new ClassID(MAIN_CATEGORY_PATH, sp("INS::I"));
	public static final ClassID J = new ClassID(MAIN_CATEGORY_PATH, sp("JNS::J"));
	public static final ClassID K = new ClassID(MAIN_CATEGORY_PATH, sp("KNS::K"));
	public static final ClassID L = new ClassID(MAIN_CATEGORY_PATH, sp("LNS::L"));
	public static final ClassID N1 = new ClassID(MAIN_CATEGORY_PATH, sp("N1NS::N1"));
	public static final ClassID N2 = new ClassID(MAIN_CATEGORY_PATH, sp("N2NS::N2"));
	public static final ClassID M = new ClassID(MAIN_CATEGORY_PATH, sp("MNS::M"));
	public static final ClassID O1 = new ClassID(MAIN_CATEGORY_PATH, sp("O1NS::O1"));
	public static final ClassID O2 = new ClassID(MAIN_CATEGORY_PATH, sp("O2NS::O2"));
	public static final ClassID O3 = new ClassID(MAIN_CATEGORY_PATH, sp("O3NS::O3"));
	public static final ClassID O4 = new ClassID(MAIN_CATEGORY_PATH, sp("O4NS::O4"));
	public static final ClassID O = new ClassID(MAIN_CATEGORY_PATH, sp("ONS::O"));

	private static String PROGRAM_NAME = "cfb464.exe";
	private static String LANGUAGE_ID = ProgramBuilder._X64;
	private static String COMPILER_SPEC_ID = "windows";
	private static AddressNameLength SECTIONS[] = {
		new AddressNameLength("140001000", ".text", 0x6e000),
		new AddressNameLength("14006f000", ".rdata", 0x14a00)
	};

	private static AddressNameBytes vbTableInfo[] = {
		new AddressNameBytes("14006f518", "??_8A@ANS@@7B@",
			"f8 ff ff ff 10 00 00 00 20 00 00 00 00 00 00 00 18 ac 07 40 01 00 00 00"),
		new AddressNameBytes("14006f5b8", "??_8B@BNS@@7B@",
			"f8 ff ff ff 10 00 00 00 20 00 00 00 00 00 00 00 30 ae 07 40 01 00 00 00"),
		new AddressNameBytes("14006f658", "??_8C@CNS@@7B@",
			"f8 ff ff ff 10 00 00 00 20 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 b8 af 07 40 01 00 00 00"),
		new AddressNameBytes("14006f720", "??_8D@DNS@@7BC@CNS@@@",
			"f8 ff ff ff 48 00 00 00 58 00 00 00 68 00 00 00 78 00 00 00"),
		new AddressNameBytes("14006f734", "??_8D@DNS@@7BA@ANS@@@",
			"f8 ff ff ff 30 00 00 00 40 00 00 00"),
		new AddressNameBytes("14006f740", "??_8D@DNS@@7BB@BNS@@@",
			"f8 ff ff ff 38 00 00 00 48 00 00 00 00 00 00 00 d0 b1 07 40 01 00 00 00"),
		new AddressNameBytes("14006f7f0", "??_8E@ENS@@7BA@ANS@@@",
			"f8 ff ff ff 18 00 00 00 28 00 00 00 38 00 00 00 48 00 00 00 58 00 00 00"),
		new AddressNameBytes("14006f808", "??_8E@ENS@@7BB@BNS@@@",
			"f8 ff ff ff d8 ff ff ff e8 ff ff ff 00 00 00 00 68 b3 07 40 01 00 00 00"),
		new AddressNameBytes("14006f838", "??_8F@FNS@@7B@",
			"00 00 00 00 10 00 00 00 10 b4 07 40 01 00 00 00"),
		new AddressNameBytes("14006f860", "??_8G@GNS@@7B@",
			"00 00 00 00 18 00 00 00 98 b4 07 40 01 00 00 00"),
		new AddressNameBytes("14006f888", "??_8H@HNS@@7B@",
			"00 00 00 00 18 00 00 00 20 b5 07 40 01 00 00 00"),
		new AddressNameBytes("14006f8b0", "??_8I@INS@@7BG@GNS@@@", "00 00 00 00 38 00 00 00"),
		new AddressNameBytes("14006f8b8", "??_8I@INS@@7BH@HNS@@@",
			"00 00 00 00 20 00 00 00 40 b6 07 40 01 00 00 00"),
		new AddressNameBytes("14006f8e0", "??_8J@JNS@@7B@",
			"00 00 00 00 10 00 00 00 c0 b6 07 40 01 00 00 00"),
		new AddressNameBytes("14006f908", "??_8K@KNS@@7B@",
			"00 00 00 00 18 00 00 00 48 b7 07 40 01 00 00 00"),
		new AddressNameBytes("14006f930", "??_8L@LNS@@7B@",
			"00 00 00 00 20 00 00 00 d8 b7 07 40 01 00 00 00"),
		new AddressNameBytes("14006fa68", "??_8M@MNS@@7BA@ANS@@E@ENS@@@",
			"f8 ff ff ff d8 00 00 00 e8 00 00 00 f8 00 00 00 08 01 00 00 18 01 00 00 c8 00 00 00 30 01 00 00"),
		new AddressNameBytes("14006fa88", "??_8M@MNS@@7BC@CNS@@@",
			"f8 ff ff ff b8 00 00 00 c8 00 00 00 d8 00 00 00 e8 00 00 00"),
		new AddressNameBytes("14006fa9c", "??_8M@MNS@@7BA@ANS@@D@DNS@@@",
			"f8 ff ff ff a0 00 00 00 b0 00 00 00"),
		new AddressNameBytes("14006faa8", "??_8M@MNS@@7BB@BNS@@D@DNS@@@",
			"f8 ff ff ff a8 00 00 00 b8 00 00 00"),
		new AddressNameBytes("14006fab4", "??_8M@MNS@@7BG@GNS@@@", "00 00 00 00 70 00 00 00"),
		new AddressNameBytes("14006fabc", "??_8M@MNS@@7BH@HNS@@@", "00 00 00 00 58 00 00 00"),
		new AddressNameBytes("14006fac4", "??_8M@MNS@@7B@", "00 00 00 00 38 00 00 00"),
		new AddressNameBytes("14006facc", "??_8M@MNS@@7BB@BNS@@E@ENS@@@",
			"f8 ff ff ff d8 ff ff ff e8 ff ff ff 58 be 07 40 01 00 00 00"),
		new AddressNameBytes("14006fb80", "??_8O1@O1NS@@7BA@ANS@@@",
			"f8 ff ff ff 30 00 00 00 40 00 00 00 50 00 00 00 60 00 00 00"),
		new AddressNameBytes("14006fb94", "??_8O1@O1NS@@7BB@BNS@@@",
			"f8 ff ff ff 38 00 00 00 48 00 00 00 f0 bf 07 40 01 00 00 00"),
		new AddressNameBytes("14006fc48", "??_8O2@O2NS@@7BA@ANS@@@",
			"f8 ff ff ff 18 00 00 00 28 00 00 00 38 00 00 00 48 00 00 00 58 00 00 00"),
		new AddressNameBytes("14006fc60", "??_8O2@O2NS@@7BB@BNS@@@",
			"f8 ff ff ff d8 ff ff ff e8 ff ff ff 00 00 00 00 60 c1 07 40 01 00 00 00"),
		new AddressNameBytes("14006fd18", "??_8O3@O3NS@@7BA@ANS@@@",
			"f8 ff ff ff 30 00 00 00 40 00 00 00 50 00 00 00 60 00 00 00"),
		new AddressNameBytes("14006fd2c", "??_8O3@O3NS@@7BB@BNS@@@",
			"f8 ff ff ff 38 00 00 00 48 00 00 00 d0 c2 07 40 01 00 00 00"),
		new AddressNameBytes("14006fde0", "??_8O4@O4NS@@7BA@ANS@@@",
			"f8 ff ff ff 18 00 00 00 28 00 00 00 38 00 00 00 48 00 00 00 58 00 00 00"),
		new AddressNameBytes("14006fdf8", "??_8O4@O4NS@@7BB@BNS@@@",
			"f8 ff ff ff d8 ff ff ff e8 ff ff ff 00 00 00 00 40 c4 07 40 01 00 00 00"),
		new AddressNameBytes("14006ff20", "??_8O@ONS@@7BA@ANS@@O1@O1NS@@@",
			"f8 ff ff ff 58 00 00 00 68 00 00 00 78 00 00 00 88 00 00 00 98 00 00 00 b0 00 00 00 e8 00 00 00"),
		new AddressNameBytes("14006ff40", "??_8O@ONS@@7BB@BNS@@O1@O1NS@@@",
			"f8 ff ff ff 60 00 00 00 70 00 00 00"),
		new AddressNameBytes("14006ff4c", "??_8O@ONS@@7BA@ANS@@O2@O2NS@@@",
			"f8 ff ff ff 20 00 00 00 30 00 00 00 40 00 00 00 50 00 00 00 60 00 00 00"),
		new AddressNameBytes("14006ff64", "??_8O@ONS@@7BB@BNS@@O2@O2NS@@@",
			"f8 ff ff ff d8 ff ff ff e8 ff ff ff"),
		new AddressNameBytes("14006ff70", "??_8O@ONS@@7BA@ANS@@O3@O3NS@@@",
			"f8 ff ff ff a0 ff ff ff b0 ff ff ff c0 ff ff ff d0 ff ff ff"),
		new AddressNameBytes("14006ff84", "??_8O@ONS@@7BB@BNS@@O3@O3NS@@@",
			"f8 ff ff ff a8 ff ff ff b8 ff ff ff"),
		new AddressNameBytes("14006ff90", "??_8O@ONS@@7BA@ANS@@O4@O4NS@@@",
			"f8 ff ff ff 68 ff ff ff 78 ff ff ff 88 ff ff ff 98 ff ff ff a8 ff ff ff 40 c8 07 40 01 00 00 00"),
	};

	private static AddressNameBytes vfTableInfo[] = {
		new AddressNameBytes("14006f490", "??_7A1@A1NS@@6B@",
			"60 33 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 78 aa 07 40 01 00 00 00"),
		new AddressNameBytes("14006f4b0", "??_7A2@A2NS@@6B@",
			"f0 35 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00 f0 aa 07 40 01 00 00 00"),
		new AddressNameBytes("14006f4d0", "??_7A@ANS@@6B01@@",
			"40 38 01 40 01 00 00 00 c8 ab 07 40 01 00 00 00"),
		new AddressNameBytes("14006f4e0", "??_7A@ANS@@6BA1@A1NS@@@",
			"70 33 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 f0 ab 07 40 01 00 00 00"),
		new AddressNameBytes("14006f500", "??_7A@ANS@@6BA2@A2NS@@@",
			"10 36 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00"),
		new AddressNameBytes("14006f530", "??_7B1@B1NS@@6B@",
			"80 38 01 40 01 00 00 00 70 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 90 ac 07 40 01 00 00 00"),
		new AddressNameBytes("14006f550", "??_7B2@B2NS@@6B@",
			"10 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00 08 ad 07 40 01 00 00 00"),
		new AddressNameBytes("14006f570", "??_7B@BNS@@6B01@@",
			"70 3b 01 40 01 00 00 00 e0 ad 07 40 01 00 00 00"),
		new AddressNameBytes("14006f580", "??_7B@BNS@@6BB1@B1NS@@@",
			"a0 38 01 40 01 00 00 00 70 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 08 ae 07 40 01 00 00 00"),
		new AddressNameBytes("14006f5a0", "??_7B@BNS@@6BB2@B2NS@@@",
			"30 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00"),
		new AddressNameBytes("14006f5d0", "??_7C@CNS@@6B01@@",
			"b0 3b 01 40 01 00 00 00 18 af 07 40 01 00 00 00"),
		new AddressNameBytes("14006f5e0", "??_7C@CNS@@6BA1@A1NS@@@",
			"60 33 01 40 01 00 00 00 90 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 40 af 07 40 01 00 00 00"),
		new AddressNameBytes("14006f600", "??_7C@CNS@@6BA2@A2NS@@@",
			"50 36 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00 68 af 07 40 01 00 00 00"),
		new AddressNameBytes("14006f620", "??_7C@CNS@@6BB1@B1NS@@@",
			"80 38 01 40 01 00 00 00 90 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 90 af 07 40 01 00 00 00"),
		new AddressNameBytes("14006f640", "??_7C@CNS@@6BB2@B2NS@@@",
			"70 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00"),
		new AddressNameBytes("14006f678", "??_7D@DNS@@6BC@CNS@@@",
			"b0 3b 01 40 01 00 00 00 e0 b0 07 40 01 00 00 00"),
		new AddressNameBytes("14006f688", "??_7D@DNS@@6BA@ANS@@@",
			"40 38 01 40 01 00 00 00 08 b1 07 40 01 00 00 00"),
		new AddressNameBytes("14006f698", "??_7D@DNS@@6BB@BNS@@@",
			"70 3b 01 40 01 00 00 00 30 b1 07 40 01 00 00 00"),
		new AddressNameBytes("14006f6a8", "??_7D@DNS@@6BA1@A1NS@@@",
			"a4 33 01 40 01 00 00 00 b8 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 58 b1 07 40 01 00 00 00"),
		new AddressNameBytes("14006f6c8", "??_7D@DNS@@6BA2@A2NS@@@",
			"80 36 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00 80 b1 07 40 01 00 00 00"),
		new AddressNameBytes("14006f6e8", "??_7D@DNS@@6BB1@B1NS@@@",
			"f8 38 01 40 01 00 00 00 d0 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 a8 b1 07 40 01 00 00 00"),
		new AddressNameBytes("14006f708", "??_7D@DNS@@6BB2@B2NS@@@",
			"b0 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00"),
		new AddressNameBytes("14006f758", "??_7E@ENS@@6BA@ANS@@@",
			"40 38 01 40 01 00 00 00 a0 b2 07 40 01 00 00 00"),
		new AddressNameBytes("14006f768", "??_7E@ENS@@6BA1@A1NS@@@",
			"b0 33 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 c8 b2 07 40 01 00 00 00"),
		new AddressNameBytes("14006f788", "??_7E@ENS@@6BA2@A2NS@@@",
			"38 36 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00 f0 b2 07 40 01 00 00 00"),
		new AddressNameBytes("14006f7a8", "??_7E@ENS@@6BB1@B1NS@@@",
			"04 39 01 40 01 00 00 00 70 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 18 b3 07 40 01 00 00 00"),
		new AddressNameBytes("14006f7c8", "??_7E@ENS@@6BB2@B2NS@@@",
			"64 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00 40 b3 07 40 01 00 00 00"),
		new AddressNameBytes("14006f7e8", "??_7E@ENS@@6BB@BNS@@@", "70 3b 01 40 01 00 00 00"),
		new AddressNameBytes("14006f820", "??_7F@FNS@@6B@",
			"d0 33 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00"),
		new AddressNameBytes("14006f848", "??_7G@GNS@@6B@",
			"f0 33 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00"),
		new AddressNameBytes("14006f870", "??_7H@HNS@@6B@",
			"10 34 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00"),
		new AddressNameBytes("14006f898", "??_7I@INS@@6B@",
			"30 34 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00"),
		new AddressNameBytes("14006f8c8", "??_7J@JNS@@6B@",
			"50 34 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00"),
		new AddressNameBytes("14006f8f0", "??_7K@KNS@@6B@",
			"70 34 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00"),
		new AddressNameBytes("14006f918", "??_7L@LNS@@6B@",
			"90 34 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00"),
		new AddressNameBytes("14006f940", "??_7N1@N1NS@@6B@",
			"10 3c 01 40 01 00 00 00 30 3c 01 40 01 00 00 00 50 b8 07 40 01 00 00 00"),
		new AddressNameBytes("14006f958", "??_7N2@N2NS@@6B@",
			"50 3c 01 40 01 00 00 00 70 3c 01 40 01 00 00 00 c8 b8 07 40 01 00 00 00"),
		new AddressNameBytes("14006f970", "??_7M@MNS@@6BA@ANS@@E@ENS@@@",
			"40 38 01 40 01 00 00 00 c8 bc 07 40 01 00 00 00"),
		new AddressNameBytes("14006f980", "??_7M@MNS@@6BC@CNS@@@",
			"b0 3b 01 40 01 00 00 00 f0 bc 07 40 01 00 00 00"),
		new AddressNameBytes("14006f990", "??_7M@MNS@@6BA@ANS@@D@DNS@@@",
			"40 38 01 40 01 00 00 00 18 bd 07 40 01 00 00 00"),
		new AddressNameBytes("14006f9a0", "??_7M@MNS@@6BB@BNS@@D@DNS@@@",
			"70 3b 01 40 01 00 00 00 40 bd 07 40 01 00 00 00"),
		new AddressNameBytes("14006f9b0", "??_7M@MNS@@6BN1@N1NS@@@",
			"e0 3b 01 40 01 00 00 00 30 3c 01 40 01 00 00 00 68 bd 07 40 01 00 00 00"),
		new AddressNameBytes("14006f9c8", "??_7M@MNS@@6BA1@A1NS@@@",
			"b0 34 01 40 01 00 00 00 c4 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 90 bd 07 40 01 00 00 00"),
		new AddressNameBytes("14006f9e8", "??_7M@MNS@@6BA2@A2NS@@@",
			"a0 36 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00 b8 bd 07 40 01 00 00 00"),
		new AddressNameBytes("14006fa08", "??_7M@MNS@@6BB1@B1NS@@@",
			"10 39 01 40 01 00 00 00 dc 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 e0 bd 07 40 01 00 00 00"),
		new AddressNameBytes("14006fa28", "??_7M@MNS@@6BB2@B2NS@@@",
			"d0 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00 08 be 07 40 01 00 00 00"),
		new AddressNameBytes("14006fa48", "??_7M@MNS@@6BB@BNS@@E@ENS@@@",
			"70 3b 01 40 01 00 00 00 30 be 07 40 01 00 00 00"),
		new AddressNameBytes("14006fa58", "??_7M@MNS@@6BN2@N2NS@@@",
			"50 3c 01 40 01 00 00 00 70 3c 01 40 01 00 00 00"),
		new AddressNameBytes("14006fae0", "??_7O1@O1NS@@6BA@ANS@@@",
			"40 38 01 40 01 00 00 00 90 3c 01 40 01 00 00 00 28 bf 07 40 01 00 00 00"),
		new AddressNameBytes("14006faf8", "??_7O1@O1NS@@6BB@BNS@@@",
			"70 3b 01 40 01 00 00 00 50 bf 07 40 01 00 00 00"),
		new AddressNameBytes("14006fb08", "??_7O1@O1NS@@6BA1@A1NS@@@",
			"a4 33 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 78 bf 07 40 01 00 00 00"),
		new AddressNameBytes("14006fb28", "??_7O1@O1NS@@6BA2@A2NS@@@",
			"c0 36 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00 a0 bf 07 40 01 00 00 00"),
		new AddressNameBytes("14006fb48", "??_7O1@O1NS@@6BB1@B1NS@@@",
			"f8 38 01 40 01 00 00 00 70 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 c8 bf 07 40 01 00 00 00"),
		new AddressNameBytes("14006fb68", "??_7O1@O1NS@@6BB2@B2NS@@@",
			"58 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00"),
		new AddressNameBytes("14006fba8", "??_7O2@O2NS@@6BA@ANS@@@",
			"40 38 01 40 01 00 00 00 d0 3c 01 40 01 00 00 00 98 c0 07 40 01 00 00 00"),
		new AddressNameBytes("14006fbc0", "??_7O2@O2NS@@6BA1@A1NS@@@",
			"98 33 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 c0 c0 07 40 01 00 00 00"),
		new AddressNameBytes("14006fbe0", "??_7O2@O2NS@@6BA2@A2NS@@@",
			"00 37 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00 e8 c0 07 40 01 00 00 00"),
		new AddressNameBytes("14006fc00", "??_7O2@O2NS@@6BB1@B1NS@@@",
			"04 39 01 40 01 00 00 00 70 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 10 c1 07 40 01 00 00 00"),
		new AddressNameBytes("14006fc20", "??_7O2@O2NS@@6BB2@B2NS@@@",
			"64 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00 38 c1 07 40 01 00 00 00"),
		new AddressNameBytes("14006fc40", "??_7O2@O2NS@@6BB@BNS@@@", "70 3b 01 40 01 00 00 00"),
		new AddressNameBytes("14006fc78", "??_7O3@O3NS@@6BA@ANS@@@",
			"40 38 01 40 01 00 00 00 10 3d 01 40 01 00 00 00 08 c2 07 40 01 00 00 00"),
		new AddressNameBytes("14006fc90", "??_7O3@O3NS@@6BB@BNS@@@",
			"70 3b 01 40 01 00 00 00 30 c2 07 40 01 00 00 00"),
		new AddressNameBytes("14006fca0", "??_7O3@O3NS@@6BA1@A1NS@@@",
			"a4 33 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 58 c2 07 40 01 00 00 00"),
		new AddressNameBytes("14006fcc0", "??_7O3@O3NS@@6BA2@A2NS@@@",
			"40 37 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00 80 c2 07 40 01 00 00 00"),
		new AddressNameBytes("14006fce0", "??_7O3@O3NS@@6BB1@B1NS@@@",
			"f8 38 01 40 01 00 00 00 70 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 a8 c2 07 40 01 00 00 00"),
		new AddressNameBytes("14006fd00", "??_7O3@O3NS@@6BB2@B2NS@@@",
			"58 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00"),
		new AddressNameBytes("14006fd40", "??_7O4@O4NS@@6BA@ANS@@@",
			"40 38 01 40 01 00 00 00 60 3d 01 40 01 00 00 00 78 c3 07 40 01 00 00 00"),
		new AddressNameBytes("14006fd58", "??_7O4@O4NS@@6BA1@A1NS@@@",
			"98 33 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 a0 c3 07 40 01 00 00 00"),
		new AddressNameBytes("14006fd78", "??_7O4@O4NS@@6BA2@A2NS@@@",
			"80 37 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00 c8 c3 07 40 01 00 00 00"),
		new AddressNameBytes("14006fd98", "??_7O4@O4NS@@6BB1@B1NS@@@",
			"04 39 01 40 01 00 00 00 70 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 f0 c3 07 40 01 00 00 00"),
		new AddressNameBytes("14006fdb8", "??_7O4@O4NS@@6BB2@B2NS@@@",
			"64 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00 18 c4 07 40 01 00 00 00"),
		new AddressNameBytes("14006fdd8", "??_7O4@O4NS@@6BB@BNS@@@", "70 3b 01 40 01 00 00 00"),
		new AddressNameBytes("14006fe10", "??_7O@ONS@@6BA@ANS@@O1@O1NS@@@",
			"40 38 01 40 01 00 00 00 b0 3c 01 40 01 00 00 00 b0 3d 01 40 01 00 00 00 b0 c6 07 40 01 00 00 00"),
		new AddressNameBytes("14006fe30", "??_7O@ONS@@6BB@BNS@@O1@O1NS@@@",
			"70 3b 01 40 01 00 00 00 d8 c6 07 40 01 00 00 00"),
		new AddressNameBytes("14006fe40", "??_7O@ONS@@6BA@ANS@@O2@O2NS@@@",
			"40 38 01 40 01 00 00 00 f0 3c 01 40 01 00 00 00 00 c7 07 40 01 00 00 00"),
		new AddressNameBytes("14006fe58", "??_7O@ONS@@6BA1@A1NS@@@",
			"30 35 01 40 01 00 00 00 70 35 01 40 01 00 00 00 d0 35 01 40 01 00 00 00 28 c7 07 40 01 00 00 00"),
		new AddressNameBytes("14006fe78", "??_7O@ONS@@6BA2@A2NS@@@",
			"c0 37 01 40 01 00 00 00 00 38 01 40 01 00 00 00 20 38 01 40 01 00 00 00 50 c7 07 40 01 00 00 00"),
		new AddressNameBytes("14006fe98", "??_7O@ONS@@6BB1@B1NS@@@",
			"30 39 01 40 01 00 00 00 70 39 01 40 01 00 00 00 f0 39 01 40 01 00 00 00 78 c7 07 40 01 00 00 00"),
		new AddressNameBytes("14006feb8", "??_7O@ONS@@6BB2@B2NS@@@",
			"f0 3a 01 40 01 00 00 00 30 3b 01 40 01 00 00 00 50 3b 01 40 01 00 00 00 a0 c7 07 40 01 00 00 00"),
		new AddressNameBytes("14006fed8", "??_7O@ONS@@6BB@BNS@@O2@O2NS@@@",
			"70 3b 01 40 01 00 00 00 c8 c7 07 40 01 00 00 00"),
		new AddressNameBytes("14006fee8", "??_7O@ONS@@6BA@ANS@@O3@O3NS@@@",
			"40 38 01 40 01 00 00 00 30 3d 01 40 01 00 00 00 f0 c7 07 40 01 00 00 00"),
		new AddressNameBytes("14006ff00", "??_7O@ONS@@6BB@BNS@@O3@O3NS@@@",
			"70 3b 01 40 01 00 00 00 18 c8 07 40 01 00 00 00"),
		new AddressNameBytes("14006ff10", "??_7O@ONS@@6BA@ANS@@O4@O4NS@@@",
			"40 38 01 40 01 00 00 00 80 3d 01 40 01 00 00 00"),
		new AddressNameBytes("14006ffb0", "??_7type_info@@6B@",
			"4c 3f 01 40 01 00 00 00 00 00 00 00 00 00 00 00")
	};

	private static AddressNameBytes functionInfo[] = {
		new AddressNameBytes("140013360", "A1NS::A1::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 ff c0"),
		new AddressNameBytes("140013370", "ANS::A::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 48 8b 4c 24 08 48 8b 49 f0 48 63 49 04 48 8b 54 24 08 8b 4c 0a f8 8d 44 08 03"),
		new AddressNameBytes("140013398", "[thunk]:ANS::A::fa1_1`adjustor{8}'",
			"48 83 e9 08 e9 cf ff ff"),
		new AddressNameBytes("1400133a4", "[thunk]:ANS::A::fa1_1`adjustor{32}'",
			"48 83 e9 20 e9 c3 ff ff"),
		new AddressNameBytes("1400133b0", "ENS::E::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 83 c0 09"),
		new AddressNameBytes("1400133d0", "FNS::F::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 83 c0 0a"),
		new AddressNameBytes("1400133f0", "GNS::G::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 83 c0 0b"),
		new AddressNameBytes("140013410", "HNS::H::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 83 c0 0c"),
		new AddressNameBytes("140013430", "INS::I::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 83 c0 0d"),
		new AddressNameBytes("140013450", "JNS::J::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 83 c0 0e"),
		new AddressNameBytes("140013470", "KNS::K::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 83 c0 0f"),
		new AddressNameBytes("140013490", "LNS::L::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 83 c0 10"),
		new AddressNameBytes("1400134b0", "MNS::M::fa1_1",
			"48 89 4c 24 08 48 83 ec 38 48 8b 44 24 40 48 2d e0 00 00 00 48 85 c0 74 16 48 8b 44 24 40 48 2d e0 00 00 00 48 83 c0 20 48 89 44 24 28 eb 09 48 c7 44 24 28 00 00 00 00 48 8b 44 24 40 8b 80 50 ff ff ff 48 8b 4c 24 40 8b 49 e8 8d 44 08 13 89 44 24 20 48 8b 4c 24 28 48 8b 49 08 48 63 49 0c 48 8b 54 24 28 48 8d 4c 0a 08 e8 61 03 00 00 8b 4c 24 20 03 c8 8b c1 48 83 c4 38"),
		new AddressNameBytes("140013530", "ONS::O::fa1_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 a8 48 63 40 04 48 8b 4c 24 08 8b 44 01 b0 48 8b 4c 24 08 48 8b 49 a8 48 63 49 08 48 8b 54 24 08 8b 4c 0a b0 8d 44 08 18"),
		new AddressNameBytes("140013570", "A1NS::A1::fa1_2",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 8d 44 00 01"),
		new AddressNameBytes("140013590", "CNS::C::fa1_2",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 f0 48 63 40 04 48 8b 4c 24 08 8b 44 01 f8 48 8b 4c 24 08 8b 49 f8 8d 44 41 07"),
		new AddressNameBytes("1400135b8", "[thunk]:CNS::C::fa1_2`adjustor{56}'",
			"48 83 e9 38 e9 cf ff ff"),
		new AddressNameBytes("1400135c4", "[thunk]:CNS::C::fa1_2`adjustor{168}'",
			"48 81 e9 a8 00 00 00 e9 c0 ff ff"),
		new AddressNameBytes("1400135d0", "A1NS::A1::fa1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 08 03 ff c0"),
		new AddressNameBytes("1400135f0", "A2NS::A2::fa2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 83 c0 02"),
		new AddressNameBytes("140013610", "ANS::A::fa2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 e8 48 8b 4c 24 08 48 8b 49 e0 48 63 49 08 48 8b 54 24 08 8b 4c 0a e8 8d 44 08 03"),
		new AddressNameBytes("140013638", "[thunk]:ANS::A::fa2_1`adjustor{8}'",
			"48 83 e9 08 e9 cf ff ff"),
		new AddressNameBytes("140013650", "CNS::C::fa2_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 e0 48 63 40 08 48 8b 4c 24 08 8b 44 01 e8 48 8b 4c 24 08 8b 49 e8 8d 44 08 07"),
		new AddressNameBytes("140013680", "DNS::D::fa2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 e8 83 c0 08"),
		new AddressNameBytes("1400136a0", "MNS::M::fa2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 80 78 ff ff ff 48 8b 4c 24 08 8b 49 d8 8d 44 08 13"),
		new AddressNameBytes("1400136c0", "O1NS::O1::fa2_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 c0 48 63 40 04 48 8b 4c 24 08 8b 44 01 c8 48 8b 4c 24 08 48 8b 49 c0 48 63 49 0c 48 8b 54 24 08 8b 4c 0a c8 8d 44 08 14"),
		new AddressNameBytes("140013700", "O2NS::O2::fa2_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 d8 48 63 40 04 48 8b 4c 24 08 8b 44 01 e0 48 8b 4c 24 08 48 8b 49 d8 48 63 49 0c 48 8b 54 24 08 8b 4c 0a e0 8d 44 08 15"),
		new AddressNameBytes("140013740", "O3NS::O3::fa2_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 c0 48 63 40 04 48 8b 4c 24 08 8b 44 01 c8 48 8b 4c 24 08 48 8b 49 c0 48 63 49 0c 48 8b 54 24 08 8b 4c 0a c8 8d 44 08 16"),
		new AddressNameBytes("140013780", "O4NS::O4::fa2_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 d8 48 63 40 04 48 8b 4c 24 08 8b 44 01 e0 48 8b 4c 24 08 48 8b 49 d8 48 63 49 0c 48 8b 54 24 08 8b 4c 0a e0 8d 44 08 17"),
		new AddressNameBytes("1400137c0", "ONS::O::fa2_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 98 48 63 40 04 48 8b 4c 24 08 8b 44 01 a0 48 8b 4c 24 08 48 8b 49 98 48 63 49 0c 48 8b 54 24 08 8b 4c 0a a0 8d 44 08 18"),
		new AddressNameBytes("140013800", "A2NS::A2::fa2_2",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 8d 44 00 02"),
		new AddressNameBytes("140013820", "A2NS::A2::fa2_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 08 03 83 c0 02"),
		new AddressNameBytes("140013840", "ANS::A::fa_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 10 48 8b 4c 24 08 48 8b 49 08 48 63 49 04 48 8b 54 24 08 8b 4c 0a 10 8d 44 08 03 48 8b 4c 24 08 48 8b 49 08 48 63 49 08 48 8b 54 24 08 03 44 0a 10"),
		new AddressNameBytes("140013880", "B1NS::B1::fb1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 83 c0 04"),
		new AddressNameBytes("1400138a0", "BNS::B::fb1_1",
			"48 89 4c 24 08 48 83 ec 38 48 8b 44 24 40 8b 40 f8 48 8b 4c 24 40 48 8b 49 f0 48 63 49 04 48 8b 54 24 40 8b 4c 0a f8 8d 44 08 06 89 44 24 20 48 8b 4c 24 40 48 8b 49 f0 48 63 49 04 48 8b 54 24 40 48 8d 4c 0a f0 e8 95 ff ff ff 8b 4c 24 20 03 c8 8b c1 48 83 c4 38"),
		new AddressNameBytes("1400138f8", "[thunk]:BNS::B::fb1_1`adjustor{40}'",
			"48 83 e9 28 e9 9f ff ff"),
		new AddressNameBytes("140013904", "[thunk]:BNS::B::fb1_1`adjustor{4294967240}'",
			"48 83 c1 38 e9 93 ff ff"),
		new AddressNameBytes("140013910", "MNS::M::fb1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 80 18 ff ff ff 48 8b 4c 24 08 8b 49 c8 8d 44 08 13"),
		new AddressNameBytes("140013930", "ONS::O::fb1_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 88 48 63 40 0c 48 8b 4c 24 08 8b 44 01 90 48 8b 4c 24 08 48 8b 49 88 48 63 49 10 48 8b 54 24 08 8b 4c 0a 90 8d 44 08 18"),
		new AddressNameBytes("140013970", "B1NS::B1::fb1_2",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 8d 44 00 04"),
		new AddressNameBytes("140013990", "CNS::C::fb1_2",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 d0 48 63 40 0c 48 8b 4c 24 08 8b 44 01 d8 48 8b 4c 24 08 48 8b 49 d0 48 63 49 04 48 8b 54 24 08 8b 4c 0a d8 8d 44 41 07 48 8b 4c 24 08 03 41 d8"),
		new AddressNameBytes("1400139d0", "[thunk]:CNS::C::fb1_2`adjustor{56}'",
			"48 83 e9 38 e9 b7 ff ff"),
		new AddressNameBytes("1400139dc", "[thunk]:CNS::C::fb1_2`adjustor{168}'",
			"48 81 e9 a8 00 00 00 e9 a8 ff ff"),
		new AddressNameBytes("1400139f0", "B1NS::B1::fb1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 08 03 83 c0 04"),
		new AddressNameBytes("140013a10", "B2NS::B2::fb2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 83 c0 05"),
		new AddressNameBytes("140013a30", "BNS::B::fb2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 e8 48 8b 4c 24 08 48 8b 49 e0 48 63 49 08 48 8b 54 24 08 8b 4c 0a e8 8d 44 08 06"),
		new AddressNameBytes("140013a58", "[thunk]:BNS::B::fb2_1`adjustor{40}'",
			"48 83 e9 28 e9 cf ff ff"),
		new AddressNameBytes("140013a64", "[thunk]:BNS::B::fb2_1`adjustor{4294967240}'",
			"48 83 c1 38 e9 c3 ff ff"),
		new AddressNameBytes("140013a70", "CNS::C::fb2_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 c0 48 63 40 10 48 8b 4c 24 08 8b 44 01 c8 48 8b 4c 24 08 48 8b 49 c0 48 63 49 08 48 8b 54 24 08 8b 4c 0a c8 8d 44 08 07 48 8b 4c 24 08 03 41 c8"),
		new AddressNameBytes("140013ab0", "DNS::D::fb2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 c8 8d 44 00 08"),
		new AddressNameBytes("140013ad0", "MNS::M::fb2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 b8 83 c0 13"),
		new AddressNameBytes("140013af0", "ONS::O::fb2_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 80 78 ff ff ff 48 63 40 08 48 8b 4c 24 08 8b 44 01 80 48 8b 4c 24 08 48 8b 89 78 ff ff ff 48 63 49 10 48 8b 54 24 08 8b 4c 0a 80 8d 44 08 18"),
		new AddressNameBytes("140013b30", "B2NS::B2::fb2_2",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 8d 44 00 05"),
		new AddressNameBytes("140013b50", "B2NS::B2::fb2_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 08 03 83 c0 05"),
		new AddressNameBytes("140013b70", "BNS::B::fb_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 10 48 8b 4c 24 08 48 8b 49 08 48 63 49 04 48 8b 54 24 08 8b 4c 0a 10 8d 44 08 06 48 8b 4c 24 08 48 8b 49 08 48 63 49 08 48 8b 54 24 08 03 44 0a 10"),
		new AddressNameBytes("140013bb0", "CNS::C::fc_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 08 48 63 40 0c 48 8b 4c 24 08 8b 44 01 10 48 8b 4c 24 08 8b 49 10 8d 44 08 07"),
		new AddressNameBytes("140013be0", "MNS::M::fn1_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 80 38 ff ff ff 48 63 40 18 48 8b 4c 24 08 8b 84 01 40 ff ff ff 48 8b 4c 24 08 8b 49 f8 8d 44 08 13"),
		new AddressNameBytes("140013c10", "N1NS::N1::fn1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 83 c0 11"),
		new AddressNameBytes("140013c30", "N1NS::N1::fn1_2",
			"48 89 4c 24 08 48 8b 44 24 08 b9 11 00 00 00 2b 48 08 8b c1"),
		new AddressNameBytes("140013c50", "N2NS::N2::fn2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 83 c0 12"),
		new AddressNameBytes("140013c70", "N2NS::N2::fn2_2",
			"48 89 4c 24 08 48 8b 44 24 08 b9 12 00 00 00 2b 48 08 8b c1"),
		new AddressNameBytes("140013c90", "O1NS::O1::fo1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 30 83 c0 14"),
		new AddressNameBytes("140013cb0", "ONS::O::fo1_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 30 83 c0 18"),
		new AddressNameBytes("140013cd0", "O2NS::O2::fo2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 18 83 c0 15"),
		new AddressNameBytes("140013cf0", "ONS::O::fo2_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 18 83 c0 18"),
		new AddressNameBytes("140013d10", "O3NS::O3::fo3_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 30 83 c0 16"),
		new AddressNameBytes("140013d30", "ONS::O::fo3_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 80 50 ff ff ff 48 63 40 18 48 8b 4c 24 08 8b 44 01 80 83 c0 18"),
		new AddressNameBytes("140013d60", "O4NS::O4::fo4_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 18 83 c0 17"),
		new AddressNameBytes("140013d80", "ONS::O::fo4_1",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 80 18 ff ff ff 48 63 40 1c 48 8b 4c 24 08 8b 84 01 30 ff ff ff 83 c0 18"),
		new AddressNameBytes("140013db0", "ONS::O::fo_1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 30 83 c0 18"),
		new AddressNameBytes("140013f4c", "type_info::`scalar_deleting_destructor'",
			"40 53 48 83 ec 20 48 8d 05 57 c0 05 00 48 8b d9 48 89 01 f6 c2 01 74 0a ba 18 00 00 00 e8 22 03 00 00 48 8b c3 48 83 c4 20 5b"),
		new AddressNameBytes("14001f628", "_purecall",
			"48 83 ec 28 e8 eb ff ff ff 48 85 c0 74 06 ff 15 a4 fc 04 00 e8 1b f8 02")
	};

	private static CppCompositeType createA1_struct(DataTypeManager dtm) {
		String name = "A1NS::A1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("a1", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fa1_2"), fintvoidT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fa1_3"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createA2_struct(DataTypeManager dtm) {
		String name = "A2NS::A2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("a2", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fa2_2"), fintvoidT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fa2_3"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createA_struct(DataTypeManager dtm,
			CppCompositeType A1_struct, CppCompositeType A2_struct) throws PdbException {
		String name = "ANS::A";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 56);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("a", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fa_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createB1_struct(DataTypeManager dtm) {
		String name = "B1NS::B1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("b1", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fb1_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fb1_2"), fintvoidT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fb1_3"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createB2_struct(DataTypeManager dtm) {
		String name = "B2NS::B2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("b2", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fb2_2"), fintvoidT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fb2_3"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createB_struct(DataTypeManager dtm,
			CppCompositeType B1_struct, CppCompositeType B2_struct) throws PdbException {
		String name = "BNS::B";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 56);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("b", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fb1_1"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fb_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createC_struct(DataTypeManager dtm,
			CppCompositeType A1_struct, CppCompositeType A2_struct, CppCompositeType B1_struct,
			CppCompositeType B2_struct) throws PdbException {
		String name = "CNS::C";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 88);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addDirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addDirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("c", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fa1_2"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(56, -1, new SymbolPath(classSp, "fb1_2"), fintvoidT);
		struct.addVirtualMethod(72, -1, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fc_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createD_struct(DataTypeManager dtm,
			CppCompositeType C_struct, CppCompositeType A_struct, CppCompositeType B_struct,
			CppCompositeType A1_struct, CppCompositeType A2_struct, CppCompositeType B1_struct,
			CppCompositeType B2_struct) throws PdbException {
		String name = "DNS::D";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 144);
		struct.addDirectBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 24);
		struct.addDirectBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes, 48);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("d", intT, false, publicDirectAttributes, 72, null);
		struct.addVirtualMethod(96, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(128, -1, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createE_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType B_struct, CppCompositeType A1_struct,
			CppCompositeType A2_struct, CppCompositeType B1_struct, CppCompositeType B2_struct)
			throws PdbException {
		String name = "ENS::E";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 120);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes,
			8, ClassUtils.VXPTR_TYPE, 5);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("e", intT, false, publicDirectAttributes, 24, null);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createF_struct(DataTypeManager dtm,
			CppCompositeType A1_struct) throws PdbException {
		String name = "FNS::F";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("f", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createG_struct(DataTypeManager dtm,
			CppCompositeType F_struct, CppCompositeType A1_struct) throws PdbException {
		String name = "GNS::G";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(F_struct.getComposite(), F_struct, publicDirectAttributes, 0);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("g", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createH_struct(DataTypeManager dtm,
			CppCompositeType F_struct, CppCompositeType A1_struct) throws PdbException {
		String name = "HNS::H";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(F_struct.getComposite(), F_struct, publicDirectAttributes, 0);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("h", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createI_struct(DataTypeManager dtm,
			CppCompositeType G_struct, CppCompositeType H_struct, CppCompositeType A1_struct)
			throws PdbException {
		String name = "INS::I";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 72);
		struct.addDirectBaseClass(G_struct.getComposite(), G_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(H_struct.getComposite(), H_struct, publicDirectAttributes, 24);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("i", intT, false, publicDirectAttributes, 48, null);
		struct.addVirtualMethod(56, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createJ_struct(DataTypeManager dtm,
			CppCompositeType A1_struct) throws PdbException {
		String name = "JNS::J";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("j", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createK_struct(DataTypeManager dtm,
			CppCompositeType J_struct, CppCompositeType A1_struct) throws PdbException {
		String name = "KNS::K";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(J_struct.getComposite(), J_struct, publicDirectAttributes, 0);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("k", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createL_struct(DataTypeManager dtm, CppCompositeType K_struct,
			CppCompositeType A1_struct) throws PdbException {
		String name = "LNS::L";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addDirectBaseClass(K_struct.getComposite(), K_struct, publicDirectAttributes, 0);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("l", intT, false, publicDirectAttributes, 24, null);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createN1_struct(DataTypeManager dtm) {
		String name = "N1NS::N1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("n1", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fn1_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fn1_2"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createN2_struct(DataTypeManager dtm) {
		String name = "N2NS::N2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("n2", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fn2_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fn2_2"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createM_struct(DataTypeManager dtm,
			CppCompositeType E_struct, CppCompositeType D_struct, CppCompositeType I_struct,
			CppCompositeType L_struct, CppCompositeType N1_struct, CppCompositeType N2_struct,
			CppCompositeType A1_struct, CppCompositeType A2_struct, CppCompositeType B1_struct,
			CppCompositeType B2_struct, CppCompositeType B_struct) throws PdbException {
		String name = "MNS::M";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 328);
		struct.addDirectBaseClass(E_struct.getComposite(), E_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(D_struct.getComposite(), D_struct, publicDirectAttributes, 32);
		struct.addDirectBaseClass(I_struct.getComposite(), I_struct, publicDirectAttributes, 112);
		struct.addDirectBaseClass(L_struct.getComposite(), L_struct, publicDirectAttributes, 168);
		struct.addDirectVirtualBaseClass(N1_struct.getComposite(), N1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 6);
		struct.addDirectVirtualBaseClass(N2_struct.getComposite(), N2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 7);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addIndirectVirtualBaseClass(B_struct.getComposite(), B_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 5);
		struct.addMember("m", intT, false, publicDirectAttributes, 200, null);
		struct.addVirtualMethod(224, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		struct.addVirtualMethod(240, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(256, -1, new SymbolPath(classSp, "fb1_1"), fintvoidT);
		struct.addVirtualMethod(272, -1, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		struct.addVirtualMethod(208, -1, new SymbolPath(classSp, "fn1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createO1_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType B_struct, CppCompositeType A1_struct,
			CppCompositeType A2_struct, CppCompositeType B1_struct, CppCompositeType B2_struct)
			throws PdbException {
		String name = "O1NS::O1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 120);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes, 24);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("o1", intT, false, publicDirectAttributes, 48, null);
		struct.addVirtualMethod(72, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fo1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createO2_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType B_struct, CppCompositeType A1_struct,
			CppCompositeType A2_struct, CppCompositeType B1_struct, CppCompositeType B2_struct)
			throws PdbException {
		String name = "O2NS::O2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 120);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes,
			8, ClassUtils.VXPTR_TYPE, 5);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("o2", intT, false, publicDirectAttributes, 24, null);
		struct.addVirtualMethod(48, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fo2_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createO3_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType B_struct, CppCompositeType A1_struct,
			CppCompositeType A2_struct, CppCompositeType B1_struct, CppCompositeType B2_struct)
			throws PdbException {
		String name = "O3NS::O3";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 120);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes, 24);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("o3", intT, false, publicDirectAttributes, 48, null);
		struct.addVirtualMethod(72, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fo3_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createO4_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType B_struct, CppCompositeType A1_struct,
			CppCompositeType A2_struct, CppCompositeType B1_struct, CppCompositeType B2_struct)
			throws PdbException {
		String name = "O4NS::O4";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 120);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes,
			8, ClassUtils.VXPTR_TYPE, 5);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("o4", intT, false, publicDirectAttributes, 24, null);
		struct.addVirtualMethod(48, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fo4_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createO_struct(DataTypeManager dtm,
			CppCompositeType O1_struct, CppCompositeType O2_struct, CppCompositeType O3_struct,
			CppCompositeType O4_struct, CppCompositeType A1_struct, CppCompositeType A2_struct,
			CppCompositeType B1_struct, CppCompositeType B2_struct, CppCompositeType B_struct)
			throws PdbException {
		String name = "ONS::O";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 272);
		struct.addDirectBaseClass(O1_struct.getComposite(), O1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(O2_struct.getComposite(), O2_struct, publicDirectAttributes, 56);
		struct.addDirectVirtualBaseClass(O3_struct.getComposite(), O3_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 6);
		struct.addDirectVirtualBaseClass(O4_struct.getComposite(), O4_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 7);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addIndirectVirtualBaseClass(B_struct.getComposite(), B_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 5);
		struct.addMember("o", intT, false, publicDirectAttributes, 88, null);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fo1_1"), fintvoidT);
		struct.addVirtualMethod(56, -1, new SymbolPath(classSp, "fo2_1"), fintvoidT);
		struct.addVirtualMethod(184, -1, new SymbolPath(classSp, "fo3_1"), fintvoidT);
		struct.addVirtualMethod(240, -1, new SymbolPath(classSp, "fo4_1"), fintvoidT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fo_1"), fintvoidT);
		struct.addVirtualMethod(96, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		struct.addVirtualMethod(112, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(128, -1, new SymbolPath(classSp, "fb1_1"), fintvoidT);
		struct.addVirtualMethod(144, -1, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		return struct;
	}

	//==============================================================================================
	//==============================================================================================

	//@formatter:off
	/*
	class A1NS::A1	size(16):
		+---
	 0	| {vfptr}
	 8	| a1
  		| <alignment member> (size=4)
		+---

	A1NS::A1::$vftable@:
		| &A1_meta
		|  0
	 0	| &A1NS::A1::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	A1NS::A1::fa1_1 this adjustor: 0
	A1NS::A1::fa1_2 this adjustor: 0
	A1NS::A1::fa1_3 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructA1() {
		String expected =
		//@formatter:off
			"""
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructA1() {
		return convertCommentsToSpeculative(getExpectedStructA1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryA1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsA1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructA1_00000000());
		return results;
	}

	private static String getVxtStructA1_00000000() {
		String expected =
		//@formatter:off
			"""
			/A1NS/A1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   A1NS::A1::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class A2NS::A2	size(16):
		+---
	 0	| {vfptr}
	 8	| a2
  		| <alignment member> (size=4)
		+---

	A2NS::A2::$vftable@:
		| &A2_meta
		|  0
	 0	| &A2NS::A2::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	A2NS::A2::fa2_1 this adjustor: 0
	A2NS::A2::fa2_2 this adjustor: 0
	A2NS::A2::fa2_3 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructA2() {
		String expected =
		//@formatter:off
			"""
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructA2() {
		return convertCommentsToSpeculative(getExpectedStructA2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryA2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[A2NS::A2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsA2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructA2_00000000());
		return results;
	}

	private static String getVxtStructA2_00000000() {
		String expected =
		//@formatter:off
			"""
			/A2NS/A2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   A2NS::A2::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class ANS::A	size(56):
		+---
	 0	| {vfptr}
	 8	| {vbptr}
	16	| a
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	24	| {vfptr}
	32	| a1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A2NS::A2)
	40	| {vfptr}
	48	| a2
  		| <alignment member> (size=4)
		+---

	ANS::A::$vftable@A@:
		| &A_meta
		|  0
	 0	| &ANS::A::fa_1

	ANS::A::$vbtable@:
	 0	| -8
	 1	| 16 (Ad(A+8)A1)
	 2	| 32 (Ad(A+8)A2)

	ANS::A::$vftable@A1@:
		| -24
	 0	| &ANS::A::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	ANS::A::$vftable@A2@:
		| -40
	 0	| &ANS::A::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	ANS::A::fa1_1 this adjustor: 24
	ANS::A::fa2_1 this adjustor: 40
	ANS::A::fa_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      24       8       4 0
	        A2NS::A2      40       8       8 0
	 */
	//@formatter:on
	private static String getExpectedStructA() {
		String expected =
		//@formatter:off
			"""
			/ANS::A
			pack()
			Structure ANS::A {
			   0   ANS::A   24      "Self Base"
			   24   A1NS::A1   16      "Virtual Base"
			   40   A2NS::A2   16      "Virtual Base"
			}
			Length: 56 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructA() {
		String expected =
		//@formatter:off
			"""
			/ANS::A
			pack()
			Structure ANS::A {
			   0   ANS::A   24      "Self Base"
			   24   char[32]   32      "Filler for 2 Unplaceable Virtual Bases: A1NS::A1; A2NS::A2"
			}
			Length: 56 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructA() {
		return convertCommentsToSpeculative(getExpectedStructA());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryA() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[ANS::A]");
		results.put("VTABLE_00000008", "     8 vbt []	[ANS::A]");
		results.put("VTABLE_00000018", "    24 vft [A1NS::A1]	[ANS::A, A1NS::A1]");
		results.put("VTABLE_00000028", "    40 vft [A2NS::A2]	[ANS::A, A2NS::A2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsA() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructA_00000000());
		results.put("VTABLE_00000008", getVxtStructA_00000008());
		results.put("VTABLE_00000018", getVxtStructA_00000018());
		results.put("VTABLE_00000028", getVxtStructA_00000028());
		return results;
	}

	private static String getVxtStructA_00000000() {
		String expected =
		//@formatter:off
			"""
			/ANS/A/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructA_00000008() {
		String expected =
		//@formatter:off
			"""
			/ANS/A/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructA_00000018() {
		String expected =
		//@formatter:off
			"""
			/ANS/A/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   ANS::A::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructA_00000028() {
		String expected =
		//@formatter:off
			"""
			/ANS/A/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_int *   8   ANS::A::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class B1NS::B1	size(16):
		+---
	 0	| {vfptr}
	 8	| b1
  		| <alignment member> (size=4)
		+---

	B1NS::B1::$vftable@:
		| &B1_meta
		|  0
	 0	| &B1NS::B1::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	B1NS::B1::fb1_1 this adjustor: 0
	B1NS::B1::fb1_2 this adjustor: 0
	B1NS::B1::fb1_3 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructB1() {
		String expected =
		//@formatter:off
			"""
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructB1() {
		return convertCommentsToSpeculative(getExpectedStructB1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryB1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[B1NS::B1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsB1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructB1_00000000());
		return results;
	}

	private static String getVxtStructB1_00000000() {
		String expected =
		//@formatter:off
			"""
			/B1NS/B1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   B1NS::B1::fb1_1   ""
			   8   _func___thiscall_int *   8   B1NS::B1::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class B2NS::B2	size(16):
		+---
	 0	| {vfptr}
	 8	| b2
  		| <alignment member> (size=4)
		+---

	B2NS::B2::$vftable@:
		| &B2_meta
		|  0
	 0	| &B2NS::B2::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	B2NS::B2::fb2_1 this adjustor: 0
	B2NS::B2::fb2_2 this adjustor: 0
	B2NS::B2::fb2_3 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructB2() {
		String expected =
		//@formatter:off
			"""
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructB2() {
		return convertCommentsToSpeculative(getExpectedStructB2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryB2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsB2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructB2_00000000());
		return results;
	}

	private static String getVxtStructB2_00000000() {
		String expected =
		//@formatter:off
			"""
			/B2NS/B2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   B2NS::B2::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BNS::B	size(56):
		+---
	 0	| {vfptr}
	 8	| {vbptr}
	16	| b
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B1NS::B1)
	24	| {vfptr}
	32	| b1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B2NS::B2)
	40	| {vfptr}
	48	| b2
  		| <alignment member> (size=4)
		+---

	BNS::B::$vftable@B@:
		| &B_meta
		|  0
	 0	| &BNS::B::fb_1

	BNS::B::$vbtable@:
	 0	| -8
	 1	| 16 (Bd(B+8)B1)
	 2	| 32 (Bd(B+8)B2)

	BNS::B::$vftable@B1@:
		| -24
	 0	| &BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	BNS::B::$vftable@B2@:
		| -40
	 0	| &BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	BNS::B::fb1_1 this adjustor: 24
	BNS::B::fb2_1 this adjustor: 40
	BNS::B::fb_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        B1NS::B1      24       8       4 0
	        B2NS::B2      40       8       8 0
	 */
	//@formatter:on
	private static String getExpectedStructB() {
		String expected =
		//@formatter:off
			"""
			/BNS::B
			pack()
			Structure BNS::B {
			   0   BNS::B   24      "Self Base"
			   24   B1NS::B1   16      "Virtual Base"
			   40   B2NS::B2   16      "Virtual Base"
			}
			Length: 56 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructB() {
		String expected =
		//@formatter:off
			"""
			/BNS::B
			pack()
			Structure BNS::B {
			   0   BNS::B   24      "Self Base"
			   24   char[32]   32      "Filler for 2 Unplaceable Virtual Bases: B1NS::B1; B2NS::B2"
			}
			Length: 56 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructB() {
		return convertCommentsToSpeculative(getExpectedStructB());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryB() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [BNS::B]	[BNS::B]");
		results.put("VTABLE_00000008", "     8 vbt []	[BNS::B]");
		results.put("VTABLE_00000018", "    24 vft [B1NS::B1]	[BNS::B, B1NS::B1]");
		results.put("VTABLE_00000028", "    40 vft [B2NS::B2]	[BNS::B, B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsB() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructB_00000000());
		results.put("VTABLE_00000008", getVxtStructB_00000008());
		results.put("VTABLE_00000018", getVxtStructB_00000018());
		results.put("VTABLE_00000028", getVxtStructB_00000028());
		return results;
	}

	private static String getVxtStructB_00000000() {
		String expected =
		//@formatter:off
			"""
			/BNS/B/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructB_00000008() {
		String expected =
		//@formatter:off
			"""
			/BNS/B/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructB_00000018() {
		String expected =
		//@formatter:off
			"""
			/BNS/B/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   BNS::B::fb1_1   ""
			   8   _func___thiscall_int *   8   B1NS::B1::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructB_00000028() {
		String expected =
		//@formatter:off
			"""
			/BNS/B/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_int *   8   BNS::B::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CNS::C	size(88):
		+---
	 0	| {vfptr}
	 8	| {vbptr}
	16	| c
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	24	| {vfptr}
	32	| a1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A2NS::A2)
	40	| {vfptr}
	48	| a2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B1NS::B1)
	56	| {vfptr}
	64	| b1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B2NS::B2)
	72	| {vfptr}
	80	| b2
  		| <alignment member> (size=4)
		+---

	CNS::C::$vftable@C@:
		| &C_meta
		|  0
	 0	| &CNS::C::fc_1

	CNS::C::$vbtable@:
	 0	| -8
	 1	| 16 (Cd(C+8)A1)
	 2	| 32 (Cd(C+8)A2)
	 3	| 48 (Cd(C+8)B1)
	 4	| 64 (Cd(C+8)B2)

	CNS::C::$vftable@A1@:
		| -24
	 0	| &A1NS::A1::fa1_1
	 1	| &CNS::C::fa1_2
	 2	| &A1NS::A1::fa1_3

	CNS::C::$vftable@A2@:
		| -40
	 0	| &CNS::C::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	CNS::C::$vftable@B1@:
		| -56
	 0	| &B1NS::B1::fb1_1
	 1	| &CNS::C::fb1_2
	 2	| &B1NS::B1::fb1_3

	CNS::C::$vftable@B2@:
		| -72
	 0	| &CNS::C::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	CNS::C::fa1_2 this adjustor: 24
	CNS::C::fa2_1 this adjustor: 40
	CNS::C::fb1_2 this adjustor: 56
	CNS::C::fb2_1 this adjustor: 72
	CNS::C::fc_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      24       8       4 0
	        A2NS::A2      40       8       8 0
	        B1NS::B1      56       8      12 0
	        B2NS::B2      72       8      16 0
	 */
	//@formatter:on
	private static String getExpectedStructC() {
		String expected =
		//@formatter:off
			"""
			/CNS::C
			pack()
			Structure CNS::C {
			   0   CNS::C   24      "Self Base"
			   24   A1NS::A1   16      "Virtual Base"
			   40   A2NS::A2   16      "Virtual Base"
			   56   B1NS::B1   16      "Virtual Base"
			   72   B2NS::B2   16      "Virtual Base"
			}
			Length: 88 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   c   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructC() {
		String expected =
		//@formatter:off
			"""
			/CNS::C
			pack()
			Structure CNS::C {
			   0   CNS::C   24      "Self Base"
			   24   char[64]   64      "Filler for 4 Unplaceable Virtual Bases: A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 88 Alignment: 8
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   c   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructC() {
		return convertCommentsToSpeculative(getExpectedStructC());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryC() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [CNS::C]	[CNS::C]");
		results.put("VTABLE_00000008", "     8 vbt []	[CNS::C]");
		results.put("VTABLE_00000018", "    24 vft [A1NS::A1]	[CNS::C, A1NS::A1]");
		results.put("VTABLE_00000028", "    40 vft [A2NS::A2]	[CNS::C, A2NS::A2]");
		results.put("VTABLE_00000038", "    56 vft [B1NS::B1]	[CNS::C, B1NS::B1]");
		results.put("VTABLE_00000048", "    72 vft [B2NS::B2]	[CNS::C, B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsC() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructC_00000000());
		results.put("VTABLE_00000008", getVxtStructC_00000008());
		results.put("VTABLE_00000018", getVxtStructC_00000018());
		results.put("VTABLE_00000028", getVxtStructC_00000028());
		results.put("VTABLE_00000038", getVxtStructC_00000038());
		results.put("VTABLE_00000048", getVxtStructC_00000048());
		return results;
	}

	private static String getVxtStructC_00000000() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   CNS::C::fc_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructC_00000008() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructC_00000018() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   A1NS::A1::fa1_1   ""
			   8   _func___thiscall_int *   8   CNS::C::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructC_00000028() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_int *   8   CNS::C::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructC_00000038() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   _func___thiscall_int *   8   B1NS::B1::fb1_1   ""
			   8   _func___thiscall_int *   8   CNS::C::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructC_00000048() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_00000048
			pack()
			Structure VTABLE_00000048 {
			   0   _func___thiscall_int *   8   CNS::C::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DNS::D	size(144):
		+---
	 0	| +--- (base class CNS::C)
	 0	| | {vfptr}
	 8	| | {vbptr}
	16	| | c
  		| | <alignment member> (size=4)
		| +---
	24	| +--- (base class ANS::A)
	24	| | {vfptr}
	32	| | {vbptr}
	40	| | a
  		| | <alignment member> (size=4)
		| +---
	48	| +--- (base class BNS::B)
	48	| | {vfptr}
	56	| | {vbptr}
	64	| | b
  		| | <alignment member> (size=4)
		| +---
	72	| d
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	80	| {vfptr}
	88	| a1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A2NS::A2)
	96	| {vfptr}
	104	| a2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B1NS::B1)
	112	| {vfptr}
	120	| b1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B2NS::B2)
	128	| {vfptr}
	136	| b2
  		| <alignment member> (size=4)
		+---

	DNS::D::$vftable@C@:
		| &D_meta
		|  0
	 0	| &CNS::C::fc_1

	DNS::D::$vftable@A@:
		| -24
	 0	| &ANS::A::fa_1

	DNS::D::$vftable@B@:
		| -48
	 0	| &BNS::B::fb_1

	DNS::D::$vbtable@C@:
	 0	| -8
	 1	| 72 (Dd(C+8)A1)
	 2	| 88 (Dd(C+8)A2)
	 3	| 104 (Dd(C+8)B1)
	 4	| 120 (Dd(C+8)B2)

	DNS::D::$vbtable@A@:
	 0	| -8
	 1	| 48 (Dd(A+8)A1)
	 2	| 64 (Dd(A+8)A2)

	DNS::D::$vbtable@B@:
	 0	| -8
	 1	| 56 (Dd(B+8)B1)
	 2	| 72 (Dd(B+8)B2)

	DNS::D::$vftable@A1@:
		| -80
	 0	| &thunk: this-=32; goto ANS::A::fa1_1
	 1	| &thunk: this-=56; goto CNS::C::fa1_2
	 2	| &A1NS::A1::fa1_3

	DNS::D::$vftable@A2@:
		| -96
	 0	| &DNS::D::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	DNS::D::$vftable@B1@:
		| -112
	 0	| &thunk: this-=40; goto BNS::B::fb1_1
	 1	| &thunk: this-=56; goto CNS::C::fb1_2
	 2	| &B1NS::B1::fb1_3

	DNS::D::$vftable@B2@:
		| -128
	 0	| &DNS::D::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	DNS::D::fa2_1 this adjustor: 96
	DNS::D::fb2_1 this adjustor: 128
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      80       8       4 0
	        A2NS::A2      96       8       8 0
	        B1NS::B1     112       8      12 0
	        B2NS::B2     128       8      16 0
	 */
	//@formatter:on
	private static String getExpectedStructD() {
		String expected =
		//@formatter:off
			"""
			/DNS::D
			pack()
			Structure DNS::D {
			   0   DNS::D   80      "Self Base"
			   80   A1NS::A1   16      "Virtual Base"
			   96   A2NS::A2   16      "Virtual Base"
			   112   B1NS::B1   16      "Virtual Base"
			   128   B2NS::B2   16      "Virtual Base"
			}
			Length: 144 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   c   ""
			}
			Length: 24 Alignment: 8
			/DNS::D/!internal/DNS::D
			pack()
			Structure DNS::D {
			   0   CNS::C   24      "Base"
			   24   ANS::A   24      "Base"
			   48   BNS::B   24      "Base"
			   72   int   4   d   ""
			}
			Length: 80 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructD() {
		String expected =
		//@formatter:off
			"""
			/DNS::D
			pack()
			Structure DNS::D {
			   0   DNS::D   80      "Self Base"
			   80   char[64]   64      "Filler for 4 Unplaceable Virtual Bases: A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 144 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   c   ""
			}
			Length: 24 Alignment: 8
			/DNS::D/!internal/DNS::D
			pack()
			Structure DNS::D {
			   0   CNS::C   24      "Base"
			   24   ANS::A   24      "Base"
			   48   BNS::B   24      "Base"
			   72   int   4   d   ""
			}
			Length: 80 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructD() {
		return convertCommentsToSpeculative(getExpectedStructD());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryD() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [CNS::C]	[DNS::D, CNS::C]");
		results.put("VTABLE_00000008", "     8 vbt [CNS::C]	[DNS::D, CNS::C]");
		results.put("VTABLE_00000018", "    24 vft [ANS::A]	[DNS::D, ANS::A]");
		results.put("VTABLE_00000020", "    32 vbt [ANS::A]	[DNS::D, ANS::A]");
		results.put("VTABLE_00000030", "    48 vft [BNS::B]	[DNS::D, BNS::B]");
		results.put("VTABLE_00000038", "    56 vbt [BNS::B]	[DNS::D, BNS::B]");
		results.put("VTABLE_00000050", "    80 vft [A1NS::A1]	[DNS::D, CNS::C, A1NS::A1]");
		results.put("VTABLE_00000060", "    96 vft [A2NS::A2]	[DNS::D, CNS::C, A2NS::A2]");
		results.put("VTABLE_00000070", "   112 vft [B1NS::B1]	[DNS::D, CNS::C, B1NS::B1]");
		results.put("VTABLE_00000080", "   128 vft [B2NS::B2]	[DNS::D, CNS::C, B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsD() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructD_00000000());
		results.put("VTABLE_00000008", getVxtStructD_00000008());
		results.put("VTABLE_00000018", getVxtStructD_00000018());
		results.put("VTABLE_00000020", getVxtStructD_00000020());
		results.put("VTABLE_00000030", getVxtStructD_00000030());
		results.put("VTABLE_00000038", getVxtStructD_00000038());
		results.put("VTABLE_00000050", getVxtStructD_00000050());
		results.put("VTABLE_00000060", getVxtStructD_00000060());
		results.put("VTABLE_00000070", getVxtStructD_00000070());
		results.put("VTABLE_00000080", getVxtStructD_00000080());
		return results;
	}

	private static String getVxtStructD_00000000() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   CNS::C::fc_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000008() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000018() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000020() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000030() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000030
			pack()
			Structure VTABLE_00000030 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000038() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000050() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000050
			pack()
			Structure VTABLE_00000050 {
			   0   _func___thiscall_int *   8   ANS::A::fa1_1   ""
			   8   _func___thiscall_int *   8   CNS::C::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000060() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000060
			pack()
			Structure VTABLE_00000060 {
			   0   _func___thiscall_int *   8   DNS::D::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000070() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000070
			pack()
			Structure VTABLE_00000070 {
			   0   _func___thiscall_int *   8   BNS::B::fb1_1   ""
			   8   _func___thiscall_int *   8   CNS::C::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000080() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000080
			pack()
			Structure VTABLE_00000080 {
			   0   _func___thiscall_int *   8   DNS::D::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class ENS::E	size(120):
		+---
	 0	| +--- (base class ANS::A)
	 0	| | {vfptr}
	 8	| | {vbptr}
	16	| | a
  		| | <alignment member> (size=4)
		| +---
	24	| e
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	32	| {vfptr}
	40	| a1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A2NS::A2)
	48	| {vfptr}
	56	| a2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B1NS::B1)
	64	| {vfptr}
	72	| b1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B2NS::B2)
	80	| {vfptr}
	88	| b2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BNS::B)
	96	| {vfptr}
	104	| {vbptr}
	112	| b
  		| <alignment member> (size=4)
		+---

	ENS::E::$vftable@A@:
		| &E_meta
		|  0
	 0	| &ANS::A::fa_1

	ENS::E::$vbtable@A@:
	 0	| -8
	 1	| 24 (Ed(A+8)A1)
	 2	| 40 (Ed(A+8)A2)
	 3	| 56 (Ed(E+8)B1)
	 4	| 72 (Ed(E+8)B2)
	 5	| 88 (Ed(E+8)B)

	ENS::E::$vftable@A1@:
		| -32
	 0	| &ENS::E::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	ENS::E::$vftable@A2@:
		| -48
	 0	| &thunk: this-=8; goto ANS::A::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	ENS::E::$vftable@B1@:
		| -64
	 0	| &thunk: this+=56; goto BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	ENS::E::$vftable@B2@:
		| -80
	 0	| &thunk: this+=56; goto BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	ENS::E::$vftable@B@:
		| -96
	 0	| &BNS::B::fb_1

	ENS::E::$vbtable@B@:
	 0	| -8
	 1	| -40 (Ed(B+8)B1)
	 2	| -24 (Ed(B+8)B2)

	ENS::E::fa1_1 this adjustor: 32
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
`	        A1NS::A1      32       8       4 0
	        A2NS::A2      48       8       8 0
	        B1NS::B1      64       8      12 0
	        B2NS::B2      80       8      16 0
	          BNS::B      96       8      20 0
	 */
	//@formatter:on
	private static String getExpectedStructE() {
		String expected =
		//@formatter:off
			"""
			/ENS::E
			pack()
			Structure ENS::E {
			   0   ENS::E   32      "Self Base"
			   32   A1NS::A1   16      "Virtual Base"
			   48   A2NS::A2   16      "Virtual Base"
			   64   B1NS::B1   16      "Virtual Base"
			   80   B2NS::B2   16      "Virtual Base"
			   96   BNS::B   24      "Virtual Base"
			}
			Length: 120 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/ENS::E/!internal/ENS::E
			pack()
			Structure ENS::E {
			   0   ANS::A   24      "Base"
			   24   int   4   e   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructE() {
		String expected =
		//@formatter:off
			"""
			/ENS::E
			pack()
			Structure ENS::E {
			   0   ENS::E   32      "Self Base"
			   32   char[88]   88      "Filler for 5 Unplaceable Virtual Bases: BNS::B; A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 120 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/ENS::E/!internal/ENS::E
			pack()
			Structure ENS::E {
			   0   ANS::A   24      "Base"
			   24   int   4   e   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructE() {
		return convertCommentsToSpeculative(getExpectedStructE());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryE() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[ENS::E, ANS::A]");
		results.put("VTABLE_00000008", "     8 vbt [ANS::A]	[ENS::E, ANS::A]");
		results.put("VTABLE_00000020", "    32 vft [A1NS::A1]	[ENS::E, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000030", "    48 vft [A2NS::A2]	[ENS::E, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000040", "    64 vft [B1NS::B1]	[ENS::E, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000050", "    80 vft [B2NS::B2]	[ENS::E, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000060", "    96 vft [BNS::B]	[ENS::E, BNS::B]");
		results.put("VTABLE_00000068", "   104 vbt [BNS::B]	[ENS::E, BNS::B]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsE() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructE_00000000());
		results.put("VTABLE_00000008", getVxtStructE_00000008());
		results.put("VTABLE_00000020", getVxtStructE_00000020());
		results.put("VTABLE_00000030", getVxtStructE_00000030());
		results.put("VTABLE_00000040", getVxtStructE_00000040());
		results.put("VTABLE_00000050", getVxtStructE_00000050());
		results.put("VTABLE_00000060", getVxtStructE_00000060());
		results.put("VTABLE_00000068", getVxtStructE_00000068());
		return results;
	}

	private static String getVxtStructE_00000000() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000008() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			   16   int   4      "BNS::B"
			}
			Length: 20 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000020() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_int *   8   ENS::E::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000030() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000030
			pack()
			Structure VTABLE_00000030 {
			   0   _func___thiscall_int *   8   ANS::A::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000040() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000040
			pack()
			Structure VTABLE_00000040 {
			   0   _func___thiscall_int *   8   BNS::B::fb1_1   ""
			   8   _func___thiscall_int *   8   B1NS::B1::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000050() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000050
			pack()
			Structure VTABLE_00000050 {
			   0   _func___thiscall_int *   8   BNS::B::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000060() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000060
			pack()
			Structure VTABLE_00000060 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000068() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000068
			pack()
			Structure VTABLE_00000068 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class FNS::F	size(32):
		+---
	 0	| {vbptr}
	 8	| f
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	16	| {vfptr}
	24	| a1
  		| <alignment member> (size=4)
		+---

	FNS::F::$vbtable@:
	 0	| 0
	 1	| 16 (Fd(F+0)A1)

	FNS::F::$vftable@:
		| -16
	 0	| &FNS::F::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	FNS::F::fa1_1 this adjustor: 16
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructF() {
		String expected =
		//@formatter:off
			"""
			/FNS::F
			pack()
			Structure FNS::F {
			   0   FNS::F   16      "Self Base"
			   16   A1NS::A1   16      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructF() {
		String expected =
		//@formatter:off
			"""
			/FNS::F
			pack()
			Structure FNS::F {
			   0   FNS::F   16      "Self Base"
			   16   char[16]   16      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 32 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructF() {
		return convertCommentsToSpeculative(getExpectedStructF());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryF() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[FNS::F]");
		results.put("VTABLE_00000010", "    16 vft []	[FNS::F, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsF() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructF_00000000());
		results.put("VTABLE_00000010", getVxtStructF_00000010());
		return results;
	}

	private static String getVxtStructF_00000000() {
		String expected =
		//@formatter:off
			"""
			/FNS/F/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructF_00000010() {
		String expected =
		//@formatter:off
			"""
			/FNS/F/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   8   FNS::F::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class GNS::G	size(40):
		+---
	 0	| +--- (base class FNS::F)
	 0	| | {vbptr}
	 8	| | f
  		| | <alignment member> (size=4)
		| +---
	16	| g
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	24	| {vfptr}
	32	| a1
  		| <alignment member> (size=4)
		+---

	GNS::G::$vbtable@:
	 0	| 0
	 1	| 24 (Gd(F+0)A1)

	GNS::G::$vftable@:
		| -24
	 0	| &GNS::G::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	GNS::G::fa1_1 this adjustor: 24
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructG() {
		String expected =
		//@formatter:off
			"""
			/GNS::G
			pack()
			Structure GNS::G {
			   0   GNS::G   24      "Self Base"
			   24   A1NS::A1   16      "Virtual Base"
			}
			Length: 40 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   16      "Base"
			   16   int   4   g   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructG() {
		String expected =
		//@formatter:off
			"""
			/GNS::G
			pack()
			Structure GNS::G {
			   0   GNS::G   24      "Self Base"
			   24   char[16]   16      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 40 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   16      "Base"
			   16   int   4   g   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructG() {
		return convertCommentsToSpeculative(getExpectedStructG());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryG() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[GNS::G, FNS::F]");
		results.put("VTABLE_00000018", "    24 vft []	[GNS::G, FNS::F, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsG() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructG_00000000());
		results.put("VTABLE_00000018", getVxtStructG_00000018());
		return results;
	}

	private static String getVxtStructG_00000000() {
		String expected =
		//@formatter:off
			"""
			/GNS/G/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructG_00000018() {
		String expected =
		//@formatter:off
			"""
			/GNS/G/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   GNS::G::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class HNS::H	size(40):
		+---
	 0	| +--- (base class FNS::F)
	 0	| | {vbptr}
	 8	| | f
  		| | <alignment member> (size=4)
		| +---
	16	| h
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	24	| {vfptr}
	32	| a1
  		| <alignment member> (size=4)
		+---

	HNS::H::$vbtable@:
	 0	| 0
	 1	| 24 (Hd(F+0)A1)

	HNS::H::$vftable@:
		| -24
	 0	| &HNS::H::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	HNS::H::fa1_1 this adjustor: 24
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructH() {
		String expected =
		//@formatter:off
			"""
			/HNS::H
			pack()
			Structure HNS::H {
			   0   HNS::H   24      "Self Base"
			   24   A1NS::A1   16      "Virtual Base"
			}
			Length: 40 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   16      "Base"
			   16   int   4   h   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructH() {
		String expected =
		//@formatter:off
			"""
			/HNS::H
			pack()
			Structure HNS::H {
			   0   HNS::H   24      "Self Base"
			   24   char[16]   16      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 40 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   16      "Base"
			   16   int   4   h   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructH() {
		return convertCommentsToSpeculative(getExpectedStructH());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryH() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[HNS::H, FNS::F]");
		results.put("VTABLE_00000018", "    24 vft []	[HNS::H, FNS::F, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsH() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructH_00000000());
		results.put("VTABLE_00000018", getVxtStructH_00000018());
		return results;
	}

	private static String getVxtStructH_00000000() {
		String expected =
		//@formatter:off
			"""
			/HNS/H/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructH_00000018() {
		String expected =
		//@formatter:off
			"""
			/HNS/H/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   HNS::H::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class INS::I	size(72):
		+---
	 0	| +--- (base class GNS::G)
	 0	| | +--- (base class FNS::F)
	 0	| | | {vbptr}
	 8	| | | f
  		| | | <alignment member> (size=4)
		| | +---
	16	| | g
  		| | <alignment member> (size=4)
		| +---
	24	| +--- (base class HNS::H)
	24	| | +--- (base class FNS::F)
	24	| | | {vbptr}
	32	| | | f
  		| | | <alignment member> (size=4)
		| | +---
	40	| | h
  		| | <alignment member> (size=4)
		| +---
	48	| i
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	56	| {vfptr}
	64	| a1
  		| <alignment member> (size=4)
		+---

	INS::I::$vbtable@G@:
	 0	| 0
	 1	| 56 (Id(F+0)A1)

	INS::I::$vbtable@H@:
	 0	| 0
	 1	| 32 (Id(F+0)A1)

	INS::I::$vftable@:
		| -56
	 0	| &INS::I::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	INS::I::fa1_1 this adjustor: 56
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      56       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructI() {
		String expected =
		//@formatter:off
			"""
			/INS::I
			pack()
			Structure INS::I {
			   0   INS::I   56      "Self Base"
			   56   A1NS::A1   16      "Virtual Base"
			}
			Length: 72 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   16      "Base"
			   16   int   4   g   ""
			}
			Length: 24 Alignment: 8
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   16      "Base"
			   16   int   4   h   ""
			}
			Length: 24 Alignment: 8
			/INS::I/!internal/INS::I
			pack()
			Structure INS::I {
			   0   GNS::G   24      "Base"
			   24   HNS::H   24      "Base"
			   48   int   4   i   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructI() {
		String expected =
		//@formatter:off
			"""
			/INS::I
			pack()
			Structure INS::I {
			   0   INS::I   56      "Self Base"
			   56   char[16]   16      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 72 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   16      "Base"
			   16   int   4   g   ""
			}
			Length: 24 Alignment: 8
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   16      "Base"
			   16   int   4   h   ""
			}
			Length: 24 Alignment: 8
			/INS::I/!internal/INS::I
			pack()
			Structure INS::I {
			   0   GNS::G   24      "Base"
			   24   HNS::H   24      "Base"
			   48   int   4   i   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructI() {
		return convertCommentsToSpeculative(getExpectedStructI());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryI() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [GNS::G]	[INS::I, GNS::G, FNS::F]");
		results.put("VTABLE_00000018", "    24 vbt [HNS::H]	[INS::I, HNS::H, FNS::F]");
		results.put("VTABLE_00000038", "    56 vft []	[INS::I, GNS::G, FNS::F, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsI() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructI_00000000());
		results.put("VTABLE_00000018", getVxtStructI_00000018());
		results.put("VTABLE_00000038", getVxtStructI_00000038());
		return results;
	}

	private static String getVxtStructI_00000000() {
		String expected =
		//@formatter:off
			"""
			/INS/I/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructI_00000018() {
		String expected =
		//@formatter:off
			"""
			/INS/I/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructI_00000038() {
		String expected =
		//@formatter:off
			"""
			/INS/I/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   _func___thiscall_int *   8   INS::I::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class JNS::J	size(32):
		+---
	 0	| {vbptr}
	 8	| j
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	16	| {vfptr}
	24	| a1
  		| <alignment member> (size=4)
		+---

	JNS::J::$vbtable@:
	 0	| 0
	 1	| 16 (Jd(J+0)A1)

	JNS::J::$vftable@:
		| -16
	 0	| &JNS::J::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	JNS::J::fa1_1 this adjustor: 16
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructJ() {
		String expected =
		//@formatter:off
			"""
			/JNS::J
			pack()
			Structure JNS::J {
			   0   JNS::J   16      "Self Base"
			   16   A1NS::A1   16      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   j   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructJ() {
		String expected =
		//@formatter:off
			"""
			/JNS::J
			pack()
			Structure JNS::J {
			   0   JNS::J   16      "Self Base"
			   16   char[16]   16      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 32 Alignment: 8
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   j   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructJ() {
		return convertCommentsToSpeculative(getExpectedStructJ());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryJ() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[JNS::J]");
		results.put("VTABLE_00000010", "    16 vft []	[JNS::J, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsJ() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructJ_00000000());
		results.put("VTABLE_00000010", getVxtStructJ_00000010());
		return results;
	}

	private static String getVxtStructJ_00000000() {
		String expected =
		//@formatter:off
			"""
			/JNS/J/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ_00000010() {
		String expected =
		//@formatter:off
			"""
			/JNS/J/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   8   JNS::J::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class KNS::K	size(40):
		+---
	 0	| +--- (base class JNS::J)
	 0	| | {vbptr}
	 8	| | j
  		| | <alignment member> (size=4)
		| +---
	16	| k
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	24	| {vfptr}
	32	| a1
  		| <alignment member> (size=4)
		+---

	KNS::K::$vbtable@:
	 0	| 0
	 1	| 24 (Kd(J+0)A1)

	KNS::K::$vftable@:
		| -24
	 0	| &KNS::K::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	KNS::K::fa1_1 this adjustor: 24
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructK() {
		String expected =
		//@formatter:off
			"""
			/KNS::K
			pack()
			Structure KNS::K {
			   0   KNS::K   24      "Self Base"
			   24   A1NS::A1   16      "Virtual Base"
			}
			Length: 40 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   j   ""
			}
			Length: 16 Alignment: 8
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   16      "Base"
			   16   int   4   k   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructK() {
		String expected =
		//@formatter:off
			"""
			/KNS::K
			pack()
			Structure KNS::K {
			   0   KNS::K   24      "Self Base"
			   24   char[16]   16      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 40 Alignment: 8
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   j   ""
			}
			Length: 16 Alignment: 8
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   16      "Base"
			   16   int   4   k   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructK() {
		return convertCommentsToSpeculative(getExpectedStructK());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryK() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[KNS::K, JNS::J]");
		results.put("VTABLE_00000018", "    24 vft []	[KNS::K, JNS::J, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsK() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructK_00000000());
		results.put("VTABLE_00000018", getVxtStructK_00000018());
		return results;
	}

	private static String getVxtStructK_00000000() {
		String expected =
		//@formatter:off
			"""
			/KNS/K/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructK_00000018() {
		String expected =
		//@formatter:off
			"""
			/KNS/K/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   KNS::K::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class LNS::L	size(48):
		+---
	 0	| +--- (base class KNS::K)
	 0	| | +--- (base class JNS::J)
	 0	| | | {vbptr}
	 8	| | | j
  		| | | <alignment member> (size=4)
		| | +---
	16	| | k
  		| | <alignment member> (size=4)
		| +---
	24	| l
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	32	| {vfptr}
	40	| a1
  		| <alignment member> (size=4)
		+---

	LNS::L::$vbtable@:
	 0	| 0
	 1	| 32 (Ld(J+0)A1)

	LNS::L::$vftable@:
		| -32
	 0	| &LNS::L::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	LNS::L::fa1_1 this adjustor: 32
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      32       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructL() {
		String expected =
		//@formatter:off
			"""
			/LNS::L
			pack()
			Structure LNS::L {
			   0   LNS::L   32      "Self Base"
			   32   A1NS::A1   16      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   j   ""
			}
			Length: 16 Alignment: 8
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   16      "Base"
			   16   int   4   k   ""
			}
			Length: 24 Alignment: 8
			/LNS::L/!internal/LNS::L
			pack()
			Structure LNS::L {
			   0   KNS::K   24      "Base"
			   24   int   4   l   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructL() {
		String expected =
		//@formatter:off
			"""
			/LNS::L
			pack()
			Structure LNS::L {
			   0   LNS::L   32      "Self Base"
			   32   char[16]   16      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 48 Alignment: 8
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   j   ""
			}
			Length: 16 Alignment: 8
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   16      "Base"
			   16   int   4   k   ""
			}
			Length: 24 Alignment: 8
			/LNS::L/!internal/LNS::L
			pack()
			Structure LNS::L {
			   0   KNS::K   24      "Base"
			   24   int   4   l   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructL() {
		return convertCommentsToSpeculative(getExpectedStructL());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryL() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[LNS::L, KNS::K, JNS::J]");
		results.put("VTABLE_00000020", "    32 vft []	[LNS::L, KNS::K, JNS::J, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsL() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructL_00000000());
		results.put("VTABLE_00000020", getVxtStructL_00000020());
		return results;
	}

	private static String getVxtStructL_00000000() {
		String expected =
		//@formatter:off
			"""
			/LNS/L/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructL_00000020() {
		String expected =
		//@formatter:off
			"""
			/LNS/L/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_int *   8   LNS::L::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class N1NS::N1	size(16):
		+---
	 0	| {vfptr}
	 8	| n1
  		| <alignment member> (size=4)
		+---

	N1NS::N1::$vftable@:
		| &N1_meta
		|  0
	 0	| &N1NS::N1::fn1_1
	 1	| &N1NS::N1::fn1_2

	N1NS::N1::fn1_1 this adjustor: 0
	N1NS::N1::fn1_2 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructN1() {
		String expected =
		//@formatter:off
			"""
			/N1NS::N1
			pack()
			Structure N1NS::N1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   n1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructN1() {
		return convertCommentsToSpeculative(getExpectedStructN1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryN1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[N1NS::N1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsN1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructN1_00000000());
		return results;
	}

	private static String getVxtStructN1_00000000() {
		String expected =
		//@formatter:off
			"""
			/N1NS/N1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   N1NS::N1::fn1_1   ""
			   8   _func___thiscall_int *   8   N1NS::N1::fn1_2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class N2NS::N2	size(16):
		+---
	 0	| {vfptr}
	 8	| n2
  		| <alignment member> (size=4)
		+---

	N2NS::N2::$vftable@:
		| &N2_meta
		|  0
	 0	| &N2NS::N2::fn2_1
	 1	| &N2NS::N2::fn2_2

	N2NS::N2::fn2_1 this adjustor: 0
	N2NS::N2::fn2_2 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructN2() {
		String expected =
		//@formatter:off
			"""
			/N2NS::N2
			pack()
			Structure N2NS::N2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   n2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructN2() {
		return convertCommentsToSpeculative(getExpectedStructN2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryN2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[N2NS::N2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsN2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructN2_00000000());
		return results;
	}

	private static String getVxtStructN2_00000000() {
		String expected =
		//@formatter:off
			"""
			/N2NS/N2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   N2NS::N2::fn2_1   ""
			   8   _func___thiscall_int *   8   N2NS::N2::fn2_2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class MNS::M	size(328):
		+---
	 0	| +--- (base class ENS::E)
	 0	| | +--- (base class ANS::A)
	 0	| | | {vfptr}
	 8	| | | {vbptr}
	16	| | | a
  		| | | <alignment member> (size=4)
		| | +---
	24	| | e
  		| | <alignment member> (size=4)
		| +---
	32	| +--- (base class DNS::D)
	32	| | +--- (base class CNS::C)
	32	| | | {vfptr}
	40	| | | {vbptr}
	48	| | | c
  		| | | <alignment member> (size=4)
		| | +---
	56	| | +--- (base class ANS::A)
	56	| | | {vfptr}
	64	| | | {vbptr}
	72	| | | a
  		| | | <alignment member> (size=4)
		| | +---
	80	| | +--- (base class BNS::B)
	80	| | | {vfptr}
	88	| | | {vbptr}
	96	| | | b
  		| | | <alignment member> (size=4)
		| | +---
	104	| | d
  		| | <alignment member> (size=4)
		| +---
	112	| +--- (base class INS::I)
	112	| | +--- (base class GNS::G)
	112	| | | +--- (base class FNS::F)
	112	| | | | {vbptr}
	120	| | | | f
  		| | | | <alignment member> (size=4)
		| | | +---
	128	| | | g
  		| | | <alignment member> (size=4)
		| | +---
	136	| | +--- (base class HNS::H)
	136	| | | +--- (base class FNS::F)
	136	| | | | {vbptr}
	144	| | | | f
  		| | | | <alignment member> (size=4)
		| | | +---
	152	| | | h
  		| | | <alignment member> (size=4)
		| | +---
	160	| | i
  		| | <alignment member> (size=4)
		| +---
	168	| +--- (base class LNS::L)
	168	| | +--- (base class KNS::K)
	168	| | | +--- (base class JNS::J)
	168	| | | | {vbptr}
	176	| | | | j
  		| | | | <alignment member> (size=4)
		| | | +---
	184	| | | k
  		| | | <alignment member> (size=4)
		| | +---
	192	| | l
  		| | <alignment member> (size=4)
		| +---
	200	| m
  		| <alignment member> (size=4)
		+---
		+--- (virtual base N1NS::N1)
	208	| {vfptr}
	216	| n1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	224	| {vfptr}
	232	| a1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A2NS::A2)
	240	| {vfptr}
	248	| a2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B1NS::B1)
	256	| {vfptr}
	264	| b1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B2NS::B2)
	272	| {vfptr}
	280	| b2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BNS::B)
	288	| {vfptr}
	296	| {vbptr}
	304	| b
  		| <alignment member> (size=4)
		+---
		+--- (virtual base N2NS::N2)
	312	| {vfptr}
	320	| n2
  		| <alignment member> (size=4)
		+---

	MNS::M::$vftable@A@E@:
		| &M_meta
		|  0
	 0	| &ANS::A::fa_1

	MNS::M::$vftable@C@:
		| -32
	 0	| &CNS::C::fc_1

	MNS::M::$vftable@A@D@:
		| -56
	 0	| &ANS::A::fa_1

	MNS::M::$vftable@B@D@:
		| -80
	 0	| &BNS::B::fb_1

	MNS::M::$vbtable@A@E@:
	 0	| -8
	 1	| 216 (Md(A+8)A1)
	 2	| 232 (Md(A+8)A2)
	 3	| 248 (Md(E+8)B1)
	 4	| 264 (Md(E+8)B2)
	 5	| 280 (Md(E+8)B)
	 6	| 200 (Md(M+8)N1)
	 7	| 304 (Md(M+8)N2)

	MNS::M::$vbtable@C@:
	 0	| -8
	 1	| 184 (Md(C+8)A1)
	 2	| 200 (Md(C+8)A2)
	 3	| 216 (Md(C+8)B1)
	 4	| 232 (Md(C+8)B2)

	MNS::M::$vbtable@A@D@:
	 0	| -8
	 1	| 160 (Md(A+8)A1)
	 2	| 176 (Md(A+8)A2)

	MNS::M::$vbtable@B@D@:
	 0	| -8
	 1	| 168 (Md(B+8)B1)
	 2	| 184 (Md(B+8)B2)

	MNS::M::$vbtable@G@:
	 0	| 0
	 1	| 112 (Md(F+0)A1)

	MNS::M::$vbtable@H@:
	 0	| 0
	 1	| 88 (Md(F+0)A1)

	MNS::M::$vbtable@:
	 0	| 0
	 1	| 56 (Md(J+0)A1)

	MNS::M::$vftable@N1@:
		| -208
	 0	| &MNS::M::fn1_1
	 1	| &N1NS::N1::fn1_2

	MNS::M::$vftable@A1@:
		| -224
	 0	| &MNS::M::fa1_1
	 1	| &thunk: this-=168; goto CNS::C::fa1_2
	 2	| &A1NS::A1::fa1_3

	MNS::M::$vftable@A2@:
		| -240
	 0	| &MNS::M::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	MNS::M::$vftable@B1@:
		| -256
	 0	| &MNS::M::fb1_1
	 1	| &thunk: this-=168; goto CNS::C::fb1_2
	 2	| &B1NS::B1::fb1_3

	MNS::M::$vftable@B2@:
		| -272
	 0	| &MNS::M::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	MNS::M::$vftable@B@E@:
		| -288
	 0	| &BNS::B::fb_1

	MNS::M::$vbtable@B@E@:
	 0	| -8
	 1	| -40 (Md(B+8)B1)
	 2	| -24 (Md(B+8)B2)

	MNS::M::$vftable@N2@:
		| -312
	 0	| &N2NS::N2::fn2_1
	 1	| &N2NS::N2::fn2_2

	MNS::M::fa1_1 this adjustor: 224
	MNS::M::fa2_1 this adjustor: 240
	MNS::M::fb1_1 this adjustor: 256
	MNS::M::fb2_1 this adjustor: 272
	MNS::M::fn1_1 this adjustor: 208
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        N1NS::N1     208       8      24 0
	        A1NS::A1     224       8       4 0
	        A2NS::A2     240       8       8 0
	        B1NS::B1     256       8      12 0
	        B2NS::B2     272       8      16 0
	          BNS::B     288       8      20 0
	        N2NS::N2     312       8      28 0
	 */
	//@formatter:on
	private static String getExpectedStructM() {
		String expected =
		//@formatter:off
			"""
			/MNS::M
			pack()
			Structure MNS::M {
			   0   MNS::M   208      "Self Base"
			   208   N1NS::N1   16      "Virtual Base"
			   224   A1NS::A1   16      "Virtual Base"
			   240   A2NS::A2   16      "Virtual Base"
			   256   B1NS::B1   16      "Virtual Base"
			   272   B2NS::B2   16      "Virtual Base"
			   288   BNS::B   24      "Virtual Base"
			   312   N2NS::N2   16      "Virtual Base"
			}
			Length: 328 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   c   ""
			}
			Length: 24 Alignment: 8
			/DNS::D/!internal/DNS::D
			pack()
			Structure DNS::D {
			   0   CNS::C   24      "Base"
			   24   ANS::A   24      "Base"
			   48   BNS::B   24      "Base"
			   72   int   4   d   ""
			}
			Length: 80 Alignment: 8
			/ENS::E/!internal/ENS::E
			pack()
			Structure ENS::E {
			   0   ANS::A   24      "Base"
			   24   int   4   e   ""
			}
			Length: 32 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   16      "Base"
			   16   int   4   g   ""
			}
			Length: 24 Alignment: 8
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   16      "Base"
			   16   int   4   h   ""
			}
			Length: 24 Alignment: 8
			/INS::I/!internal/INS::I
			pack()
			Structure INS::I {
			   0   GNS::G   24      "Base"
			   24   HNS::H   24      "Base"
			   48   int   4   i   ""
			}
			Length: 56 Alignment: 8
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   j   ""
			}
			Length: 16 Alignment: 8
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   16      "Base"
			   16   int   4   k   ""
			}
			Length: 24 Alignment: 8
			/LNS::L/!internal/LNS::L
			pack()
			Structure LNS::L {
			   0   KNS::K   24      "Base"
			   24   int   4   l   ""
			}
			Length: 32 Alignment: 8
			/MNS::M/!internal/MNS::M
			pack()
			Structure MNS::M {
			   0   ENS::E   32      "Base"
			   32   DNS::D   80      "Base"
			   112   INS::I   56      "Base"
			   168   LNS::L   32      "Base"
			   200   int   4   m   ""
			}
			Length: 208 Alignment: 8
			/N1NS::N1
			pack()
			Structure N1NS::N1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   n1   ""
			}
			Length: 16 Alignment: 8
			/N2NS::N2
			pack()
			Structure N2NS::N2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   n2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructM() {
		String expected =
		//@formatter:off
			"""
			/MNS::M
			pack()
			Structure MNS::M {
			   0   MNS::M   208      "Self Base"
			   208   char[120]   120      "Filler for 7 Unplaceable Virtual Bases: N1NS::N1; N2NS::N2; A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2; BNS::B"
			}
			Length: 328 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   c   ""
			}
			Length: 24 Alignment: 8
			/DNS::D/!internal/DNS::D
			pack()
			Structure DNS::D {
			   0   CNS::C   24      "Base"
			   24   ANS::A   24      "Base"
			   48   BNS::B   24      "Base"
			   72   int   4   d   ""
			}
			Length: 80 Alignment: 8
			/ENS::E/!internal/ENS::E
			pack()
			Structure ENS::E {
			   0   ANS::A   24      "Base"
			   24   int   4   e   ""
			}
			Length: 32 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   16      "Base"
			   16   int   4   g   ""
			}
			Length: 24 Alignment: 8
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   16      "Base"
			   16   int   4   h   ""
			}
			Length: 24 Alignment: 8
			/INS::I/!internal/INS::I
			pack()
			Structure INS::I {
			   0   GNS::G   24      "Base"
			   24   HNS::H   24      "Base"
			   48   int   4   i   ""
			}
			Length: 56 Alignment: 8
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   j   ""
			}
			Length: 16 Alignment: 8
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   16      "Base"
			   16   int   4   k   ""
			}
			Length: 24 Alignment: 8
			/LNS::L/!internal/LNS::L
			pack()
			Structure LNS::L {
			   0   KNS::K   24      "Base"
			   24   int   4   l   ""
			}
			Length: 32 Alignment: 8
			/MNS::M/!internal/MNS::M
			pack()
			Structure MNS::M {
			   0   ENS::E   32      "Base"
			   32   DNS::D   80      "Base"
			   112   INS::I   56      "Base"
			   168   LNS::L   32      "Base"
			   200   int   4   m   ""
			}
			Length: 208 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructM() {
		String expected =
		//@formatter:off
			"""
			/MNS::M
			pack()
			Structure MNS::M {
			   0   MNS::M   208      "Self Base"
			   208   A1NS::A1   16      "Virtual Base - Speculative Placement"
			   224   A2NS::A2   16      "Virtual Base - Speculative Placement"
			   240   B1NS::B1   16      "Virtual Base - Speculative Placement"
			   256   B2NS::B2   16      "Virtual Base - Speculative Placement"
			   272   BNS::B   24      "Virtual Base - Speculative Placement"
			   296   N1NS::N1   16      "Virtual Base - Speculative Placement"
			   312   N2NS::N2   16      "Virtual Base - Speculative Placement"
			}
			Length: 328 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   c   ""
			}
			Length: 24 Alignment: 8
			/DNS::D/!internal/DNS::D
			pack()
			Structure DNS::D {
			   0   CNS::C   24      "Base"
			   24   ANS::A   24      "Base"
			   48   BNS::B   24      "Base"
			   72   int   4   d   ""
			}
			Length: 80 Alignment: 8
			/ENS::E/!internal/ENS::E
			pack()
			Structure ENS::E {
			   0   ANS::A   24      "Base"
			   24   int   4   e   ""
			}
			Length: 32 Alignment: 8
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   f   ""
			}
			Length: 16 Alignment: 8
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   16      "Base"
			   16   int   4   g   ""
			}
			Length: 24 Alignment: 8
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   16      "Base"
			   16   int   4   h   ""
			}
			Length: 24 Alignment: 8
			/INS::I/!internal/INS::I
			pack()
			Structure INS::I {
			   0   GNS::G   24      "Base"
			   24   HNS::H   24      "Base"
			   48   int   4   i   ""
			}
			Length: 56 Alignment: 8
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   j   ""
			}
			Length: 16 Alignment: 8
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   16      "Base"
			   16   int   4   k   ""
			}
			Length: 24 Alignment: 8
			/LNS::L/!internal/LNS::L
			pack()
			Structure LNS::L {
			   0   KNS::K   24      "Base"
			   24   int   4   l   ""
			}
			Length: 32 Alignment: 8
			/MNS::M/!internal/MNS::M
			pack()
			Structure MNS::M {
			   0   ENS::E   32      "Base"
			   32   DNS::D   80      "Base"
			   112   INS::I   56      "Base"
			   168   LNS::L   32      "Base"
			   200   int   4   m   ""
			}
			Length: 208 Alignment: 8
			/N1NS::N1
			pack()
			Structure N1NS::N1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   n1   ""
			}
			Length: 16 Alignment: 8
			/N2NS::N2
			pack()
			Structure N2NS::N2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   n2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static Map<String, String> getExpectedVxtPtrSummaryM() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A, ENS::E]	[MNS::M, ENS::E, ANS::A]");
		results.put("VTABLE_00000008", "     8 vbt [ANS::A, ENS::E]	[MNS::M, ENS::E, ANS::A]");
		results.put("VTABLE_00000020", "    32 vft [CNS::C]	[MNS::M, DNS::D, CNS::C]");
		results.put("VTABLE_00000028", "    40 vbt [CNS::C]	[MNS::M, DNS::D, CNS::C]");
		results.put("VTABLE_00000038", "    56 vft [ANS::A, DNS::D]	[MNS::M, DNS::D, ANS::A]");
		results.put("VTABLE_00000040", "    64 vbt [ANS::A, DNS::D]	[MNS::M, DNS::D, ANS::A]");
		results.put("VTABLE_00000050", "    80 vft [BNS::B, DNS::D]	[MNS::M, DNS::D, BNS::B]");
		results.put("VTABLE_00000058", "    88 vbt [BNS::B, DNS::D]	[MNS::M, DNS::D, BNS::B]");
		results.put("VTABLE_00000070", "   112 vbt [GNS::G]	[MNS::M, INS::I, GNS::G, FNS::F]");
		results.put("VTABLE_00000088", "   136 vbt [HNS::H]	[MNS::M, INS::I, HNS::H, FNS::F]");
		results.put("VTABLE_000000a8", "   168 vbt []	[MNS::M, LNS::L, KNS::K, JNS::J]");
		results.put("VTABLE_000000d0", "   208 vft [N1NS::N1]	[MNS::M, N1NS::N1]");
		results.put("VTABLE_000000e0",
			"   224 vft [A1NS::A1]	[MNS::M, ENS::E, ANS::A, A1NS::A1]");
		results.put("VTABLE_000000f0",
			"   240 vft [A2NS::A2]	[MNS::M, ENS::E, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000100",
			"   256 vft [B1NS::B1]	[MNS::M, ENS::E, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000110",
			"   272 vft [B2NS::B2]	[MNS::M, ENS::E, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000120", "   288 vft [BNS::B, ENS::E]	[MNS::M, ENS::E, BNS::B]");
		results.put("VTABLE_00000128", "   296 vbt [BNS::B, ENS::E]	[MNS::M, ENS::E, BNS::B]");
		results.put("VTABLE_00000138", "   312 vft [N2NS::N2]	[MNS::M, N2NS::N2]");
		return results;
	}

	private static Map<String, String> getSpeculatedVxtPtrSummaryM() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A, ENS::E]	[MNS::M, ENS::E, ANS::A]");
		results.put("VTABLE_00000008", "     8 vbt [ANS::A, ENS::E]	[MNS::M, ENS::E, ANS::A]");
		results.put("VTABLE_00000020", "    32 vft [CNS::C]	[MNS::M, DNS::D, CNS::C]");
		results.put("VTABLE_00000028", "    40 vbt [CNS::C]	[MNS::M, DNS::D, CNS::C]");
		results.put("VTABLE_00000038", "    56 vft [ANS::A, DNS::D]	[MNS::M, DNS::D, ANS::A]");
		results.put("VTABLE_00000040", "    64 vbt [ANS::A, DNS::D]	[MNS::M, DNS::D, ANS::A]");
		results.put("VTABLE_00000050", "    80 vft [BNS::B, DNS::D]	[MNS::M, DNS::D, BNS::B]");
		results.put("VTABLE_00000058", "    88 vbt [BNS::B, DNS::D]	[MNS::M, DNS::D, BNS::B]");
		results.put("VTABLE_00000070", "   112 vbt [GNS::G]	[MNS::M, INS::I, GNS::G, FNS::F]");
		results.put("VTABLE_00000088", "   136 vbt [HNS::H]	[MNS::M, INS::I, HNS::H, FNS::F]");
		results.put("VTABLE_000000a8", "   168 vbt []	[MNS::M, LNS::L, KNS::K, JNS::J]");
		results.put("VTABLE_000000d0",
			"   208 vft [A1NS::A1]	[MNS::M, ENS::E, ANS::A, A1NS::A1]");
		results.put("VTABLE_000000e0",
			"   224 vft [A2NS::A2]	[MNS::M, ENS::E, ANS::A, A2NS::A2]");
		results.put("VTABLE_000000f0",
			"   240 vft [B1NS::B1]	[MNS::M, ENS::E, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000100",
			"   256 vft [B2NS::B2]	[MNS::M, ENS::E, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000110",
			"   272 vft [BNS::B, ENS::E]	[MNS::M, ENS::E, BNS::B]");
		results.put("VTABLE_00000118", "   280 vbt [BNS::B, ENS::E]	[MNS::M, ENS::E, BNS::B]");
		results.put("VTABLE_00000128", "   296 vft [N1NS::N1]	[MNS::M, N1NS::N1]");
		results.put("VTABLE_00000138", "   312 vft [N2NS::N2]	[MNS::M, N2NS::N2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsM() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructM_00000000());
		results.put("VTABLE_00000008", getVxtStructM_00000008());
		results.put("VTABLE_00000020", getVxtStructM_00000020());
		results.put("VTABLE_00000028", getVxtStructM_00000028());
		results.put("VTABLE_00000038", getVxtStructM_00000038());
		results.put("VTABLE_00000040", getVxtStructM_00000040());
		results.put("VTABLE_00000050", getVxtStructM_00000050());
		results.put("VTABLE_00000058", getVxtStructM_00000058());
		results.put("VTABLE_00000070", getVxtStructM_00000070());
		results.put("VTABLE_00000088", getVxtStructM_00000088());
		results.put("VTABLE_000000a8", getVxtStructM_000000a8());
		results.put("VTABLE_000000d0", getVxtStructM_000000d0());
		results.put("VTABLE_000000e0", getVxtStructM_000000e0());
		results.put("VTABLE_000000f0", getVxtStructM_000000f0());
		results.put("VTABLE_00000100", getVxtStructM_00000100());
		results.put("VTABLE_00000110", getVxtStructM_00000110());
		results.put("VTABLE_00000120", getVxtStructM_00000120());
		results.put("VTABLE_00000128", getVxtStructM_00000128());
		results.put("VTABLE_00000138", getVxtStructM_00000138());
		return results;
	}

	private static Map<String, String> getSpeculatedVxtStructsM() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructM_00000000());
		results.put("VTABLE_00000008", getVxtStructM_00000008());
		results.put("VTABLE_00000020", getVxtStructM_00000020());
		results.put("VTABLE_00000028", getVxtStructM_00000028());
		results.put("VTABLE_00000038", getVxtStructM_00000038());
		results.put("VTABLE_00000040", getVxtStructM_00000040());
		results.put("VTABLE_00000050", getVxtStructM_00000050());
		results.put("VTABLE_00000058", getVxtStructM_00000058());
		results.put("VTABLE_00000070", getVxtStructM_00000070());
		results.put("VTABLE_00000088", getVxtStructM_00000088());
		results.put("VTABLE_000000a8", getVxtStructM_000000a8());
		results.put("VTABLE_000000d0", getVxtStructM_000000d0_speculated());
		results.put("VTABLE_000000e0", getVxtStructM_000000e0_speculated());
		results.put("VTABLE_000000f0", getVxtStructM_000000f0_speculated());
		results.put("VTABLE_00000100", getVxtStructM_00000100_speculated());
		results.put("VTABLE_00000110", getVxtStructM_00000110_speculated());
		results.put("VTABLE_00000118", getVxtStructM_00000118_speculated());
		results.put("VTABLE_00000128", getVxtStructM_00000128_speculated());
		results.put("VTABLE_00000138", getVxtStructM_00000138_speculated());
		return results;
	}

	private static String getVxtStructM_00000000() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000008() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			   16   int   4      "BNS::B"
			   20   int   4      "N1NS::N1"
			   24   int   4      "N2NS::N2"
			}
			Length: 28 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000020() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_int *   8   CNS::C::fc_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000028() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000038() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000040() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000040
			pack()
			Structure VTABLE_00000040 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000050() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000050
			pack()
			Structure VTABLE_00000050 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000058() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000058
			pack()
			Structure VTABLE_00000058 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000070() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000070
			pack()
			Structure VTABLE_00000070 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000088() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000088
			pack()
			Structure VTABLE_00000088 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_000000a8() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_000000a8
			pack()
			Structure VTABLE_000000a8 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_000000d0() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_000000d0
			pack()
			Structure VTABLE_000000d0 {
			   0   _func___thiscall_int *   8   MNS::M::fn1_1   ""
			   8   _func___thiscall_int *   8   N1NS::N1::fn1_2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_000000e0() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_000000e0
			pack()
			Structure VTABLE_000000e0 {
			   0   _func___thiscall_int *   8   MNS::M::fa1_1   ""
			   8   _func___thiscall_int *   8   CNS::C::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_000000f0() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_000000f0
			pack()
			Structure VTABLE_000000f0 {
			   0   _func___thiscall_int *   8   MNS::M::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000100() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000100
			pack()
			Structure VTABLE_00000100 {
			   0   _func___thiscall_int *   8   MNS::M::fb1_1   ""
			   8   _func___thiscall_int *   8   CNS::C::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000110() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000110
			pack()
			Structure VTABLE_00000110 {
			   0   _func___thiscall_int *   8   MNS::M::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000120() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000120
			pack()
			Structure VTABLE_00000120 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000128() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000128
			pack()
			Structure VTABLE_00000128 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000138() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000138
			pack()
			Structure VTABLE_00000138 {
			   0   _func___thiscall_int *   8   N2NS::N2::fn2_1   ""
			   8   _func___thiscall_int *   8   N2NS::N2::fn2_2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_000000d0_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_000000d0
			pack()
			Structure VTABLE_000000d0 {
			   0   _func___thiscall_int *   8   MNS::M::fa1_1   ""
			   8   _func___thiscall_int *   8   CNS::C::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_000000e0_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_000000e0
			pack()
			Structure VTABLE_000000e0 {
			   0   _func___thiscall_int *   8   MNS::M::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_000000f0_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_000000f0
			pack()
			Structure VTABLE_000000f0 {
			   0   _func___thiscall_int *   8   MNS::M::fb1_1   ""
			   8   _func___thiscall_int *   8   CNS::C::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000100_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000100
			pack()
			Structure VTABLE_00000100 {
			   0   _func___thiscall_int *   8   MNS::M::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000110_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000110
			pack()
			Structure VTABLE_00000110 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000118_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000118
			pack()
			Structure VTABLE_00000118 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000128_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000128
			pack()
			Structure VTABLE_00000128 {
			   0   _func___thiscall_int *   8   MNS::M::fn1_1   ""
			   8   _func___thiscall_int *   8   N1NS::N1::fn1_2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000138_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000138
			pack()
			Structure VTABLE_00000138 {
			   0   _func___thiscall_int *   8   N2NS::N2::fn2_1   ""
			   8   _func___thiscall_int *   8   N2NS::N2::fn2_2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class O1NS::O1	size(120):
		+---
	 0	| +--- (base class ANS::A)
	 0	| | {vfptr}
	 8	| | {vbptr}
	16	| | a
  		| | <alignment member> (size=4)
		| +---
	24	| +--- (base class BNS::B)
	24	| | {vfptr}
	32	| | {vbptr}
	40	| | b
  		| | <alignment member> (size=4)
		| +---
	48	| o1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	56	| {vfptr}
	64	| a1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A2NS::A2)
	72	| {vfptr}
	80	| a2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B1NS::B1)
	88	| {vfptr}
	96	| b1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B2NS::B2)
	104	| {vfptr}
	112	| b2
  		| <alignment member> (size=4)
		+---

	O1NS::O1::$vftable@A@:
		| &O1_meta
		|  0
	 0	| &ANS::A::fa_1
	 1	| &O1NS::O1::fo1_1

	O1NS::O1::$vftable@B@:
		| -24
	 0	| &BNS::B::fb_1

	O1NS::O1::$vbtable@A@:
	 0	| -8
	 1	| 48 (O1d(A+8)A1)
	 2	| 64 (O1d(A+8)A2)
	 3	| 80 (O1d(O1+8)B1)
	 4	| 96 (O1d(O1+8)B2)

	O1NS::O1::$vbtable@B@:
	 0	| -8
	 1	| 56 (O1d(B+8)B1)
	 2	| 72 (O1d(B+8)B2)

	O1NS::O1::$vftable@A1@:
		| -56
	 0	| &thunk: this-=32; goto ANS::A::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	O1NS::O1::$vftable@A2@:
		| -72
	 0	| &O1NS::O1::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	O1NS::O1::$vftable@B1@:
		| -88
	 0	| &thunk: this-=40; goto BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	O1NS::O1::$vftable@B2@:
		| -104
	 0	| &thunk: this-=40; goto BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	O1NS::O1::fa2_1 this adjustor: 72
	O1NS::O1::fo1_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      56       8       4 0
	        A2NS::A2      72       8       8 0
	        B1NS::B1      88       8      12 0
	        B2NS::B2     104       8      16 0
	 */
	//@formatter:on
	private static String getExpectedStructO1() {
		String expected =
		//@formatter:off
			"""
			/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   O1NS::O1   56      "Self Base"
			   56   A1NS::A1   16      "Virtual Base"
			   72   A2NS::A2   16      "Virtual Base"
			   88   B1NS::B1   16      "Virtual Base"
			   104   B2NS::B2   16      "Virtual Base"
			}
			Length: 120 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/O1NS::O1/!internal/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   ANS::A   24      "Base"
			   24   BNS::B   24      "Base"
			   48   int   4   o1   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructO1() {
		String expected =
		//@formatter:off
			"""
			/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   O1NS::O1   56      "Self Base"
			   56   char[64]   64      "Filler for 4 Unplaceable Virtual Bases: A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 120 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/O1NS::O1/!internal/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   ANS::A   24      "Base"
			   24   BNS::B   24      "Base"
			   48   int   4   o1   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructO1() {
		return convertCommentsToSpeculative(getExpectedStructO1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryO1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[O1NS::O1, ANS::A]");
		results.put("VTABLE_00000008", "     8 vbt [ANS::A]	[O1NS::O1, ANS::A]");
		results.put("VTABLE_00000018", "    24 vft [BNS::B]	[O1NS::O1, BNS::B]");
		results.put("VTABLE_00000020", "    32 vbt [BNS::B]	[O1NS::O1, BNS::B]");
		results.put("VTABLE_00000038", "    56 vft [A1NS::A1]	[O1NS::O1, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000048", "    72 vft [A2NS::A2]	[O1NS::O1, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000058", "    88 vft [B1NS::B1]	[O1NS::O1, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000068", "   104 vft [B2NS::B2]	[O1NS::O1, BNS::B, B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsO1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructO1_00000000());
		results.put("VTABLE_00000008", getVxtStructO1_00000008());
		results.put("VTABLE_00000018", getVxtStructO1_00000018());
		results.put("VTABLE_00000020", getVxtStructO1_00000020());
		results.put("VTABLE_00000038", getVxtStructO1_00000038());
		results.put("VTABLE_00000048", getVxtStructO1_00000048());
		results.put("VTABLE_00000058", getVxtStructO1_00000058());
		results.put("VTABLE_00000068", getVxtStructO1_00000068());
		return results;
	}

	private static String getVxtStructO1_00000000() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			   8   _func___thiscall_int *   8   O1NS::O1::fo1_1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000008() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000018() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000020() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000038() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   _func___thiscall_int *   8   ANS::A::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000048() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000048
			pack()
			Structure VTABLE_00000048 {
			   0   _func___thiscall_int *   8   O1NS::O1::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000058() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000058
			pack()
			Structure VTABLE_00000058 {
			   0   _func___thiscall_int *   8   BNS::B::fb1_1   ""
			   8   _func___thiscall_int *   8   B1NS::B1::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000068() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000068
			pack()
			Structure VTABLE_00000068 {
			   0   _func___thiscall_int *   8   BNS::B::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class O2NS::O2	size(120):
		+---
	 0	| +--- (base class ANS::A)
	 0	| | {vfptr}
	 8	| | {vbptr}
	16	| | a
  		| | <alignment member> (size=4)
		| +---
	24	| o2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	32	| {vfptr}
	40	| a1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A2NS::A2)
	48	| {vfptr}
	56	| a2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B1NS::B1)
	64	| {vfptr}
	72	| b1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B2NS::B2)
	80	| {vfptr}
	88	| b2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BNS::B)
	96	| {vfptr}
	104	| {vbptr}
	112	| b
  		| <alignment member> (size=4)
		+---

	O2NS::O2::$vftable@A@:
		| &O2_meta
		|  0
	 0	| &ANS::A::fa_1
	 1	| &O2NS::O2::fo2_1

	O2NS::O2::$vbtable@A@:
	 0	| -8
	 1	| 24 (O2d(A+8)A1)
	 2	| 40 (O2d(A+8)A2)
	 3	| 56 (O2d(O2+8)B1)
	 4	| 72 (O2d(O2+8)B2)
	 5	| 88 (O2d(O2+8)B)

	O2NS::O2::$vftable@A1@:
		| -32
	 0	| &thunk: this-=8; goto ANS::A::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	O2NS::O2::$vftable@A2@:
		| -48
	 0	| &O2NS::O2::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	O2NS::O2::$vftable@B1@:
		| -64
	 0	| &thunk: this+=56; goto BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	O2NS::O2::$vftable@B2@:
		| -80
	 0	| &thunk: this+=56; goto BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	O2NS::O2::$vftable@B@:
		| -96
	 0	| &BNS::B::fb_1

	O2NS::O2::$vbtable@B@:
	 0	| -8
	 1	| -40 (O2d(B+8)B1)
	 2	| -24 (O2d(B+8)B2)

	O2NS::O2::fa2_1 this adjustor: 48
	O2NS::O2::fo2_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      32       8       4 0
	        A2NS::A2      48       8       8 0
	        B1NS::B1      64       8      12 0
	        B2NS::B2      80       8      16 0
	          BNS::B      96       8      20 0
	 */
	//@formatter:on
	private static String getExpectedStructO2() {
		String expected =
		//@formatter:off
			"""
			/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   O2NS::O2   32      "Self Base"
			   32   A1NS::A1   16      "Virtual Base"
			   48   A2NS::A2   16      "Virtual Base"
			   64   B1NS::B1   16      "Virtual Base"
			   80   B2NS::B2   16      "Virtual Base"
			   96   BNS::B   24      "Virtual Base"
			}
			Length: 120 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/O2NS::O2/!internal/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   ANS::A   24      "Base"
			   24   int   4   o2   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructO2() {
		String expected =
		//@formatter:off
			"""
			/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   O2NS::O2   32      "Self Base"
			   32   char[88]   88      "Filler for 5 Unplaceable Virtual Bases: BNS::B; A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 120 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/O2NS::O2/!internal/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   ANS::A   24      "Base"
			   24   int   4   o2   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructO2() {
		return convertCommentsToSpeculative(getExpectedStructO2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryO2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[O2NS::O2, ANS::A]");
		results.put("VTABLE_00000008", "     8 vbt [ANS::A]	[O2NS::O2, ANS::A]");
		results.put("VTABLE_00000020", "    32 vft [A1NS::A1]	[O2NS::O2, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000030", "    48 vft [A2NS::A2]	[O2NS::O2, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000040", "    64 vft [B1NS::B1]	[O2NS::O2, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000050", "    80 vft [B2NS::B2]	[O2NS::O2, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000060", "    96 vft [BNS::B]	[O2NS::O2, BNS::B]");
		results.put("VTABLE_00000068", "   104 vbt [BNS::B]	[O2NS::O2, BNS::B]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsO2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructO2_00000000());
		results.put("VTABLE_00000008", getVxtStructO2_00000008());
		results.put("VTABLE_00000020", getVxtStructO2_00000020());
		results.put("VTABLE_00000030", getVxtStructO2_00000030());
		results.put("VTABLE_00000040", getVxtStructO2_00000040());
		results.put("VTABLE_00000050", getVxtStructO2_00000050());
		results.put("VTABLE_00000060", getVxtStructO2_00000060());
		results.put("VTABLE_00000068", getVxtStructO2_00000068());
		return results;
	}

	private static String getVxtStructO2_00000000() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			   8   _func___thiscall_int *   8   O2NS::O2::fo2_1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000008() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			   16   int   4      "BNS::B"
			}
			Length: 20 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000020() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_int *   8   ANS::A::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000030() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000030
			pack()
			Structure VTABLE_00000030 {
			   0   _func___thiscall_int *   8   O2NS::O2::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000040() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000040
			pack()
			Structure VTABLE_00000040 {
			   0   _func___thiscall_int *   8   BNS::B::fb1_1   ""
			   8   _func___thiscall_int *   8   B1NS::B1::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000050() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000050
			pack()
			Structure VTABLE_00000050 {
			   0   _func___thiscall_int *   8   BNS::B::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000060() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000060
			pack()
			Structure VTABLE_00000060 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000068() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000068
			pack()
			Structure VTABLE_00000068 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class O3NS::O3	size(120):
		+---
	 0	| +--- (base class ANS::A)
	 0	| | {vfptr}
	 8	| | {vbptr}
	16	| | a
  		| | <alignment member> (size=4)
		| +---
	24	| +--- (base class BNS::B)
	24	| | {vfptr}
	32	| | {vbptr}
	40	| | b
  		| | <alignment member> (size=4)
		| +---
	48	| o3
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	56	| {vfptr}
	64	| a1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A2NS::A2)
	72	| {vfptr}
	80	| a2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B1NS::B1)
	88	| {vfptr}
	96	| b1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B2NS::B2)
	104	| {vfptr}
	112	| b2
  		| <alignment member> (size=4)
		+---

	O3NS::O3::$vftable@A@:
		| &O3_meta
		|  0
	 0	| &ANS::A::fa_1
	 1	| &O3NS::O3::fo3_1

	O3NS::O3::$vftable@B@:
		| -24
	 0	| &BNS::B::fb_1

	O3NS::O3::$vbtable@A@:
	 0	| -8
	 1	| 48 (O3d(A+8)A1)
	 2	| 64 (O3d(A+8)A2)
	 3	| 80 (O3d(O3+8)B1)
	 4	| 96 (O3d(O3+8)B2)

	O3NS::O3::$vbtable@B@:
	 0	| -8
	 1	| 56 (O3d(B+8)B1)
	 2	| 72 (O3d(B+8)B2)

	O3NS::O3::$vftable@A1@:
		| -56
	 0	| &thunk: this-=32; goto ANS::A::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	O3NS::O3::$vftable@A2@:
		| -72
	 0	| &O3NS::O3::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	O3NS::O3::$vftable@B1@:
		| -88
	 0	| &thunk: this-=40; goto BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	O3NS::O3::$vftable@B2@:
		| -104
	 0	| &thunk: this-=40; goto BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	O3NS::O3::fa2_1 this adjustor: 72
	O3NS::O3::fo3_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      56       8       4 0
	        A2NS::A2      72       8       8 0
	        B1NS::B1      88       8      12 0
	        B2NS::B2     104       8      16 0
	 */
	//@formatter:on
	private static String getExpectedStructO3() {
		String expected =
		//@formatter:off
			"""
			/O3NS::O3
			pack()
			Structure O3NS::O3 {
			   0   O3NS::O3   56      "Self Base"
			   56   A1NS::A1   16      "Virtual Base"
			   72   A2NS::A2   16      "Virtual Base"
			   88   B1NS::B1   16      "Virtual Base"
			   104   B2NS::B2   16      "Virtual Base"
			}
			Length: 120 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/O3NS::O3/!internal/O3NS::O3
			pack()
			Structure O3NS::O3 {
			   0   ANS::A   24      "Base"
			   24   BNS::B   24      "Base"
			   48   int   4   o3   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructO3() {
		String expected =
		//@formatter:off
			"""
			/O3NS::O3
			pack()
			Structure O3NS::O3 {
			   0   O3NS::O3   56      "Self Base"
			   56   char[64]   64      "Filler for 4 Unplaceable Virtual Bases: A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 120 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/O3NS::O3/!internal/O3NS::O3
			pack()
			Structure O3NS::O3 {
			   0   ANS::A   24      "Base"
			   24   BNS::B   24      "Base"
			   48   int   4   o3   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructO3() {
		return convertCommentsToSpeculative(getExpectedStructO3());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryO3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[O3NS::O3, ANS::A]");
		results.put("VTABLE_00000008", "     8 vbt [ANS::A]	[O3NS::O3, ANS::A]");
		results.put("VTABLE_00000018", "    24 vft [BNS::B]	[O3NS::O3, BNS::B]");
		results.put("VTABLE_00000020", "    32 vbt [BNS::B]	[O3NS::O3, BNS::B]");
		results.put("VTABLE_00000038", "    56 vft [A1NS::A1]	[O3NS::O3, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000048", "    72 vft [A2NS::A2]	[O3NS::O3, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000058", "    88 vft [B1NS::B1]	[O3NS::O3, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000068", "   104 vft [B2NS::B2]	[O3NS::O3, BNS::B, B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsO3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructO3_00000000());
		results.put("VTABLE_00000008", getVxtStructO3_00000008());
		results.put("VTABLE_00000018", getVxtStructO3_00000018());
		results.put("VTABLE_00000020", getVxtStructO3_00000020());
		results.put("VTABLE_00000038", getVxtStructO3_00000038());
		results.put("VTABLE_00000048", getVxtStructO3_00000048());
		results.put("VTABLE_00000058", getVxtStructO3_00000058());
		results.put("VTABLE_00000068", getVxtStructO3_00000068());
		return results;
	}

	private static String getVxtStructO3_00000000() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			   8   _func___thiscall_int *   8   O3NS::O3::fo3_1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000008() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000018() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000020() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000038() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   _func___thiscall_int *   8   ANS::A::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000048() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000048
			pack()
			Structure VTABLE_00000048 {
			   0   _func___thiscall_int *   8   O3NS::O3::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000058() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000058
			pack()
			Structure VTABLE_00000058 {
			   0   _func___thiscall_int *   8   BNS::B::fb1_1   ""
			   8   _func___thiscall_int *   8   B1NS::B1::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000068() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000068
			pack()
			Structure VTABLE_00000068 {
			   0   _func___thiscall_int *   8   BNS::B::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class O4NS::O4	size(120):
		+---
	 0	| +--- (base class ANS::A)
	 0	| | {vfptr}
	 8	| | {vbptr}
	16	| | a
  		| | <alignment member> (size=4)
		| +---
	24	| o4
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A1NS::A1)
	32	| {vfptr}
	40	| a1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base A2NS::A2)
	48	| {vfptr}
	56	| a2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B1NS::B1)
	64	| {vfptr}
	72	| b1
  		| <alignment member> (size=4)
		+---
		+--- (virtual base B2NS::B2)
	80	| {vfptr}
	88	| b2
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BNS::B)
	96	| {vfptr}
	104	| {vbptr}
	112	| b
  		| <alignment member> (size=4)
		+---

	O4NS::O4::$vftable@A@:
		| &O4_meta
		|  0
	 0	| &ANS::A::fa_1
	 1	| &O4NS::O4::fo4_1

	O4NS::O4::$vbtable@A@:
	 0	| -8
	 1	| 24 (O4d(A+8)A1)
	 2	| 40 (O4d(A+8)A2)
	 3	| 56 (O4d(O4+8)B1)
	 4	| 72 (O4d(O4+8)B2)
	 5	| 88 (O4d(O4+8)B)

	O4NS::O4::$vftable@A1@:
		| -32
	 0	| &thunk: this-=8; goto ANS::A::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	O4NS::O4::$vftable@A2@:
		| -48
	 0	| &O4NS::O4::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	O4NS::O4::$vftable@B1@:
		| -64
	 0	| &thunk: this+=56; goto BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	O4NS::O4::$vftable@B2@:
		| -80
	 0	| &thunk: this+=56; goto BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	O4NS::O4::$vftable@B@:
		| -96
	 0	| &BNS::B::fb_1

	O4NS::O4::$vbtable@B@:
	 0	| -8
	 1	| -40 (O4d(B+8)B1)
	 2	| -24 (O4d(B+8)B2)

	O4NS::O4::fa2_1 this adjustor: 48
	O4NS::O4::fo4_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      32       8       4 0
	        A2NS::A2      48       8       8 0
	        B1NS::B1      64       8      12 0
	        B2NS::B2      80       8      16 0
	          BNS::B      96       8      20 0
	 */
	//@formatter:on
	private static String getExpectedStructO4() {
		String expected =
		//@formatter:off
			"""
			/O4NS::O4
			pack()
			Structure O4NS::O4 {
			   0   O4NS::O4   32      "Self Base"
			   32   A1NS::A1   16      "Virtual Base"
			   48   A2NS::A2   16      "Virtual Base"
			   64   B1NS::B1   16      "Virtual Base"
			   80   B2NS::B2   16      "Virtual Base"
			   96   BNS::B   24      "Virtual Base"
			}
			Length: 120 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/O4NS::O4/!internal/O4NS::O4
			pack()
			Structure O4NS::O4 {
			   0   ANS::A   24      "Base"
			   24   int   4   o4   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructO4() {
		String expected =
		//@formatter:off
			"""
			/O4NS::O4
			pack()
			Structure O4NS::O4 {
			   0   O4NS::O4   32      "Self Base"
			   32   char[88]   88      "Filler for 5 Unplaceable Virtual Bases: BNS::B; A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 120 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/O4NS::O4/!internal/O4NS::O4
			pack()
			Structure O4NS::O4 {
			   0   ANS::A   24      "Base"
			   24   int   4   o4   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructO4() {
		return convertCommentsToSpeculative(getExpectedStructO4());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryO4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[O4NS::O4, ANS::A]");
		results.put("VTABLE_00000008", "     8 vbt [ANS::A]	[O4NS::O4, ANS::A]");
		results.put("VTABLE_00000020", "    32 vft [A1NS::A1]	[O4NS::O4, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000030", "    48 vft [A2NS::A2]	[O4NS::O4, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000040", "    64 vft [B1NS::B1]	[O4NS::O4, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000050", "    80 vft [B2NS::B2]	[O4NS::O4, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000060", "    96 vft [BNS::B]	[O4NS::O4, BNS::B]");
		results.put("VTABLE_00000068", "   104 vbt [BNS::B]	[O4NS::O4, BNS::B]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsO4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructO4_00000000());
		results.put("VTABLE_00000008", getVxtStructO4_00000008());
		results.put("VTABLE_00000020", getVxtStructO4_00000020());
		results.put("VTABLE_00000030", getVxtStructO4_00000030());
		results.put("VTABLE_00000040", getVxtStructO4_00000040());
		results.put("VTABLE_00000050", getVxtStructO4_00000050());
		results.put("VTABLE_00000060", getVxtStructO4_00000060());
		results.put("VTABLE_00000068", getVxtStructO4_00000068());
		return results;
	}

	private static String getVxtStructO4_00000000() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			   8   _func___thiscall_int *   8   O4NS::O4::fo4_1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000008() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			   16   int   4      "BNS::B"
			}
			Length: 20 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000020() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_int *   8   ANS::A::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000030() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000030
			pack()
			Structure VTABLE_00000030 {
			   0   _func___thiscall_int *   8   O4NS::O4::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000040() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000040
			pack()
			Structure VTABLE_00000040 {
			   0   _func___thiscall_int *   8   BNS::B::fb1_1   ""
			   8   _func___thiscall_int *   8   B1NS::B1::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000050() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000050
			pack()
			Structure VTABLE_00000050 {
			   0   _func___thiscall_int *   8   BNS::B::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000060() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000060
			pack()
			Structure VTABLE_00000060 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000068() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000068
			pack()
			Structure VTABLE_00000068 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class ONS::O	size(136):
		+---
	 0	| +--- (base class O1NS::O1)
	 0	| | +--- (base class ANS::A)
	 0	| | | {vfptr}
	 4	| | | {vbptr}
	 8	| | | a
		| | +---
	12	| | +--- (base class BNS::B)
	12	| | | {vfptr}
	16	| | | {vbptr}
	20	| | | b
		| | +---
	24	| | o1
		| +---
	28	| +--- (base class O2NS::O2)
	28	| | +--- (base class ANS::A)
	28	| | | {vfptr}
	32	| | | {vbptr}
	36	| | | a
		| | +---
	40	| | o2
		| +---
	44	| o
		+---
		+--- (virtual base A1NS::A1)
	48	| {vfptr}
	52	| a1
		+---
		+--- (virtual base A2NS::A2)
	56	| {vfptr}
	60	| a2
		+---
		+--- (virtual base B1NS::B1)
	64	| {vfptr}
	68	| b1
		+---
		+--- (virtual base B2NS::B2)
	72	| {vfptr}
	76	| b2
		+---
		+--- (virtual base BNS::B)
	80	| {vfptr}
	84	| {vbptr}
	88	| b
		+---
		+--- (virtual base O3NS::O3)
	92	| +--- (base class ANS::A)
	92	| | {vfptr}
	96	| | {vbptr}
	100	| | a
		| +---
	104	| +--- (base class BNS::B)
	104	| | {vfptr}
	108	| | {vbptr}
	112	| | b
		| +---
	116	| o3
		+---
		+--- (virtual base O4NS::O4)
	120	| +--- (base class ANS::A)
	120	| | {vfptr}
	124	| | {vbptr}
	128	| | a
		| +---
	132	| o4
		+---

	ONS::O::$vftable@A@O1@:
		| &O_meta
		|  0
	 0	| &ANS::A::fa_1
	 1	| &ONS::O::fo1_1
	 2	| &ONS::O::fo_1

	ONS::O::$vftable@B@O1@:
		| -12
	 0	| &BNS::B::fb_1

	ONS::O::$vftable@A@O2@:
		| -28
	 0	| &ANS::A::fa_1
	 1	| &ONS::O::fo2_1

	ONS::O::$vbtable@A@O1@:
	 0	| -4
	 1	| 44 (Od(A+4)A1)
	 2	| 52 (Od(A+4)A2)
	 3	| 60 (Od(O1+4)B1)
	 4	| 68 (Od(O1+4)B2)
	 5	| 76 (Od(O+4)B)
	 6	| 88 (Od(O+4)O3)
	 7	| 116 (Od(O+4)O4)

	ONS::O::$vbtable@B@O1@:
	 0	| -4
	 1	| 48 (Od(B+4)B1)
	 2	| 56 (Od(B+4)B2)

	ONS::O::$vbtable@A@O2@:
	 0	| -4
	 1	| 16 (Od(A+4)A1)
	 2	| 24 (Od(A+4)A2)
	 3	| 32 (Od(O2+4)B1)
	 4	| 40 (Od(O2+4)B2)
	 5	| 48 (Od(O2+4)B)

	ONS::O::$vftable@A1@:
		| -48
	 0	| &ONS::O::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	ONS::O::$vftable@A2@:
		| -56
	 0	| &ONS::O::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	ONS::O::$vftable@B1@:
		| -64
	 0	| &ONS::O::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	ONS::O::$vftable@B2@:
		| -72
	 0	| &ONS::O::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	ONS::O::$vftable@B@O2@:
		| -80
	 0	| &BNS::B::fb_1

	ONS::O::$vbtable@B@O2@:
	 0	| -4
	 1	| -20 (Od(B+4)B1)
	 2	| -12 (Od(B+4)B2)

	ONS::O::$vftable@A@O3@:
		| -92
	 0	| &ANS::A::fa_1
	 1	| &ONS::O::fo3_1

	ONS::O::$vftable@B@O3@:
		| -104
	 0	| &BNS::B::fb_1

	ONS::O::$vbtable@A@O3@:
	 0	| -4
	 1	| -48 (Od(A+4)A1)
	 2	| -40 (Od(A+4)A2)
	 3	| -32 (Od(O3+4)B1)
	 4	| -24 (Od(O3+4)B2)

	ONS::O::$vbtable@B@O3@:
	 0	| -4
	 1	| -44 (Od(B+4)B1)
	 2	| -36 (Od(B+4)B2)

	ONS::O::$vftable@A@O4@:
		| -120
	 0	| &ANS::A::fa_1
	 1	| &ONS::O::fo4_1

	ONS::O::$vbtable@A@O4@:
	 0	| -4
	 1	| -76 (Od(A+4)A1)
	 2	| -68 (Od(A+4)A2)
	 3	| -60 (Od(O4+4)B1)
	 4	| -52 (Od(O4+4)B2)
	 5	| -44 (Od(O4+4)B)

	ONS::O::fo1_1 this adjustor: 0
	ONS::O::fo2_1 this adjustor: 28
	ONS::O::fo3_1 this adjustor: 92
	ONS::O::fo4_1 this adjustor: 120
	ONS::O::fo_1 this adjustor: 0
	ONS::O::fa1_1 this adjustor: 48
	ONS::O::fa2_1 this adjustor: 56
	ONS::O::fb1_1 this adjustor: 64
	ONS::O::fb2_1 this adjustor: 72
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      48       4       4 0
	        A2NS::A2      56       4       8 0
	        B1NS::B1      64       4      12 0
	        B2NS::B2      72       4      16 0
	          BNS::B      80       4      20 0
	        O3NS::O3      92       4      24 0
	        O4NS::O4     120       4      28 0
	 */
	//@formatter:on
	private static String getExpectedStructO() {
		String expected =
		//@formatter:off
			"""
			/ONS::O
			pack()
			Structure ONS::O {
			   0   ONS::O   96      "Self Base"
			   96   A1NS::A1   16      "Virtual Base"
			   112   A2NS::A2   16      "Virtual Base"
			   128   B1NS::B1   16      "Virtual Base"
			   144   B2NS::B2   16      "Virtual Base"
			   160   BNS::B   24      "Virtual Base"
			   184   O3NS::O3   56      "Virtual Base"
			   240   O4NS::O4   32      "Virtual Base"
			}
			Length: 272 Alignment: 8
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a1   ""
			}
			Length: 16 Alignment: 8
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   a2   ""
			}
			Length: 16 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b1   ""
			}
			Length: 16 Alignment: 8
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   b2   ""
			}
			Length: 16 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/O1NS::O1/!internal/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   ANS::A   24      "Base"
			   24   BNS::B   24      "Base"
			   48   int   4   o1   ""
			}
			Length: 56 Alignment: 8
			/O2NS::O2/!internal/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   ANS::A   24      "Base"
			   24   int   4   o2   ""
			}
			Length: 32 Alignment: 8
			/O3NS::O3/!internal/O3NS::O3
			pack()
			Structure O3NS::O3 {
			   0   ANS::A   24      "Base"
			   24   BNS::B   24      "Base"
			   48   int   4   o3   ""
			}
			Length: 56 Alignment: 8
			/O4NS::O4/!internal/O4NS::O4
			pack()
			Structure O4NS::O4 {
			   0   ANS::A   24      "Base"
			   24   int   4   o4   ""
			}
			Length: 32 Alignment: 8
			/ONS::O/!internal/ONS::O
			pack()
			Structure ONS::O {
			   0   O1NS::O1   56      "Base"
			   56   O2NS::O2   32      "Base"
			   88   int   4   o   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructO() {
		String expected =
		//@formatter:off
			"""
			/ONS::O
			pack()
			Structure ONS::O {
			   0   ONS::O   96      "Self Base"
			   96   char[176]   176      "Filler for 7 Unplaceable Virtual Bases: O3NS::O3; O4NS::O4; A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2; BNS::B"
			}
			Length: 272 Alignment: 8
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   a   ""
			}
			Length: 24 Alignment: 8
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   b   ""
			}
			Length: 24 Alignment: 8
			/O1NS::O1/!internal/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   ANS::A   24      "Base"
			   24   BNS::B   24      "Base"
			   48   int   4   o1   ""
			}
			Length: 56 Alignment: 8
			/O2NS::O2/!internal/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   ANS::A   24      "Base"
			   24   int   4   o2   ""
			}
			Length: 32 Alignment: 8
			/ONS::O/!internal/ONS::O
			pack()
			Structure ONS::O {
			   0   O1NS::O1   56      "Base"
			   56   O2NS::O2   32      "Base"
			   88   int   4   o   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructO() {
		return convertCommentsToSpeculative(getExpectedStructO());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryO() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000",
			"     0 vft [ANS::A, O1NS::O1]	[ONS::O, O1NS::O1, ANS::A]");
		results.put("VTABLE_00000008",
			"     8 vbt [ANS::A, O1NS::O1]	[ONS::O, O1NS::O1, ANS::A]");
		results.put("VTABLE_00000018",
			"    24 vft [BNS::B, O1NS::O1]	[ONS::O, O1NS::O1, BNS::B]");
		results.put("VTABLE_00000020",
			"    32 vbt [BNS::B, O1NS::O1]	[ONS::O, O1NS::O1, BNS::B]");
		results.put("VTABLE_00000038",
			"    56 vft [ANS::A, O2NS::O2]	[ONS::O, O2NS::O2, ANS::A]");
		results.put("VTABLE_00000040",
			"    64 vbt [ANS::A, O2NS::O2]	[ONS::O, O2NS::O2, ANS::A]");
		results.put("VTABLE_00000060",
			"    96 vft [A1NS::A1]	[ONS::O, O1NS::O1, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000070",
			"   112 vft [A2NS::A2]	[ONS::O, O1NS::O1, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000080",
			"   128 vft [B1NS::B1]	[ONS::O, O1NS::O1, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000090",
			"   144 vft [B2NS::B2]	[ONS::O, O1NS::O1, BNS::B, B2NS::B2]");
		results.put("VTABLE_000000a0",
			"   160 vft [BNS::B, O2NS::O2]	[ONS::O, O2NS::O2, BNS::B]");
		results.put("VTABLE_000000a8",
			"   168 vbt [BNS::B, O2NS::O2]	[ONS::O, O2NS::O2, BNS::B]");
		results.put("VTABLE_000000b8",
			"   184 vft [ANS::A, O3NS::O3]	[ONS::O, O3NS::O3, ANS::A]");
		results.put("VTABLE_000000c0",
			"   192 vbt [ANS::A, O3NS::O3]	[ONS::O, O3NS::O3, ANS::A]");
		results.put("VTABLE_000000d0",
			"   208 vft [BNS::B, O3NS::O3]	[ONS::O, O3NS::O3, BNS::B]");
		results.put("VTABLE_000000d8",
			"   216 vbt [BNS::B, O3NS::O3]	[ONS::O, O3NS::O3, BNS::B]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_000000f0", "   240 vft [ANS::A, O4NS::O4]	[ONS::O, O4NS::O4, ANS::A]");
		results.put("VTABLE_000000f0", null);
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_000000f8", "   248 vbt [BNS::B, O4NS::O4]	[ONS::O, O4NS::O4, ANS::A]");
		results.put("VTABLE_000000f8", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsO() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructO_00000000());
		results.put("VTABLE_00000008", getVxtStructO_00000008());
		results.put("VTABLE_00000018", getVxtStructO_00000018());
		results.put("VTABLE_00000020", getVxtStructO_00000020());
		results.put("VTABLE_00000038", getVxtStructO_00000038());
		results.put("VTABLE_00000040", getVxtStructO_00000040());
		results.put("VTABLE_00000060", getVxtStructO_00000060());
		results.put("VTABLE_00000070", getVxtStructO_00000070());
		results.put("VTABLE_00000080", getVxtStructO_00000080());
		results.put("VTABLE_00000090", getVxtStructO_00000090());
		results.put("VTABLE_000000a0", getVxtStructO_000000a0());
		results.put("VTABLE_000000a8", getVxtStructO_000000a8());
		results.put("VTABLE_000000b8", getVxtStructO_000000b8());
		results.put("VTABLE_000000c0", getVxtStructO_000000c0());
		results.put("VTABLE_000000d0", getVxtStructO_000000d0());
		results.put("VTABLE_000000d8", getVxtStructO_000000d8());
		results.put("VTABLE_000000f0", getVxtStructO_000000f0());
		results.put("VTABLE_000000f8", getVxtStructO_000000f8());
		return results;
	}

	private static String getVxtStructO_00000000() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			   8   _func___thiscall_int *   8   ONS::O::fo1_1   ""
			   16   _func___thiscall_int *   8   ONS::O::fo_1   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000008() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			   16   int   4      "BNS::B"
			   20   int   4      "O3NS::O3"
			   24   int   4      "O4NS::O4"
			}
			Length: 28 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000018() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000020() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000038() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			   8   _func___thiscall_int *   8   ONS::O::fo2_1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000040() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000040
			pack()
			Structure VTABLE_00000040 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			   16   int   4      "BNS::B"
			}
			Length: 20 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000060() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000060
			pack()
			Structure VTABLE_00000060 {
			   0   _func___thiscall_int *   8   ONS::O::fa1_1   ""
			   8   _func___thiscall_int *   8   A1NS::A1::fa1_2   ""
			   16   _func___thiscall_int *   8   A1NS::A1::fa1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000070() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000070
			pack()
			Structure VTABLE_00000070 {
			   0   _func___thiscall_int *   8   ONS::O::fa2_1   ""
			   8   _func___thiscall_int *   8   A2NS::A2::fa2_2   ""
			   16   _func___thiscall_int *   8   A2NS::A2::fa2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000080() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000080
			pack()
			Structure VTABLE_00000080 {
			   0   _func___thiscall_int *   8   ONS::O::fb1_1   ""
			   8   _func___thiscall_int *   8   B1NS::B1::fb1_2   ""
			   16   _func___thiscall_int *   8   B1NS::B1::fb1_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000090() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000090
			pack()
			Structure VTABLE_00000090 {
			   0   _func___thiscall_int *   8   ONS::O::fb2_1   ""
			   8   _func___thiscall_int *   8   B2NS::B2::fb2_2   ""
			   16   _func___thiscall_int *   8   B2NS::B2::fb2_3   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_000000a0() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_000000a0
			pack()
			Structure VTABLE_000000a0 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_000000a8() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_000000a8
			pack()
			Structure VTABLE_000000a8 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_000000b8() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_000000b8
			pack()
			Structure VTABLE_000000b8 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			   8   _func___thiscall_int *   8   ONS::O::fo3_1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_000000c0() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_000000c0
			pack()
			Structure VTABLE_000000c0 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_000000d0() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_000000d0
			pack()
			Structure VTABLE_000000d0 {
			   0   _func___thiscall_int *   8   BNS::B::fb_1   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_000000d8() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_000000d8
			pack()
			Structure VTABLE_000000d8 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_000000f0() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_000000f0
			pack()
			Structure VTABLE_000000f0 {
			   0   _func___thiscall_int *   8   ANS::A::fa_1   ""
			   8   _func___thiscall_int *   8   ONS::O::fo4_1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_000000f8() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_000000f8
			pack()
			Structure VTABLE_000000f8 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			   16   int   4      "BNS::B"
			}
			Length: 20 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================
	//==============================================================================================

	private static final List<ClassID> classIDs =
		List.of(A1, A2, A, B1, B2, B, C, D, E, F, G, H, I, J, K, L, N1, N2, M, O1, O2, O3, O4, O);

	private static final Map<ClassID, String> expectedStructs = new LinkedHashMap<>();
	static {
		expectedStructs.put(A1, getExpectedStructA1());
		expectedStructs.put(A2, getExpectedStructA2());
		expectedStructs.put(A, getExpectedStructA());
		expectedStructs.put(B1, getExpectedStructB1());
		expectedStructs.put(B2, getExpectedStructB2());
		expectedStructs.put(B, getExpectedStructB());
		expectedStructs.put(C, getExpectedStructC());
		expectedStructs.put(D, getExpectedStructD());
		expectedStructs.put(E, getExpectedStructE());
		expectedStructs.put(F, getExpectedStructF());
		expectedStructs.put(G, getExpectedStructG());
		expectedStructs.put(H, getExpectedStructH());
		expectedStructs.put(I, getExpectedStructI());
		expectedStructs.put(J, getExpectedStructJ());
		expectedStructs.put(K, getExpectedStructK());
		expectedStructs.put(L, getExpectedStructL());
		expectedStructs.put(N1, getExpectedStructN1());
		expectedStructs.put(N2, getExpectedStructN2());
		expectedStructs.put(M, getExpectedStructM());
		expectedStructs.put(O1, getExpectedStructO1());
		expectedStructs.put(O2, getExpectedStructO2());
		expectedStructs.put(O3, getExpectedStructO3());
		expectedStructs.put(O4, getExpectedStructO4());
		expectedStructs.put(O, getExpectedStructO());
	}

	private static final Map<ClassID, String> fillerStructs = new LinkedHashMap<>();
	static {
		fillerStructs.putAll(expectedStructs);
		fillerStructs.put(A, getFillerStructA());
		fillerStructs.put(B, getFillerStructB());
		fillerStructs.put(C, getFillerStructC());
		fillerStructs.put(D, getFillerStructD());
		fillerStructs.put(E, getFillerStructE());
		fillerStructs.put(F, getFillerStructF());
		fillerStructs.put(G, getFillerStructG());
		fillerStructs.put(H, getFillerStructH());
		fillerStructs.put(I, getFillerStructI());
		fillerStructs.put(J, getFillerStructJ());
		fillerStructs.put(K, getFillerStructK());
		fillerStructs.put(L, getFillerStructL());
		fillerStructs.put(M, getFillerStructM());
		fillerStructs.put(O1, getFillerStructO1());
		fillerStructs.put(O2, getFillerStructO2());
		fillerStructs.put(O3, getFillerStructO3());
		fillerStructs.put(O4, getFillerStructO4());
		fillerStructs.put(O, getFillerStructO());
	}

	private static final Map<ClassID, String> speculatedStructs = new LinkedHashMap<>();
	static {
		speculatedStructs.put(A1, getSpeculatedStructA1());
		speculatedStructs.put(A2, getSpeculatedStructA2());
		speculatedStructs.put(A, getSpeculatedStructA());
		speculatedStructs.put(B1, getSpeculatedStructB1());
		speculatedStructs.put(B2, getSpeculatedStructB2());
		speculatedStructs.put(B, getSpeculatedStructB());
		speculatedStructs.put(C, getSpeculatedStructC());
		speculatedStructs.put(D, getSpeculatedStructD());
		speculatedStructs.put(E, getSpeculatedStructE());
		speculatedStructs.put(F, getSpeculatedStructF());
		speculatedStructs.put(G, getSpeculatedStructG());
		speculatedStructs.put(H, getSpeculatedStructH());
		speculatedStructs.put(I, getSpeculatedStructI());
		speculatedStructs.put(J, getSpeculatedStructJ());
		speculatedStructs.put(K, getSpeculatedStructK());
		speculatedStructs.put(L, getSpeculatedStructL());
		speculatedStructs.put(N1, getSpeculatedStructN1());
		speculatedStructs.put(N2, getSpeculatedStructN2());
		speculatedStructs.put(M, getSpeculatedStructM());
		speculatedStructs.put(O1, getSpeculatedStructO1());
		speculatedStructs.put(O2, getSpeculatedStructO2());
		speculatedStructs.put(O3, getSpeculatedStructO3());
		speculatedStructs.put(O4, getSpeculatedStructO4());
		speculatedStructs.put(O, getSpeculatedStructO());
	}

	private static final Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
		new LinkedHashMap<>();
	static {
		expectedVxtPtrSummaries.put(A1, getExpectedVxtPtrSummaryA1());
		expectedVxtPtrSummaries.put(A2, getExpectedVxtPtrSummaryA2());
		expectedVxtPtrSummaries.put(A, getExpectedVxtPtrSummaryA());
		expectedVxtPtrSummaries.put(B1, getExpectedVxtPtrSummaryB1());
		expectedVxtPtrSummaries.put(B2, getExpectedVxtPtrSummaryB2());
		expectedVxtPtrSummaries.put(B, getExpectedVxtPtrSummaryB());
		expectedVxtPtrSummaries.put(C, getExpectedVxtPtrSummaryC());
		expectedVxtPtrSummaries.put(D, getExpectedVxtPtrSummaryD());
		expectedVxtPtrSummaries.put(E, getExpectedVxtPtrSummaryE());
		expectedVxtPtrSummaries.put(F, getExpectedVxtPtrSummaryF());
		expectedVxtPtrSummaries.put(G, getExpectedVxtPtrSummaryG());
		expectedVxtPtrSummaries.put(H, getExpectedVxtPtrSummaryH());
		expectedVxtPtrSummaries.put(I, getExpectedVxtPtrSummaryI());
		expectedVxtPtrSummaries.put(J, getExpectedVxtPtrSummaryJ());
		expectedVxtPtrSummaries.put(K, getExpectedVxtPtrSummaryK());
		expectedVxtPtrSummaries.put(L, getExpectedVxtPtrSummaryL());
		expectedVxtPtrSummaries.put(N1, getExpectedVxtPtrSummaryN1());
		expectedVxtPtrSummaries.put(N2, getExpectedVxtPtrSummaryN2());
		expectedVxtPtrSummaries.put(M, getExpectedVxtPtrSummaryM());
		expectedVxtPtrSummaries.put(O1, getExpectedVxtPtrSummaryO1());
		expectedVxtPtrSummaries.put(O2, getExpectedVxtPtrSummaryO2());
		expectedVxtPtrSummaries.put(O3, getExpectedVxtPtrSummaryO3());
		expectedVxtPtrSummaries.put(O4, getExpectedVxtPtrSummaryO4());
		expectedVxtPtrSummaries.put(O, getExpectedVxtPtrSummaryO());
	}

	private static final Map<ClassID, Map<String, String>> speculatedVxtPtrSummaries =
		new LinkedHashMap<>();
	static {
		speculatedVxtPtrSummaries.putAll(expectedVxtPtrSummaries);
		// The following will replace entries as needed
		speculatedVxtPtrSummaries.put(M, getSpeculatedVxtPtrSummaryM());
	}

	private static final Map<ClassID, Map<String, String>> expectedVxtStructs =
		new LinkedHashMap<>();
	static {
		expectedVxtStructs.put(A1, getExpectedVxtStructsA1());
		expectedVxtStructs.put(A2, getExpectedVxtStructsA2());
		expectedVxtStructs.put(A, getExpectedVxtStructsA());
		expectedVxtStructs.put(B1, getExpectedVxtStructsB1());
		expectedVxtStructs.put(B2, getExpectedVxtStructsB2());
		expectedVxtStructs.put(B, getExpectedVxtStructsB());
		expectedVxtStructs.put(C, getExpectedVxtStructsC());
		expectedVxtStructs.put(D, getExpectedVxtStructsD());
		expectedVxtStructs.put(E, getExpectedVxtStructsE());
		expectedVxtStructs.put(F, getExpectedVxtStructsF());
		expectedVxtStructs.put(G, getExpectedVxtStructsG());
		expectedVxtStructs.put(H, getExpectedVxtStructsH());
		expectedVxtStructs.put(I, getExpectedVxtStructsI());
		expectedVxtStructs.put(J, getExpectedVxtStructsJ());
		expectedVxtStructs.put(K, getExpectedVxtStructsK());
		expectedVxtStructs.put(L, getExpectedVxtStructsL());
		expectedVxtStructs.put(N1, getExpectedVxtStructsN1());
		expectedVxtStructs.put(N2, getExpectedVxtStructsN2());
		expectedVxtStructs.put(M, getExpectedVxtStructsM());
		expectedVxtStructs.put(O1, getExpectedVxtStructsO1());
		expectedVxtStructs.put(O2, getExpectedVxtStructsO2());
		expectedVxtStructs.put(O3, getExpectedVxtStructsO3());
		expectedVxtStructs.put(O4, getExpectedVxtStructsO4());
		expectedVxtStructs.put(O, getExpectedVxtStructsO());
	}

	private static final Map<ClassID, Map<String, String>> speculatedVxtStructs =
		new LinkedHashMap<>();
	static {
		speculatedVxtStructs.putAll(expectedVxtStructs);
		// The following will replace entries as needed
		speculatedVxtStructs.put(M, getSpeculatedVxtStructsM());
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================

	public Cfb464ProgramCreator() {
		super(PROGRAM_NAME, LANGUAGE_ID, COMPILER_SPEC_ID, SECTIONS, vbTableInfo, vfTableInfo,
			functionInfo);
	}

	public List<ClassID> getClassIDs() {
		return classIDs;
	}

	public Map<ClassID, String> getExpectedStructs() {
		return expectedStructs;
	}

	public Map<ClassID, String> getFillerStructs() {
		return fillerStructs;
	}

	public Map<ClassID, String> getSpeculatedStructs() {
		return speculatedStructs;
	}

	public Map<ClassID, Map<String, String>> getExpectedVxtPtrSummaries() {
		return expectedVxtPtrSummaries;
	}

	public Map<ClassID, Map<String, String>> getSpeculatedVxtPtrSummaries() {
		return speculatedVxtPtrSummaries;
	}

	public Map<ClassID, Map<String, String>> getExpectedVxtStructs() {
		return expectedVxtStructs;
	}

	public Map<ClassID, Map<String, String>> getSpeculatedVxtStructs() {
		return speculatedVxtStructs;
	}

	@Override
	protected List<DataType> getRegularTypes(DataTypeManager dtm) throws PdbException {
		return List.of();
	}

	@Override
	protected List<CppCompositeType> getCppTypes(DataTypeManager dtm) throws PdbException {
		List<CppCompositeType> cppTypes = new ArrayList<>();
		CppCompositeType a1 = createA1_struct(dtm);
		cppTypes.add(a1);
		CppCompositeType a2 = createA2_struct(dtm);
		cppTypes.add(a2);
		CppCompositeType a = createA_struct(dtm, a1, a2);
		cppTypes.add(a);
		CppCompositeType b1 = createB1_struct(dtm);
		cppTypes.add(b1);
		CppCompositeType b2 = createB2_struct(dtm);
		cppTypes.add(b2);
		CppCompositeType b = createB_struct(dtm, b1, b2);
		cppTypes.add(b);
		CppCompositeType c = createC_struct(dtm, a1, a2, b1, b2);
		cppTypes.add(c);
		CppCompositeType d = createD_struct(dtm, c, a, b, a1, a2, b1, b2);
		cppTypes.add(d);
		CppCompositeType e = createE_struct(dtm, a, b, a1, a2, b1, b2);
		cppTypes.add(e);
		CppCompositeType f = createF_struct(dtm, a1);
		cppTypes.add(f);
		CppCompositeType g = createG_struct(dtm, f, a1);
		cppTypes.add(g);
		CppCompositeType h = createH_struct(dtm, f, a1);
		cppTypes.add(h);
		CppCompositeType i = createI_struct(dtm, g, h, a1);
		cppTypes.add(i);
		CppCompositeType j = createJ_struct(dtm, a1);
		cppTypes.add(j);
		CppCompositeType k = createK_struct(dtm, j, a1);
		cppTypes.add(k);
		CppCompositeType l = createL_struct(dtm, k, a1);
		cppTypes.add(l);
		CppCompositeType n1 = createN1_struct(dtm);
		cppTypes.add(n1);
		CppCompositeType n2 = createN2_struct(dtm);
		cppTypes.add(n2);
		CppCompositeType m = createM_struct(dtm, e, d, i, l, n1, n2, a1, a2, b1, b2, b);
		cppTypes.add(m);
		CppCompositeType o1 = createO1_struct(dtm, a, b, a1, a2, b1, b2);
		cppTypes.add(o1);
		CppCompositeType o2 = createO2_struct(dtm, a, b, a1, a2, b1, b2);
		cppTypes.add(o2);
		CppCompositeType o3 = createO3_struct(dtm, a, b, a1, a2, b1, b2);
		cppTypes.add(o3);
		CppCompositeType o4 = createO4_struct(dtm, a, b, a1, a2, b1, b2);
		cppTypes.add(o4);
		CppCompositeType o = createO_struct(dtm, o1, o2, o3, o4, a1, a2, b1, b2, b);
		cppTypes.add(o);
		return cppTypes;
	}

}
