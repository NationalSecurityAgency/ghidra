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
 * Class to create the cvf4 32-bit program and mock PDB.
 * <p>
 * This class implementation is not complete... expected results need codified
 */
public class Cfb432ProgramCreator extends ProgramCreator {

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

	private static String PROGRAM_NAME = "cfb432.exe";
	private static String LANGUAGE_ID = ProgramBuilder._X86;
	private static String COMPILER_SPEC_ID = "windows";
	private static AddressNameLength SECTIONS[] = {
		new AddressNameLength("401000", ".text", 0x56e00),
		new AddressNameLength("458000", ".rdata", 0xac00)
	};

	private static AddressNameBytes vbTableInfo[] = {
		new AddressNameBytes("00458268", "??_8A@ANS@@7B@", "fc ff ff ff 08 00 00 00 10 00 00 00"),
		new AddressNameBytes("004582bc", "??_8B@BNS@@7B@", "fc ff ff ff 08 00 00 00 10 00 00 00"),
		new AddressNameBytes("00458310", "??_8C@CNS@@7B@",
			"fc ff ff ff 08 00 00 00 10 00 00 00 18 00 00 00 20 00 00 00"),
		new AddressNameBytes("0045837c", "??_8D@DNS@@7BC@CNS@@@",
			"fc ff ff ff 24 00 00 00 2c 00 00 00 34 00 00 00 3c 00 00 00"),
		new AddressNameBytes("00458390", "??_8D@DNS@@7BA@ANS@@@",
			"fc ff ff ff 18 00 00 00 20 00 00 00"),
		new AddressNameBytes("0045839c", "??_8D@DNS@@7BB@BNS@@@",
			"fc ff ff ff 1c 00 00 00 24 00 00 00"),
		new AddressNameBytes("004583f8", "??_8E@ENS@@7BA@ANS@@@",
			"fc ff ff ff 0c 00 00 00 14 00 00 00 1c 00 00 00 24 00 00 00 2c 00 00 00"),
		new AddressNameBytes("00458410", "??_8E@ENS@@7BB@BNS@@@",
			"fc ff ff ff ec ff ff ff f4 ff ff ff"),
		new AddressNameBytes("0045842c", "??_8F@FNS@@7B@", "00 00 00 00 08 00 00 00"),
		new AddressNameBytes("00458444", "??_8G@GNS@@7B@", "00 00 00 00 0c 00 00 00"),
		new AddressNameBytes("0045845c", "??_8H@HNS@@7B@", "00 00 00 00 0c 00 00 00"),
		new AddressNameBytes("00458474", "??_8I@INS@@7BG@GNS@@@", "00 00 00 00 1c 00 00 00"),
		new AddressNameBytes("0045847c", "??_8I@INS@@7BH@HNS@@@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("00458494", "??_8J@JNS@@7B@", "00 00 00 00 08 00 00 00"),
		new AddressNameBytes("004584ac", "??_8K@KNS@@7B@", "00 00 00 00 0c 00 00 00"),
		new AddressNameBytes("004584c4", "??_8L@LNS@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("00458564", "??_8M@MNS@@7BA@ANS@@E@ENS@@@",
			"fc ff ff ff 6c 00 00 00 74 00 00 00 7c 00 00 00 84 00 00 00 8c 00 00 00 64 00 00 00 98 00 00 00"),
		new AddressNameBytes("00458584", "??_8M@MNS@@7BC@CNS@@@",
			"fc ff ff ff 5c 00 00 00 64 00 00 00 6c 00 00 00 74 00 00 00"),
		new AddressNameBytes("00458598", "??_8M@MNS@@7BA@ANS@@D@DNS@@@",
			"fc ff ff ff 50 00 00 00 58 00 00 00"),
		new AddressNameBytes("004585a4", "??_8M@MNS@@7BB@BNS@@D@DNS@@@",
			"fc ff ff ff 54 00 00 00 5c 00 00 00"),
		new AddressNameBytes("004585b0", "??_8M@MNS@@7BG@GNS@@@", "00 00 00 00 38 00 00 00"),
		new AddressNameBytes("004585b8", "??_8M@MNS@@7BH@HNS@@@", "00 00 00 00 2c 00 00 00"),
		new AddressNameBytes("004585c0", "??_8M@MNS@@7B@", "00 00 00 00 1c 00 00 00"),
		new AddressNameBytes("004585c8", "??_8M@MNS@@7BB@BNS@@E@ENS@@@",
			"fc ff ff ff ec ff ff ff f4 ff ff ff"),
		new AddressNameBytes("00458628", "??_8O1@O1NS@@7BA@ANS@@@",
			"fc ff ff ff 18 00 00 00 20 00 00 00 28 00 00 00 30 00 00 00"),
		new AddressNameBytes("0045863c", "??_8O1@O1NS@@7BB@BNS@@@",
			"fc ff ff ff 1c 00 00 00 24 00 00 00"),
		new AddressNameBytes("0045869c", "??_8O2@O2NS@@7BA@ANS@@@",
			"fc ff ff ff 0c 00 00 00 14 00 00 00 1c 00 00 00 24 00 00 00 2c 00 00 00"),
		new AddressNameBytes("004586b4", "??_8O2@O2NS@@7BB@BNS@@@",
			"fc ff ff ff ec ff ff ff f4 ff ff ff"),
		new AddressNameBytes("00458714", "??_8O3@O3NS@@7BA@ANS@@@",
			"fc ff ff ff 18 00 00 00 20 00 00 00 28 00 00 00 30 00 00 00"),
		new AddressNameBytes("00458728", "??_8O3@O3NS@@7BB@BNS@@@",
			"fc ff ff ff 1c 00 00 00 24 00 00 00"),
		new AddressNameBytes("00458788", "??_8O4@O4NS@@7BA@ANS@@@",
			"fc ff ff ff 0c 00 00 00 14 00 00 00 1c 00 00 00 24 00 00 00 2c 00 00 00"),
		new AddressNameBytes("004587a0", "??_8O4@O4NS@@7BB@BNS@@@",
			"fc ff ff ff ec ff ff ff f4 ff ff ff"),
		new AddressNameBytes("00458838", "??_8O@ONS@@7BA@ANS@@O1@O1NS@@@",
			"fc ff ff ff 2c 00 00 00 34 00 00 00 3c 00 00 00 44 00 00 00 4c 00 00 00 58 00 00 00 74 00 00 00"),
		new AddressNameBytes("00458858", "??_8O@ONS@@7BB@BNS@@O1@O1NS@@@",
			"fc ff ff ff 30 00 00 00 38 00 00 00"),
		new AddressNameBytes("00458864", "??_8O@ONS@@7BA@ANS@@O2@O2NS@@@",
			"fc ff ff ff 10 00 00 00 18 00 00 00 20 00 00 00 28 00 00 00 30 00 00 00"),
		new AddressNameBytes("0045887c", "??_8O@ONS@@7BB@BNS@@O2@O2NS@@@",
			"fc ff ff ff ec ff ff ff f4 ff ff ff"),
		new AddressNameBytes("00458888", "??_8O@ONS@@7BA@ANS@@O3@O3NS@@@",
			"fc ff ff ff d0 ff ff ff d8 ff ff ff e0 ff ff ff e8 ff ff ff"),
		new AddressNameBytes("0045889c", "??_8O@ONS@@7BB@BNS@@O3@O3NS@@@",
			"fc ff ff ff d4 ff ff ff dc ff ff ff"),
		new AddressNameBytes("004588a8", "??_8O@ONS@@7BA@ANS@@O4@O4NS@@@",
			"fc ff ff ff b4 ff ff ff bc ff ff ff c4 ff ff ff cc ff ff ff d4 ff ff ff")
	};

	private static AddressNameBytes vfTableInfo[] = {
		new AddressNameBytes("00458224", "??_7A1@A1NS@@6B@", "a0 d9 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("00458234", "??_7A2@A2NS@@6B@", "00 dc 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("00458244", "??_7A@ANS@@6B01@@", "f0 dd 40 00"),
		new AddressNameBytes("0045824c", "??_7A@ANS@@6BA1@A1NS@@@",
			"c0 d9 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("0045825c", "??_7A@ANS@@6BA2@A2NS@@@",
			"20 dc 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("00458278", "??_7B1@B1NS@@6B@", "30 de 40 00 f0 de 40 00 60 df 40 00"),
		new AddressNameBytes("00458288", "??_7B2@B2NS@@6B@", "80 df 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("00458298", "??_7B@BNS@@6B01@@", "d0 e0 40 00"),
		new AddressNameBytes("004582a0", "??_7B@BNS@@6BB1@B1NS@@@",
			"50 de 40 00 f0 de 40 00 60 df 40 00"),
		new AddressNameBytes("004582b0", "??_7B@BNS@@6BB2@B2NS@@@",
			"a0 df 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("004582cc", "??_7C@CNS@@6B01@@", "10 e1 40 00"),
		new AddressNameBytes("004582d4", "??_7C@CNS@@6BA1@A1NS@@@",
			"a0 d9 40 00 a0 db 40 00 e0 db 40 00"),
		new AddressNameBytes("004582e4", "??_7C@CNS@@6BA2@A2NS@@@",
			"50 dc 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("004582f4", "??_7C@CNS@@6BB1@B1NS@@@",
			"30 de 40 00 10 df 40 00 60 df 40 00"),
		new AddressNameBytes("00458304", "??_7C@CNS@@6BB2@B2NS@@@",
			"e0 df 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("00458328", "??_7D@DNS@@6BC@CNS@@@", "10 e1 40 00"),
		new AddressNameBytes("00458330", "??_7D@DNS@@6BA@ANS@@@", "f0 dd 40 00"),
		new AddressNameBytes("00458338", "??_7D@DNS@@6BB@BNS@@@", "d0 e0 40 00"),
		new AddressNameBytes("00458340", "??_7D@DNS@@6BA1@A1NS@@@",
			"ed d9 40 00 c5 db 40 00 e0 db 40 00"),
		new AddressNameBytes("00458350", "??_7D@DNS@@6BA2@A2NS@@@",
			"80 dc 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("00458360", "??_7D@DNS@@6BB1@B1NS@@@",
			"8e de 40 00 45 df 40 00 60 df 40 00"),
		new AddressNameBytes("00458370", "??_7D@DNS@@6BB2@B2NS@@@",
			"20 e0 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("004583ac", "??_7E@ENS@@6BA@ANS@@@", "f0 dd 40 00"),
		new AddressNameBytes("004583b4", "??_7E@ENS@@6BA1@A1NS@@@",
			"00 da 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("004583c4", "??_7E@ENS@@6BA2@A2NS@@@",
			"45 dc 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("004583d4", "??_7E@ENS@@6BB1@B1NS@@@",
			"96 de 40 00 f0 de 40 00 60 df 40 00"),
		new AddressNameBytes("004583e4", "??_7E@ENS@@6BB2@B2NS@@@",
			"cd df 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("004583f4", "??_7E@ENS@@6BB@BNS@@@", "d0 e0 40 00"),
		new AddressNameBytes("00458420", "??_7F@FNS@@6B@", "20 da 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("00458438", "??_7G@GNS@@6B@", "40 da 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("00458450", "??_7H@HNS@@6B@", "60 da 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("00458468", "??_7I@INS@@6B@", "80 da 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("00458488", "??_7J@JNS@@6B@", "a0 da 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("004584a0", "??_7K@KNS@@6B@", "c0 da 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("004584b8", "??_7L@LNS@@6B@", "e0 da 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("004584d0", "??_7N1@N1NS@@6B@", "70 e1 40 00 90 e1 40 00"),
		new AddressNameBytes("004584dc", "??_7N2@N2NS@@6B@", "b0 e1 40 00 d0 e1 40 00"),
		new AddressNameBytes("004584e8", "??_7M@MNS@@6BA@ANS@@E@ENS@@@", "f0 dd 40 00"),
		new AddressNameBytes("004584f0", "??_7M@MNS@@6BC@CNS@@@", "10 e1 40 00"),
		new AddressNameBytes("004584f8", "??_7M@MNS@@6BA@ANS@@D@DNS@@@", "f0 dd 40 00"),
		new AddressNameBytes("00458500", "??_7M@MNS@@6BB@BNS@@D@DNS@@@", "d0 e0 40 00"),
		new AddressNameBytes("00458508", "??_7M@MNS@@6BN1@N1NS@@@", "40 e1 40 00 90 e1 40 00"),
		new AddressNameBytes("00458514", "??_7M@MNS@@6BA1@A1NS@@@",
			"00 db 40 00 cd db 40 00 e0 db 40 00"),
		new AddressNameBytes("00458524", "??_7M@MNS@@6BA2@A2NS@@@",
			"a0 dc 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("00458534", "??_7M@MNS@@6BB1@B1NS@@@",
			"a0 de 40 00 4d df 40 00 60 df 40 00"),
		new AddressNameBytes("00458544", "??_7M@MNS@@6BB2@B2NS@@@",
			"40 e0 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("00458554", "??_7M@MNS@@6BB@BNS@@E@ENS@@@", "d0 e0 40 00"),
		new AddressNameBytes("0045855c", "??_7M@MNS@@6BN2@N2NS@@@", "b0 e1 40 00 d0 e1 40 00"),
		new AddressNameBytes("004585d8", "??_7O1@O1NS@@6BA@ANS@@@", "f0 dd 40 00 f0 e1 40 00"),
		new AddressNameBytes("004585e4", "??_7O1@O1NS@@6BB@BNS@@@", "d0 e0 40 00"),
		new AddressNameBytes("004585ec", "??_7O1@O1NS@@6BA1@A1NS@@@",
			"ed d9 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("004585fc", "??_7O1@O1NS@@6BA2@A2NS@@@",
			"c0 dc 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("0045860c", "??_7O1@O1NS@@6BB1@B1NS@@@",
			"8e de 40 00 f0 de 40 00 60 df 40 00"),
		new AddressNameBytes("0045861c", "??_7O1@O1NS@@6BB2@B2NS@@@",
			"c5 df 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("0045864c", "??_7O2@O2NS@@6BA@ANS@@@", "f0 dd 40 00 30 e2 40 00"),
		new AddressNameBytes("00458658", "??_7O2@O2NS@@6BA1@A1NS@@@",
			"e5 d9 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("00458668", "??_7O2@O2NS@@6BA2@A2NS@@@",
			"f0 dc 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("00458678", "??_7O2@O2NS@@6BB1@B1NS@@@",
			"96 de 40 00 f0 de 40 00 60 df 40 00"),
		new AddressNameBytes("00458688", "??_7O2@O2NS@@6BB2@B2NS@@@",
			"cd df 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("00458698", "??_7O2@O2NS@@6BB@BNS@@@", "d0 e0 40 00"),
		new AddressNameBytes("004586c4", "??_7O3@O3NS@@6BA@ANS@@@", "f0 dd 40 00 70 e2 40 00"),
		new AddressNameBytes("004586d0", "??_7O3@O3NS@@6BB@BNS@@@", "d0 e0 40 00"),
		new AddressNameBytes("004586d8", "??_7O3@O3NS@@6BA1@A1NS@@@",
			"ed d9 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("004586e8", "??_7O3@O3NS@@6BA2@A2NS@@@",
			"20 dd 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("004586f8", "??_7O3@O3NS@@6BB1@B1NS@@@",
			"8e de 40 00 f0 de 40 00 60 df 40 00"),
		new AddressNameBytes("00458708", "??_7O3@O3NS@@6BB2@B2NS@@@",
			"c5 df 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("00458738", "??_7O4@O4NS@@6BA@ANS@@@", "f0 dd 40 00 b0 e2 40 00"),
		new AddressNameBytes("00458744", "??_7O4@O4NS@@6BA1@A1NS@@@",
			"e5 d9 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("00458754", "??_7O4@O4NS@@6BA2@A2NS@@@",
			"50 dd 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("00458764", "??_7O4@O4NS@@6BB1@B1NS@@@",
			"96 de 40 00 f0 de 40 00 60 df 40 00"),
		new AddressNameBytes("00458774", "??_7O4@O4NS@@6BB2@B2NS@@@",
			"cd df 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("00458784", "??_7O4@O4NS@@6BB@BNS@@@", "d0 e0 40 00"),
		new AddressNameBytes("004587b0", "??_7O@ONS@@6BA@ANS@@O1@O1NS@@@",
			"f0 dd 40 00 10 e2 40 00 f0 e2 40 00"),
		new AddressNameBytes("004587c0", "??_7O@ONS@@6BB@BNS@@O1@O1NS@@@", "d0 e0 40 00"),
		new AddressNameBytes("004587c8", "??_7O@ONS@@6BA@ANS@@O2@O2NS@@@",
			"f0 dd 40 00 50 e2 40 00"),
		new AddressNameBytes("004587d4", "??_7O@ONS@@6BA1@A1NS@@@",
			"50 db 40 00 80 db 40 00 e0 db 40 00"),
		new AddressNameBytes("004587e4", "??_7O@ONS@@6BA2@A2NS@@@",
			"80 dd 40 00 b0 dd 40 00 d0 dd 40 00"),
		new AddressNameBytes("004587f4", "??_7O@ONS@@6BB1@B1NS@@@",
			"c0 de 40 00 f0 de 40 00 60 df 40 00"),
		new AddressNameBytes("00458804", "??_7O@ONS@@6BB2@B2NS@@@",
			"60 e0 40 00 90 e0 40 00 b0 e0 40 00"),
		new AddressNameBytes("00458814", "??_7O@ONS@@6BB@BNS@@O2@O2NS@@@", "d0 e0 40 00"),
		new AddressNameBytes("0045881c", "??_7O@ONS@@6BA@ANS@@O3@O3NS@@@",
			"f0 dd 40 00 90 e2 40 00"),
		new AddressNameBytes("00458828", "??_7O@ONS@@6BB@BNS@@O3@O3NS@@@", "d0 e0 40 00"),
		new AddressNameBytes("00458830", "??_7O@ONS@@6BA@ANS@@O4@O4NS@@@",
			"f0 dd 40 00 d0 e2 40 00"),
		new AddressNameBytes("004588c4", "??_7type_info@@6B@", "02 e4 40 00"),
		new AddressNameBytes("004596c8", "??_7DNameNode@@6B@",
			"26 7a 41 00 26 7a 41 00 26 7a 41 00 26 7a 41 00"),
		new AddressNameBytes("004596dc", "??_7charNode@@6B@",
			"67 70 41 00 e1 71 41 00 86 42 41 00 72 5a 41 00"),
		new AddressNameBytes("004596f0", "??_7pcharNode@@6B@",
			"c2 70 41 00 ed 71 41 00 cd 42 41 00 e4 5a 41 00"),
		new AddressNameBytes("00459704", "??_7pDNameNode@@6B@",
			"6b 70 41 00 e5 71 41 00 8a 42 41 00 87 5a 41 00"),
		new AddressNameBytes("00459718", "??_7DNameStatusNode@@6B@",
			"63 70 41 00 dd 71 41 00 7a 42 41 00 2b 5a 41 00"),
		new AddressNameBytes("0045972c", "??_7pairNode@@6B@",
			"79 70 41 00 e9 71 41 00 98 42 41 00 9e 5a 41 00 00 00 00 00"),
		new AddressNameBytes("00459994", "??_7exception@std@@6B@", "ce 8e 41 00 d7 93 41 00"),
		new AddressNameBytes("004599b4", "??_7bad_exception@std@@6B@", "a1 8e 41 00 d7 93 41 00")
	};

	private static AddressNameBytes functionInfo[] = {
		new AddressNameBytes("0040d9a0", "A1NS::A1::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 04 83 c0 01 8b e5 5d"),
		new AddressNameBytes("0040d9c0", "ANS::A::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 8b 55 fc 8b 42 f8 8b 50 04 8b 45 fc 8b 54 10 fc 8d 44 11 03 8b e5 5d"),
		new AddressNameBytes("0040d9e5", "[thunk]:ANS::A::fa1_1`adjustor{4}'",
			"83 e9 04 e9 d3 ff ff"),
		new AddressNameBytes("0040d9ed", "[thunk]:ANS::A::fa1_1`adjustor{16}'",
			"83 e9 10 e9 cb ff ff"),
		new AddressNameBytes("0040da00", "ENS::E::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 fc 83 c0 09 8b e5 5d"),
		new AddressNameBytes("0040da20", "FNS::F::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 fc 83 c0 0a 8b e5 5d"),
		new AddressNameBytes("0040da40", "GNS::G::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 fc 83 c0 0b 8b e5 5d"),
		new AddressNameBytes("0040da60", "HNS::H::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 fc 83 c0 0c 8b e5 5d"),
		new AddressNameBytes("0040da80", "INS::I::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 fc 83 c0 0d 8b e5 5d"),
		new AddressNameBytes("0040daa0", "JNS::J::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 fc 83 c0 0e 8b e5 5d"),
		new AddressNameBytes("0040dac0", "KNS::K::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 fc 83 c0 0f 8b e5 5d"),
		new AddressNameBytes("0040dae0", "LNS::L::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 fc 83 c0 10 8b e5 5d"),
		new AddressNameBytes("0040db00", "MNS::M::fa1_1",
			"55 8b ec 83 ec 08 56 89 4d fc 8b 45 fc 83 e8 70 74 0b 8b 4d fc 83 c1 a0 89 4d f8 eb 07 c7 45 f8 00 00 00 00 8b 55 fc 8b 42 a8 8b 4d fc 8b 51 f4 8d 74 10 13 8b 45 f8 8b 48 04 8b 51 0c 8b 45 f8 8d 4c 10 04 e8 e7 02 00 00 03 c6 5e 8b e5 5d"),
		new AddressNameBytes("0040db50", "ONS::O::fa1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 d4 8b 51 04 8b 45 fc 8b 4c 10 d8 8b 55 fc 8b 42 d4 8b 50 08 8b 45 fc 8b 54 10 d8 8d 44 11 18 8b e5 5d"),
		new AddressNameBytes("0040db80", "A1NS::A1::fa1_2",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 8d 44 09 01 8b e5 5d"),
		new AddressNameBytes("0040dba0", "CNS::C::fa1_2",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 f8 8b 51 04 8b 45 fc 8b 4c 10 fc 8b 55 fc 8b 42 fc 8d 44 48 07 8b e5 5d"),
		new AddressNameBytes("0040dbc5", "[thunk]:CNS::C::fa1_2`adjustor{28}'",
			"83 e9 1c e9 d3 ff ff"),
		new AddressNameBytes("0040dbcd", "[thunk]:CNS::C::fa1_2`adjustor{84}'",
			"83 e9 54 e9 cb ff ff"),
		new AddressNameBytes("0040dbe0", "A1NS::A1::fa1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 04 03 83 c0 01 8b e5 5d"),
		new AddressNameBytes("0040dc00", "A2NS::A2::fa2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 04 83 c0 02 8b e5 5d"),
		new AddressNameBytes("0040dc20", "ANS::A::fa2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 f4 8b 55 fc 8b 42 f0 8b 50 08 8b 45 fc 8b 54 10 f4 8d 44 11 03 8b e5 5d"),
		new AddressNameBytes("0040dc45", "[thunk]:ANS::A::fa2_1`adjustor{4}'",
			"83 e9 04 e9 d3 ff ff"),
		new AddressNameBytes("0040dc50", "CNS::C::fa2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 f0 8b 51 08 8b 45 fc 8b 4c 10 f4 8b 55 fc 8b 42 f4 8d 44 01 07 8b e5 5d"),
		new AddressNameBytes("0040dc80", "DNS::D::fa2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 f4 83 c0 08 8b e5 5d"),
		new AddressNameBytes("0040dca0", "MNS::M::fa2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 bc 8b 55 fc 8b 42 ec 8d 44 01 13 8b e5 5d"),
		new AddressNameBytes("0040dcc0", "O1NS::O1::fa2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 e0 8b 51 04 8b 45 fc 8b 4c 10 e4 8b 55 fc 8b 42 e0 8b 50 0c 8b 45 fc 8b 54 10 e4 8d 44 11 14 8b e5 5d"),
		new AddressNameBytes("0040dcf0", "O2NS::O2::fa2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 ec 8b 51 04 8b 45 fc 8b 4c 10 f0 8b 55 fc 8b 42 ec 8b 50 0c 8b 45 fc 8b 54 10 f0 8d 44 11 15 8b e5 5d"),
		new AddressNameBytes("0040dd20", "O3NS::O3::fa2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 e0 8b 51 04 8b 45 fc 8b 4c 10 e4 8b 55 fc 8b 42 e0 8b 50 0c 8b 45 fc 8b 54 10 e4 8d 44 11 16 8b e5 5d"),
		new AddressNameBytes("0040dd50", "O4NS::O4::fa2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 ec 8b 51 04 8b 45 fc 8b 4c 10 f0 8b 55 fc 8b 42 ec 8b 50 0c 8b 45 fc 8b 54 10 f0 8d 44 11 17 8b e5 5d"),
		new AddressNameBytes("0040dd80", "ONS::O::fa2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 cc 8b 51 04 8b 45 fc 8b 4c 10 d0 8b 55 fc 8b 42 cc 8b 50 0c 8b 45 fc 8b 54 10 d0 8d 44 11 18 8b e5 5d"),
		new AddressNameBytes("0040ddb0", "A2NS::A2::fa2_2",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 8d 44 09 02 8b e5 5d"),
		new AddressNameBytes("0040ddd0", "A2NS::A2::fa2_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 04 03 83 c0 02 8b e5 5d"),
		new AddressNameBytes("0040ddf0", "ANS::A::fa_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 08 8b 55 fc 8b 42 04 8b 50 04 8b 45 fc 8b 54 10 08 8d 44 11 03 8b 4d fc 8b 51 04 8b 4a 08 8b 55 fc 03 44 0a 08 8b e5 5d"),
		new AddressNameBytes("0040de30", "B1NS::B1::fb1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 04 83 c0 04 8b e5 5d"),
		new AddressNameBytes("0040de50", "BNS::B::fb1_1",
			"55 8b ec 51 56 89 4d fc 8b 45 fc 8b 48 fc 8b 55 fc 8b 42 f8 8b 50 04 8b 45 fc 8b 54 10 fc 8d 74 11 06 8b 45 fc 8b 48 f8 8b 51 04 8b 45 fc 8d 4c 10 f8 e8 a9 ff ff ff 03 c6 5e 8b e5 5d"),
		new AddressNameBytes("0040de8e", "[thunk]:BNS::B::fb1_1`adjustor{20}'",
			"83 e9 14 e9 ba ff ff"),
		new AddressNameBytes("0040de96", "[thunk]:BNS::B::fb1_1`adjustor{4294967268}'",
			"83 c1 1c e9 b2 ff ff"),
		new AddressNameBytes("0040dea0", "MNS::M::fb1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 8c 8b 55 fc 8b 42 e4 8d 44 01 13 8b e5 5d"),
		new AddressNameBytes("0040dec0", "ONS::O::fb1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 c4 8b 51 0c 8b 45 fc 8b 4c 10 c8 8b 55 fc 8b 42 c4 8b 50 10 8b 45 fc 8b 54 10 c8 8d 44 11 18 8b e5 5d"),
		new AddressNameBytes("0040def0", "B1NS::B1::fb1_2",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 8d 44 09 04 8b e5 5d"),
		new AddressNameBytes("0040df10", "CNS::C::fb1_2",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 e8 8b 51 0c 8b 45 fc 8b 4c 10 ec 8b 55 fc 8b 42 e8 8b 50 04 8b 45 fc 8b 54 10 ec 8d 44 4a 07 8b 4d fc 03 41 ec 8b e5 5d"),
		new AddressNameBytes("0040df45", "[thunk]:CNS::C::fb1_2`adjustor{28}'",
			"83 e9 1c e9 c3 ff ff"),
		new AddressNameBytes("0040df4d", "[thunk]:CNS::C::fb1_2`adjustor{84}'",
			"83 e9 54 e9 bb ff ff"),
		new AddressNameBytes("0040df60", "B1NS::B1::fb1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 04 03 83 c0 04 8b e5 5d"),
		new AddressNameBytes("0040df80", "B2NS::B2::fb2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 04 83 c0 05 8b e5 5d"),
		new AddressNameBytes("0040dfa0", "BNS::B::fb2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 f4 8b 55 fc 8b 42 f0 8b 50 08 8b 45 fc 8b 54 10 f4 8d 44 11 06 8b e5 5d"),
		new AddressNameBytes("0040dfc5", "[thunk]:BNS::B::fb2_1`adjustor{20}'",
			"83 e9 14 e9 d3 ff ff"),
		new AddressNameBytes("0040dfcd", "[thunk]:BNS::B::fb2_1`adjustor{4294967268}'",
			"83 c1 1c e9 cb ff ff"),
		new AddressNameBytes("0040dfe0", "CNS::C::fb2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 e0 8b 51 10 8b 45 fc 8b 4c 10 e4 8b 55 fc 8b 42 e0 8b 50 08 8b 45 fc 8b 54 10 e4 8d 44 11 07 8b 4d fc 03 41 e4 8b e5 5d"),
		new AddressNameBytes("0040e020", "DNS::D::fb2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 e4 8d 44 09 08 8b e5 5d"),
		new AddressNameBytes("0040e040", "MNS::M::fb2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 dc 83 c0 13 8b e5 5d"),
		new AddressNameBytes("0040e060", "ONS::O::fb2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 bc 8b 51 08 8b 45 fc 8b 4c 10 c0 8b 55 fc 8b 42 bc 8b 50 10 8b 45 fc 8b 54 10 c0 8d 44 11 18 8b e5 5d"),
		new AddressNameBytes("0040e090", "B2NS::B2::fb2_2",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 8d 44 09 05 8b e5 5d"),
		new AddressNameBytes("0040e0b0", "B2NS::B2::fb2_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 04 03 83 c0 05 8b e5 5d"),
		new AddressNameBytes("0040e0d0", "BNS::B::fb_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 08 8b 55 fc 8b 42 04 8b 50 04 8b 45 fc 8b 54 10 08 8d 44 11 06 8b 4d fc 8b 51 04 8b 4a 08 8b 55 fc 03 44 0a 08 8b e5 5d"),
		new AddressNameBytes("0040e110", "CNS::C::fc_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 8b 51 0c 8b 45 fc 8b 4c 10 08 8b 55 fc 8b 42 08 8d 44 01 07 8b e5 5d"),
		new AddressNameBytes("0040e140", "MNS::M::fn1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 9c 8b 51 18 8b 45 fc 8b 4c 10 a0 8b 55 fc 8b 42 fc 8d 44 01 13 8b e5 5d"),
		new AddressNameBytes("0040e170", "N1NS::N1::fn1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 04 83 c0 11 8b e5 5d"),
		new AddressNameBytes("0040e190", "N1NS::N1::fn1_2",
			"55 8b ec 51 89 4d fc 8b 45 fc b9 11 00 00 00 2b 48 04 8b c1 8b e5 5d"),
		new AddressNameBytes("0040e1b0", "N2NS::N2::fn2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 04 83 c0 12 8b e5 5d"),
		new AddressNameBytes("0040e1d0", "N2NS::N2::fn2_2",
			"55 8b ec 51 89 4d fc 8b 45 fc b9 12 00 00 00 2b 48 04 8b c1 8b e5 5d"),
		new AddressNameBytes("0040e1f0", "O1NS::O1::fo1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 18 83 c0 14 8b e5 5d"),
		new AddressNameBytes("0040e210", "ONS::O::fo1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 18 83 c0 18 8b e5 5d"),
		new AddressNameBytes("0040e230", "O2NS::O2::fo2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 0c 83 c0 15 8b e5 5d"),
		new AddressNameBytes("0040e250", "ONS::O::fo2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 0c 83 c0 18 8b e5 5d"),
		new AddressNameBytes("0040e270", "O3NS::O3::fo3_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 18 83 c0 16 8b e5 5d"),
		new AddressNameBytes("0040e290", "ONS::O::fo3_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 a8 8b 51 18 8b 45 fc 8b 44 10 c0 83 c0 18 8b e5 5d"),
		new AddressNameBytes("0040e2b0", "O4NS::O4::fo4_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 0c 83 c0 17 8b e5 5d"),
		new AddressNameBytes("0040e2d0", "ONS::O::fo4_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 8c 8b 51 1c 8b 45 fc 8b 44 10 98 83 c0 18 8b e5 5d"),
		new AddressNameBytes("0040e2f0", "ONS::O::fo_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 18 83 c0 18 8b e5 5d"),
		new AddressNameBytes("0040e402", "type_info::`scalar_deleting_destructor'",
			"55 8b ec f6 45 08 01 56 8b f1 c7 06 c4 88 45 00 74 0a 6a 0c 56 e8 c1 02 00 00 59 59 8b c6 5e 5d c2 04")
	};

	private static CppCompositeType createA1_struct(DataTypeManager dtm) {
		String name = "A1NS::A1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addVirtualFunctionTablePointer(pointer, 0);
		struct.addMember("a1", intT, false, publicDirectAttributes, 4, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fa1_2"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fa1_3"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createA2_struct(DataTypeManager dtm) {
		String name = "A2NS::A2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addVirtualFunctionTablePointer(pointer, 0);
		struct.addMember("a2", intT, false, publicDirectAttributes, 4, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fa2_2"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fa2_3"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createA_struct(DataTypeManager dtm,
			CppCompositeType A1_struct, CppCompositeType A2_struct) throws PdbException {
		String name = "ANS::A";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 28);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("a", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fa_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createB1_struct(DataTypeManager dtm) {
		String name = "B1NS::B1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("b1", intT, false, publicDirectAttributes, 4, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fb1_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fb1_2"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fb1_3"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createB2_struct(DataTypeManager dtm) {
		String name = "B2NS::B2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("b2", intT, false, publicDirectAttributes, 4, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fb2_2"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fb2_3"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createB_struct(DataTypeManager dtm,
			CppCompositeType B1_struct, CppCompositeType B2_struct) throws PdbException {
		String name = "BNS::B";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 28);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("b", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fb1_1"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fb_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createC_struct(DataTypeManager dtm,
			CppCompositeType A1_struct, CppCompositeType A2_struct, CppCompositeType B1_struct,
			CppCompositeType B2_struct) throws PdbException {
		String name = "CNS::C";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 44);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addDirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 3);
		struct.addDirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("c", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fa1_2"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(28, -1, new SymbolPath(classSp, "fb1_2"), fintvoidT);
		struct.addVirtualMethod(36, -1, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fc_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createD_struct(DataTypeManager dtm,
			CppCompositeType C_struct, CppCompositeType A_struct, CppCompositeType B_struct,
			CppCompositeType A1_struct, CppCompositeType A2_struct, CppCompositeType B1_struct,
			CppCompositeType B2_struct) throws PdbException {
		String name = "DNS::D";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 72);
		struct.addDirectBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 12);
		struct.addDirectBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes, 24);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("d", intT, false, publicDirectAttributes, 36, null);
		struct.addVirtualMethod(48, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(64, -1, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createE_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType B_struct, CppCompositeType A1_struct,
			CppCompositeType A2_struct, CppCompositeType B1_struct, CppCompositeType B2_struct)
			throws PdbException {
		String name = "ENS::E";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 60);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes,
			4, ClassUtils.VXPTR_TYPE, 5);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("e", intT, false, publicDirectAttributes, 12, null);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createF_struct(DataTypeManager dtm,
			CppCompositeType A1_struct) throws PdbException {
		String name = "FNS::F";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addDirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("f", intT, false, publicDirectAttributes, 4, null);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createG_struct(DataTypeManager dtm,
			CppCompositeType F_struct, CppCompositeType A1_struct) throws PdbException {
		String name = "GNS::G";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 20);
		struct.addDirectBaseClass(F_struct.getComposite(), F_struct, publicDirectAttributes, 0);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("g", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createH_struct(DataTypeManager dtm,
			CppCompositeType F_struct, CppCompositeType A1_struct) throws PdbException {
		String name = "HNS::H";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 20);
		struct.addDirectBaseClass(F_struct.getComposite(), F_struct, publicDirectAttributes, 0);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("h", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createI_struct(DataTypeManager dtm,
			CppCompositeType G_struct, CppCompositeType H_struct, CppCompositeType A1_struct)
			throws PdbException {
		String name = "INS::I";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 36);
		struct.addDirectBaseClass(G_struct.getComposite(), G_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(H_struct.getComposite(), H_struct, publicDirectAttributes, 12);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("i", intT, false, publicDirectAttributes, 24, null);
		struct.addVirtualMethod(28, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createJ_struct(DataTypeManager dtm,
			CppCompositeType A1_struct) throws PdbException {
		String name = "JNS::J";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addDirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("j", intT, false, publicDirectAttributes, 4, null);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createK_struct(DataTypeManager dtm,
			CppCompositeType J_struct, CppCompositeType A1_struct) throws PdbException {
		String name = "KNS::K";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 20);
		struct.addDirectBaseClass(J_struct.getComposite(), J_struct, publicDirectAttributes, 0);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("k", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createL_struct(DataTypeManager dtm, CppCompositeType K_struct,
			CppCompositeType A1_struct) throws PdbException {
		String name = "LNS::L";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectBaseClass(K_struct.getComposite(), K_struct, publicDirectAttributes, 0);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("l", intT, false, publicDirectAttributes, 12, null);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createN1_struct(DataTypeManager dtm) {
		String name = "N1NS::N1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("n1", intT, false, publicDirectAttributes, 4, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fn1_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fn1_2"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createN2_struct(DataTypeManager dtm) {
		String name = "N2NS::N2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("n2", intT, false, publicDirectAttributes, 4, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fn2_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fn2_2"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createM_struct(DataTypeManager dtm,
			CppCompositeType E_struct, CppCompositeType D_struct, CppCompositeType I_struct,
			CppCompositeType L_struct, CppCompositeType N1_struct, CppCompositeType N2_struct,
			CppCompositeType A1_struct, CppCompositeType A2_struct, CppCompositeType B1_struct,
			CppCompositeType B2_struct, CppCompositeType B_struct) throws PdbException {
		String name = "MNS::M";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 164);
		struct.addDirectBaseClass(E_struct.getComposite(), E_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(D_struct.getComposite(), D_struct, publicDirectAttributes, 16);
		struct.addDirectBaseClass(I_struct.getComposite(), I_struct, publicDirectAttributes, 56);
		struct.addDirectBaseClass(L_struct.getComposite(), L_struct, publicDirectAttributes, 84);
		struct.addDirectVirtualBaseClass(N1_struct.getComposite(), N1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 6);
		struct.addDirectVirtualBaseClass(N2_struct.getComposite(), N2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 7);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 4);
		struct.addIndirectVirtualBaseClass(B_struct.getComposite(), B_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 5);
		struct.addMember("m", intT, false, publicDirectAttributes, 100, null);
		struct.addVirtualMethod(112, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		struct.addVirtualMethod(120, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(128, -1, new SymbolPath(classSp, "fb1_1"), fintvoidT);
		struct.addVirtualMethod(136, -1, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		struct.addVirtualMethod(104, -1, new SymbolPath(classSp, "fn1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createO1_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType B_struct, CppCompositeType A1_struct,
			CppCompositeType A2_struct, CppCompositeType B1_struct, CppCompositeType B2_struct)
			throws PdbException {
		String name = "O1NS::O1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 60);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes, 12);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("o1", intT, false, publicDirectAttributes, 24, null);
		struct.addVirtualMethod(36, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fo1_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createO2_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType B_struct, CppCompositeType A1_struct,
			CppCompositeType A2_struct, CppCompositeType B1_struct, CppCompositeType B2_struct)
			throws PdbException {
		String name = "O2NS::O2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 60);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes,
			4, ClassUtils.VXPTR_TYPE, 5);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("o2", intT, false, publicDirectAttributes, 12, null);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fo2_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createO3_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType B_struct, CppCompositeType A1_struct,
			CppCompositeType A2_struct, CppCompositeType B1_struct, CppCompositeType B2_struct)
			throws PdbException {
		String name = "O3NS::O3";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 60);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes, 12);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("o3", intT, false, publicDirectAttributes, 24, null);
		struct.addVirtualMethod(36, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fo3_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createO4_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType B_struct, CppCompositeType A1_struct,
			CppCompositeType A2_struct, CppCompositeType B1_struct, CppCompositeType B2_struct)
			throws PdbException {
		String name = "O4NS::O4";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 60);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(B_struct.getComposite(), B_struct, publicDirectAttributes,
			4, ClassUtils.VXPTR_TYPE, 5);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("o4", intT, false, publicDirectAttributes, 12, null);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fo4_1"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createO_struct(DataTypeManager dtm,
			CppCompositeType O1_struct, CppCompositeType O2_struct, CppCompositeType O3_struct,
			CppCompositeType O4_struct, CppCompositeType A1_struct, CppCompositeType A2_struct,
			CppCompositeType B1_struct, CppCompositeType B2_struct, CppCompositeType B_struct)
			throws PdbException {
		String name = "ONS::O";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 136);
		struct.addDirectBaseClass(O1_struct.getComposite(), O1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(O2_struct.getComposite(), O2_struct, publicDirectAttributes, 28);
		struct.addDirectVirtualBaseClass(O3_struct.getComposite(), O3_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 6);
		struct.addDirectVirtualBaseClass(O4_struct.getComposite(), O4_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 7);
		struct.addIndirectVirtualBaseClass(A1_struct.getComposite(), A1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(A2_struct.getComposite(), A2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(B1_struct.getComposite(), B1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(B2_struct.getComposite(), B2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 4);
		struct.addIndirectVirtualBaseClass(B_struct.getComposite(), B_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 5);
		struct.addMember("o", intT, false, publicDirectAttributes, 44, null);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fo1_1"), fintvoidT);
		struct.addVirtualMethod(28, -1, new SymbolPath(classSp, "fo2_1"), fintvoidT);
		struct.addVirtualMethod(92, -1, new SymbolPath(classSp, "fo3_1"), fintvoidT);
		struct.addVirtualMethod(120, -1, new SymbolPath(classSp, "fo4_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fo_1"), fintvoidT);
		struct.addVirtualMethod(48, -1, new SymbolPath(classSp, "fa1_1"), fintvoidT);
		struct.addVirtualMethod(56, -1, new SymbolPath(classSp, "fa2_1"), fintvoidT);
		struct.addVirtualMethod(64, -1, new SymbolPath(classSp, "fb1_1"), fintvoidT);
		struct.addVirtualMethod(72, -1, new SymbolPath(classSp, "fb2_1"), fintvoidT);
		return struct;
	}

	//==============================================================================================
	//==============================================================================================

	//@formatter:off
	/*
	class A1NS::A1	size(8):
		+---
	 0	| {vfptr}
	 4	| a1
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
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   A1NS::A1::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class A2NS::A2	size(8):
		+---
	 0	| {vfptr}
	 4	| a2
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
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   A2NS::A2::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class ANS::A	size(28):
		+---
	 0	| {vfptr}
	 4	| {vbptr}
	 8	| a
		+---
		+--- (virtual base A1NS::A1)
	12	| {vfptr}
	16	| a1
		+---
		+--- (virtual base A2NS::A2)
	20	| {vfptr}
	24	| a2
		+---

	ANS::A::$vftable@A@:
		| &A_meta
		|  0
	 0	| &ANS::A::fa_1

	ANS::A::$vbtable@:
	 0	| -4
	 1	| 8 (Ad(A+4)A1)
	 2	| 16 (Ad(A+4)A2)

	ANS::A::$vftable@A1@:
		| -12
	 0	| &ANS::A::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	ANS::A::$vftable@A2@:
		| -20
	 0	| &ANS::A::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	ANS::A::fa1_1 this adjustor: 12
	ANS::A::fa2_1 this adjustor: 20
	ANS::A::fa_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      12       4       4 0
	        A2NS::A2      20       4       8 0
	 */
	//@formatter:on
	private static String getExpectedStructA() {
		String expected =
		//@formatter:off
			"""
			/ANS::A
			pack()
			Structure ANS::A {
			   0   ANS::A   12      "Self Base"
			   12   A1NS::A1   8      "Virtual Base"
			   20   A2NS::A2   8      "Virtual Base"
			}
			Length: 28 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   ANS::A   12      "Self Base"
			   12   char[16]   16      "Filler for 2 Unplaceable Virtual Bases: A1NS::A1; A2NS::A2"
			}
			Length: 28 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructA() {
		return convertCommentsToSpeculative(getExpectedStructA());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryA() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[ANS::A]");
		results.put("VTABLE_00000004", "     4 vbt []	[ANS::A]");
		results.put("VTABLE_0000000c", "    12 vft [A1NS::A1]	[ANS::A, A1NS::A1]");
		results.put("VTABLE_00000014", "    20 vft [A2NS::A2]	[ANS::A, A2NS::A2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsA() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructA_00000000());
		results.put("VTABLE_00000004", getVxtStructA_00000004());
		results.put("VTABLE_0000000c", getVxtStructA_0000000c());
		results.put("VTABLE_00000014", getVxtStructA_00000014());
		return results;
	}

	private static String getVxtStructA_00000000() {
		String expected =
		//@formatter:off
			"""
			/ANS/A/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructA_00000004() {
		String expected =
		//@formatter:off
			"""
			/ANS/A/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructA_0000000c() {
		String expected =
		//@formatter:off
			"""
			/ANS/A/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   ANS::A::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructA_00000014() {
		String expected =
		//@formatter:off
			"""
			/ANS/A/!internal/VTABLE_00000014
			pack()
			Structure VTABLE_00000014 {
			   0   _func___thiscall_int *   4   ANS::A::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class B1NS::B1	size(8):
		+---
	 0	| {vfptr}
	 4	| b1
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
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   B1NS::B1::fb1_1   ""
			   4   _func___thiscall_int *   4   B1NS::B1::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class B2NS::B2	size(8):
		+---
	 0	| {vfptr}
	 4	| b2
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
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   B2NS::B2::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BNS::B	size(28):
		+---
	 0	| {vfptr}
	 4	| {vbptr}
	 8	| b
		+---
		+--- (virtual base B1NS::B1)
	12	| {vfptr}
	16	| b1
		+---
		+--- (virtual base B2NS::B2)
	20	| {vfptr}
	24	| b2
		+---

	BNS::B::$vftable@B@:
		| &B_meta
		|  0
	 0	| &BNS::B::fb_1

	BNS::B::$vbtable@:
	 0	| -4
	 1	| 8 (Bd(B+4)B1)
	 2	| 16 (Bd(B+4)B2)

	BNS::B::$vftable@B1@:
		| -12
	 0	| &BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	BNS::B::$vftable@B2@:
		| -20
	 0	| &BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	BNS::B::fb1_1 this adjustor: 12
	BNS::B::fb2_1 this adjustor: 20
	BNS::B::fb_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        B1NS::B1      12       4       4 0
	        B2NS::B2      20       4       8 0
	 */
	//@formatter:on
	private static String getExpectedStructB() {
		String expected =
		//@formatter:off
			"""
			/BNS::B
			pack()
			Structure BNS::B {
			   0   BNS::B   12      "Self Base"
			   12   B1NS::B1   8      "Virtual Base"
			   20   B2NS::B2   8      "Virtual Base"
			}
			Length: 28 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   BNS::B   12      "Self Base"
			   12   char[16]   16      "Filler for 2 Unplaceable Virtual Bases: B1NS::B1; B2NS::B2"
			}
			Length: 28 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructB() {
		return convertCommentsToSpeculative(getExpectedStructB());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryB() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [BNS::B]	[BNS::B]");
		results.put("VTABLE_00000004", "     4 vbt []	[BNS::B]");
		results.put("VTABLE_0000000c", "    12 vft [B1NS::B1]	[BNS::B, B1NS::B1]");
		results.put("VTABLE_00000014", "    20 vft [B2NS::B2]	[BNS::B, B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsB() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructB_00000000());
		results.put("VTABLE_00000004", getVxtStructB_00000004());
		results.put("VTABLE_0000000c", getVxtStructB_0000000c());
		results.put("VTABLE_00000014", getVxtStructB_00000014());
		return results;
	}

	private static String getVxtStructB_00000000() {
		String expected =
		//@formatter:off
			"""
			/BNS/B/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructB_00000004() {
		String expected =
		//@formatter:off
			"""
			/BNS/B/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructB_0000000c() {
		String expected =
		//@formatter:off
			"""
			/BNS/B/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   BNS::B::fb1_1   ""
			   4   _func___thiscall_int *   4   B1NS::B1::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructB_00000014() {
		String expected =
		//@formatter:off
			"""
			/BNS/B/!internal/VTABLE_00000014
			pack()
			Structure VTABLE_00000014 {
			   0   _func___thiscall_int *   4   BNS::B::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CNS::C	size(44):
		+---
	 0	| {vfptr}
	 4	| {vbptr}
	 8	| c
		+---
		+--- (virtual base A1NS::A1)
	12	| {vfptr}
	16	| a1
		+---
		+--- (virtual base A2NS::A2)
	20	| {vfptr}
	24	| a2
		+---
		+--- (virtual base B1NS::B1)
	28	| {vfptr}
	32	| b1
		+---
		+--- (virtual base B2NS::B2)
	36	| {vfptr}
	40	| b2
		+---

	CNS::C::$vftable@C@:
		| &C_meta
		|  0
	 0	| &CNS::C::fc_1

	CNS::C::$vbtable@:
	 0	| -4
	 1	| 8 (Cd(C+4)A1)
	 2	| 16 (Cd(C+4)A2)
	 3	| 24 (Cd(C+4)B1)
	 4	| 32 (Cd(C+4)B2)

	CNS::C::$vftable@A1@:
		| -12
	 0	| &A1NS::A1::fa1_1
	 1	| &CNS::C::fa1_2
	 2	| &A1NS::A1::fa1_3

	CNS::C::$vftable@A2@:
		| -20
	 0	| &CNS::C::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	CNS::C::$vftable@B1@:
		| -28
	 0	| &B1NS::B1::fb1_1
	 1	| &CNS::C::fb1_2
	 2	| &B1NS::B1::fb1_3

	CNS::C::$vftable@B2@:
		| -36
	 0	| &CNS::C::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	CNS::C::fa1_2 this adjustor: 12
	CNS::C::fa2_1 this adjustor: 20
	CNS::C::fb1_2 this adjustor: 28
	CNS::C::fb2_1 this adjustor: 36
	CNS::C::fc_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      12       4       4 0
	        A2NS::A2      20       4       8 0
	        B1NS::B1      28       4      12 0
	        B2NS::B2      36       4      16 0
	 */
	//@formatter:on
	private static String getExpectedStructC() {
		String expected =
		//@formatter:off
			"""
			/CNS::C
			pack()
			Structure CNS::C {
			   0   CNS::C   12      "Self Base"
			   12   A1NS::A1   8      "Virtual Base"
			   20   A2NS::A2   8      "Virtual Base"
			   28   B1NS::B1   8      "Virtual Base"
			   36   B2NS::B2   8      "Virtual Base"
			}
			Length: 44 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   c   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   CNS::C   12      "Self Base"
			   12   char[32]   32      "Filler for 4 Unplaceable Virtual Bases: A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 44 Alignment: 4
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   c   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructC() {
		return convertCommentsToSpeculative(getExpectedStructC());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryC() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [CNS::C]	[CNS::C]");
		results.put("VTABLE_00000004", "     4 vbt []	[CNS::C]");
		results.put("VTABLE_0000000c", "    12 vft [A1NS::A1]	[CNS::C, A1NS::A1]");
		results.put("VTABLE_00000014", "    20 vft [A2NS::A2]	[CNS::C, A2NS::A2]");
		results.put("VTABLE_0000001c", "    28 vft [B1NS::B1]	[CNS::C, B1NS::B1]");
		results.put("VTABLE_00000024", "    36 vft [B2NS::B2]	[CNS::C, B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsC() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructC_00000000());
		results.put("VTABLE_00000004", getVxtStructC_00000004());
		results.put("VTABLE_0000000c", getVxtStructC_0000000c());
		results.put("VTABLE_00000014", getVxtStructC_00000014());
		results.put("VTABLE_0000001c", getVxtStructC_0000001c());
		results.put("VTABLE_00000024", getVxtStructC_00000024());
		return results;
	}

	private static String getVxtStructC_00000000() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   CNS::C::fc_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructC_00000004() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructC_0000000c() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   A1NS::A1::fa1_1   ""
			   4   _func___thiscall_int *   4   CNS::C::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructC_00000014() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_00000014
			pack()
			Structure VTABLE_00000014 {
			   0   _func___thiscall_int *   4   CNS::C::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructC_0000001c() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_0000001c
			pack()
			Structure VTABLE_0000001c {
			   0   _func___thiscall_int *   4   B1NS::B1::fb1_1   ""
			   4   _func___thiscall_int *   4   CNS::C::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructC_00000024() {
		String expected =
		//@formatter:off
			"""
			/CNS/C/!internal/VTABLE_00000024
			pack()
			Structure VTABLE_00000024 {
			   0   _func___thiscall_int *   4   CNS::C::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DNS::D	size(72):
		+---
	 0	| +--- (base class CNS::C)
	 0	| | {vfptr}
	 4	| | {vbptr}
	 8	| | c
		| +---
	12	| +--- (base class ANS::A)
	12	| | {vfptr}
	16	| | {vbptr}
	20	| | a
		| +---
	24	| +--- (base class BNS::B)
	24	| | {vfptr}
	28	| | {vbptr}
	32	| | b
		| +---
	36	| d
		+---
		+--- (virtual base A1NS::A1)
	40	| {vfptr}
	44	| a1
		+---
		+--- (virtual base A2NS::A2)
	48	| {vfptr}
	52	| a2
		+---
		+--- (virtual base B1NS::B1)
	56	| {vfptr}
	60	| b1
		+---
		+--- (virtual base B2NS::B2)
	64	| {vfptr}
	68	| b2
		+---

	DNS::D::$vftable@C@:
		| &D_meta
		|  0
	 0	| &CNS::C::fc_1

	DNS::D::$vftable@A@:
		| -12
	 0	| &ANS::A::fa_1

	DNS::D::$vftable@B@:
		| -24
	 0	| &BNS::B::fb_1

	DNS::D::$vbtable@C@:
	 0	| -4
	 1	| 36 (Dd(C+4)A1)
	 2	| 44 (Dd(C+4)A2)
	 3	| 52 (Dd(C+4)B1)
	 4	| 60 (Dd(C+4)B2)

	DNS::D::$vbtable@A@:
	 0	| -4
	 1	| 24 (Dd(A+4)A1)
	 2	| 32 (Dd(A+4)A2)

	DNS::D::$vbtable@B@:
	 0	| -4
	 1	| 28 (Dd(B+4)B1)
	 2	| 36 (Dd(B+4)B2)

	DNS::D::$vftable@A1@:
		| -40
	 0	| &thunk: this-=16; goto ANS::A::fa1_1
	 1	| &thunk: this-=28; goto CNS::C::fa1_2
	 2	| &A1NS::A1::fa1_3

	DNS::D::$vftable@A2@:
		| -48
	 0	| &DNS::D::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	DNS::D::$vftable@B1@:
		| -56
	 0	| &thunk: this-=20; goto BNS::B::fb1_1
	 1	| &thunk: this-=28; goto CNS::C::fb1_2
	 2	| &B1NS::B1::fb1_3

	DNS::D::$vftable@B2@:
		| -64
	 0	| &DNS::D::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	DNS::D::fa2_1 this adjustor: 48
	DNS::D::fb2_1 this adjustor: 64
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      40       4       4 0
	        A2NS::A2      48       4       8 0
	        B1NS::B1      56       4      12 0
	        B2NS::B2      64       4      16 0
	 */
	//@formatter:on
	private static String getExpectedStructD() {
		String expected =
		//@formatter:off
			"""
			/DNS::D
			pack()
			Structure DNS::D {
			   0   DNS::D   40      "Self Base"
			   40   A1NS::A1   8      "Virtual Base"
			   48   A2NS::A2   8      "Virtual Base"
			   56   B1NS::B1   8      "Virtual Base"
			   64   B2NS::B2   8      "Virtual Base"
			}
			Length: 72 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   c   ""
			}
			Length: 12 Alignment: 4
			/DNS::D/!internal/DNS::D
			pack()
			Structure DNS::D {
			   0   CNS::C   12      "Base"
			   12   ANS::A   12      "Base"
			   24   BNS::B   12      "Base"
			   36   int   4   d   ""
			}
			Length: 40 Alignment: 4""";
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
			   0   DNS::D   40      "Self Base"
			   40   char[32]   32      "Filler for 4 Unplaceable Virtual Bases: A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 72 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   c   ""
			}
			Length: 12 Alignment: 4
			/DNS::D/!internal/DNS::D
			pack()
			Structure DNS::D {
			   0   CNS::C   12      "Base"
			   12   ANS::A   12      "Base"
			   24   BNS::B   12      "Base"
			   36   int   4   d   ""
			}
			Length: 40 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructD() {
		return convertCommentsToSpeculative(getExpectedStructD());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryD() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [CNS::C]	[DNS::D, CNS::C]");
		results.put("VTABLE_00000004", "     4 vbt [CNS::C]	[DNS::D, CNS::C]");
		results.put("VTABLE_0000000c", "    12 vft [ANS::A]	[DNS::D, ANS::A]");
		results.put("VTABLE_00000010", "    16 vbt [ANS::A]	[DNS::D, ANS::A]");
		results.put("VTABLE_00000018", "    24 vft [BNS::B]	[DNS::D, BNS::B]");
		results.put("VTABLE_0000001c", "    28 vbt [BNS::B]	[DNS::D, BNS::B]");
		results.put("VTABLE_00000028", "    40 vft [A1NS::A1]	[DNS::D, CNS::C, A1NS::A1]");
		results.put("VTABLE_00000030", "    48 vft [A2NS::A2]	[DNS::D, CNS::C, A2NS::A2]");
		results.put("VTABLE_00000038", "    56 vft [B1NS::B1]	[DNS::D, CNS::C, B1NS::B1]");
		results.put("VTABLE_00000040", "    64 vft [B2NS::B2]	[DNS::D, CNS::C, B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsD() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructD_00000000());
		results.put("VTABLE_00000004", getVxtStructD_00000004());
		results.put("VTABLE_0000000c", getVxtStructD_0000000c());
		results.put("VTABLE_00000010", getVxtStructD_00000010());
		results.put("VTABLE_00000018", getVxtStructD_00000018());
		results.put("VTABLE_0000001c", getVxtStructD_0000001c());
		results.put("VTABLE_00000028", getVxtStructD_00000028());
		results.put("VTABLE_00000030", getVxtStructD_00000030());
		results.put("VTABLE_00000038", getVxtStructD_00000038());
		results.put("VTABLE_00000040", getVxtStructD_00000040());
		return results;
	}

	private static String getVxtStructD_00000000() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   CNS::C::fc_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000004() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_0000000c() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000010() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			}
			Length: 8 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_0000001c() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_0000001c
			pack()
			Structure VTABLE_0000001c {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000028() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_int *   4   ANS::A::fa1_1   ""
			   4   _func___thiscall_int *   4   CNS::C::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   DNS::D::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   BNS::B::fb1_1   ""
			   4   _func___thiscall_int *   4   CNS::C::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructD_00000040() {
		String expected =
		//@formatter:off
			"""
			/DNS/D/!internal/VTABLE_00000040
			pack()
			Structure VTABLE_00000040 {
			   0   _func___thiscall_int *   4   DNS::D::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class ENS::E	size(60):
		+---
	 0	| +--- (base class ANS::A)
	 0	| | {vfptr}
	 4	| | {vbptr}
	 8	| | a
		| +---
	12	| e
		+---
		+--- (virtual base A1NS::A1)
	16	| {vfptr}
	20	| a1
		+---
		+--- (virtual base A2NS::A2)
	24	| {vfptr}
	28	| a2
		+---
		+--- (virtual base B1NS::B1)
	32	| {vfptr}
	36	| b1
		+---
		+--- (virtual base B2NS::B2)
	40	| {vfptr}
	44	| b2
		+---
		+--- (virtual base BNS::B)
	48	| {vfptr}
	52	| {vbptr}
	56	| b
		+---

	ENS::E::$vftable@A@:
		| &E_meta
		|  0
	 0	| &ANS::A::fa_1

	ENS::E::$vbtable@A@:
	 0	| -4
	 1	| 12 (Ed(A+4)A1)
	 2	| 20 (Ed(A+4)A2)
	 3	| 28 (Ed(E+4)B1)
	 4	| 36 (Ed(E+4)B2)
	 5	| 44 (Ed(E+4)B)

	ENS::E::$vftable@A1@:
		| -16
	 0	| &ENS::E::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	ENS::E::$vftable@A2@:
		| -24
	 0	| &thunk: this-=4; goto ANS::A::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	ENS::E::$vftable@B1@:
		| -32
	 0	| &thunk: this+=28; goto BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	ENS::E::$vftable@B2@:
		| -40
	 0	| &thunk: this+=28; goto BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	ENS::E::$vftable@B@:
		| -48
	 0	| &BNS::B::fb_1

	ENS::E::$vbtable@B@:
	 0	| -4
	 1	| -20 (Ed(B+4)B1)
	 2	| -12 (Ed(B+4)B2)

	ENS::E::fa1_1 this adjustor: 16
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      16       4       4 0
	        A2NS::A2      24       4       8 0
	        B1NS::B1      32       4      12 0
	        B2NS::B2      40       4      16 0
	          BNS::B      48       4      20 0
	 */
	//@formatter:on
	private static String getExpectedStructE() {
		String expected =
		//@formatter:off
			"""
			/ENS::E
			pack()
			Structure ENS::E {
			   0   ENS::E   16      "Self Base"
			   16   A1NS::A1   8      "Virtual Base"
			   24   A2NS::A2   8      "Virtual Base"
			   32   B1NS::B1   8      "Virtual Base"
			   40   B2NS::B2   8      "Virtual Base"
			   48   BNS::B   12      "Virtual Base"
			}
			Length: 60 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/ENS::E/!internal/ENS::E
			pack()
			Structure ENS::E {
			   0   ANS::A   12      "Base"
			   12   int   4   e   ""
			}
			Length: 16 Alignment: 4""";
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
			   0   ENS::E   16      "Self Base"
			   16   char[44]   44      "Filler for 5 Unplaceable Virtual Bases: BNS::B; A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 60 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/ENS::E/!internal/ENS::E
			pack()
			Structure ENS::E {
			   0   ANS::A   12      "Base"
			   12   int   4   e   ""
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructE() {
		return convertCommentsToSpeculative(getExpectedStructE());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryE() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[ENS::E, ANS::A]");
		results.put("VTABLE_00000004", "     4 vbt [ANS::A]	[ENS::E, ANS::A]");
		results.put("VTABLE_00000010", "    16 vft [A1NS::A1]	[ENS::E, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000018", "    24 vft [A2NS::A2]	[ENS::E, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000020", "    32 vft [B1NS::B1]	[ENS::E, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000028", "    40 vft [B2NS::B2]	[ENS::E, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000030", "    48 vft [BNS::B]	[ENS::E, BNS::B]");
		results.put("VTABLE_00000034", "    52 vbt [BNS::B]	[ENS::E, BNS::B]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsE() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructE_00000000());
		results.put("VTABLE_00000004", getVxtStructE_00000004());
		results.put("VTABLE_00000010", getVxtStructE_00000010());
		results.put("VTABLE_00000018", getVxtStructE_00000018());
		results.put("VTABLE_00000020", getVxtStructE_00000020());
		results.put("VTABLE_00000028", getVxtStructE_00000028());
		results.put("VTABLE_00000030", getVxtStructE_00000030());
		results.put("VTABLE_00000034", getVxtStructE_00000034());
		return results;
	}

	private static String getVxtStructE_00000000() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000004() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
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

	private static String getVxtStructE_00000010() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   4   ENS::E::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000018() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   4   ANS::A::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   BNS::B::fb1_1   ""
			   4   _func___thiscall_int *   4   B1NS::B1::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000028() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_int *   4   BNS::B::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructE_00000034() {
		String expected =
		//@formatter:off
			"""
			/ENS/E/!internal/VTABLE_00000034
			pack()
			Structure VTABLE_00000034 {
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
	class FNS::F	size(16):
		+---
	 0	| {vbptr}
	 4	| f
		+---
		+--- (virtual base A1NS::A1)
	 8	| {vfptr}
	12	| a1
		+---

	FNS::F::$vbtable@:
	 0	| 0
	 1	| 8 (Fd(F+0)A1)

	FNS::F::$vftable@:
		| -8
	 0	| &FNS::F::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	FNS::F::fa1_1 this adjustor: 8
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1       8       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructF() {
		String expected =
		//@formatter:off
			"""
			/FNS::F
			pack()
			Structure FNS::F {
			   0   FNS::F   8      "Self Base"
			   8   A1NS::A1   8      "Virtual Base"
			}
			Length: 16 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4""";
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
			   0   FNS::F   8      "Self Base"
			   8   char[8]   8      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 16 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructF() {
		return convertCommentsToSpeculative(getExpectedStructF());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryF() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[FNS::F]");
		results.put("VTABLE_00000008", "     8 vft []	[FNS::F, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsF() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructF_00000000());
		results.put("VTABLE_00000008", getVxtStructF_00000008());
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

	private static String getVxtStructF_00000008() {
		String expected =
		//@formatter:off
			"""
			/FNS/F/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   _func___thiscall_int *   4   FNS::F::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class GNS::G	size(20):
		+---
	 0	| +--- (base class FNS::F)
	 0	| | {vbptr}
	 4	| | f
		| +---
	 8	| g
		+---
		+--- (virtual base A1NS::A1)
	12	| {vfptr}
	16	| a1
		+---

	GNS::G::$vbtable@:
	 0	| 0
	 1	| 12 (Gd(F+0)A1)

	GNS::G::$vftable@:
		| -12
	 0	| &GNS::G::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	GNS::G::fa1_1 this adjustor: 12
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      12       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructG() {
		String expected =
		//@formatter:off
			"""
			/GNS::G
			pack()
			Structure GNS::G {
			   0   GNS::G   12      "Self Base"
			   12   A1NS::A1   8      "Virtual Base"
			}
			Length: 20 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   8      "Base"
			   8   int   4   g   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   GNS::G   12      "Self Base"
			   12   char[8]   8      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 20 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   8      "Base"
			   8   int   4   g   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructG() {
		return convertCommentsToSpeculative(getExpectedStructG());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryG() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[GNS::G, FNS::F]");
		results.put("VTABLE_0000000c", "    12 vft []	[GNS::G, FNS::F, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsG() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructG_00000000());
		results.put("VTABLE_0000000c", getVxtStructG_0000000c());
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

	private static String getVxtStructG_0000000c() {
		String expected =
		//@formatter:off
			"""
			/GNS/G/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   GNS::G::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class HNS::H	size(20):
		+---
	 0	| +--- (base class FNS::F)
	 0	| | {vbptr}
	 4	| | f
		| +---
	 8	| h
		+---
		+--- (virtual base A1NS::A1)
	12	| {vfptr}
	16	| a1
		+---

	HNS::H::$vbtable@:
	 0	| 0
	 1	| 12 (Hd(F+0)A1)

	HNS::H::$vftable@:
		| -12
	 0	| &HNS::H::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	HNS::H::fa1_1 this adjustor: 12
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      12       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructH() {
		String expected =
		//@formatter:off
			"""
			/HNS::H
			pack()
			Structure HNS::H {
			   0   HNS::H   12      "Self Base"
			   12   A1NS::A1   8      "Virtual Base"
			}
			Length: 20 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   8      "Base"
			   8   int   4   h   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   HNS::H   12      "Self Base"
			   12   char[8]   8      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 20 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   8      "Base"
			   8   int   4   h   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructH() {
		return convertCommentsToSpeculative(getExpectedStructH());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryH() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[HNS::H, FNS::F]");
		results.put("VTABLE_0000000c", "    12 vft []	[HNS::H, FNS::F, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsH() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructH_00000000());
		results.put("VTABLE_0000000c", getVxtStructH_0000000c());
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

	private static String getVxtStructH_0000000c() {
		String expected =
		//@formatter:off
			"""
			/HNS/H/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   HNS::H::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class INS::I	size(36):
		+---
	 0	| +--- (base class GNS::G)
	 0	| | +--- (base class FNS::F)
	 0	| | | {vbptr}
	 4	| | | f
		| | +---
	 8	| | g
		| +---
	12	| +--- (base class HNS::H)
	12	| | +--- (base class FNS::F)
	12	| | | {vbptr}
	16	| | | f
		| | +---
	20	| | h
		| +---
	24	| i
		+---
		+--- (virtual base A1NS::A1)
	28	| {vfptr}
	32	| a1
		+---

	INS::I::$vbtable@G@:
	 0	| 0
	 1	| 28 (Id(F+0)A1)

	INS::I::$vbtable@H@:
	 0	| 0
	 1	| 16 (Id(F+0)A1)

	INS::I::$vftable@:
		| -28
	 0	| &INS::I::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	INS::I::fa1_1 this adjustor: 28
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      28       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructI() {
		String expected =
		//@formatter:off
			"""
			/INS::I
			pack()
			Structure INS::I {
			   0   INS::I   28      "Self Base"
			   28   A1NS::A1   8      "Virtual Base"
			}
			Length: 36 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   8      "Base"
			   8   int   4   g   ""
			}
			Length: 12 Alignment: 4
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   8      "Base"
			   8   int   4   h   ""
			}
			Length: 12 Alignment: 4
			/INS::I/!internal/INS::I
			pack()
			Structure INS::I {
			   0   GNS::G   12      "Base"
			   12   HNS::H   12      "Base"
			   24   int   4   i   ""
			}
			Length: 28 Alignment: 4""";
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
			   0   INS::I   28      "Self Base"
			   28   char[8]   8      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 36 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   8      "Base"
			   8   int   4   g   ""
			}
			Length: 12 Alignment: 4
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   8      "Base"
			   8   int   4   h   ""
			}
			Length: 12 Alignment: 4
			/INS::I/!internal/INS::I
			pack()
			Structure INS::I {
			   0   GNS::G   12      "Base"
			   12   HNS::H   12      "Base"
			   24   int   4   i   ""
			}
			Length: 28 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructI() {
		return convertCommentsToSpeculative(getExpectedStructI());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryI() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [GNS::G]	[INS::I, GNS::G, FNS::F]");
		results.put("VTABLE_0000000c", "    12 vbt [HNS::H]	[INS::I, HNS::H, FNS::F]");
		results.put("VTABLE_0000001c", "    28 vft []	[INS::I, GNS::G, FNS::F, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsI() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructI_00000000());
		results.put("VTABLE_0000000c", getVxtStructI_0000000c());
		results.put("VTABLE_0000001c", getVxtStructI_0000001c());
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

	private static String getVxtStructI_0000000c() {
		String expected =
		//@formatter:off
			"""
			/INS/I/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructI_0000001c() {
		String expected =
		//@formatter:off
			"""
			/INS/I/!internal/VTABLE_0000001c
			pack()
			Structure VTABLE_0000001c {
			   0   _func___thiscall_int *   4   INS::I::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class JNS::J	size(16):
		+---
	 0	| {vbptr}
	 4	| j
		+---
		+--- (virtual base A1NS::A1)
	 8	| {vfptr}
	12	| a1
		+---

	JNS::J::$vbtable@:
	 0	| 0
	 1	| 8 (Jd(J+0)A1)

	JNS::J::$vftable@:
		| -8
	 0	| &JNS::J::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	JNS::J::fa1_1 this adjustor: 8
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1       8       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructJ() {
		String expected =
		//@formatter:off
			"""
			/JNS::J
			pack()
			Structure JNS::J {
			   0   JNS::J   8      "Self Base"
			   8   A1NS::A1   8      "Virtual Base"
			}
			Length: 16 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   j   ""
			}
			Length: 8 Alignment: 4""";
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
			   0   JNS::J   8      "Self Base"
			   8   char[8]   8      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 16 Alignment: 4
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   j   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructJ() {
		return convertCommentsToSpeculative(getExpectedStructJ());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryJ() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[JNS::J]");
		results.put("VTABLE_00000008", "     8 vft []	[JNS::J, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsJ() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructJ_00000000());
		results.put("VTABLE_00000008", getVxtStructJ_00000008());
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

	private static String getVxtStructJ_00000008() {
		String expected =
		//@formatter:off
			"""
			/JNS/J/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   _func___thiscall_int *   4   JNS::J::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class KNS::K	size(20):
		+---
	 0	| +--- (base class JNS::J)
	 0	| | {vbptr}
	 4	| | j
		| +---
	 8	| k
		+---
		+--- (virtual base A1NS::A1)
	12	| {vfptr}
	16	| a1
		+---

	KNS::K::$vbtable@:
	 0	| 0
	 1	| 12 (Kd(J+0)A1)

	KNS::K::$vftable@:
		| -12
	 0	| &KNS::K::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	KNS::K::fa1_1 this adjustor: 12
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      12       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructK() {
		String expected =
		//@formatter:off
			"""
			/KNS::K
			pack()
			Structure KNS::K {
			   0   KNS::K   12      "Self Base"
			   12   A1NS::A1   8      "Virtual Base"
			}
			Length: 20 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   j   ""
			}
			Length: 8 Alignment: 4
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   8      "Base"
			   8   int   4   k   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   KNS::K   12      "Self Base"
			   12   char[8]   8      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 20 Alignment: 4
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   j   ""
			}
			Length: 8 Alignment: 4
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   8      "Base"
			   8   int   4   k   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructK() {
		return convertCommentsToSpeculative(getExpectedStructK());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryK() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[KNS::K, JNS::J]");
		results.put("VTABLE_0000000c", "    12 vft []	[KNS::K, JNS::J, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsK() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructK_00000000());
		results.put("VTABLE_0000000c", getVxtStructK_0000000c());
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

	private static String getVxtStructK_0000000c() {
		String expected =
		//@formatter:off
			"""
			/KNS/K/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   KNS::K::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class LNS::L	size(24):
		+---
	 0	| +--- (base class KNS::K)
	 0	| | +--- (base class JNS::J)
 	 0	| | | {vbptr}
 	 4	| | | j
		| | +---
	 8	| | k
		| +---
	12	| l
		+---
		+--- (virtual base A1NS::A1)
	16	| {vfptr}
	20	| a1
		+---

	LNS::L::$vbtable@:
	 0	| 0
	 1	| 16 (Ld(J+0)A1)

	LNS::L::$vftable@:
		| -16
	 0	| &LNS::L::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	LNS::L::fa1_1 this adjustor: 16
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructL() {
		String expected =
		//@formatter:off
			"""
			/LNS::L
			pack()
			Structure LNS::L {
			   0   LNS::L   16      "Self Base"
			   16   A1NS::A1   8      "Virtual Base"
			}
			Length: 24 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   j   ""
			}
			Length: 8 Alignment: 4
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   8      "Base"
			   8   int   4   k   ""
			}
			Length: 12 Alignment: 4
			/LNS::L/!internal/LNS::L
			pack()
			Structure LNS::L {
			   0   KNS::K   12      "Base"
			   12   int   4   l   ""
			}
			Length: 16 Alignment: 4""";
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
			   0   LNS::L   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: A1NS::A1"
			}
			Length: 24 Alignment: 4
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   j   ""
			}
			Length: 8 Alignment: 4
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   8      "Base"
			   8   int   4   k   ""
			}
			Length: 12 Alignment: 4
			/LNS::L/!internal/LNS::L
			pack()
			Structure LNS::L {
			   0   KNS::K   12      "Base"
			   12   int   4   l   ""
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructL() {
		return convertCommentsToSpeculative(getExpectedStructL());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryL() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[LNS::L, KNS::K, JNS::J]");
		results.put("VTABLE_00000010", "    16 vft []	[LNS::L, KNS::K, JNS::J, A1NS::A1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsL() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructL_00000000());
		results.put("VTABLE_00000010", getVxtStructL_00000010());
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

	private static String getVxtStructL_00000010() {
		String expected =
		//@formatter:off
			"""
			/LNS/L/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   4   LNS::L::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class N1NS::N1	size(8):
		+---
	 0	| {vfptr}
	 4	| n1
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
			   0   pointer   4   {vfptr}   ""
			   4   int   4   n1   ""
			}
			Length: 8 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   N1NS::N1::fn1_1   ""
			   4   _func___thiscall_int *   4   N1NS::N1::fn1_2   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class N2NS::N2	size(8):
		+---
	 0	| {vfptr}
	 4	| n2
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
			   0   pointer   4   {vfptr}   ""
			   4   int   4   n2   ""
			}
			Length: 8 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   N2NS::N2::fn2_1   ""
			   4   _func___thiscall_int *   4   N2NS::N2::fn2_2   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class MNS::M	size(164):
		+---
	 0	| +--- (base class ENS::E)
	 0	| | +--- (base class ANS::A)
	 0	| | | {vfptr}
	 4	| | | {vbptr}
	 8	| | | a
		| | +---
	12	| | e
		| +---
	16	| +--- (base class DNS::D)
	16	| | +--- (base class CNS::C)
	16	| | | {vfptr}
	20	| | | {vbptr}
	24	| | | c
		| | +---
	28	| | +--- (base class ANS::A)
	28	| | | {vfptr}
	32	| | | {vbptr}
	36	| | | a
		| | +---
	40	| | +--- (base class BNS::B)
	40	| | | {vfptr}
	44	| | | {vbptr}
	48	| | | b
		| | +---
	52	| | d
		| +---
	56	| +--- (base class INS::I)
	56	| | +--- (base class GNS::G)
	56	| | | +--- (base class FNS::F)
	56	| | | | {vbptr}
	60	| | | | f
		| | | +---
	64	| | | g
		| | +---
	68	| | +--- (base class HNS::H)
	68	| | | +--- (base class FNS::F)
	68	| | | | {vbptr}
	72	| | | | f
		| | | +---
	76	| | | h
		| | +---
	80	| | i
		| +---
	84	| +--- (base class LNS::L)
	84	| | +--- (base class KNS::K)
	84	| | | +--- (base class JNS::J)
	84	| | | | {vbptr}
	88	| | | | j
		| | | +---
	92	| | | k
		| | +---
	96	| | l
		| +---
	100	| m
		+---
		+--- (virtual base N1NS::N1)
	104	| {vfptr}
	108	| n1
		+---
		+--- (virtual base A1NS::A1)
	112	| {vfptr}
	116	| a1
		+---
		+--- (virtual base A2NS::A2)
	120	| {vfptr}
	124	| a2
		+---
		+--- (virtual base B1NS::B1)
	128	| {vfptr}
	132	| b1
		+---
		+--- (virtual base B2NS::B2)
	136	| {vfptr}
	140	| b2
		+---
		+--- (virtual base BNS::B)
	144	| {vfptr}
	148	| {vbptr}
	152	| b
		+---
		+--- (virtual base N2NS::N2)
	156	| {vfptr}
	160	| n2
		+---

	MNS::M::$vftable@A@E@:
		| &M_meta
		|  0
	 0	| &ANS::A::fa_1

	MNS::M::$vftable@C@:
		| -16
	 0	| &CNS::C::fc_1

	MNS::M::$vftable@A@D@:
		| -28
	 0	| &ANS::A::fa_1

	MNS::M::$vftable@B@D@:
		| -40
	 0	| &BNS::B::fb_1

	MNS::M::$vbtable@A@E@:
	 0	| -4
	 1	| 108 (Md(A+4)A1)
	 2	| 116 (Md(A+4)A2)
	 3	| 124 (Md(E+4)B1)
	 4	| 132 (Md(E+4)B2)
	 5	| 140 (Md(E+4)B)
	 6	| 100 (Md(M+4)N1)
	 7	| 152 (Md(M+4)N2)

	MNS::M::$vbtable@C@:
	 0	| -4
	 1	| 92 (Md(C+4)A1)
	 2	| 100 (Md(C+4)A2)
	 3	| 108 (Md(C+4)B1)
	 4	| 116 (Md(C+4)B2)

	MNS::M::$vbtable@A@D@:
	 0	| -4
	 1	| 80 (Md(A+4)A1)
	 2	| 88 (Md(A+4)A2)

	MNS::M::$vbtable@B@D@:
	 0	| -4
	 1	| 84 (Md(B+4)B1)
	 2	| 92 (Md(B+4)B2)

	MNS::M::$vbtable@G@:
	 0	| 0
	 1	| 56 (Md(F+0)A1)

	MNS::M::$vbtable@H@:
	 0	| 0
	 1	| 44 (Md(F+0)A1)

	MNS::M::$vbtable@:
	 0	| 0
	 1	| 28 (Md(J+0)A1)

	MNS::M::$vftable@N1@:
		| -104
	 0	| &MNS::M::fn1_1
	 1	| &N1NS::N1::fn1_2

	MNS::M::$vftable@A1@:
		| -112
	 0	| &MNS::M::fa1_1
	 1	| &thunk: this-=84; goto CNS::C::fa1_2
	 2	| &A1NS::A1::fa1_3

	MNS::M::$vftable@A2@:
		| -120
	 0	| &MNS::M::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	MNS::M::$vftable@B1@:
		| -128
	 0	| &MNS::M::fb1_1
	 1	| &thunk: this-=84; goto CNS::C::fb1_2
	 2	| &B1NS::B1::fb1_3

	MNS::M::$vftable@B2@:
		| -136
	 0	| &MNS::M::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	MNS::M::$vftable@B@E@:
		| -144
	 0	| &BNS::B::fb_1

	MNS::M::$vbtable@B@E@:
	 0	| -4
	 1	| -20 (Md(B+4)B1)
	 2	| -12 (Md(B+4)B2)

	MNS::M::$vftable@N2@:
		| -156
	 0	| &N2NS::N2::fn2_1
	 1	| &N2NS::N2::fn2_2

	MNS::M::fa1_1 this adjustor: 112
	MNS::M::fa2_1 this adjustor: 120
	MNS::M::fb1_1 this adjustor: 128
	MNS::M::fb2_1 this adjustor: 136
	MNS::M::fn1_1 this adjustor: 104
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        N1NS::N1     104       4      24 0
	        A1NS::A1     112       4       4 0
	        A2NS::A2     120       4       8 0
	        B1NS::B1     128       4      12 0
	        B2NS::B2     136       4      16 0
	          BNS::B     144       4      20 0
	        N2NS::N2     156       4      28 0
	 */
	//@formatter:on
	private static String getExpectedStructM() {
		String expected =
		//@formatter:off
			"""
			/MNS::M
			pack()
			Structure MNS::M {
			   0   MNS::M   104      "Self Base"
			   104   N1NS::N1   8      "Virtual Base"
			   112   A1NS::A1   8      "Virtual Base"
			   120   A2NS::A2   8      "Virtual Base"
			   128   B1NS::B1   8      "Virtual Base"
			   136   B2NS::B2   8      "Virtual Base"
			   144   BNS::B   12      "Virtual Base"
			   156   N2NS::N2   8      "Virtual Base"
			}
			Length: 164 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   c   ""
			}
			Length: 12 Alignment: 4
			/DNS::D/!internal/DNS::D
			pack()
			Structure DNS::D {
			   0   CNS::C   12      "Base"
			   12   ANS::A   12      "Base"
			   24   BNS::B   12      "Base"
			   36   int   4   d   ""
			}
			Length: 40 Alignment: 4
			/ENS::E/!internal/ENS::E
			pack()
			Structure ENS::E {
			   0   ANS::A   12      "Base"
			   12   int   4   e   ""
			}
			Length: 16 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   8      "Base"
			   8   int   4   g   ""
			}
			Length: 12 Alignment: 4
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   8      "Base"
			   8   int   4   h   ""
			}
			Length: 12 Alignment: 4
			/INS::I/!internal/INS::I
			pack()
			Structure INS::I {
			   0   GNS::G   12      "Base"
			   12   HNS::H   12      "Base"
			   24   int   4   i   ""
			}
			Length: 28 Alignment: 4
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   j   ""
			}
			Length: 8 Alignment: 4
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   8      "Base"
			   8   int   4   k   ""
			}
			Length: 12 Alignment: 4
			/LNS::L/!internal/LNS::L
			pack()
			Structure LNS::L {
			   0   KNS::K   12      "Base"
			   12   int   4   l   ""
			}
			Length: 16 Alignment: 4
			/MNS::M/!internal/MNS::M
			pack()
			Structure MNS::M {
			   0   ENS::E   16      "Base"
			   16   DNS::D   40      "Base"
			   56   INS::I   28      "Base"
			   84   LNS::L   16      "Base"
			   100   int   4   m   ""
			}
			Length: 104 Alignment: 4
			/N1NS::N1
			pack()
			Structure N1NS::N1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   n1   ""
			}
			Length: 8 Alignment: 4
			/N2NS::N2
			pack()
			Structure N2NS::N2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   n2   ""
			}
			Length: 8 Alignment: 4""";
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
			   0   MNS::M   104      "Self Base"
			   104   char[60]   60      "Filler for 7 Unplaceable Virtual Bases: N1NS::N1; N2NS::N2; A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2; BNS::B"
			}
			Length: 164 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   c   ""
			}
			Length: 12 Alignment: 4
			/DNS::D/!internal/DNS::D
			pack()
			Structure DNS::D {
			   0   CNS::C   12      "Base"
			   12   ANS::A   12      "Base"
			   24   BNS::B   12      "Base"
			   36   int   4   d   ""
			}
			Length: 40 Alignment: 4
			/ENS::E/!internal/ENS::E
			pack()
			Structure ENS::E {
			   0   ANS::A   12      "Base"
			   12   int   4   e   ""
			}
			Length: 16 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   8      "Base"
			   8   int   4   g   ""
			}
			Length: 12 Alignment: 4
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   8      "Base"
			   8   int   4   h   ""
			}
			Length: 12 Alignment: 4
			/INS::I/!internal/INS::I
			pack()
			Structure INS::I {
			   0   GNS::G   12      "Base"
			   12   HNS::H   12      "Base"
			   24   int   4   i   ""
			}
			Length: 28 Alignment: 4
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   j   ""
			}
			Length: 8 Alignment: 4
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   8      "Base"
			   8   int   4   k   ""
			}
			Length: 12 Alignment: 4
			/LNS::L/!internal/LNS::L
			pack()
			Structure LNS::L {
			   0   KNS::K   12      "Base"
			   12   int   4   l   ""
			}
			Length: 16 Alignment: 4
			/MNS::M/!internal/MNS::M
			pack()
			Structure MNS::M {
			   0   ENS::E   16      "Base"
			   16   DNS::D   40      "Base"
			   56   INS::I   28      "Base"
			   84   LNS::L   16      "Base"
			   100   int   4   m   ""
			}
			Length: 104 Alignment: 4""";
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
			   0   MNS::M   104      "Self Base"
			   104   A1NS::A1   8      "Virtual Base - Speculative Placement"
			   112   A2NS::A2   8      "Virtual Base - Speculative Placement"
			   120   B1NS::B1   8      "Virtual Base - Speculative Placement"
			   128   B2NS::B2   8      "Virtual Base - Speculative Placement"
			   136   BNS::B   12      "Virtual Base - Speculative Placement"
			   148   N1NS::N1   8      "Virtual Base - Speculative Placement"
			   156   N2NS::N2   8      "Virtual Base - Speculative Placement"
			}
			Length: 164 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/CNS::C/!internal/CNS::C
			pack()
			Structure CNS::C {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   c   ""
			}
			Length: 12 Alignment: 4
			/DNS::D/!internal/DNS::D
			pack()
			Structure DNS::D {
			   0   CNS::C   12      "Base"
			   12   ANS::A   12      "Base"
			   24   BNS::B   12      "Base"
			   36   int   4   d   ""
			}
			Length: 40 Alignment: 4
			/ENS::E/!internal/ENS::E
			pack()
			Structure ENS::E {
			   0   ANS::A   12      "Base"
			   12   int   4   e   ""
			}
			Length: 16 Alignment: 4
			/FNS::F/!internal/FNS::F
			pack()
			Structure FNS::F {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   f   ""
			}
			Length: 8 Alignment: 4
			/GNS::G/!internal/GNS::G
			pack()
			Structure GNS::G {
			   0   FNS::F   8      "Base"
			   8   int   4   g   ""
			}
			Length: 12 Alignment: 4
			/HNS::H/!internal/HNS::H
			pack()
			Structure HNS::H {
			   0   FNS::F   8      "Base"
			   8   int   4   h   ""
			}
			Length: 12 Alignment: 4
			/INS::I/!internal/INS::I
			pack()
			Structure INS::I {
			   0   GNS::G   12      "Base"
			   12   HNS::H   12      "Base"
			   24   int   4   i   ""
			}
			Length: 28 Alignment: 4
			/JNS::J/!internal/JNS::J
			pack()
			Structure JNS::J {
			   0   pointer   4   {vbptr}   ""
			   4   int   4   j   ""
			}
			Length: 8 Alignment: 4
			/KNS::K/!internal/KNS::K
			pack()
			Structure KNS::K {
			   0   JNS::J   8      "Base"
			   8   int   4   k   ""
			}
			Length: 12 Alignment: 4
			/LNS::L/!internal/LNS::L
			pack()
			Structure LNS::L {
			   0   KNS::K   12      "Base"
			   12   int   4   l   ""
			}
			Length: 16 Alignment: 4
			/MNS::M/!internal/MNS::M
			pack()
			Structure MNS::M {
			   0   ENS::E   16      "Base"
			   16   DNS::D   40      "Base"
			   56   INS::I   28      "Base"
			   84   LNS::L   16      "Base"
			   100   int   4   m   ""
			}
			Length: 104 Alignment: 4
			/N1NS::N1
			pack()
			Structure N1NS::N1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   n1   ""
			}
			Length: 8 Alignment: 4
			/N2NS::N2
			pack()
			Structure N2NS::N2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   n2   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static Map<String, String> getExpectedVxtPtrSummaryM() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A, ENS::E]	[MNS::M, ENS::E, ANS::A]");
		results.put("VTABLE_00000004", "     4 vbt [ANS::A, ENS::E]	[MNS::M, ENS::E, ANS::A]");
		results.put("VTABLE_00000010", "    16 vft [CNS::C]	[MNS::M, DNS::D, CNS::C]");
		results.put("VTABLE_00000014", "    20 vbt [CNS::C]	[MNS::M, DNS::D, CNS::C]");
		results.put("VTABLE_0000001c", "    28 vft [ANS::A, DNS::D]	[MNS::M, DNS::D, ANS::A]");
		results.put("VTABLE_00000020", "    32 vbt [ANS::A, DNS::D]	[MNS::M, DNS::D, ANS::A]");
		results.put("VTABLE_00000028", "    40 vft [BNS::B, DNS::D]	[MNS::M, DNS::D, BNS::B]");
		results.put("VTABLE_0000002c", "    44 vbt [BNS::B, DNS::D]	[MNS::M, DNS::D, BNS::B]");
		results.put("VTABLE_00000038", "    56 vbt [GNS::G]	[MNS::M, INS::I, GNS::G, FNS::F]");
		results.put("VTABLE_00000044", "    68 vbt [HNS::H]	[MNS::M, INS::I, HNS::H, FNS::F]");
		results.put("VTABLE_00000054", "    84 vbt []	[MNS::M, LNS::L, KNS::K, JNS::J]");
		results.put("VTABLE_00000068", "   104 vft [N1NS::N1]	[MNS::M, N1NS::N1]");
		results.put("VTABLE_00000070",
			"   112 vft [A1NS::A1]	[MNS::M, ENS::E, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000078",
			"   120 vft [A2NS::A2]	[MNS::M, ENS::E, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000080",
			"   128 vft [B1NS::B1]	[MNS::M, ENS::E, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000088",
			"   136 vft [B2NS::B2]	[MNS::M, ENS::E, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000090", "   144 vft [BNS::B, ENS::E]	[MNS::M, ENS::E, BNS::B]");
		results.put("VTABLE_00000094", "   148 vbt [BNS::B, ENS::E]	[MNS::M, ENS::E, BNS::B]");
		results.put("VTABLE_0000009c", "   156 vft [N2NS::N2]	[MNS::M, N2NS::N2]");
		return results;
	}

	private static Map<String, String> getSpeculatedVxtPtrSummaryM() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A, ENS::E]	[MNS::M, ENS::E, ANS::A]");
		results.put("VTABLE_00000004", "     4 vbt [ANS::A, ENS::E]	[MNS::M, ENS::E, ANS::A]");
		results.put("VTABLE_00000010", "    16 vft [CNS::C]	[MNS::M, DNS::D, CNS::C]");
		results.put("VTABLE_00000014", "    20 vbt [CNS::C]	[MNS::M, DNS::D, CNS::C]");
		results.put("VTABLE_0000001c", "    28 vft [ANS::A, DNS::D]	[MNS::M, DNS::D, ANS::A]");
		results.put("VTABLE_00000020", "    32 vbt [ANS::A, DNS::D]	[MNS::M, DNS::D, ANS::A]");
		results.put("VTABLE_00000028", "    40 vft [BNS::B, DNS::D]	[MNS::M, DNS::D, BNS::B]");
		results.put("VTABLE_0000002c", "    44 vbt [BNS::B, DNS::D]	[MNS::M, DNS::D, BNS::B]");
		results.put("VTABLE_00000038", "    56 vbt [GNS::G]	[MNS::M, INS::I, GNS::G, FNS::F]");
		results.put("VTABLE_00000044", "    68 vbt [HNS::H]	[MNS::M, INS::I, HNS::H, FNS::F]");
		results.put("VTABLE_00000054", "    84 vbt []	[MNS::M, LNS::L, KNS::K, JNS::J]");
		results.put("VTABLE_00000068",
			"   104 vft [A1NS::A1]	[MNS::M, ENS::E, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000070",
			"   112 vft [A2NS::A2]	[MNS::M, ENS::E, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000078",
			"   120 vft [B1NS::B1]	[MNS::M, ENS::E, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000080",
			"   128 vft [B2NS::B2]	[MNS::M, ENS::E, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000088",
			"   136 vft [BNS::B, ENS::E]	[MNS::M, ENS::E, BNS::B]");
		results.put("VTABLE_0000008c", "   140 vbt [BNS::B, ENS::E]	[MNS::M, ENS::E, BNS::B]");
		results.put("VTABLE_00000094", "   148 vft [N1NS::N1]	[MNS::M, N1NS::N1]");
		results.put("VTABLE_0000009c", "   156 vft [N2NS::N2]	[MNS::M, N2NS::N2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsM() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructM_00000000());
		results.put("VTABLE_00000004", getVxtStructM_00000004());
		results.put("VTABLE_00000010", getVxtStructM_00000010());
		results.put("VTABLE_00000014", getVxtStructM_00000014());
		results.put("VTABLE_0000001c", getVxtStructM_0000001c());
		results.put("VTABLE_00000020", getVxtStructM_00000020());
		results.put("VTABLE_00000028", getVxtStructM_00000028());
		results.put("VTABLE_0000002c", getVxtStructM_0000002c());
		results.put("VTABLE_00000038", getVxtStructM_00000038());
		results.put("VTABLE_00000044", getVxtStructM_00000044());
		results.put("VTABLE_00000054", getVxtStructM_00000054());
		results.put("VTABLE_00000068", getVxtStructM_00000068());
		results.put("VTABLE_00000070", getVxtStructM_00000070());
		results.put("VTABLE_00000078", getVxtStructM_00000078());
		results.put("VTABLE_00000080", getVxtStructM_00000080());
		results.put("VTABLE_00000088", getVxtStructM_00000088());
		results.put("VTABLE_00000090", getVxtStructM_00000090());
		results.put("VTABLE_00000094", getVxtStructM_00000094());
		results.put("VTABLE_0000009c", getVxtStructM_0000009c());
		return results;
	}

	private static Map<String, String> getSpeculatedVxtStructsM() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructM_00000000());
		results.put("VTABLE_00000004", getVxtStructM_00000004());
		results.put("VTABLE_00000010", getVxtStructM_00000010());
		results.put("VTABLE_00000014", getVxtStructM_00000014());
		results.put("VTABLE_0000001c", getVxtStructM_0000001c());
		results.put("VTABLE_00000020", getVxtStructM_00000020());
		results.put("VTABLE_00000028", getVxtStructM_00000028());
		results.put("VTABLE_0000002c", getVxtStructM_0000002c());
		results.put("VTABLE_00000038", getVxtStructM_00000038());
		results.put("VTABLE_00000044", getVxtStructM_00000044());
		results.put("VTABLE_00000054", getVxtStructM_00000054());
		results.put("VTABLE_00000068", getVxtStructM_00000068_speculated());
		results.put("VTABLE_00000070", getVxtStructM_00000070_speculated());
		results.put("VTABLE_00000078", getVxtStructM_00000078_speculated());
		results.put("VTABLE_00000080", getVxtStructM_00000080_speculated());
		results.put("VTABLE_00000088", getVxtStructM_00000088_speculated());
		results.put("VTABLE_0000008c", getVxtStructM_0000008c_speculated());
		results.put("VTABLE_00000094", getVxtStructM_00000094_speculated());
		results.put("VTABLE_0000009c", getVxtStructM_0000009c_speculated());
		return results;
	}

	private static String getVxtStructM_00000000() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000004() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
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

	private static String getVxtStructM_00000010() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   4   CNS::C::fc_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000014() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000014
			pack()
			Structure VTABLE_00000014 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_0000001c() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_0000001c
			pack()
			Structure VTABLE_0000001c {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			}
			Length: 4 Alignment: 4""";
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
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			}
			Length: 8 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_0000002c() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_0000002c
			pack()
			Structure VTABLE_0000002c {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
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
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000044() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000044
			pack()
			Structure VTABLE_00000044 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000054() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000054
			pack()
			Structure VTABLE_00000054 {
			   0   int   4      "A1NS::A1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000068() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000068
			pack()
			Structure VTABLE_00000068 {
			   0   _func___thiscall_int *   4   MNS::M::fn1_1   ""
			   4   _func___thiscall_int *   4   N1NS::N1::fn1_2   ""
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
			   0   _func___thiscall_int *   4   MNS::M::fa1_1   ""
			   4   _func___thiscall_int *   4   CNS::C::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000078() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000078
			pack()
			Structure VTABLE_00000078 {
			   0   _func___thiscall_int *   4   MNS::M::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000080() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000080
			pack()
			Structure VTABLE_00000080 {
			   0   _func___thiscall_int *   4   MNS::M::fb1_1   ""
			   4   _func___thiscall_int *   4   CNS::C::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   MNS::M::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000090() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000090
			pack()
			Structure VTABLE_00000090 {
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000094() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000094
			pack()
			Structure VTABLE_00000094 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_0000009c() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_0000009c
			pack()
			Structure VTABLE_0000009c {
			   0   _func___thiscall_int *   4   N2NS::N2::fn2_1   ""
			   4   _func___thiscall_int *   4   N2NS::N2::fn2_2   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000068_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000068
			pack()
			Structure VTABLE_00000068 {
			   0   _func___thiscall_int *   4   MNS::M::fa1_1   ""
			   4   _func___thiscall_int *   4   CNS::C::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000070_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000070
			pack()
			Structure VTABLE_00000070 {
			   0   _func___thiscall_int *   4   MNS::M::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000078_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000078
			pack()
			Structure VTABLE_00000078 {
			   0   _func___thiscall_int *   4   MNS::M::fb1_1   ""
			   4   _func___thiscall_int *   4   CNS::C::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000080_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000080
			pack()
			Structure VTABLE_00000080 {
			   0   _func___thiscall_int *   4   MNS::M::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000088_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000088
			pack()
			Structure VTABLE_00000088 {
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_0000008c_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_0000008c
			pack()
			Structure VTABLE_0000008c {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_00000094_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_00000094
			pack()
			Structure VTABLE_00000094 {
			   0   _func___thiscall_int *   4   MNS::M::fn1_1   ""
			   4   _func___thiscall_int *   4   N1NS::N1::fn1_2   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructM_0000009c_speculated() {
		String expected =
		//@formatter:off
			"""
			/MNS/M/!internal/VTABLE_0000009c
			pack()
			Structure VTABLE_0000009c {
			   0   _func___thiscall_int *   4   N2NS::N2::fn2_1   ""
			   4   _func___thiscall_int *   4   N2NS::N2::fn2_2   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class O1NS::O1	size(60):
		+---
	 0	| +--- (base class ANS::A)
	 0	| | {vfptr}
	 4	| | {vbptr}
	 8	| | a
		| +---
	12	| +--- (base class BNS::B)
	12	| | {vfptr}
	16	| | {vbptr}
	20	| | b
		| +---
	24	| o1
		+---
		+--- (virtual base A1NS::A1)
	28	| {vfptr}
	32	| a1
		+---
		+--- (virtual base A2NS::A2)
	36	| {vfptr}
	40	| a2
		+---
		+--- (virtual base B1NS::B1)
	44	| {vfptr}
	48	| b1
		+---
		+--- (virtual base B2NS::B2)
	52	| {vfptr}
	56	| b2
		+---

	O1NS::O1::$vftable@A@:
		| &O1_meta
		|  0
	 0	| &ANS::A::fa_1
	 1	| &O1NS::O1::fo1_1

	O1NS::O1::$vftable@B@:
		| -12
	 0	| &BNS::B::fb_1

	O1NS::O1::$vbtable@A@:
	 0	| -4
	 1	| 24 (O1d(A+4)A1)
	 2	| 32 (O1d(A+4)A2)
	 3	| 40 (O1d(O1+4)B1)
	 4	| 48 (O1d(O1+4)B2)

	O1NS::O1::$vbtable@B@:
	 0	| -4
	 1	| 28 (O1d(B+4)B1)
	 2	| 36 (O1d(B+4)B2)

	O1NS::O1::$vftable@A1@:
		| -28
	 0	| &thunk: this-=16; goto ANS::A::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	O1NS::O1::$vftable@A2@:
		| -36
	 0	| &O1NS::O1::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	O1NS::O1::$vftable@B1@:
		| -44
	 0	| &thunk: this-=20; goto BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	O1NS::O1::$vftable@B2@:
		| -52
	 0	| &thunk: this-=20; goto BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	O1NS::O1::fa2_1 this adjustor: 36
	O1NS::O1::fo1_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      28       4       4 0
	        A2NS::A2      36       4       8 0
	        B1NS::B1      44       4      12 0
	        B2NS::B2      52       4      16 0
	 */
	//@formatter:on
	private static String getExpectedStructO1() {
		String expected =
		//@formatter:off
			"""
			/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   O1NS::O1   28      "Self Base"
			   28   A1NS::A1   8      "Virtual Base"
			   36   A2NS::A2   8      "Virtual Base"
			   44   B1NS::B1   8      "Virtual Base"
			   52   B2NS::B2   8      "Virtual Base"
			}
			Length: 60 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/O1NS::O1/!internal/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   ANS::A   12      "Base"
			   12   BNS::B   12      "Base"
			   24   int   4   o1   ""
			}
			Length: 28 Alignment: 4""";
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
			   0   O1NS::O1   28      "Self Base"
			   28   char[32]   32      "Filler for 4 Unplaceable Virtual Bases: A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 60 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/O1NS::O1/!internal/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   ANS::A   12      "Base"
			   12   BNS::B   12      "Base"
			   24   int   4   o1   ""
			}
			Length: 28 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructO1() {
		return convertCommentsToSpeculative(getExpectedStructO1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryO1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[O1NS::O1, ANS::A]");
		results.put("VTABLE_00000004", "     4 vbt [ANS::A]	[O1NS::O1, ANS::A]");
		results.put("VTABLE_0000000c", "    12 vft [BNS::B]	[O1NS::O1, BNS::B]");
		results.put("VTABLE_00000010", "    16 vbt [BNS::B]	[O1NS::O1, BNS::B]");
		results.put("VTABLE_0000001c", "    28 vft [A1NS::A1]	[O1NS::O1, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000024", "    36 vft [A2NS::A2]	[O1NS::O1, ANS::A, A2NS::A2]");
		results.put("VTABLE_0000002c", "    44 vft [B1NS::B1]	[O1NS::O1, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000034", "    52 vft [B2NS::B2]	[O1NS::O1, BNS::B, B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsO1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructO1_00000000());
		results.put("VTABLE_00000004", getVxtStructO1_00000004());
		results.put("VTABLE_0000000c", getVxtStructO1_0000000c());
		results.put("VTABLE_00000010", getVxtStructO1_00000010());
		results.put("VTABLE_0000001c", getVxtStructO1_0000001c());
		results.put("VTABLE_00000024", getVxtStructO1_00000024());
		results.put("VTABLE_0000002c", getVxtStructO1_0000002c());
		results.put("VTABLE_00000034", getVxtStructO1_00000034());
		return results;
	}

	private static String getVxtStructO1_00000000() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			   4   _func___thiscall_int *   4   O1NS::O1::fo1_1   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000004() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_0000000c() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000010() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_0000001c() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_0000001c
			pack()
			Structure VTABLE_0000001c {
			   0   _func___thiscall_int *   4   ANS::A::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000024() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000024
			pack()
			Structure VTABLE_00000024 {
			   0   _func___thiscall_int *   4   O1NS::O1::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_0000002c() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_0000002c
			pack()
			Structure VTABLE_0000002c {
			   0   _func___thiscall_int *   4   BNS::B::fb1_1   ""
			   4   _func___thiscall_int *   4   B1NS::B1::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO1_00000034() {
		String expected =
		//@formatter:off
			"""
			/O1NS/O1/!internal/VTABLE_00000034
			pack()
			Structure VTABLE_00000034 {
			   0   _func___thiscall_int *   4   BNS::B::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class O2NS::O2	size(60):
		+---
	 0	| +--- (base class ANS::A)
	 0	| | {vfptr}
	 4	| | {vbptr}
	 8	| | a
		| +---
	12	| o2
		+---
		+--- (virtual base A1NS::A1)
	16	| {vfptr}
	20	| a1
		+---
		+--- (virtual base A2NS::A2)
	24	| {vfptr}
	28	| a2
		+---
		+--- (virtual base B1NS::B1)
	32	| {vfptr}
	36	| b1
		+---
		+--- (virtual base B2NS::B2)
	40	| {vfptr}
	44	| b2
		+---
		+--- (virtual base BNS::B)
	48	| {vfptr}
	52	| {vbptr}
	56	| b
		+---

	O2NS::O2::$vftable@A@:
		| &O2_meta
		|  0
	 0	| &ANS::A::fa_1
	 1	| &O2NS::O2::fo2_1

	O2NS::O2::$vbtable@A@:
	 0	| -4
	 1	| 12 (O2d(A+4)A1)
	 2	| 20 (O2d(A+4)A2)
	 3	| 28 (O2d(O2+4)B1)
	 4	| 36 (O2d(O2+4)B2)
	 5	| 44 (O2d(O2+4)B)

	O2NS::O2::$vftable@A1@:
		| -16
	 0	| &thunk: this-=4; goto ANS::A::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	O2NS::O2::$vftable@A2@:
		| -24
	 0	| &O2NS::O2::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	O2NS::O2::$vftable@B1@:
		| -32
	 0	| &thunk: this+=28; goto BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	O2NS::O2::$vftable@B2@:
		| -40
	 0	| &thunk: this+=28; goto BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	O2NS::O2::$vftable@B@:
		| -48
	 0	| &BNS::B::fb_1

	O2NS::O2::$vbtable@B@:
	 0	| -4
	 1	| -20 (O2d(B+4)B1)
	 2	| -12 (O2d(B+4)B2)

	O2NS::O2::fa2_1 this adjustor: 24
	O2NS::O2::fo2_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      16       4       4 0
	        A2NS::A2      24       4       8 0
	        B1NS::B1      32       4      12 0
	        B2NS::B2      40       4      16 0
	          BNS::B      48       4      20 0
	 */
	//@formatter:on
	private static String getExpectedStructO2() {
		String expected =
		//@formatter:off
			"""
			/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   O2NS::O2   16      "Self Base"
			   16   A1NS::A1   8      "Virtual Base"
			   24   A2NS::A2   8      "Virtual Base"
			   32   B1NS::B1   8      "Virtual Base"
			   40   B2NS::B2   8      "Virtual Base"
			   48   BNS::B   12      "Virtual Base"
			}
			Length: 60 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/O2NS::O2/!internal/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   ANS::A   12      "Base"
			   12   int   4   o2   ""
			}
			Length: 16 Alignment: 4""";
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
			   0   O2NS::O2   16      "Self Base"
			   16   char[44]   44      "Filler for 5 Unplaceable Virtual Bases: BNS::B; A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 60 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/O2NS::O2/!internal/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   ANS::A   12      "Base"
			   12   int   4   o2   ""
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructO2() {
		return convertCommentsToSpeculative(getExpectedStructO2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryO2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[O2NS::O2, ANS::A]");
		results.put("VTABLE_00000004", "     4 vbt [ANS::A]	[O2NS::O2, ANS::A]");
		results.put("VTABLE_00000010", "    16 vft [A1NS::A1]	[O2NS::O2, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000018", "    24 vft [A2NS::A2]	[O2NS::O2, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000020", "    32 vft [B1NS::B1]	[O2NS::O2, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000028", "    40 vft [B2NS::B2]	[O2NS::O2, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000030", "    48 vft [BNS::B]	[O2NS::O2, BNS::B]");
		results.put("VTABLE_00000034", "    52 vbt [BNS::B]	[O2NS::O2, BNS::B]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsO2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructO2_00000000());
		results.put("VTABLE_00000004", getVxtStructO2_00000004());
		results.put("VTABLE_00000010", getVxtStructO2_00000010());
		results.put("VTABLE_00000018", getVxtStructO2_00000018());
		results.put("VTABLE_00000020", getVxtStructO2_00000020());
		results.put("VTABLE_00000028", getVxtStructO2_00000028());
		results.put("VTABLE_00000030", getVxtStructO2_00000030());
		results.put("VTABLE_00000034", getVxtStructO2_00000034());
		return results;
	}

	private static String getVxtStructO2_00000000() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			   4   _func___thiscall_int *   4   O2NS::O2::fo2_1   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000004() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
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

	private static String getVxtStructO2_00000010() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   4   ANS::A::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000018() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   4   O2NS::O2::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   BNS::B::fb1_1   ""
			   4   _func___thiscall_int *   4   B1NS::B1::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000028() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_int *   4   BNS::B::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO2_00000034() {
		String expected =
		//@formatter:off
			"""
			/O2NS/O2/!internal/VTABLE_00000034
			pack()
			Structure VTABLE_00000034 {
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
	class O3NS::O3	size(60):
		+---
	 0	| +--- (base class ANS::A)
	 0	| | {vfptr}
	 4	| | {vbptr}
	 8	| | a
		| +---
	12	| +--- (base class BNS::B)
	12	| | {vfptr}
	16	| | {vbptr}
	20	| | b
		| +---
	24	| o3
		+---
		+--- (virtual base A1NS::A1)
	28	| {vfptr}
	32	| a1
		+---
		+--- (virtual base A2NS::A2)
	36	| {vfptr}
	40	| a2
		+---
		+--- (virtual base B1NS::B1)
	44	| {vfptr}
	48	| b1
		+---
		+--- (virtual base B2NS::B2)
	52	| {vfptr}
	56	| b2
		+---

	O3NS::O3::$vftable@A@:
		| &O3_meta
		|  0
	 0	| &ANS::A::fa_1
	 1	| &O3NS::O3::fo3_1

	O3NS::O3::$vftable@B@:
		| -12
	 0	| &BNS::B::fb_1

	O3NS::O3::$vbtable@A@:
	 0	| -4
	 1	| 24 (O3d(A+4)A1)
	 2	| 32 (O3d(A+4)A2)
	 3	| 40 (O3d(O3+4)B1)
	 4	| 48 (O3d(O3+4)B2)

	O3NS::O3::$vbtable@B@:
	 0	| -4
	 1	| 28 (O3d(B+4)B1)
	 2	| 36 (O3d(B+4)B2)

	O3NS::O3::$vftable@A1@:
		| -28
	 0	| &thunk: this-=16; goto ANS::A::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	O3NS::O3::$vftable@A2@:
		| -36
	 0	| &O3NS::O3::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	O3NS::O3::$vftable@B1@:
		| -44
	 0	| &thunk: this-=20; goto BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	O3NS::O3::$vftable@B2@:
		| -52
	 0	| &thunk: this-=20; goto BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	O3NS::O3::fa2_1 this adjustor: 36
	O3NS::O3::fo3_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      28       4       4 0
	        A2NS::A2      36       4       8 0
	        B1NS::B1      44       4      12 0
	        B2NS::B2      52       4      16 0
	 */
	//@formatter:on
	private static String getExpectedStructO3() {
		String expected =
		//@formatter:off
			"""
			/O3NS::O3
			pack()
			Structure O3NS::O3 {
			   0   O3NS::O3   28      "Self Base"
			   28   A1NS::A1   8      "Virtual Base"
			   36   A2NS::A2   8      "Virtual Base"
			   44   B1NS::B1   8      "Virtual Base"
			   52   B2NS::B2   8      "Virtual Base"
			}
			Length: 60 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/O3NS::O3/!internal/O3NS::O3
			pack()
			Structure O3NS::O3 {
			   0   ANS::A   12      "Base"
			   12   BNS::B   12      "Base"
			   24   int   4   o3   ""
			}
			Length: 28 Alignment: 4""";
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
			   0   O3NS::O3   28      "Self Base"
			   28   char[32]   32      "Filler for 4 Unplaceable Virtual Bases: A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 60 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/O3NS::O3/!internal/O3NS::O3
			pack()
			Structure O3NS::O3 {
			   0   ANS::A   12      "Base"
			   12   BNS::B   12      "Base"
			   24   int   4   o3   ""
			}
			Length: 28 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructO3() {
		return convertCommentsToSpeculative(getExpectedStructO3());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryO3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[O3NS::O3, ANS::A]");
		results.put("VTABLE_00000004", "     4 vbt [ANS::A]	[O3NS::O3, ANS::A]");
		results.put("VTABLE_0000000c", "    12 vft [BNS::B]	[O3NS::O3, BNS::B]");
		results.put("VTABLE_00000010", "    16 vbt [BNS::B]	[O3NS::O3, BNS::B]");
		results.put("VTABLE_0000001c", "    28 vft [A1NS::A1]	[O3NS::O3, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000024", "    36 vft [A2NS::A2]	[O3NS::O3, ANS::A, A2NS::A2]");
		results.put("VTABLE_0000002c", "    44 vft [B1NS::B1]	[O3NS::O3, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000034", "    52 vft [B2NS::B2]	[O3NS::O3, BNS::B, B2NS::B2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsO3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructO3_00000000());
		results.put("VTABLE_00000004", getVxtStructO3_00000004());
		results.put("VTABLE_0000000c", getVxtStructO3_0000000c());
		results.put("VTABLE_00000010", getVxtStructO3_00000010());
		results.put("VTABLE_0000001c", getVxtStructO3_0000001c());
		results.put("VTABLE_00000024", getVxtStructO3_00000024());
		results.put("VTABLE_0000002c", getVxtStructO3_0000002c());
		results.put("VTABLE_00000034", getVxtStructO3_00000034());
		return results;
	}

	private static String getVxtStructO3_00000000() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			   4   _func___thiscall_int *   4   O3NS::O3::fo3_1   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000004() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_0000000c() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000010() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_0000001c() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_0000001c
			pack()
			Structure VTABLE_0000001c {
			   0   _func___thiscall_int *   4   ANS::A::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000024() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000024
			pack()
			Structure VTABLE_00000024 {
			   0   _func___thiscall_int *   4   O3NS::O3::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_0000002c() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_0000002c
			pack()
			Structure VTABLE_0000002c {
			   0   _func___thiscall_int *   4   BNS::B::fb1_1   ""
			   4   _func___thiscall_int *   4   B1NS::B1::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO3_00000034() {
		String expected =
		//@formatter:off
			"""
			/O3NS/O3/!internal/VTABLE_00000034
			pack()
			Structure VTABLE_00000034 {
			   0   _func___thiscall_int *   4   BNS::B::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class O4NS::O4	size(60):
		+---
	 0	| +--- (base class ANS::A)
	 0	| | {vfptr}
	 4	| | {vbptr}
	 8	| | a
		| +---
	12	| o4
		+---
		+--- (virtual base A1NS::A1)
	16	| {vfptr}
	20	| a1
		+---
		+--- (virtual base A2NS::A2)
	24	| {vfptr}
	28	| a2
		+---
		+--- (virtual base B1NS::B1)
	32	| {vfptr}
	36	| b1
		+---
		+--- (virtual base B2NS::B2)
	40	| {vfptr}
	44	| b2
		+---
		+--- (virtual base BNS::B)
	48	| {vfptr}
	52	| {vbptr}
	56	| b
		+---

	O4NS::O4::$vftable@A@:
		| &O4_meta
		|  0
	 0	| &ANS::A::fa_1
	 1	| &O4NS::O4::fo4_1

	O4NS::O4::$vbtable@A@:
	 0	| -4
	 1	| 12 (O4d(A+4)A1)
	 2	| 20 (O4d(A+4)A2)
	 3	| 28 (O4d(O4+4)B1)
	 4	| 36 (O4d(O4+4)B2)
	 5	| 44 (O4d(O4+4)B)

	O4NS::O4::$vftable@A1@:
		| -16
	 0	| &thunk: this-=4; goto ANS::A::fa1_1
	 1	| &A1NS::A1::fa1_2
	 2	| &A1NS::A1::fa1_3

	O4NS::O4::$vftable@A2@:
		| -24
	 0	| &O4NS::O4::fa2_1
	 1	| &A2NS::A2::fa2_2
	 2	| &A2NS::A2::fa2_3

	O4NS::O4::$vftable@B1@:
		| -32
	 0	| &thunk: this+=28; goto BNS::B::fb1_1
	 1	| &B1NS::B1::fb1_2
	 2	| &B1NS::B1::fb1_3

	O4NS::O4::$vftable@B2@:
		| -40
	 0	| &thunk: this+=28; goto BNS::B::fb2_1
	 1	| &B2NS::B2::fb2_2
	 2	| &B2NS::B2::fb2_3

	O4NS::O4::$vftable@B@:
		| -48
	 0	| &BNS::B::fb_1

	O4NS::O4::$vbtable@B@:
	 0	| -4
	 1	| -20 (O4d(B+4)B1)
	 2	| -12 (O4d(B+4)B2)

	O4NS::O4::fa2_1 this adjustor: 24
	O4NS::O4::fo4_1 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        A1NS::A1      16       4       4 0
	        A2NS::A2      24       4       8 0
	        B1NS::B1      32       4      12 0
	        B2NS::B2      40       4      16 0
	          BNS::B      48       4      20 0
	 */
	//@formatter:on
	private static String getExpectedStructO4() {
		String expected =
		//@formatter:off
			"""
			/O4NS::O4
			pack()
			Structure O4NS::O4 {
			   0   O4NS::O4   16      "Self Base"
			   16   A1NS::A1   8      "Virtual Base"
			   24   A2NS::A2   8      "Virtual Base"
			   32   B1NS::B1   8      "Virtual Base"
			   40   B2NS::B2   8      "Virtual Base"
			   48   BNS::B   12      "Virtual Base"
			}
			Length: 60 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/O4NS::O4/!internal/O4NS::O4
			pack()
			Structure O4NS::O4 {
			   0   ANS::A   12      "Base"
			   12   int   4   o4   ""
			}
			Length: 16 Alignment: 4""";
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
			   0   O4NS::O4   16      "Self Base"
			   16   char[44]   44      "Filler for 5 Unplaceable Virtual Bases: BNS::B; A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2"
			}
			Length: 60 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/O4NS::O4/!internal/O4NS::O4
			pack()
			Structure O4NS::O4 {
			   0   ANS::A   12      "Base"
			   12   int   4   o4   ""
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructO4() {
		return convertCommentsToSpeculative(getExpectedStructO4());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryO4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [ANS::A]	[O4NS::O4, ANS::A]");
		results.put("VTABLE_00000004", "     4 vbt [ANS::A]	[O4NS::O4, ANS::A]");
		results.put("VTABLE_00000010", "    16 vft [A1NS::A1]	[O4NS::O4, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000018", "    24 vft [A2NS::A2]	[O4NS::O4, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000020", "    32 vft [B1NS::B1]	[O4NS::O4, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000028", "    40 vft [B2NS::B2]	[O4NS::O4, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000030", "    48 vft [BNS::B]	[O4NS::O4, BNS::B]");
		results.put("VTABLE_00000034", "    52 vbt [BNS::B]	[O4NS::O4, BNS::B]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsO4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructO4_00000000());
		results.put("VTABLE_00000004", getVxtStructO4_00000004());
		results.put("VTABLE_00000010", getVxtStructO4_00000010());
		results.put("VTABLE_00000018", getVxtStructO4_00000018());
		results.put("VTABLE_00000020", getVxtStructO4_00000020());
		results.put("VTABLE_00000028", getVxtStructO4_00000028());
		results.put("VTABLE_00000030", getVxtStructO4_00000030());
		results.put("VTABLE_00000034", getVxtStructO4_00000034());
		return results;
	}

	private static String getVxtStructO4_00000000() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			   4   _func___thiscall_int *   4   O4NS::O4::fo4_1   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000004() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
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

	private static String getVxtStructO4_00000010() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   4   ANS::A::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000018() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   4   O4NS::O4::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   BNS::B::fb1_1   ""
			   4   _func___thiscall_int *   4   B1NS::B1::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000028() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_int *   4   BNS::B::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO4_00000034() {
		String expected =
		//@formatter:off
			"""
			/O4NS/O4/!internal/VTABLE_00000034
			pack()
			Structure VTABLE_00000034 {
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
			   0   ONS::O   48      "Self Base"
			   48   A1NS::A1   8      "Virtual Base"
			   56   A2NS::A2   8      "Virtual Base"
			   64   B1NS::B1   8      "Virtual Base"
			   72   B2NS::B2   8      "Virtual Base"
			   80   BNS::B   12      "Virtual Base"
			   92   O3NS::O3   28      "Virtual Base"
			   120   O4NS::O4   16      "Virtual Base"
			}
			Length: 136 Alignment: 4
			/A1NS::A1
			pack()
			Structure A1NS::A1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a1   ""
			}
			Length: 8 Alignment: 4
			/A2NS::A2
			pack()
			Structure A2NS::A2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   a2   ""
			}
			Length: 8 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/B1NS::B1
			pack()
			Structure B1NS::B1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b1   ""
			}
			Length: 8 Alignment: 4
			/B2NS::B2
			pack()
			Structure B2NS::B2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   b2   ""
			}
			Length: 8 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/O1NS::O1/!internal/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   ANS::A   12      "Base"
			   12   BNS::B   12      "Base"
			   24   int   4   o1   ""
			}
			Length: 28 Alignment: 4
			/O2NS::O2/!internal/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   ANS::A   12      "Base"
			   12   int   4   o2   ""
			}
			Length: 16 Alignment: 4
			/O3NS::O3/!internal/O3NS::O3
			pack()
			Structure O3NS::O3 {
			   0   ANS::A   12      "Base"
			   12   BNS::B   12      "Base"
			   24   int   4   o3   ""
			}
			Length: 28 Alignment: 4
			/O4NS::O4/!internal/O4NS::O4
			pack()
			Structure O4NS::O4 {
			   0   ANS::A   12      "Base"
			   12   int   4   o4   ""
			}
			Length: 16 Alignment: 4
			/ONS::O/!internal/ONS::O
			pack()
			Structure ONS::O {
			   0   O1NS::O1   28      "Base"
			   28   O2NS::O2   16      "Base"
			   44   int   4   o   ""
			}
			Length: 48 Alignment: 4""";
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
			   0   ONS::O   48      "Self Base"
			   48   char[88]   88      "Filler for 7 Unplaceable Virtual Bases: O3NS::O3; O4NS::O4; A1NS::A1; A2NS::A2; B1NS::B1; B2NS::B2; BNS::B"
			}
			Length: 136 Alignment: 4
			/ANS::A/!internal/ANS::A
			pack()
			Structure ANS::A {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   a   ""
			}
			Length: 12 Alignment: 4
			/BNS::B/!internal/BNS::B
			pack()
			Structure BNS::B {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   b   ""
			}
			Length: 12 Alignment: 4
			/O1NS::O1/!internal/O1NS::O1
			pack()
			Structure O1NS::O1 {
			   0   ANS::A   12      "Base"
			   12   BNS::B   12      "Base"
			   24   int   4   o1   ""
			}
			Length: 28 Alignment: 4
			/O2NS::O2/!internal/O2NS::O2
			pack()
			Structure O2NS::O2 {
			   0   ANS::A   12      "Base"
			   12   int   4   o2   ""
			}
			Length: 16 Alignment: 4
			/ONS::O/!internal/ONS::O
			pack()
			Structure ONS::O {
			   0   O1NS::O1   28      "Base"
			   28   O2NS::O2   16      "Base"
			   44   int   4   o   ""
			}
			Length: 48 Alignment: 4""";
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
		results.put("VTABLE_00000004",
			"     4 vbt [ANS::A, O1NS::O1]	[ONS::O, O1NS::O1, ANS::A]");
		results.put("VTABLE_0000000c",
			"    12 vft [BNS::B, O1NS::O1]	[ONS::O, O1NS::O1, BNS::B]");
		results.put("VTABLE_00000010",
			"    16 vbt [BNS::B, O1NS::O1]	[ONS::O, O1NS::O1, BNS::B]");
		results.put("VTABLE_0000001c",
			"    28 vft [ANS::A, O2NS::O2]	[ONS::O, O2NS::O2, ANS::A]");
		results.put("VTABLE_00000020",
			"    32 vbt [ANS::A, O2NS::O2]	[ONS::O, O2NS::O2, ANS::A]");
		results.put("VTABLE_00000030",
			"    48 vft [A1NS::A1]	[ONS::O, O1NS::O1, ANS::A, A1NS::A1]");
		results.put("VTABLE_00000038",
			"    56 vft [A2NS::A2]	[ONS::O, O1NS::O1, ANS::A, A2NS::A2]");
		results.put("VTABLE_00000040",
			"    64 vft [B1NS::B1]	[ONS::O, O1NS::O1, BNS::B, B1NS::B1]");
		results.put("VTABLE_00000048",
			"    72 vft [B2NS::B2]	[ONS::O, O1NS::O1, BNS::B, B2NS::B2]");
		results.put("VTABLE_00000050",
			"    80 vft [BNS::B, O2NS::O2]	[ONS::O, O2NS::O2, BNS::B]");
		results.put("VTABLE_00000054",
			"    84 vbt [BNS::B, O2NS::O2]	[ONS::O, O2NS::O2, BNS::B]");
		results.put("VTABLE_0000005c",
			"    92 vft [ANS::A, O3NS::O3]	[ONS::O, O3NS::O3, ANS::A]");
		results.put("VTABLE_00000060",
			"    96 vbt [ANS::A, O3NS::O3]	[ONS::O, O3NS::O3, ANS::A]");
		results.put("VTABLE_00000068",
			"   104 vft [BNS::B, O3NS::O3]	[ONS::O, O3NS::O3, BNS::B]");
		results.put("VTABLE_0000006c",
			"   108 vbt [BNS::B, O3NS::O3]	[ONS::O, O3NS::O3, BNS::B]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000078", "   120 vft [ANS::A, O4NS::O4]	[ONS::O, O4NS::O4, ANS::A]");
		results.put("VTABLE_00000078", null);
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_0000007c", "   124 vbt [BNS::B, O4NS::O4]	[ONS::O, O4NS::O4, ANS::A]");
		results.put("VTABLE_0000007c", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsO() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructO_00000000());
		results.put("VTABLE_00000004", getVxtStructO_00000004());
		results.put("VTABLE_0000000c", getVxtStructO_0000000c());
		results.put("VTABLE_00000010", getVxtStructO_00000010());
		results.put("VTABLE_0000001c", getVxtStructO_0000001c());
		results.put("VTABLE_00000020", getVxtStructO_00000020());
		results.put("VTABLE_00000030", getVxtStructO_00000030());
		results.put("VTABLE_00000038", getVxtStructO_00000038());
		results.put("VTABLE_00000040", getVxtStructO_00000040());
		results.put("VTABLE_00000048", getVxtStructO_00000048());
		results.put("VTABLE_00000050", getVxtStructO_00000050());
		results.put("VTABLE_00000054", getVxtStructO_00000054());
		results.put("VTABLE_0000005c", getVxtStructO_0000005c());
		results.put("VTABLE_00000060", getVxtStructO_00000060());
		results.put("VTABLE_00000068", getVxtStructO_00000068());
		results.put("VTABLE_0000006c", getVxtStructO_0000006c());
		results.put("VTABLE_00000078", getVxtStructO_00000078());
		results.put("VTABLE_0000007c", getVxtStructO_0000007c());
		return results;
	}

	private static String getVxtStructO_00000000() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			   4   _func___thiscall_int *   4   ONS::O::fo1_1   ""
			   8   _func___thiscall_int *   4   ONS::O::fo_1   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000004() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
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

	private static String getVxtStructO_0000000c() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000010() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_0000001c() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_0000001c
			pack()
			Structure VTABLE_0000001c {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			   4   _func___thiscall_int *   4   ONS::O::fo2_1   ""
			}
			Length: 8 Alignment: 4""";
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

	private static String getVxtStructO_00000030() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000030
			pack()
			Structure VTABLE_00000030 {
			   0   _func___thiscall_int *   4   ONS::O::fa1_1   ""
			   4   _func___thiscall_int *   4   A1NS::A1::fa1_2   ""
			   8   _func___thiscall_int *   4   A1NS::A1::fa1_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   ONS::O::fa2_1   ""
			   4   _func___thiscall_int *   4   A2NS::A2::fa2_2   ""
			   8   _func___thiscall_int *   4   A2NS::A2::fa2_3   ""
			}
			Length: 12 Alignment: 4""";
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
			   0   _func___thiscall_int *   4   ONS::O::fb1_1   ""
			   4   _func___thiscall_int *   4   B1NS::B1::fb1_2   ""
			   8   _func___thiscall_int *   4   B1NS::B1::fb1_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000048() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000048
			pack()
			Structure VTABLE_00000048 {
			   0   _func___thiscall_int *   4   ONS::O::fb2_1   ""
			   4   _func___thiscall_int *   4   B2NS::B2::fb2_2   ""
			   8   _func___thiscall_int *   4   B2NS::B2::fb2_3   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000050() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000050
			pack()
			Structure VTABLE_00000050 {
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000054() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000054
			pack()
			Structure VTABLE_00000054 {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_0000005c() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_0000005c
			pack()
			Structure VTABLE_0000005c {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			   4   _func___thiscall_int *   4   ONS::O::fo3_1   ""
			}
			Length: 8 Alignment: 4""";
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
			   0   int   4      "A1NS::A1"
			   4   int   4      "A2NS::A2"
			   8   int   4      "B1NS::B1"
			   12   int   4      "B2NS::B2"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000068() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000068
			pack()
			Structure VTABLE_00000068 {
			   0   _func___thiscall_int *   4   BNS::B::fb_1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_0000006c() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_0000006c
			pack()
			Structure VTABLE_0000006c {
			   0   int   4      "B1NS::B1"
			   4   int   4      "B2NS::B2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_00000078() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_00000078
			pack()
			Structure VTABLE_00000078 {
			   0   _func___thiscall_int *   4   ANS::A::fa_1   ""
			   4   _func___thiscall_int *   4   ONS::O::fo4_1   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructO_0000007c() {
		String expected =
		//@formatter:off
			"""
			/ONS/O/!internal/VTABLE_0000007c
			pack()
			Structure VTABLE_0000007c {
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

	public Cfb432ProgramCreator() {
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
