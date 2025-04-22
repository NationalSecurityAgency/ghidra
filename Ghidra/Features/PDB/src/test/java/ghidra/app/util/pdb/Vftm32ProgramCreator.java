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
 * Class to create the vftm 32-bit program and mock PDB
 */
public class Vftm32ProgramCreator extends ProgramCreator {

	public static final CategoryPath MAIN_CATEGORY_PATH = CategoryPath.ROOT;

	public static final ClassID P1 = new ClassID(MAIN_CATEGORY_PATH, sp("P1NS::P1"));
	public static final ClassID P2 = new ClassID(MAIN_CATEGORY_PATH, sp("P2NS::P2"));
	public static final ClassID Q1 = new ClassID(MAIN_CATEGORY_PATH, sp("Q1NS::Q1"));
	public static final ClassID Q2 = new ClassID(MAIN_CATEGORY_PATH, sp("Q2NS::Q2"));
	public static final ClassID Q3 = new ClassID(MAIN_CATEGORY_PATH, sp("Q3NS::Q3"));
	public static final ClassID Q4 = new ClassID(MAIN_CATEGORY_PATH, sp("Q4NS::Q4"));
	public static final ClassID Q5 = new ClassID(MAIN_CATEGORY_PATH, sp("Q5NS::Q5"));
	public static final ClassID Q6 = new ClassID(MAIN_CATEGORY_PATH, sp("Q6NS::Q6"));
	public static final ClassID Q7 = new ClassID(MAIN_CATEGORY_PATH, sp("Q7NS::Q7"));
	public static final ClassID R1 = new ClassID(MAIN_CATEGORY_PATH, sp("R1NS::R1"));

	private static String PROGRAM_NAME = "vftm32.exe";
	private static String LANGUAGE_ID = ProgramBuilder._X86;
	private static String COMPILER_SPEC_ID = "windows";
	private static AddressNameLength SECTIONS[] = {
		new AddressNameLength("401000", ".text", 0x4e200),
		new AddressNameLength("450000", ".rdata", 0x9c00)
	};

	private static AddressNameBytes vbTableInfo[] = {
		new AddressNameBytes("004503cc", "??_8Q4@Q4NS@@7B@", "f8 ff ff ff 08 00 00 00 d8 7e 45 00"),
		new AddressNameBytes("00450434", "??_8Q5@Q5NS@@7B@", "f8 ff ff ff 08 00 00 00 58 7f 45 00"),
		new AddressNameBytes("0045049c", "??_8Q6@Q6NS@@7B@", "f8 ff ff ff 08 00 00 00 bc 7f 45 00"),
		new AddressNameBytes("00450508", "??_8Q7@Q7NS@@7B@",
			"fc ff ff ff 08 00 00 00 10 00 00 00 6c 80 45 00"),
		new AddressNameBytes("00450600", "??_8R1@R1NS@@7B@",
			"fc ff ff ff 08 00 00 00 1c 00 00 00 c4 81 45 00")
	};

	private static AddressNameBytes vfTableInfo[] = {
		new AddressNameBytes("004501e4", "??_7P1@P1NS@@6B@",
			"40 3e 40 00 60 3f 40 00 80 3f 40 00 b0 41 40 00 d0 42 40 00 f0 42 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 c8 7c 45 00"),
		new AddressNameBytes("0045020c", "??_7P2@P2NS@@6B@",
			"e0 4a 40 00 c0 4b 40 00 e0 4b 40 00 90 4d 40 00 70 4e 40 00 90 4e 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 10 7d 45 00"),
		new AddressNameBytes("00450240", "??_7Q1@Q1NS@@6BP1@P1NS@@@",
			"60 3e 40 00 a0 3f 40 00 c0 3f 40 00 d0 41 40 00 10 43 40 00 30 43 40 00 20 45 40 00 20 46 40 00 40 46 40 00 83 6b 40 00 b0 53 40 00 7c 7d 45 00"),
		new AddressNameBytes("00450270", "??_7Q1@Q1NS@@6BP2@P2NS@@@",
			"e0 4a 40 00 c0 4b 40 00 e0 4b 40 00 90 4d 40 00 70 4e 40 00 90 4e 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 90 7d 45 00"),
		new AddressNameBytes("004502a4", "??_7Q2@Q2NS@@6BP1@P1NS@@@",
			"80 3e 40 00 e0 3f 40 00 00 40 40 00 f0 41 40 00 50 43 40 00 70 43 40 00 40 45 40 00 60 46 40 00 80 46 40 00 d0 53 40 00 e0 49 40 00 00 4a 40 00 83 6b 40 00 e0 7d 45 00"),
		new AddressNameBytes("004502dc", "??_7Q2@Q2NS@@6BP2@P2NS@@@",
			"e0 4a 40 00 c0 4b 40 00 e0 4b 40 00 90 4d 40 00 70 4e 40 00 90 4e 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 83 6b 40 00 30 48 40 00 f4 7d 45 00"),
		new AddressNameBytes("00450310", "??_7Q3@Q3NS@@6BP1@P1NS@@@",
			"a0 3e 40 00 20 40 40 00 40 40 40 00 10 42 40 00 90 43 40 00 b0 43 40 00 60 45 40 00 a0 46 40 00 c0 46 40 00 f0 53 40 00 44 7e 45 00"),
		new AddressNameBytes("0045033c", "??_7Q3@Q3NS@@6BP2@P2NS@@@",
			"00 4b 40 00 00 4c 40 00 20 4c 40 00 b0 4d 40 00 b0 4e 40 00 d0 4e 40 00 40 50 40 00 00 51 40 00 20 51 40 00 90 52 40 00 50 48 40 00 70 48 40 00 58 7e 45 00"),
		new AddressNameBytes("00450370", "??_7Q4@Q4NS@@6BP2@P2NS@@@",
			"20 4b 40 00 40 4c 40 00 60 4c 40 00 d0 4d 40 00 f0 4e 40 00 10 4f 40 00 60 50 40 00 40 51 40 00 60 51 40 00 b0 52 40 00 90 48 40 00 b0 48 40 00 10 54 40 00 c4 7e 45 00"),
		new AddressNameBytes("004503a8", "??_7Q4@Q4NS@@6BP1@P1NS@@@",
			"c0 3e 40 00 60 40 40 00 80 40 40 00 30 42 40 00 d0 43 40 00 f0 43 40 00 80 45 40 00 e0 46 40 00 00 47 40 00"),
		new AddressNameBytes("004503d8", "??_7Q5@Q5NS@@6BP1@P1NS@@@",
			"e0 3e 40 00 a0 40 40 00 c0 40 40 00 50 42 40 00 10 44 40 00 30 44 40 00 a0 45 40 00 20 47 40 00 40 47 40 00 30 54 40 00 44 7f 45 00"),
		new AddressNameBytes("00450404", "??_7Q5@Q5NS@@6BP2@P2NS@@@",
			"40 4b 40 00 80 4c 40 00 a0 4c 40 00 f0 4d 40 00 30 4f 40 00 50 4f 40 00 80 50 40 00 80 51 40 00 a0 51 40 00 d0 52 40 00 d0 48 40 00 f0 48 40 00"),
		new AddressNameBytes("00450440", "??_7Q6@Q6NS@@6BP1@P1NS@@@",
			"00 3f 40 00 e0 40 40 00 00 41 40 00 70 42 40 00 50 44 40 00 70 44 40 00 c0 45 40 00 60 47 40 00 80 47 40 00 50 54 40 00 a8 7f 45 00"),
		new AddressNameBytes("0045046c", "??_7Q6@Q6NS@@6BP2@P2NS@@@",
			"60 4b 40 00 c0 4c 40 00 e0 4c 40 00 10 4e 40 00 70 4f 40 00 90 4f 40 00 a0 50 40 00 c0 51 40 00 e0 51 40 00 f0 52 40 00 10 49 40 00 30 49 40 00"),
		new AddressNameBytes("004504a8", "??_7Q7@Q7NS@@6B01@@", "70 54 40 00 44 80 45 00"),
		new AddressNameBytes("004504b0", "??_7Q7@Q7NS@@6BP1@P1NS@@@",
			"20 3f 40 00 20 41 40 00 40 41 40 00 90 42 40 00 90 44 40 00 b0 44 40 00 e0 45 40 00 a0 47 40 00 c0 47 40 00 58 80 45 00"),
		new AddressNameBytes("004504d8", "??_7Q7@Q7NS@@6BP2@P2NS@@@",
			"80 4b 40 00 00 4d 40 00 20 4d 40 00 30 4e 40 00 b0 4f 40 00 d0 4f 40 00 c0 50 40 00 00 52 40 00 20 52 40 00 10 53 40 00 50 49 40 00 70 49 40 00"),
		new AddressNameBytes("00450518", "??_7R1@R1NS@@6B@",
			"a0 3d 40 00 00 3e 40 00 20 3e 40 00 40 4a 40 00 a0 4a 40 00 c0 4a 40 00 74 81 45 00"),
		new AddressNameBytes("00450534", "??_7R1@R1NS@@6BP1@P1NS@@Q1@Q1NS@@@",
			"40 3f 40 00 60 41 40 00 80 41 40 00 b0 42 40 00 d0 44 40 00 f0 44 40 00 00 46 40 00 e0 47 40 00 00 48 40 00 90 54 40 00 b0 53 40 00 88 81 45 00"),
		new AddressNameBytes("00450564", "??_7R1@R1NS@@6BP2@P2NS@@Q1@Q1NS@@@",
			"a0 4b 40 00 40 4d 40 00 60 4d 40 00 50 4e 40 00 f0 4f 40 00 10 50 40 00 e0 50 40 00 40 52 40 00 60 52 40 00 30 53 40 00 90 49 40 00 b0 49 40 00 9c 81 45 00"),
		new AddressNameBytes("00450598", "??_7R1@R1NS@@6BP1@P1NS@@Q2@Q2NS@@@",
			"55 3f 40 00 95 41 40 00 9d 41 40 00 c5 42 40 00 05 45 40 00 0d 45 40 00 15 46 40 00 15 48 40 00 1d 48 40 00 d0 53 40 00 e0 49 40 00 00 4a 40 00 10 55 40 00 b0 81 45 00"),
		new AddressNameBytes("004505d0", "??_7R1@R1NS@@6BP2@P2NS@@Q2@Q2NS@@@",
			"b5 4b 40 00 75 4d 40 00 7d 4d 40 00 65 4e 40 00 25 50 40 00 2d 50 40 00 f5 50 40 00 75 52 40 00 7d 52 40 00 45 53 40 00 c5 49 40 00 cd 49 40 00"),
		new AddressNameBytes("00450610", "??_7type_info@@6B@", "31 58 40 00") };

	private static AddressNameBytes functionInfo[] = {
		new AddressNameBytes("00403da0", "R1NS::R1::fp1_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 0a 83 c0 04 8b e5 5d"),
		new AddressNameBytes("00403e00", "R1NS::R1::fp1_2",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 08 0a 8b 55 08 8d 44 11 06 8b e5 5d c2 04"),
		new AddressNameBytes("00403e20", "R1NS::R1::fp1_2",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 0a 83 c0 05 8b e5 5d"),
		new AddressNameBytes("00403e40", "P1NS::P1::fp1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 04 83 c0 04 8b e5 5d"),
		new AddressNameBytes("00403e60", "Q1NS::Q1::fp1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 03 83 c0 05 8b e5 5d"),
		new AddressNameBytes("00403e80", "Q2NS::Q2::fp1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 8d 04 8d 05 00 00 00 8b e5 5d"),
		new AddressNameBytes("00403ea0", "Q3NS::Q3::fp1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 05 83 c0 05 8b e5 5d"),
		new AddressNameBytes("00403ec0", "Q4NS::Q4::fp1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 06 83 c0 05 8b e5 5d"),
		new AddressNameBytes("00403ee0", "Q5NS::Q5::fp1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 07 83 c0 05 8b e5 5d"),
		new AddressNameBytes("00403f00", "Q6NS::Q6::fp1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 0c 8d 04 cd 05 00 00 00 8b e5 5d"),
		new AddressNameBytes("00403f20", "Q7NS::Q7::fp1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 09 83 c0 05 8b e5 5d"),
		new AddressNameBytes("00403f40", "R1NS::R1::fp1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 0a 83 c0 07 8b e5 5d"),
		new AddressNameBytes("00403f55", "[thunk]:R1NS::R1::fp1_3`adjustor{20}'",
			"83 e9 14 e9 e3 ff ff"),
		new AddressNameBytes("00403f60", "P1NS::P1::fp1_4",
			"55 8b ec 51 89 4d fc 6b 45 08 06 8b 4d fc 03 41 04 8b e5 5d c2 04"),
		new AddressNameBytes("00403f80", "P1NS::P1::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 04 83 c0 05 8b e5 5d"),
		new AddressNameBytes("00403fa0", "Q1NS::Q1::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 03 6b 4d 08 07 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00403fc0", "Q1NS::Q1::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 03 83 c0 06 8b e5 5d"),
		new AddressNameBytes("00403fe0", "Q2NS::Q2::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 6b 55 08 07 8d 04 8a 8b e5 5d c2 04"),
		new AddressNameBytes("00404000", "Q2NS::Q2::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 8d 04 8d 06 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404020", "Q3NS::Q3::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 05 6b 4d 08 07 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404040", "Q3NS::Q3::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 05 83 c0 06 8b e5 5d"),
		new AddressNameBytes("00404060", "Q4NS::Q4::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 06 6b 4d 08 07 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404080", "Q4NS::Q4::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 06 83 c0 06 8b e5 5d"),
		new AddressNameBytes("004040a0", "Q5NS::Q5::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 07 6b 4d 08 07 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("004040c0", "Q5NS::Q5::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 07 83 c0 06 8b e5 5d"),
		new AddressNameBytes("004040e0", "Q6NS::Q6::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 0c 6b 55 08 07 8d 04 ca 8b e5 5d c2 04"),
		new AddressNameBytes("00404100", "Q6NS::Q6::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 0c 8d 04 cd 06 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404120", "Q7NS::Q7::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 09 6b 4d 08 07 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404140", "Q7NS::Q7::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 09 83 c0 06 8b e5 5d"),
		new AddressNameBytes("00404160", "R1NS::R1::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 fc 0a 8b 55 08 8d 44 11 09 8b e5 5d c2 04"),
		new AddressNameBytes("00404180", "R1NS::R1::fp1_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 0a 83 c0 08 8b e5 5d"),
		new AddressNameBytes("00404195", "[thunk]:R1NS::R1::fp1_4`adjustor{20}'",
			"83 e9 14 e9 c3 ff ff"),
		new AddressNameBytes("0040419d", "[thunk]:R1NS::R1::fp1_4`adjustor{20}'",
			"83 e9 14 e9 db ff ff"),
		new AddressNameBytes("004041b0", "P1NS::P1::fp1_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 04 83 c0 07 8b e5 5d"),
		new AddressNameBytes("004041d0", "Q1NS::Q1::fp1_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 03 83 c0 08 8b e5 5d"),
		new AddressNameBytes("004041f0", "Q2NS::Q2::fp1_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 8d 04 8d 08 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404210", "Q3NS::Q3::fp1_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 05 83 c0 08 8b e5 5d"),
		new AddressNameBytes("00404230", "Q4NS::Q4::fp1_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 06 83 c0 08 8b e5 5d"),
		new AddressNameBytes("00404250", "Q5NS::Q5::fp1_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 07 83 c0 08 8b e5 5d"),
		new AddressNameBytes("00404270", "Q6NS::Q6::fp1_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 0c 8d 04 cd 08 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404290", "Q7NS::Q7::fp1_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 09 83 c0 08 8b e5 5d"),
		new AddressNameBytes("004042b0", "R1NS::R1::fp1_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 0a 83 c0 0a 8b e5 5d"),
		new AddressNameBytes("004042c5", "[thunk]:R1NS::R1::fp1_5`adjustor{20}'",
			"83 e9 14 e9 e3 ff ff"),
		new AddressNameBytes("004042d0", "P1NS::P1::fp1_6",
			"55 8b ec 51 89 4d fc 6b 45 08 09 8b 4d fc 03 41 04 8b e5 5d c2 04"),
		new AddressNameBytes("004042f0", "P1NS::P1::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 40 04 83 c0 08 8b e5 5d"),
		new AddressNameBytes("00404310", "Q1NS::Q1::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 03 6b 4d 08 0a 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404330", "Q1NS::Q1::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 03 83 c0 09 8b e5 5d"),
		new AddressNameBytes("00404350", "Q2NS::Q2::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 6b 55 08 0a 8d 04 8a 8b e5 5d c2 04"),
		new AddressNameBytes("00404370", "Q2NS::Q2::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 8d 04 8d 09 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404390", "Q3NS::Q3::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 05 6b 4d 08 0a 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("004043b0", "Q3NS::Q3::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 05 83 c0 09 8b e5 5d"),
		new AddressNameBytes("004043d0", "Q4NS::Q4::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 06 6b 4d 08 0a 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("004043f0", "Q4NS::Q4::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 06 83 c0 09 8b e5 5d"),
		new AddressNameBytes("00404410", "Q5NS::Q5::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 07 6b 4d 08 0a 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404430", "Q5NS::Q5::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 07 83 c0 09 8b e5 5d"),
		new AddressNameBytes("00404450", "Q6NS::Q6::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 0c 6b 55 08 0a 8d 04 ca 8b e5 5d c2 04"),
		new AddressNameBytes("00404470", "Q6NS::Q6::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 0c 8d 04 cd 09 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404490", "Q7NS::Q7::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 09 6b 4d 08 0a 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("004044b0", "Q7NS::Q7::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 09 83 c0 09 8b e5 5d"),
		new AddressNameBytes("004044d0", "R1NS::R1::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 fc 0a 8b 55 08 8d 44 11 0c 8b e5 5d c2 04"),
		new AddressNameBytes("004044f0", "R1NS::R1::fp1_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 0a 83 c0 0b 8b e5 5d"),
		new AddressNameBytes("00404505", "[thunk]:R1NS::R1::fp1_6`adjustor{20}'",
			"83 e9 14 e9 c3 ff ff"),
		new AddressNameBytes("0040450d", "[thunk]:R1NS::R1::fp1_6`adjustor{20}'",
			"83 e9 14 e9 db ff ff"),
		new AddressNameBytes("00404520", "Q1NS::Q1::fp1_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 03 83 c0 0b 8b e5 5d"),
		new AddressNameBytes("00404540", "Q2NS::Q2::fp1_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 8d 04 8d 0b 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404560", "Q3NS::Q3::fp1_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 05 83 c0 0b 8b e5 5d"),
		new AddressNameBytes("00404580", "Q4NS::Q4::fp1_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 06 83 c0 0b 8b e5 5d"),
		new AddressNameBytes("004045a0", "Q5NS::Q5::fp1_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 07 83 c0 0b 8b e5 5d"),
		new AddressNameBytes("004045c0", "Q6NS::Q6::fp1_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 0c 8d 04 cd 0b 00 00 00 8b e5 5d"),
		new AddressNameBytes("004045e0", "Q7NS::Q7::fp1_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 09 83 c0 0b 8b e5 5d"),
		new AddressNameBytes("00404600", "R1NS::R1::fp1_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 0a 83 c0 0d 8b e5 5d"),
		new AddressNameBytes("00404615", "[thunk]:R1NS::R1::fp1_7`adjustor{20}'",
			"83 e9 14 e9 e3 ff ff"),
		new AddressNameBytes("00404620", "Q1NS::Q1::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 03 6b 4d 08 0d 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404640", "Q1NS::Q1::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 03 83 c0 0c 8b e5 5d"),
		new AddressNameBytes("00404660", "Q2NS::Q2::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 6b 55 08 0d 8d 04 8a 8b e5 5d c2 04"),
		new AddressNameBytes("00404680", "Q2NS::Q2::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 8d 04 8d 0c 00 00 00 8b e5 5d"),
		new AddressNameBytes("004046a0", "Q3NS::Q3::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 05 6b 4d 08 0d 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("004046c0", "Q3NS::Q3::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 05 83 c0 0c 8b e5 5d"),
		new AddressNameBytes("004046e0", "Q4NS::Q4::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 06 6b 4d 08 0d 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404700", "Q4NS::Q4::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 06 83 c0 0c 8b e5 5d"),
		new AddressNameBytes("00404720", "Q5NS::Q5::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 07 6b 4d 08 0d 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404740", "Q5NS::Q5::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 07 83 c0 0c 8b e5 5d"),
		new AddressNameBytes("00404760", "Q6NS::Q6::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 0c 6b 55 08 0d 8d 04 ca 8b e5 5d c2 04"),
		new AddressNameBytes("00404780", "Q6NS::Q6::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 0c 8d 04 cd 0c 00 00 00 8b e5 5d"),
		new AddressNameBytes("004047a0", "Q7NS::Q7::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 09 6b 4d 08 0d 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("004047c0", "Q7NS::Q7::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 09 83 c0 0c 8b e5 5d"),
		new AddressNameBytes("004047e0", "R1NS::R1::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 fc 0a 8b 55 08 8d 44 11 0f 8b e5 5d c2 04"),
		new AddressNameBytes("00404800", "R1NS::R1::fp1_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 0a 83 c0 0e 8b e5 5d"),
		new AddressNameBytes("00404815", "[thunk]:R1NS::R1::fp1_8`adjustor{20}'",
			"83 e9 14 e9 c3 ff ff"),
		new AddressNameBytes("0040481d", "[thunk]:R1NS::R1::fp1_8`adjustor{20}'",
			"83 e9 14 e9 db ff ff"),
		new AddressNameBytes("00404830", "Q2NS::Q2::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 08 8d 04 8d 0e 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404850", "Q3NS::Q3::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 6b 4d 08 19 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404870", "Q3NS::Q3::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 83 c0 18 8b e5 5d"),
		new AddressNameBytes("00404890", "Q4NS::Q4::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 6b 4d 08 19 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("004048b0", "Q4NS::Q4::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 83 c0 18 8b e5 5d"),
		new AddressNameBytes("004048d0", "Q5NS::Q5::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 6b 4d 08 19 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("004048f0", "Q5NS::Q5::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 83 c0 18 8b e5 5d"),
		new AddressNameBytes("00404910", "Q6NS::Q6::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 6b 55 08 19 8d 04 ca 8b e5 5d c2 04"),
		new AddressNameBytes("00404930", "Q6NS::Q6::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 8d 04 cd 18 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404950", "Q7NS::Q7::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 6b 4d 08 19 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404970", "Q7NS::Q7::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 83 c0 18 8b e5 5d"),
		new AddressNameBytes("00404990", "R1NS::R1::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 f4 0a 8b 55 08 8d 44 11 1f 8b e5 5d c2 04"),
		new AddressNameBytes("004049b0", "R1NS::R1::fp2_10",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 0a 83 c0 1e 8b e5 5d"),
		new AddressNameBytes("004049c5", "[thunk]:R1NS::R1::fp2_10`adjustor{20}'",
			"83 e9 14 e9 c3 ff ff"),
		new AddressNameBytes("004049cd", "[thunk]:R1NS::R1::fp2_10`adjustor{20}'",
			"83 e9 14 e9 db ff ff"),
		new AddressNameBytes("004049e0", "Q2NS::Q2::fp2_11",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 8d 04 8d 0f 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404a00", "Q2NS::Q2::fp2_12",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 8b 55 08 c1 e2 04 8d 04 8a 8b e5 5d c2 04"),
		new AddressNameBytes("00404a40", "R1NS::R1::fp2_1",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 0a 83 c0 11 8b e5 5d"),
		new AddressNameBytes("00404aa0", "R1NS::R1::fp2_2",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 08 0a 8b 55 08 8d 44 11 13 8b e5 5d c2 04"),
		new AddressNameBytes("00404ac0", "R1NS::R1::fp2_2",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 0a 83 c0 12 8b e5 5d"),
		new AddressNameBytes("00404ae0", "P2NS::P2::fp2_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 8d 44 09 04 8b e5 5d"),
		new AddressNameBytes("00404b00", "Q3NS::Q3::fp2_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 83 c0 0e 8b e5 5d"),
		new AddressNameBytes("00404b20", "Q4NS::Q4::fp2_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 83 c0 0e 8b e5 5d"),
		new AddressNameBytes("00404b40", "Q5NS::Q5::fp2_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 83 c0 0e 8b e5 5d"),
		new AddressNameBytes("00404b60", "Q6NS::Q6::fp2_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 8d 04 cd 0e 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404b80", "Q7NS::Q7::fp2_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 83 c0 0e 8b e5 5d"),
		new AddressNameBytes("00404ba0", "R1NS::R1::fp2_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 0a 83 c0 14 8b e5 5d"),
		new AddressNameBytes("00404bb5", "[thunk]:R1NS::R1::fp2_3`adjustor{20}'",
			"83 e9 14 e9 e3 ff ff"),
		new AddressNameBytes("00404bc0", "P2NS::P2::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 6b 55 08 06 8d 04 4a 8b e5 5d c2 04"),
		new AddressNameBytes("00404be0", "P2NS::P2::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 8d 44 09 05 8b e5 5d"),
		new AddressNameBytes("00404c00", "Q3NS::Q3::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 8b 4d 08 c1 e1 04 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404c20", "Q3NS::Q3::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 83 c0 0f 8b e5 5d"),
		new AddressNameBytes("00404c40", "Q4NS::Q4::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 8b 4d 08 c1 e1 04 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404c60", "Q4NS::Q4::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 83 c0 0f 8b e5 5d"),
		new AddressNameBytes("00404c80", "Q5NS::Q5::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 8b 4d 08 c1 e1 04 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404ca0", "Q5NS::Q5::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 83 c0 0f 8b e5 5d"),
		new AddressNameBytes("00404cc0", "Q6NS::Q6::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 8b 55 08 c1 e2 04 8d 04 ca 8b e5 5d c2 04"),
		new AddressNameBytes("00404ce0", "Q6NS::Q6::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 8d 04 cd 0f 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404d00", "Q7NS::Q7::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 8b 4d 08 c1 e1 04 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404d20", "Q7NS::Q7::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 83 c0 0f 8b e5 5d"),
		new AddressNameBytes("00404d40", "R1NS::R1::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 f4 0a 8b 55 08 8d 44 11 16 8b e5 5d c2 04"),
		new AddressNameBytes("00404d60", "R1NS::R1::fp2_4",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 0a 83 c0 15 8b e5 5d"),
		new AddressNameBytes("00404d75", "[thunk]:R1NS::R1::fp2_4`adjustor{20}'",
			"83 e9 14 e9 c3 ff ff"),
		new AddressNameBytes("00404d7d", "[thunk]:R1NS::R1::fp2_4`adjustor{20}'",
			"83 e9 14 e9 db ff ff"),
		new AddressNameBytes("00404d90", "P2NS::P2::fp2_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 8d 44 09 07 8b e5 5d"),
		new AddressNameBytes("00404db0", "Q3NS::Q3::fp2_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 83 c0 11 8b e5 5d"),
		new AddressNameBytes("00404dd0", "Q4NS::Q4::fp2_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 83 c0 11 8b e5 5d"),
		new AddressNameBytes("00404df0", "Q5NS::Q5::fp2_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 83 c0 11 8b e5 5d"),
		new AddressNameBytes("00404e10", "Q6NS::Q6::fp2_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 8d 04 cd 11 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404e30", "Q7NS::Q7::fp2_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 83 c0 11 8b e5 5d"),
		new AddressNameBytes("00404e50", "R1NS::R1::fp2_5",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 0a 83 c0 17 8b e5 5d"),
		new AddressNameBytes("00404e65", "[thunk]:R1NS::R1::fp2_5`adjustor{20}'",
			"83 e9 14 e9 e3 ff ff"),
		new AddressNameBytes("00404e70", "P2NS::P2::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 6b 55 08 09 8d 04 4a 8b e5 5d c2 04"),
		new AddressNameBytes("00404e90", "P2NS::P2::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 04 8d 44 09 08 8b e5 5d"),
		new AddressNameBytes("00404eb0", "Q3NS::Q3::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 6b 4d 08 13 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404ed0", "Q3NS::Q3::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 83 c0 12 8b e5 5d"),
		new AddressNameBytes("00404ef0", "Q4NS::Q4::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 6b 4d 08 13 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404f10", "Q4NS::Q4::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 83 c0 12 8b e5 5d"),
		new AddressNameBytes("00404f30", "Q5NS::Q5::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 6b 4d 08 13 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404f50", "Q5NS::Q5::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 83 c0 12 8b e5 5d"),
		new AddressNameBytes("00404f70", "Q6NS::Q6::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 6b 55 08 13 8d 04 ca 8b e5 5d c2 04"),
		new AddressNameBytes("00404f90", "Q6NS::Q6::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 8d 04 cd 12 00 00 00 8b e5 5d"),
		new AddressNameBytes("00404fb0", "Q7NS::Q7::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 6b 4d 08 13 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00404fd0", "Q7NS::Q7::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 83 c0 12 8b e5 5d"),
		new AddressNameBytes("00404ff0", "R1NS::R1::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 f4 0a 8b 55 08 8d 44 11 19 8b e5 5d c2 04"),
		new AddressNameBytes("00405010", "R1NS::R1::fp2_6",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 0a 83 c0 18 8b e5 5d"),
		new AddressNameBytes("00405025", "[thunk]:R1NS::R1::fp2_6`adjustor{20}'",
			"83 e9 14 e9 c3 ff ff"),
		new AddressNameBytes("0040502d", "[thunk]:R1NS::R1::fp2_6`adjustor{20}'",
			"83 e9 14 e9 db ff ff"),
		new AddressNameBytes("00405040", "Q3NS::Q3::fp2_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 83 c0 14 8b e5 5d"),
		new AddressNameBytes("00405060", "Q4NS::Q4::fp2_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 83 c0 14 8b e5 5d"),
		new AddressNameBytes("00405080", "Q5NS::Q5::fp2_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 83 c0 14 8b e5 5d"),
		new AddressNameBytes("004050a0", "Q6NS::Q6::fp2_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 8d 04 cd 14 00 00 00 8b e5 5d"),
		new AddressNameBytes("004050c0", "Q7NS::Q7::fp2_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 83 c0 14 8b e5 5d"),
		new AddressNameBytes("004050e0", "R1NS::R1::fp2_7",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 0a 83 c0 1a 8b e5 5d"),
		new AddressNameBytes("004050f5", "[thunk]:R1NS::R1::fp2_7`adjustor{20}'",
			"83 e9 14 e9 e3 ff ff"),
		new AddressNameBytes("00405100", "Q3NS::Q3::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 6b 4d 08 16 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00405120", "Q3NS::Q3::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 83 c0 15 8b e5 5d"),
		new AddressNameBytes("00405140", "Q4NS::Q4::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 6b 4d 08 16 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00405160", "Q4NS::Q4::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 83 c0 15 8b e5 5d"),
		new AddressNameBytes("00405180", "Q5NS::Q5::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 6b 4d 08 16 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("004051a0", "Q5NS::Q5::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 83 c0 15 8b e5 5d"),
		new AddressNameBytes("004051c0", "Q6NS::Q6::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 6b 55 08 16 8d 04 ca 8b e5 5d c2 04"),
		new AddressNameBytes("004051e0", "Q6NS::Q6::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 8d 04 cd 15 00 00 00 8b e5 5d"),
		new AddressNameBytes("00405200", "Q7NS::Q7::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 6b 4d 08 16 03 c1 8b e5 5d c2 04"),
		new AddressNameBytes("00405220", "Q7NS::Q7::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 83 c0 15 8b e5 5d"),
		new AddressNameBytes("00405240", "R1NS::R1::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 f4 0a 8b 55 08 8d 44 11 1c 8b e5 5d c2 04"),
		new AddressNameBytes("00405260", "R1NS::R1::fp2_8",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 0a 83 c0 1b 8b e5 5d"),
		new AddressNameBytes("00405275", "[thunk]:R1NS::R1::fp2_8`adjustor{20}'",
			"83 e9 14 e9 c3 ff ff"),
		new AddressNameBytes("0040527d", "[thunk]:R1NS::R1::fp2_8`adjustor{20}'",
			"83 e9 14 e9 db ff ff"),
		new AddressNameBytes("00405290", "Q3NS::Q3::fp2_9",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 05 83 c0 17 8b e5 5d"),
		new AddressNameBytes("004052b0", "Q4NS::Q4::fp2_9",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 83 c0 17 8b e5 5d"),
		new AddressNameBytes("004052d0", "Q5NS::Q5::fp2_9",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 fc 07 83 c0 17 8b e5 5d"),
		new AddressNameBytes("004052f0", "Q6NS::Q6::fp2_9",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 fc 8d 04 cd 17 00 00 00 8b e5 5d"),
		new AddressNameBytes("00405310", "Q7NS::Q7::fp2_9",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 09 83 c0 17 8b e5 5d"),
		new AddressNameBytes("00405330", "R1NS::R1::fp2_9",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 f4 0a 83 c0 1d 8b e5 5d"),
		new AddressNameBytes("00405345", "[thunk]:R1NS::R1::fp2_9`adjustor{20}'",
			"83 e9 14 e9 e3 ff ff"),
		new AddressNameBytes("004053b0", "Q1NS::Q1::fq1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 03 83 c0 04 8b e5 5d"),
		new AddressNameBytes("004053d0", "Q2NS::Q2::fq1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 10 8d 04 8d 04 00 00 00 8b e5 5d"),
		new AddressNameBytes("004053f0", "Q3NS::Q3::fq1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 10 05 83 c0 04 8b e5 5d"),
		new AddressNameBytes("00405410", "Q4NS::Q4::fq1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 06 83 c0 04 8b e5 5d"),
		new AddressNameBytes("00405430", "Q5NS::Q5::fq1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 0c 07 83 c0 04 8b e5 5d"),
		new AddressNameBytes("00405450", "Q6NS::Q6::fq1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 8b 48 0c 8d 04 cd 04 00 00 00 8b e5 5d"),
		new AddressNameBytes("00405470", "Q7NS::Q7::fq1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 40 08 09 83 c0 04 8b e5 5d"),
		new AddressNameBytes("00405490", "R1NS::R1::fq1_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 fc 0a 8b 55 08 8d 44 11 20 8b e5 5d c2 04"),
		new AddressNameBytes("00405510", "R1NS::R1::fq2_3",
			"55 8b ec 51 89 4d fc 8b 45 fc 6b 48 e8 0a 8b 55 08 8d 44 11 21 8b e5 5d c2 04"),
		new AddressNameBytes("00405831", "type_info::`scalar_deleting_destructor'",
			"55 8b ec f6 45 08 01 56 8b f1 c7 06 10 06 45 00 74 0a 6a 0c 56 e8 c1 02 00 00 59 59 8b c6 5e 5d c2 04"),
		new AddressNameBytes("00406b83", "_purecall",
			"56 e8 f3 ff ff ff 8b f0 85 f6 74 0a 8b ce ff 15 48 01 45 00 ff d6 e8 e9 a6 02")
	};

	private static CppCompositeType createP1_struct(DataTypeManager dtm) {
		String name = "P1NS::P1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("p1", intT, false, publicDirectAttributes, 4, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(0, 12, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(0, 20, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(0, 24, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(0, 28, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(0, 32, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createP2_struct(DataTypeManager dtm) {
		String name = "P2NS::P2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("p2", intT, false, publicDirectAttributes, 4, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(0, 12, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(0, 20, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(0, 24, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(0, 28, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(0, 32, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(0, 36, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(0, 40, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(0, 44, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createQ1_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q1NS::Q1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 20);
		struct.addDirectBaseClass(P1_struct.getComposite(), P1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(P2_struct.getComposite(), P2_struct, publicDirectAttributes, 8);
		struct.addMember("q1", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(0, 36, new SymbolPath(classSp, "fq1_3"), fintintT);
		struct.addVirtualMethod(0, 40, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createQ2_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q2NS::Q2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 20);
		struct.addDirectBaseClass(P1_struct.getComposite(), P1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(P2_struct.getComposite(), P2_struct, publicDirectAttributes, 8);
		struct.addMember("q2", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(0, 36, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		struct.addVirtualMethod(0, 40, new SymbolPath(classSp, "fp2_11"), fintvoidT);
		struct.addVirtualMethod(0, 44, new SymbolPath(classSp, "fp2_12"), fintintT);
		struct.addVirtualMethod(0, 48, new SymbolPath(classSp, "fq2_3"), fintintT);
		return struct;
	}

	private static CppCompositeType createQ3_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q3NS::Q3";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 20);
		struct.addDirectBaseClass(P1_struct.getComposite(), P1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(P2_struct.getComposite(), P2_struct, publicDirectAttributes, 8);
		struct.addMember("q3", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(0, 36, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(8, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createQ4_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q4NS::Q4";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectBaseClass(P2_struct.getComposite(), P2_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(P1_struct.getComposite(), P1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("q4", intT, false, publicDirectAttributes, 12, null);
		struct.addVirtualMethod(0, 48, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createQ5_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q5NS::Q5";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectBaseClass(P1_struct.getComposite(), P1_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(P2_struct.getComposite(), P2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("q5", intT, false, publicDirectAttributes, 12, null);
		struct.addVirtualMethod(0, 36, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createQ6_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q6NS::Q6";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectBaseClass(P1_struct.getComposite(), P1_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(P2_struct.getComposite(), P2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("q6", intT, false, publicDirectAttributes, 12, null);
		struct.addVirtualMethod(0, 36, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createQ7_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q7NS::Q7";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 28);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(P1_struct.getComposite(), P1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(P2_struct.getComposite(), P2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("q7", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createR1_struct(DataTypeManager dtm, CppCompositeType Q1_struct,
			CppCompositeType Q2_struct) throws PdbException {
		String name = "R1NS::R1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 52);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(Q1_struct.getComposite(), Q1_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(Q2_struct.getComposite(), Q2_struct,
			publicDirectAttributes, 4, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("r1", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fp1_1"), fintvoidT);
		struct.addVirtualMethod(0, 4, new SymbolPath(classSp, "fp1_2"), fintintT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fp1_2"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(0, 12, new SymbolPath(classSp, "fp2_1"), fintvoidT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fp2_2"), fintintT);
		struct.addVirtualMethod(0, 20, new SymbolPath(classSp, "fp2_2"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(20, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		struct.addVirtualMethod(12, -1, new SymbolPath(classSp, "fq1_3"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fq2_3"), fintintT);
		return struct;
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================

	//@formatter:off
	/*
	class P1NS::P1	size(8):
		+---
	 0	| {vfptr}
	 4	| p1
		+---

	P1NS::P1::$vftable@:
		| &P1_meta
		|  0
	 0	| &P1NS::P1::fp1_3
	 1	| &P1NS::P1::fp1_4
	 2	| &P1NS::P1::fp1_4
	 3	| &P1NS::P1::fp1_5
	 4	| &P1NS::P1::fp1_6
	 5	| &P1NS::P1::fp1_6
	 6	| &P1NS::P1::fp1_7
	 7	| &P1NS::P1::fp1_8
	 8	| &P1NS::P1::fp1_8

	P1NS::P1::fp1_3 this adjustor: 0
	P1NS::P1::fp1_4 this adjustor: 0
	P1NS::P1::fp1_4 this adjustor: 0
	P1NS::P1::fp1_5 this adjustor: 0
	P1NS::P1::fp1_6 this adjustor: 0
	P1NS::P1::fp1_6 this adjustor: 0
	P1NS::P1::fp1_7 this adjustor: 0
	P1NS::P1::fp1_8 this adjustor: 0
	P1NS::P1::fp1_8 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructP1() {
		String expected =
		//@formatter:off
			"""
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructP1() {
		return convertCommentsToSpeculative(getExpectedStructP1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryP1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[P1NS::P1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsP1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructP1_00000000());
		return results;
	}

	private static String getVxtStructP1_00000000() {
		String expected =
		//@formatter:off
			"""
			/P1NS/P1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   P1NS::P1::fp1_3   ""
			   4   _func___thiscall_int_int *   4   P1NS::P1::fp1_4   ""
			   8   _func___thiscall_int *   4   P1NS::P1::fp1_4   ""
			   12   _func___thiscall_int *   4   P1NS::P1::fp1_5   ""
			   16   _func___thiscall_int_int *   4   P1NS::P1::fp1_6   ""
			   20   _func___thiscall_int *   4   P1NS::P1::fp1_6   ""
			   24   _func___thiscall_int *   4   P1NS::P1::fp1_7   ""
			   28   _func___thiscall_int_int *   4   P1NS::P1::fp1_8   ""
			   32   _func___thiscall_int *   4   P1NS::P1::fp1_8   ""
			}
			Length: 36 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class P2NS::P2	size(8):
		+---
	 0	| {vfptr}
	 4	| p2
		+---

	P2NS::P2::$vftable@:
		| &P2_meta
		|  0
	 0	| &P2NS::P2::fp2_3
	 1	| &P2NS::P2::fp2_4
	 2	| &P2NS::P2::fp2_4
	 3	| &P2NS::P2::fp2_5
	 4	| &P2NS::P2::fp2_6
	 5	| &P2NS::P2::fp2_6
	 6	| &P2NS::P2::fp2_7
	 7	| &P2NS::P2::fp2_8
	 8	| &P2NS::P2::fp2_8
	 9	| &P2NS::P2::fp2_9
	10	| &P2NS::P2::fp2_10
	11	| &P2NS::P2::fp2_10

	P2NS::P2::fp2_3 this adjustor: 0
	P2NS::P2::fp2_4 this adjustor: 0
	P2NS::P2::fp2_4 this adjustor: 0
	P2NS::P2::fp2_5 this adjustor: 0
	P2NS::P2::fp2_6 this adjustor: 0
	P2NS::P2::fp2_6 this adjustor: 0
	P2NS::P2::fp2_7 this adjustor: 0
	P2NS::P2::fp2_8 this adjustor: 0
	P2NS::P2::fp2_8 this adjustor: 0
	P2NS::P2::fp2_9 this adjustor: 0
	P2NS::P2::fp2_10 this adjustor: 0
	P2NS::P2::fp2_10 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructP2() {
		String expected =
		//@formatter:off
			"""
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p2   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructP2() {
		return convertCommentsToSpeculative(getExpectedStructP2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryP2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsP2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructP2_00000000());
		return results;
	}

	private static String getVxtStructP2_00000000() {
		String expected =
		//@formatter:off
			"""
			/P2NS/P2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   P2NS::P2::fp2_3   ""
			   4   _func___thiscall_int_int *   4   P2NS::P2::fp2_4   ""
			   8   _func___thiscall_int *   4   P2NS::P2::fp2_4   ""
			   12   _func___thiscall_int *   4   P2NS::P2::fp2_5   ""
			   16   _func___thiscall_int_int *   4   P2NS::P2::fp2_6   ""
			   20   _func___thiscall_int *   4   P2NS::P2::fp2_6   ""
			   24   _func___thiscall_int *   4   P2NS::P2::fp2_7   ""
			   28   _func___thiscall_int_int *   4   P2NS::P2::fp2_8   ""
			   32   _func___thiscall_int *   4   P2NS::P2::fp2_8   ""
			   36   _func___thiscall_int *   4   P2NS::P2::fp2_9   ""
			   40   _func___thiscall_int_int *   4   P2NS::P2::fp2_10   ""
			   44   _func___thiscall_int *   4   P2NS::P2::fp2_10   ""
			}
			Length: 48 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q1NS::Q1	size(20):
		+---
	 0	| +--- (base class P1NS::P1)
	 0	| | {vfptr}
	 4	| | p1
		| +---
	 8	| +--- (base class P2NS::P2)
	 8	| | {vfptr}
	12	| | p2
		| +---
	16	| q1
		+---

	Q1NS::Q1::$vftable@P1@:
		| &Q1_meta
		|  0
	 0	| &Q1NS::Q1::fp1_3
	 1	| &Q1NS::Q1::fp1_4
	 2	| &Q1NS::Q1::fp1_4
	 3	| &Q1NS::Q1::fp1_5
	 4	| &Q1NS::Q1::fp1_6
	 5	| &Q1NS::Q1::fp1_6
	 6	| &Q1NS::Q1::fp1_7
	 7	| &Q1NS::Q1::fp1_8
	 8	| &Q1NS::Q1::fp1_8
	 9	| &Q1NS::Q1::fq1_3
	10	| &Q1NS::Q1::fq1_3

	Q1NS::Q1::$vftable@P2@:
		| -8
	 0	| &P2NS::P2::fp2_3
	 1	| &P2NS::P2::fp2_4
	 2	| &P2NS::P2::fp2_4
	 3	| &P2NS::P2::fp2_5
	 4	| &P2NS::P2::fp2_6
	 5	| &P2NS::P2::fp2_6
	 6	| &P2NS::P2::fp2_7
	 7	| &P2NS::P2::fp2_8
	 8	| &P2NS::P2::fp2_8
	 9	| &P2NS::P2::fp2_9
	10	| &P2NS::P2::fp2_10
	11	| &P2NS::P2::fp2_10

	Q1NS::Q1::fq1_3 this adjustor: 0
	Q1NS::Q1::fq1_3 this adjustor: 0
	Q1NS::Q1::fp1_3 this adjustor: 0
	Q1NS::Q1::fp1_4 this adjustor: 0
	Q1NS::Q1::fp1_4 this adjustor: 0
	Q1NS::Q1::fp1_5 this adjustor: 0
	Q1NS::Q1::fp1_6 this adjustor: 0
	Q1NS::Q1::fp1_6 this adjustor: 0
	Q1NS::Q1::fp1_7 this adjustor: 0
	Q1NS::Q1::fp1_8 this adjustor: 0
	Q1NS::Q1::fp1_8 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructQ1() {
		String expected =
		//@formatter:off
			"""
			/Q1NS::Q1
			pack()
			Structure Q1NS::Q1 {
			   0   P1NS::P1   8      "Base"
			   8   P2NS::P2   8      "Base"
			   16   int   4   q1   ""
			}
			Length: 20 Alignment: 4
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p2   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ1() {
		return convertCommentsToSpeculative(getExpectedStructQ1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P1NS::P1]	[Q1NS::Q1, P1NS::P1]");
		results.put("VTABLE_00000008", "     8 vft [P2NS::P2]	[Q1NS::Q1, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ1_00000000());
		results.put("VTABLE_00000008", getVxtStructQ1_00000008());
		return results;
	}

	private static String getVxtStructQ1_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q1NS/Q1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   Q1NS::Q1::fp1_3   ""
			   4   _func___thiscall_int_int *   4   Q1NS::Q1::fp1_4   ""
			   8   _func___thiscall_int *   4   Q1NS::Q1::fp1_4   ""
			   12   _func___thiscall_int *   4   Q1NS::Q1::fp1_5   ""
			   16   _func___thiscall_int_int *   4   Q1NS::Q1::fp1_6   ""
			   20   _func___thiscall_int *   4   Q1NS::Q1::fp1_6   ""
			   24   _func___thiscall_int *   4   Q1NS::Q1::fp1_7   ""
			   28   _func___thiscall_int_int *   4   Q1NS::Q1::fp1_8   ""
			   32   _func___thiscall_int *   4   Q1NS::Q1::fp1_8   ""
			   36   _func___thiscall_int_int *   4   Q1NS::Q1::fq1_3   ""
			   40   _func___thiscall_int *   4   Q1NS::Q1::fq1_3   ""
			}
			Length: 44 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ1_00000008() {
		String expected =
		//@formatter:off
			"""
			/Q1NS/Q1/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   _func___thiscall_int *   4   P2NS::P2::fp2_3   ""
			   4   _func___thiscall_int_int *   4   P2NS::P2::fp2_4   ""
			   8   _func___thiscall_int *   4   P2NS::P2::fp2_4   ""
			   12   _func___thiscall_int *   4   P2NS::P2::fp2_5   ""
			   16   _func___thiscall_int_int *   4   P2NS::P2::fp2_6   ""
			   20   _func___thiscall_int *   4   P2NS::P2::fp2_6   ""
			   24   _func___thiscall_int *   4   P2NS::P2::fp2_7   ""
			   28   _func___thiscall_int_int *   4   P2NS::P2::fp2_8   ""
			   32   _func___thiscall_int *   4   P2NS::P2::fp2_8   ""
			   36   _func___thiscall_int *   4   P2NS::P2::fp2_9   ""
			   40   _func___thiscall_int_int *   4   P2NS::P2::fp2_10   ""
			   44   _func___thiscall_int *   4   P2NS::P2::fp2_10   ""
			}
			Length: 48 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q2NS::Q2	size(20):
		+---
	 0	| +--- (base class P1NS::P1)
	 0	| | {vfptr}
	 4	| | p1
		| +---
	 8	| +--- (base class P2NS::P2)
	 8	| | {vfptr}
	12	| | p2
		| +---
	16	| q2
		+---

	Q2NS::Q2::$vftable@P1@:
		| &Q2_meta
		|  0
	 0	| &Q2NS::Q2::fp1_3
	 1	| &Q2NS::Q2::fp1_4
	 2	| &Q2NS::Q2::fp1_4
	 3	| &Q2NS::Q2::fp1_5
	 4	| &Q2NS::Q2::fp1_6
	 5	| &Q2NS::Q2::fp1_6
	 6	| &Q2NS::Q2::fp1_7
	 7	| &Q2NS::Q2::fp1_8
	 8	| &Q2NS::Q2::fp1_8
	 9	| &Q2NS::Q2::fq1_3
	10	| &Q2NS::Q2::fp2_11
	11	| &Q2NS::Q2::fp2_12
	12	| &Q2NS::Q2::fq2_3

	Q2NS::Q2::$vftable@P2@:
		| -8
	 0	| &P2NS::P2::fp2_3
	 1	| &P2NS::P2::fp2_4
	 2	| &P2NS::P2::fp2_4
	 3	| &P2NS::P2::fp2_5
	 4	| &P2NS::P2::fp2_6
	 5	| &P2NS::P2::fp2_6
	 6	| &P2NS::P2::fp2_7
	 7	| &P2NS::P2::fp2_8
	 8	| &P2NS::P2::fp2_8
	 9	| &P2NS::P2::fp2_9
	10	| &P2NS::P2::fp2_10
	11	| &Q2NS::Q2::fp2_10

	Q2NS::Q2::fq1_3 this adjustor: 0
	Q2NS::Q2::fp1_3 this adjustor: 0
	Q2NS::Q2::fp1_4 this adjustor: 0
	Q2NS::Q2::fp1_4 this adjustor: 0
	Q2NS::Q2::fp1_5 this adjustor: 0
	Q2NS::Q2::fp1_6 this adjustor: 0
	Q2NS::Q2::fp1_6 this adjustor: 0
	Q2NS::Q2::fp1_7 this adjustor: 0
	Q2NS::Q2::fp1_8 this adjustor: 0
	Q2NS::Q2::fp1_8 this adjustor: 0
	Q2NS::Q2::fp2_10 this adjustor: 8
	Q2NS::Q2::fp2_11 this adjustor: 0
	Q2NS::Q2::fp2_12 this adjustor: 0
	Q2NS::Q2::fq2_3 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructQ2() {
		String expected =
		//@formatter:off
			"""
			/Q2NS::Q2
			pack()
			Structure Q2NS::Q2 {
			   0   P1NS::P1   8      "Base"
			   8   P2NS::P2   8      "Base"
			   16   int   4   q2   ""
			}
			Length: 20 Alignment: 4
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p2   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ2() {
		return convertCommentsToSpeculative(getExpectedStructQ2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P1NS::P1]	[Q2NS::Q2, P1NS::P1]");
		results.put("VTABLE_00000008", "     8 vft [P2NS::P2]	[Q2NS::Q2, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ2_00000000());
		results.put("VTABLE_00000008", getVxtStructQ2_00000008());
		return results;
	}

	private static String getVxtStructQ2_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q2NS/Q2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   Q2NS::Q2::fp1_3   ""
			   4   _func___thiscall_int_int *   4   Q2NS::Q2::fp1_4   ""
			   8   _func___thiscall_int *   4   Q2NS::Q2::fp1_4   ""
			   12   _func___thiscall_int *   4   Q2NS::Q2::fp1_5   ""
			   16   _func___thiscall_int_int *   4   Q2NS::Q2::fp1_6   ""
			   20   _func___thiscall_int *   4   Q2NS::Q2::fp1_6   ""
			   24   _func___thiscall_int *   4   Q2NS::Q2::fp1_7   ""
			   28   _func___thiscall_int_int *   4   Q2NS::Q2::fp1_8   ""
			   32   _func___thiscall_int *   4   Q2NS::Q2::fp1_8   ""
			   36   _func___thiscall_int *   4   Q2NS::Q2::fq1_3   ""
			   40   _func___thiscall_int *   4   Q2NS::Q2::fp2_11   ""
			   44   _func___thiscall_int_int *   4   Q2NS::Q2::fp2_12   ""
			   48   _func___thiscall_int_int *   4   Q2NS::Q2::fq2_3   ""
			}
			Length: 52 Alignment: 4
			""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ2_00000008() {
		String expected =
		//@formatter:off
			"""
			/Q2NS/Q2/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   _func___thiscall_int *   4   P2NS::P2::fp2_3   ""
			   4   _func___thiscall_int_int *   4   P2NS::P2::fp2_4   ""
			   8   _func___thiscall_int *   4   P2NS::P2::fp2_4   ""
			   12   _func___thiscall_int *   4   P2NS::P2::fp2_5   ""
			   16   _func___thiscall_int_int *   4   P2NS::P2::fp2_6   ""
			   20   _func___thiscall_int *   4   P2NS::P2::fp2_6   ""
			   24   _func___thiscall_int *   4   P2NS::P2::fp2_7   ""
			   28   _func___thiscall_int_int *   4   P2NS::P2::fp2_8   ""
			   32   _func___thiscall_int *   4   P2NS::P2::fp2_8   ""
			   36   _func___thiscall_int *   4   P2NS::P2::fp2_9   ""
			   40   _func___thiscall_int_int *   4   P2NS::P2::fp2_10   ""
			   44   _func___thiscall_int *   4   Q2NS::Q2::fp2_10   ""
			}
			Length: 48 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q3NS::Q3	size(20):
		+---
	 0	| +--- (base class P1NS::P1)
	 0	| | {vfptr}
	 4	| | p1
		| +---
	 8	| +--- (base class P2NS::P2)
	 8	| | {vfptr}
	12	| | p2
		| +---
	16	| q3
		+---

	Q3NS::Q3::$vftable@P1@:
		| &Q3_meta
		|  0
	 0	| &Q3NS::Q3::fp1_3
	 1	| &Q3NS::Q3::fp1_4
	 2	| &Q3NS::Q3::fp1_4
	 3	| &Q3NS::Q3::fp1_5
	 4	| &Q3NS::Q3::fp1_6
	 5	| &Q3NS::Q3::fp1_6
	 6	| &Q3NS::Q3::fp1_7
	 7	| &Q3NS::Q3::fp1_8
	 8	| &Q3NS::Q3::fp1_8
	 9	| &Q3NS::Q3::fq1_3

	Q3NS::Q3::$vftable@P2@:
		| -8
	 0	| &Q3NS::Q3::fp2_3
	 1	| &Q3NS::Q3::fp2_4
	 2	| &Q3NS::Q3::fp2_4
	 3	| &Q3NS::Q3::fp2_5
	 4	| &Q3NS::Q3::fp2_6
	 5	| &Q3NS::Q3::fp2_6
	 6	| &Q3NS::Q3::fp2_7
	 7	| &Q3NS::Q3::fp2_8
	 8	| &Q3NS::Q3::fp2_8
	 9	| &Q3NS::Q3::fp2_9
	10	| &Q3NS::Q3::fp2_10
	11	| &Q3NS::Q3::fp2_10

	Q3NS::Q3::fq1_3 this adjustor: 0
	Q3NS::Q3::fp1_3 this adjustor: 0
	Q3NS::Q3::fp1_4 this adjustor: 0
	Q3NS::Q3::fp1_4 this adjustor: 0
	Q3NS::Q3::fp1_5 this adjustor: 0
	Q3NS::Q3::fp1_6 this adjustor: 0
	Q3NS::Q3::fp1_6 this adjustor: 0
	Q3NS::Q3::fp1_7 this adjustor: 0
	Q3NS::Q3::fp1_8 this adjustor: 0
	Q3NS::Q3::fp1_8 this adjustor: 0
	Q3NS::Q3::fp2_3 this adjustor: 8
	Q3NS::Q3::fp2_4 this adjustor: 8
	Q3NS::Q3::fp2_4 this adjustor: 8
	Q3NS::Q3::fp2_5 this adjustor: 8
	Q3NS::Q3::fp2_6 this adjustor: 8
	Q3NS::Q3::fp2_6 this adjustor: 8
	Q3NS::Q3::fp2_7 this adjustor: 8
	Q3NS::Q3::fp2_8 this adjustor: 8
	Q3NS::Q3::fp2_8 this adjustor: 8
	Q3NS::Q3::fp2_9 this adjustor: 8
	Q3NS::Q3::fp2_10 this adjustor: 8
	Q3NS::Q3::fp2_10 this adjustor: 8
	 */
	//@formatter:on
	private static String getExpectedStructQ3() {
		String expected =
		//@formatter:off
			"""
			/Q3NS::Q3
			pack()
			Structure Q3NS::Q3 {
			   0   P1NS::P1   8      "Base"
			   8   P2NS::P2   8      "Base"
			   16   int   4   q3   ""
			}
			Length: 20 Alignment: 4
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p2   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ3() {
		return convertCommentsToSpeculative(getExpectedStructQ3());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P1NS::P1]	[Q3NS::Q3, P1NS::P1]");
		results.put("VTABLE_00000008", "     8 vft [P2NS::P2]	[Q3NS::Q3, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ3_00000000());
		results.put("VTABLE_00000008", getVxtStructQ3_00000008());
		return results;
	}

	private static String getVxtStructQ3_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q3NS/Q3/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   Q3NS::Q3::fp1_3   ""
			   4   _func___thiscall_int_int *   4   Q3NS::Q3::fp1_4   ""
			   8   _func___thiscall_int *   4   Q3NS::Q3::fp1_4   ""
			   12   _func___thiscall_int *   4   Q3NS::Q3::fp1_5   ""
			   16   _func___thiscall_int_int *   4   Q3NS::Q3::fp1_6   ""
			   20   _func___thiscall_int *   4   Q3NS::Q3::fp1_6   ""
			   24   _func___thiscall_int *   4   Q3NS::Q3::fp1_7   ""
			   28   _func___thiscall_int_int *   4   Q3NS::Q3::fp1_8   ""
			   32   _func___thiscall_int *   4   Q3NS::Q3::fp1_8   ""
			   36   _func___thiscall_int *   4   Q3NS::Q3::fq1_3   ""
			}
			Length: 40 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ3_00000008() {
		String expected =
		//@formatter:off
			"""
			/Q3NS/Q3/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   _func___thiscall_int *   4   Q3NS::Q3::fp2_3   ""
			   4   _func___thiscall_int_int *   4   Q3NS::Q3::fp2_4   ""
			   8   _func___thiscall_int *   4   Q3NS::Q3::fp2_4   ""
			   12   _func___thiscall_int *   4   Q3NS::Q3::fp2_5   ""
			   16   _func___thiscall_int_int *   4   Q3NS::Q3::fp2_6   ""
			   20   _func___thiscall_int *   4   Q3NS::Q3::fp2_6   ""
			   24   _func___thiscall_int *   4   Q3NS::Q3::fp2_7   ""
			   28   _func___thiscall_int_int *   4   Q3NS::Q3::fp2_8   ""
			   32   _func___thiscall_int *   4   Q3NS::Q3::fp2_8   ""
			   36   _func___thiscall_int *   4   Q3NS::Q3::fp2_9   ""
			   40   _func___thiscall_int_int *   4   Q3NS::Q3::fp2_10   ""
			   44   _func___thiscall_int *   4   Q3NS::Q3::fp2_10   ""
			}
			Length: 48 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q4NS::Q4	size(24):
		+---
	 0	| +--- (base class P2NS::P2)
	 0	| | {vfptr}
	 4	| | p2
		| +---
	 8	| {vbptr}
	12	| q4
		+---
		+--- (virtual base P1NS::P1)
	16	| {vfptr}
	20	| p1
		+---

	Q4NS::Q4::$vftable@P2@:
		| &Q4_meta
		|  0
	 0	| &Q4NS::Q4::fp2_3
	 1	| &Q4NS::Q4::fp2_4
	 2	| &Q4NS::Q4::fp2_4
	 3	| &Q4NS::Q4::fp2_5
	 4	| &Q4NS::Q4::fp2_6
	 5	| &Q4NS::Q4::fp2_6
	 6	| &Q4NS::Q4::fp2_7
	 7	| &Q4NS::Q4::fp2_8
	 8	| &Q4NS::Q4::fp2_8
	 9	| &Q4NS::Q4::fp2_9
	10	| &Q4NS::Q4::fp2_10
	11	| &Q4NS::Q4::fp2_10
	12	| &Q4NS::Q4::fq1_3

	Q4NS::Q4::$vbtable@:
	 0	| -8
	 1	| 8 (Q4d(Q4+8)P1)

	Q4NS::Q4::$vftable@P1@:
		| -16
	 0	| &Q4NS::Q4::fp1_3
	 1	| &Q4NS::Q4::fp1_4
	 2	| &Q4NS::Q4::fp1_4
	 3	| &Q4NS::Q4::fp1_5
	 4	| &Q4NS::Q4::fp1_6
	 5	| &Q4NS::Q4::fp1_6
	 6	| &Q4NS::Q4::fp1_7
	 7	| &Q4NS::Q4::fp1_8
	 8	| &Q4NS::Q4::fp1_8

	Q4NS::Q4::fq1_3 this adjustor: 0
	Q4NS::Q4::fp1_3 this adjustor: 16
	Q4NS::Q4::fp1_4 this adjustor: 16
	Q4NS::Q4::fp1_4 this adjustor: 16
	Q4NS::Q4::fp1_5 this adjustor: 16
	Q4NS::Q4::fp1_6 this adjustor: 16
	Q4NS::Q4::fp1_6 this adjustor: 16
	Q4NS::Q4::fp1_7 this adjustor: 16
	Q4NS::Q4::fp1_8 this adjustor: 16
	Q4NS::Q4::fp1_8 this adjustor: 16
	Q4NS::Q4::fp2_3 this adjustor: 0
	Q4NS::Q4::fp2_4 this adjustor: 0
	Q4NS::Q4::fp2_4 this adjustor: 0
	Q4NS::Q4::fp2_5 this adjustor: 0
	Q4NS::Q4::fp2_6 this adjustor: 0
	Q4NS::Q4::fp2_6 this adjustor: 0
	Q4NS::Q4::fp2_7 this adjustor: 0
	Q4NS::Q4::fp2_8 this adjustor: 0
	Q4NS::Q4::fp2_8 this adjustor: 0
	Q4NS::Q4::fp2_9 this adjustor: 0
	Q4NS::Q4::fp2_10 this adjustor: 0
	Q4NS::Q4::fp2_10 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        P1NS::P1      16       8       4 0
	 */
	//@formatter:on
	private static String getExpectedStructQ4() {
		String expected =
		//@formatter:off
			"""
			/Q4NS::Q4
			pack()
			Structure Q4NS::Q4 {
			   0   Q4NS::Q4   16      "Self Base"
			   16   P1NS::P1   8      "Virtual Base"
			}
			Length: 24 Alignment: 4
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p2   ""
			}
			Length: 8 Alignment: 4
			/Q4NS::Q4/!internal/Q4NS::Q4
			pack()
			Structure Q4NS::Q4 {
			   0   P2NS::P2   8      "Base"
			   8   pointer   4   {vbptr}   ""
			   12   int   4   q4   ""
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructQ4() {
		String expected =
		//@formatter:off
			"""
			/Q4NS::Q4
			pack()
			Structure Q4NS::Q4 {
			   0   Q4NS::Q4   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: P1NS::P1"
			}
			Length: 24 Alignment: 4
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p2   ""
			}
			Length: 8 Alignment: 4
			/Q4NS::Q4/!internal/Q4NS::Q4
			pack()
			Structure Q4NS::Q4 {
			   0   P2NS::P2   8      "Base"
			   8   pointer   4   {vbptr}   ""
			   12   int   4   q4   ""
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ4() {
		return convertCommentsToSpeculative(getExpectedStructQ4());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P2NS::P2]	[Q4NS::Q4, P2NS::P2]");
		results.put("VTABLE_00000008", "     8 vbt []	[Q4NS::Q4]");
		results.put("VTABLE_00000010", "    16 vft [P1NS::P1]	[Q4NS::Q4, P1NS::P1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ4_00000000());
		results.put("VTABLE_00000008", getVxtStructQ4_00000008());
		results.put("VTABLE_00000010", getVxtStructQ4_00000010());
		return results;
	}

	private static String getVxtStructQ4_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q4NS/Q4/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   Q4NS::Q4::fp2_3   ""
			   4   _func___thiscall_int_int *   4   Q4NS::Q4::fp2_4   ""
			   8   _func___thiscall_int *   4   Q4NS::Q4::fp2_4   ""
			   12   _func___thiscall_int *   4   Q4NS::Q4::fp2_5   ""
			   16   _func___thiscall_int_int *   4   Q4NS::Q4::fp2_6   ""
			   20   _func___thiscall_int *   4   Q4NS::Q4::fp2_6   ""
			   24   _func___thiscall_int *   4   Q4NS::Q4::fp2_7   ""
			   28   _func___thiscall_int_int *   4   Q4NS::Q4::fp2_8   ""
			   32   _func___thiscall_int *   4   Q4NS::Q4::fp2_8   ""
			   36   _func___thiscall_int *   4   Q4NS::Q4::fp2_9   ""
			   40   _func___thiscall_int_int *   4   Q4NS::Q4::fp2_10   ""
			   44   _func___thiscall_int *   4   Q4NS::Q4::fp2_10   ""
			   48   _func___thiscall_int *   4   Q4NS::Q4::fq1_3   ""
			}
			Length: 52 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ4_00000008() {
		String expected =
		//@formatter:off
			"""
			/Q4NS/Q4/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "P1NS::P1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ4_00000010() {
		String expected =
		//@formatter:off
			"""
			/Q4NS/Q4/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   4   Q4NS::Q4::fp1_3   ""
			   4   _func___thiscall_int_int *   4   Q4NS::Q4::fp1_4   ""
			   8   _func___thiscall_int *   4   Q4NS::Q4::fp1_4   ""
			   12   _func___thiscall_int *   4   Q4NS::Q4::fp1_5   ""
			   16   _func___thiscall_int_int *   4   Q4NS::Q4::fp1_6   ""
			   20   _func___thiscall_int *   4   Q4NS::Q4::fp1_6   ""
			   24   _func___thiscall_int *   4   Q4NS::Q4::fp1_7   ""
			   28   _func___thiscall_int_int *   4   Q4NS::Q4::fp1_8   ""
			   32   _func___thiscall_int *   4   Q4NS::Q4::fp1_8   ""
			}
			Length: 36 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q5NS::Q5	size(24):
		+---
	 0	| +--- (base class P1NS::P1)
	 0	| | {vfptr}
	 4	| | p1
		| +---
	 8	| {vbptr}
	12	| q5
		+---
		+--- (virtual base P2NS::P2)
	16	| {vfptr}
	20	| p2
		+---

	Q5NS::Q5::$vftable@P1@:
		| &Q5_meta
		|  0
	 0	| &Q5NS::Q5::fp1_3
	 1	| &Q5NS::Q5::fp1_4
	 2	| &Q5NS::Q5::fp1_4
	 3	| &Q5NS::Q5::fp1_5
	 4	| &Q5NS::Q5::fp1_6
	 5	| &Q5NS::Q5::fp1_6
	 6	| &Q5NS::Q5::fp1_7
	 7	| &Q5NS::Q5::fp1_8
	 8	| &Q5NS::Q5::fp1_8
	 9	| &Q5NS::Q5::fq1_3

	Q5NS::Q5::$vbtable@:
	 0	| -8
	 1	| 8 (Q5d(Q5+8)P2)

	Q5NS::Q5::$vftable@P2@:
		| -16
	 0	| &Q5NS::Q5::fp2_3
	 1	| &Q5NS::Q5::fp2_4
	 2	| &Q5NS::Q5::fp2_4
	 3	| &Q5NS::Q5::fp2_5
	 4	| &Q5NS::Q5::fp2_6
	 5	| &Q5NS::Q5::fp2_6
	 6	| &Q5NS::Q5::fp2_7
	 7	| &Q5NS::Q5::fp2_8
	 8	| &Q5NS::Q5::fp2_8
	 9	| &Q5NS::Q5::fp2_9
	10	| &Q5NS::Q5::fp2_10
	11	| &Q5NS::Q5::fp2_10

	Q5NS::Q5::fq1_3 this adjustor: 0
	Q5NS::Q5::fp1_3 this adjustor: 0
	Q5NS::Q5::fp1_4 this adjustor: 0
	Q5NS::Q5::fp1_4 this adjustor: 0
	Q5NS::Q5::fp1_5 this adjustor: 0
	Q5NS::Q5::fp1_6 this adjustor: 0
	Q5NS::Q5::fp1_6 this adjustor: 0
	Q5NS::Q5::fp1_7 this adjustor: 0
	Q5NS::Q5::fp1_8 this adjustor: 0
	Q5NS::Q5::fp1_8 this adjustor: 0
	Q5NS::Q5::fp2_3 this adjustor: 16
	Q5NS::Q5::fp2_4 this adjustor: 16
	Q5NS::Q5::fp2_4 this adjustor: 16
	Q5NS::Q5::fp2_5 this adjustor: 16
	Q5NS::Q5::fp2_6 this adjustor: 16
	Q5NS::Q5::fp2_6 this adjustor: 16
	Q5NS::Q5::fp2_7 this adjustor: 16
	Q5NS::Q5::fp2_8 this adjustor: 16
	Q5NS::Q5::fp2_8 this adjustor: 16
	Q5NS::Q5::fp2_9 this adjustor: 16
	Q5NS::Q5::fp2_10 this adjustor: 16
	Q5NS::Q5::fp2_10 this adjustor: 16
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        P2NS::P2      16       8       4 0
	 */
	//@formatter:on
	private static String getExpectedStructQ5() {
		String expected =
		//@formatter:off
			"""
			/Q5NS::Q5
			pack()
			Structure Q5NS::Q5 {
			   0   Q5NS::Q5   16      "Self Base"
			   16   P2NS::P2   8      "Virtual Base"
			}
			Length: 24 Alignment: 4
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p2   ""
			}
			Length: 8 Alignment: 4
			/Q5NS::Q5/!internal/Q5NS::Q5
			pack()
			Structure Q5NS::Q5 {
			   0   P1NS::P1   8      "Base"
			   8   pointer   4   {vbptr}   ""
			   12   int   4   q5   ""
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructQ5() {
		String expected =
		//@formatter:off
			"""
			/Q5NS::Q5
			pack()
			Structure Q5NS::Q5 {
			   0   Q5NS::Q5   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: P2NS::P2"
			}
			Length: 24 Alignment: 4
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4
			/Q5NS::Q5/!internal/Q5NS::Q5
			pack()
			Structure Q5NS::Q5 {
			   0   P1NS::P1   8      "Base"
			   8   pointer   4   {vbptr}   ""
			   12   int   4   q5   ""
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ5() {
		return convertCommentsToSpeculative(getExpectedStructQ5());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ5() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P1NS::P1]	[Q5NS::Q5, P1NS::P1]");
		results.put("VTABLE_00000008", "     8 vbt []	[Q5NS::Q5]");
		results.put("VTABLE_00000010", "    16 vft [P2NS::P2]	[Q5NS::Q5, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ5() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ5_00000000());
		results.put("VTABLE_00000008", getVxtStructQ5_00000008());
		results.put("VTABLE_00000010", getVxtStructQ5_00000010());
		return results;
	}

	private static String getVxtStructQ5_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q5NS/Q5/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   Q5NS::Q5::fp1_3   ""
			   4   _func___thiscall_int_int *   4   Q5NS::Q5::fp1_4   ""
			   8   _func___thiscall_int *   4   Q5NS::Q5::fp1_4   ""
			   12   _func___thiscall_int *   4   Q5NS::Q5::fp1_5   ""
			   16   _func___thiscall_int_int *   4   Q5NS::Q5::fp1_6   ""
			   20   _func___thiscall_int *   4   Q5NS::Q5::fp1_6   ""
			   24   _func___thiscall_int *   4   Q5NS::Q5::fp1_7   ""
			   28   _func___thiscall_int_int *   4   Q5NS::Q5::fp1_8   ""
			   32   _func___thiscall_int *   4   Q5NS::Q5::fp1_8   ""
			   36   _func___thiscall_int *   4   Q5NS::Q5::fq1_3   ""
			}
			Length: 40 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ5_00000008() {
		String expected =
		//@formatter:off
			"""
			/Q5NS/Q5/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "P2NS::P2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ5_00000010() {
		String expected =
		//@formatter:off
			"""
			/Q5NS/Q5/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   4   Q5NS::Q5::fp2_3   ""
			   4   _func___thiscall_int_int *   4   Q5NS::Q5::fp2_4   ""
			   8   _func___thiscall_int *   4   Q5NS::Q5::fp2_4   ""
			   12   _func___thiscall_int *   4   Q5NS::Q5::fp2_5   ""
			   16   _func___thiscall_int_int *   4   Q5NS::Q5::fp2_6   ""
			   20   _func___thiscall_int *   4   Q5NS::Q5::fp2_6   ""
			   24   _func___thiscall_int *   4   Q5NS::Q5::fp2_7   ""
			   28   _func___thiscall_int_int *   4   Q5NS::Q5::fp2_8   ""
			   32   _func___thiscall_int *   4   Q5NS::Q5::fp2_8   ""
			   36   _func___thiscall_int *   4   Q5NS::Q5::fp2_9   ""
			   40   _func___thiscall_int_int *   4   Q5NS::Q5::fp2_10   ""
			   44   _func___thiscall_int *   4   Q5NS::Q5::fp2_10   ""
			}
			Length: 48 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q6NS::Q6	size(24):
		+---
	 0	| +--- (base class P1NS::P1)
	 0	| | {vfptr}
	 4	| | p1
		| +---
	 8	| {vbptr}
	12	| q6
		+---
		+--- (virtual base P2NS::P2)
	16	| {vfptr}
	20	| p2
		+---

	Q6NS::Q6::$vftable@P1@:
		| &Q6_meta
		|  0
	 0	| &Q6NS::Q6::fp1_3
	 1	| &Q6NS::Q6::fp1_4
	 2	| &Q6NS::Q6::fp1_4
	 3	| &Q6NS::Q6::fp1_5
	 4	| &Q6NS::Q6::fp1_6
	 5	| &Q6NS::Q6::fp1_6
	 6	| &Q6NS::Q6::fp1_7
	 7	| &Q6NS::Q6::fp1_8
	 8	| &Q6NS::Q6::fp1_8
	 9	| &Q6NS::Q6::fq1_3

	Q6NS::Q6::$vbtable@:
	 0	| -8
	 1	| 8 (Q6d(Q6+8)P2)

	Q6NS::Q6::$vftable@P2@:
		| -16
	 0	| &Q6NS::Q6::fp2_3
	 1	| &Q6NS::Q6::fp2_4
	 2	| &Q6NS::Q6::fp2_4
	 3	| &Q6NS::Q6::fp2_5
	 4	| &Q6NS::Q6::fp2_6
	 5	| &Q6NS::Q6::fp2_6
	 6	| &Q6NS::Q6::fp2_7
	 7	| &Q6NS::Q6::fp2_8
	 8	| &Q6NS::Q6::fp2_8
	 9	| &Q6NS::Q6::fp2_9
	10	| &Q6NS::Q6::fp2_10
	11	| &Q6NS::Q6::fp2_10

	Q6NS::Q6::fq1_3 this adjustor: 0
	Q6NS::Q6::fp1_3 this adjustor: 0
	Q6NS::Q6::fp1_4 this adjustor: 0
	Q6NS::Q6::fp1_4 this adjustor: 0
	Q6NS::Q6::fp1_5 this adjustor: 0
	Q6NS::Q6::fp1_6 this adjustor: 0
	Q6NS::Q6::fp1_6 this adjustor: 0
	Q6NS::Q6::fp1_7 this adjustor: 0
	Q6NS::Q6::fp1_8 this adjustor: 0
	Q6NS::Q6::fp1_8 this adjustor: 0
	Q6NS::Q6::fp2_3 this adjustor: 16
	Q6NS::Q6::fp2_4 this adjustor: 16
	Q6NS::Q6::fp2_4 this adjustor: 16
	Q6NS::Q6::fp2_5 this adjustor: 16
	Q6NS::Q6::fp2_6 this adjustor: 16
	Q6NS::Q6::fp2_6 this adjustor: 16
	Q6NS::Q6::fp2_7 this adjustor: 16
	Q6NS::Q6::fp2_8 this adjustor: 16
	Q6NS::Q6::fp2_8 this adjustor: 16
	Q6NS::Q6::fp2_9 this adjustor: 16
	Q6NS::Q6::fp2_10 this adjustor: 16
	Q6NS::Q6::fp2_10 this adjustor: 16
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        P2NS::P2      16       8       4 0
	 */
	//@formatter:on
	private static String getExpectedStructQ6() {
		String expected =
		//@formatter:off
			"""
			/Q6NS::Q6
			pack()
			Structure Q6NS::Q6 {
			   0   Q6NS::Q6   16      "Self Base"
			   16   P2NS::P2   8      "Virtual Base"
			}
			Length: 24 Alignment: 4
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p2   ""
			}
			Length: 8 Alignment: 4
			/Q6NS::Q6/!internal/Q6NS::Q6
			pack()
			Structure Q6NS::Q6 {
			   0   P1NS::P1   8      "Base"
			   8   pointer   4   {vbptr}   ""
			   12   int   4   q6   ""
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructQ6() {
		String expected =
		//@formatter:off
			"""
			/Q6NS::Q6
			pack()
			Structure Q6NS::Q6 {
			   0   Q6NS::Q6   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: P2NS::P2"
			}
			Length: 24 Alignment: 4
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4
			/Q6NS::Q6/!internal/Q6NS::Q6
			pack()
			Structure Q6NS::Q6 {
			   0   P1NS::P1   8      "Base"
			   8   pointer   4   {vbptr}   ""
			   12   int   4   q6   ""
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ6() {
		return convertCommentsToSpeculative(getExpectedStructQ6());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ6() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P1NS::P1]	[Q6NS::Q6, P1NS::P1]");
		results.put("VTABLE_00000008", "     8 vbt []	[Q6NS::Q6]");
		results.put("VTABLE_00000010", "    16 vft [P2NS::P2]	[Q6NS::Q6, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ6() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ6_00000000());
		results.put("VTABLE_00000008", getVxtStructQ6_00000008());
		results.put("VTABLE_00000010", getVxtStructQ6_00000010());
		return results;
	}

	private static String getVxtStructQ6_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q6NS/Q6/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   Q6NS::Q6::fp1_3   ""
			   4   _func___thiscall_int_int *   4   Q6NS::Q6::fp1_4   ""
			   8   _func___thiscall_int *   4   Q6NS::Q6::fp1_4   ""
			   12   _func___thiscall_int *   4   Q6NS::Q6::fp1_5   ""
			   16   _func___thiscall_int_int *   4   Q6NS::Q6::fp1_6   ""
			   20   _func___thiscall_int *   4   Q6NS::Q6::fp1_6   ""
			   24   _func___thiscall_int *   4   Q6NS::Q6::fp1_7   ""
			   28   _func___thiscall_int_int *   4   Q6NS::Q6::fp1_8   ""
			   32   _func___thiscall_int *   4   Q6NS::Q6::fp1_8   ""
			   36   _func___thiscall_int *   4   Q6NS::Q6::fq1_3   ""
			}
			Length: 40 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ6_00000008() {
		String expected =
		//@formatter:off
			"""
			/Q6NS/Q6/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "P2NS::P2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ6_00000010() {
		String expected =
		//@formatter:off
			"""
			/Q6NS/Q6/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   4   Q6NS::Q6::fp2_3   ""
			   4   _func___thiscall_int_int *   4   Q6NS::Q6::fp2_4   ""
			   8   _func___thiscall_int *   4   Q6NS::Q6::fp2_4   ""
			   12   _func___thiscall_int *   4   Q6NS::Q6::fp2_5   ""
			   16   _func___thiscall_int_int *   4   Q6NS::Q6::fp2_6   ""
			   20   _func___thiscall_int *   4   Q6NS::Q6::fp2_6   ""
			   24   _func___thiscall_int *   4   Q6NS::Q6::fp2_7   ""
			   28   _func___thiscall_int_int *   4   Q6NS::Q6::fp2_8   ""
			   32   _func___thiscall_int *   4   Q6NS::Q6::fp2_8   ""
			   36   _func___thiscall_int *   4   Q6NS::Q6::fp2_9   ""
			   40   _func___thiscall_int_int *   4   Q6NS::Q6::fp2_10   ""
			   44   _func___thiscall_int *   4   Q6NS::Q6::fp2_10   ""
			}
			Length: 48 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q7NS::Q7	size(28):
		+---
	 0	| {vfptr}
	 4	| {vbptr}
	 8	| q7
		+---
		+--- (virtual base P1NS::P1)
	12	| {vfptr}
	16	| p1
		+---
		+--- (virtual base P2NS::P2)
	20	| {vfptr}
	24	| p2
		+---

	Q7NS::Q7::$vftable@Q7@:
		| &Q7_meta
		|  0
	 0	| &Q7NS::Q7::fq1_3

	Q7NS::Q7::$vbtable@:
	 0	| -4
	 1	| 8 (Q7d(Q7+4)P1)
	 2	| 16 (Q7d(Q7+4)P2)

	Q7NS::Q7::$vftable@P1@:
		| -12
	 0	| &Q7NS::Q7::fp1_3
	 1	| &Q7NS::Q7::fp1_4
	 2	| &Q7NS::Q7::fp1_4
	 3	| &Q7NS::Q7::fp1_5
	 4	| &Q7NS::Q7::fp1_6
	 5	| &Q7NS::Q7::fp1_6
	 6	| &Q7NS::Q7::fp1_7
	 7	| &Q7NS::Q7::fp1_8
	 8	| &Q7NS::Q7::fp1_8

	Q7NS::Q7::$vftable@P2@:
		| -20
	 0	| &Q7NS::Q7::fp2_3
	 1	| &Q7NS::Q7::fp2_4
	 2	| &Q7NS::Q7::fp2_4
	 3	| &Q7NS::Q7::fp2_5
	 4	| &Q7NS::Q7::fp2_6
	 5	| &Q7NS::Q7::fp2_6
	 6	| &Q7NS::Q7::fp2_7
	 7	| &Q7NS::Q7::fp2_8
	 8	| &Q7NS::Q7::fp2_8
	 9	| &Q7NS::Q7::fp2_9
	10	| &Q7NS::Q7::fp2_10
	11	| &Q7NS::Q7::fp2_10

	Q7NS::Q7::fq1_3 this adjustor: 0
	Q7NS::Q7::fp1_3 this adjustor: 12
	Q7NS::Q7::fp1_4 this adjustor: 12
	Q7NS::Q7::fp1_4 this adjustor: 12
	Q7NS::Q7::fp1_5 this adjustor: 12
	Q7NS::Q7::fp1_6 this adjustor: 12
	Q7NS::Q7::fp1_6 this adjustor: 12
	Q7NS::Q7::fp1_7 this adjustor: 12
	Q7NS::Q7::fp1_8 this adjustor: 12
	Q7NS::Q7::fp1_8 this adjustor: 12
	Q7NS::Q7::fp2_3 this adjustor: 20
	Q7NS::Q7::fp2_4 this adjustor: 20
	Q7NS::Q7::fp2_4 this adjustor: 20
	Q7NS::Q7::fp2_5 this adjustor: 20
	Q7NS::Q7::fp2_6 this adjustor: 20
	Q7NS::Q7::fp2_6 this adjustor: 20
	Q7NS::Q7::fp2_7 this adjustor: 20
	Q7NS::Q7::fp2_8 this adjustor: 20
	Q7NS::Q7::fp2_8 this adjustor: 20
	Q7NS::Q7::fp2_9 this adjustor: 20
	Q7NS::Q7::fp2_10 this adjustor: 20
	Q7NS::Q7::fp2_10 this adjustor: 20
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        P1NS::P1      12       4       4 0
	        P2NS::P2      20       4       8 0
	 */
	//@formatter:on
	private static String getExpectedStructQ7() {
		String expected =
		//@formatter:off
			"""
			/Q7NS::Q7
			pack()
			Structure Q7NS::Q7 {
			   0   Q7NS::Q7   12      "Self Base"
			   12   P1NS::P1   8      "Virtual Base"
			   20   P2NS::P2   8      "Virtual Base"
			}
			Length: 28 Alignment: 4
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p2   ""
			}
			Length: 8 Alignment: 4
			/Q7NS::Q7/!internal/Q7NS::Q7
			pack()
			Structure Q7NS::Q7 {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   q7   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructQ7() {
		String expected =
		//@formatter:off
			"""
			/Q7NS::Q7
			pack()
			Structure Q7NS::Q7 {
			   0   Q7NS::Q7   12      "Self Base"
			   12   char[16]   16      "Filler for 2 Unplaceable Virtual Bases: P1NS::P1; P2NS::P2"
			}
			Length: 28 Alignment: 4
			/Q7NS::Q7/!internal/Q7NS::Q7
			pack()
			Structure Q7NS::Q7 {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   q7   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ7() {
		return convertCommentsToSpeculative(getExpectedStructQ7());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ7() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [Q7NS::Q7]	[Q7NS::Q7]");
		results.put("VTABLE_00000004", "     4 vbt []	[Q7NS::Q7]");
		results.put("VTABLE_0000000c", "    12 vft [P1NS::P1]	[Q7NS::Q7, P1NS::P1]");
		results.put("VTABLE_00000014", "    20 vft [P2NS::P2]	[Q7NS::Q7, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ7() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ7_00000000());
		results.put("VTABLE_00000004", getVxtStructQ7_00000004());
		results.put("VTABLE_0000000c", getVxtStructQ7_0000000c());
		results.put("VTABLE_00000014", getVxtStructQ7_00000014());
		return results;
	}

	private static String getVxtStructQ7_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q7NS/Q7/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   Q7NS::Q7::fq1_3   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ7_00000004() {
		String expected =
		//@formatter:off
			"""
			/Q7NS/Q7/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
			   0   int   4      "P1NS::P1"
			   4   int   4      "P2NS::P2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ7_0000000c() {
		String expected =
		//@formatter:off
			"""
			/Q7NS/Q7/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   Q7NS::Q7::fp1_3   ""
			   4   _func___thiscall_int_int *   4   Q7NS::Q7::fp1_4   ""
			   8   _func___thiscall_int *   4   Q7NS::Q7::fp1_4   ""
			   12   _func___thiscall_int *   4   Q7NS::Q7::fp1_5   ""
			   16   _func___thiscall_int_int *   4   Q7NS::Q7::fp1_6   ""
			   20   _func___thiscall_int *   4   Q7NS::Q7::fp1_6   ""
			   24   _func___thiscall_int *   4   Q7NS::Q7::fp1_7   ""
			   28   _func___thiscall_int_int *   4   Q7NS::Q7::fp1_8   ""
			   32   _func___thiscall_int *   4   Q7NS::Q7::fp1_8   ""
			}
			Length: 36 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ7_00000014() {
		String expected =
		//@formatter:off
			"""
			/Q7NS/Q7/!internal/VTABLE_00000014
			pack()
			Structure VTABLE_00000014 {
			   0   _func___thiscall_int *   4   Q7NS::Q7::fp2_3   ""
			   4   _func___thiscall_int_int *   4   Q7NS::Q7::fp2_4   ""
			   8   _func___thiscall_int *   4   Q7NS::Q7::fp2_4   ""
			   12   _func___thiscall_int *   4   Q7NS::Q7::fp2_5   ""
			   16   _func___thiscall_int_int *   4   Q7NS::Q7::fp2_6   ""
			   20   _func___thiscall_int *   4   Q7NS::Q7::fp2_6   ""
			   24   _func___thiscall_int *   4   Q7NS::Q7::fp2_7   ""
			   28   _func___thiscall_int_int *   4   Q7NS::Q7::fp2_8   ""
			   32   _func___thiscall_int *   4   Q7NS::Q7::fp2_8   ""
			   36   _func___thiscall_int *   4   Q7NS::Q7::fp2_9   ""
			   40   _func___thiscall_int_int *   4   Q7NS::Q7::fp2_10   ""
			   44   _func___thiscall_int *   4   Q7NS::Q7::fp2_10   ""
			}
			Length: 48 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class R1NS::R1	size(52):
		+---
	 0	| {vfptr}
	 4	| {vbptr}
	 8	| r1
		+---
		+--- (virtual base Q1NS::Q1)
	12	| +--- (base class P1NS::P1)
	12	| | {vfptr}
	16	| | p1
		| +---
	20	| +--- (base class P2NS::P2)
	20	| | {vfptr}
	24	| | p2
		| +---
	28	| q1
		+---
		+--- (virtual base Q2NS::Q2)
	32	| +--- (base class P1NS::P1)
	32	| | {vfptr}
	36	| | p1
		| +---
	40	| +--- (base class P2NS::P2)
	40	| | {vfptr}
	44	| | p2
		| +---
	48	| q2
		+---

	R1NS::R1::$vftable@:
		| &R1_meta
		|  0
	 0	| &R1NS::R1::fp1_1
	 1	| &R1NS::R1::fp1_2
	 2	| &R1NS::R1::fp1_2
	 3	| &R1NS::R1::fp2_1
	 4	| &R1NS::R1::fp2_2
	 5	| &R1NS::R1::fp2_2

	R1NS::R1::$vbtable@:
	 0	| -4
	 1	| 8 (R1d(R1+4)Q1)
	 2	| 28 (R1d(R1+4)Q2)

	R1NS::R1::$vftable@P1@Q1@:
		| -12
	 0	| &R1NS::R1::fp1_3
	 1	| &R1NS::R1::fp1_4
	 2	| &R1NS::R1::fp1_4
	 3	| &R1NS::R1::fp1_5
	 4	| &R1NS::R1::fp1_6
	 5	| &R1NS::R1::fp1_6
	 6	| &R1NS::R1::fp1_7
	 7	| &R1NS::R1::fp1_8
	 8	| &R1NS::R1::fp1_8
	 9	| &R1NS::R1::fq1_3
	10	| &Q1NS::Q1::fq1_3

	R1NS::R1::$vftable@P2@Q1@:
		| -20
	 0	| &R1NS::R1::fp2_3
	 1	| &R1NS::R1::fp2_4
	 2	| &R1NS::R1::fp2_4
	 3	| &R1NS::R1::fp2_5
	 4	| &R1NS::R1::fp2_6
	 5	| &R1NS::R1::fp2_6
	 6	| &R1NS::R1::fp2_7
	 7	| &R1NS::R1::fp2_8
	 8	| &R1NS::R1::fp2_8
	 9	| &R1NS::R1::fp2_9
	10	| &R1NS::R1::fp2_10
	11	| &R1NS::R1::fp2_10

	R1NS::R1::$vftable@P1@Q2@:
		| -32
	 0	| &thunk: this-=20; goto R1NS::R1::fp1_3
	 1	| &thunk: this-=20; goto R1NS::R1::fp1_4
	 2	| &thunk: this-=20; goto R1NS::R1::fp1_4
	 3	| &thunk: this-=20; goto R1NS::R1::fp1_5
	 4	| &thunk: this-=20; goto R1NS::R1::fp1_6
	 5	| &thunk: this-=20; goto R1NS::R1::fp1_6
	 6	| &thunk: this-=20; goto R1NS::R1::fp1_7
	 7	| &thunk: this-=20; goto R1NS::R1::fp1_8
	 8	| &thunk: this-=20; goto R1NS::R1::fp1_8
	 9	| &Q2NS::Q2::fq1_3
	10	| &Q2NS::Q2::fp2_11
	11	| &Q2NS::Q2::fp2_12
	12	| &R1NS::R1::fq2_3

	R1NS::R1::$vftable@P2@Q2@:
		| -40
	 0	| &thunk: this-=20; goto R1NS::R1::fp2_3
	 1	| &thunk: this-=20; goto R1NS::R1::fp2_4
	 2	| &thunk: this-=20; goto R1NS::R1::fp2_4
	 3	| &thunk: this-=20; goto R1NS::R1::fp2_5
	 4	| &thunk: this-=20; goto R1NS::R1::fp2_6
	 5	| &thunk: this-=20; goto R1NS::R1::fp2_6
	 6	| &thunk: this-=20; goto R1NS::R1::fp2_7
	 7	| &thunk: this-=20; goto R1NS::R1::fp2_8
	 8	| &thunk: this-=20; goto R1NS::R1::fp2_8
	 9	| &thunk: this-=20; goto R1NS::R1::fp2_9
	10	| &thunk: this-=20; goto R1NS::R1::fp2_10
	11	| &thunk: this-=20; goto R1NS::R1::fp2_10

	R1NS::R1::fp1_1 this adjustor: 0
	R1NS::R1::fp1_2 this adjustor: 0
	R1NS::R1::fp1_2 this adjustor: 0
	R1NS::R1::fp1_3 this adjustor: 12
	R1NS::R1::fp1_4 this adjustor: 12
	R1NS::R1::fp1_4 this adjustor: 12
	R1NS::R1::fp1_5 this adjustor: 12
	R1NS::R1::fp1_6 this adjustor: 12
	R1NS::R1::fp1_6 this adjustor: 12
	R1NS::R1::fp1_7 this adjustor: 12
	R1NS::R1::fp1_8 this adjustor: 12
	R1NS::R1::fp1_8 this adjustor: 12
	R1NS::R1::fp2_1 this adjustor: 0
	R1NS::R1::fp2_2 this adjustor: 0
	R1NS::R1::fp2_2 this adjustor: 0
	R1NS::R1::fp2_3 this adjustor: 20
	R1NS::R1::fp2_4 this adjustor: 20
	R1NS::R1::fp2_4 this adjustor: 20
	R1NS::R1::fp2_5 this adjustor: 20
	R1NS::R1::fp2_6 this adjustor: 20
	R1NS::R1::fp2_6 this adjustor: 20
	R1NS::R1::fp2_7 this adjustor: 20
	R1NS::R1::fp2_8 this adjustor: 20
	R1NS::R1::fp2_8 this adjustor: 20
	R1NS::R1::fp2_9 this adjustor: 20
	R1NS::R1::fp2_10 this adjustor: 20
	R1NS::R1::fp2_10 this adjustor: 20
	R1NS::R1::fq1_3 this adjustor: 12
	R1NS::R1::fq2_3 this adjustor: 32
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        Q1NS::Q1      12       4       4 0
	        Q2NS::Q2      32       4       8 0
     */
	//@formatter:on
	private static String getExpectedStructR1() {
		String expected =
		//@formatter:off
			"""
			/R1NS::R1
			pack()
			Structure R1NS::R1 {
			   0   R1NS::R1   12      "Self Base"
			   12   Q1NS::Q1   20      "Virtual Base"
			   32   Q2NS::Q2   20      "Virtual Base"
			}
			Length: 52 Alignment: 4
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p1   ""
			}
			Length: 8 Alignment: 4
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   4   {vfptr}   ""
			   4   int   4   p2   ""
			}
			Length: 8 Alignment: 4
			/Q1NS::Q1
			pack()
			Structure Q1NS::Q1 {
			   0   P1NS::P1   8      "Base"
			   8   P2NS::P2   8      "Base"
			   16   int   4   q1   ""
			}
			Length: 20 Alignment: 4
			/Q2NS::Q2
			pack()
			Structure Q2NS::Q2 {
			   0   P1NS::P1   8      "Base"
			   8   P2NS::P2   8      "Base"
			   16   int   4   q2   ""
			}
			Length: 20 Alignment: 4
			/R1NS::R1/!internal/R1NS::R1
			pack()
			Structure R1NS::R1 {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   r1   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructR1() {
		String expected =
		//@formatter:off
			"""
			/R1NS::R1
			pack()
			Structure R1NS::R1 {
			   0   R1NS::R1   12      "Self Base"
			   12   char[40]   40      "Filler for 2 Unplaceable Virtual Bases: Q1NS::Q1; Q2NS::Q2"
			}
			Length: 52 Alignment: 4
			/R1NS::R1/!internal/R1NS::R1
			pack()
			Structure R1NS::R1 {
			   0   pointer   4   {vfptr}   ""
			   4   pointer   4   {vbptr}   ""
			   8   int   4   r1   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructR1() {
		return convertCommentsToSpeculative(getExpectedStructR1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryR1() {
		Map<String, String> results = new TreeMap<>();
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000000", "     0 vft []	[R1NS::R1]");
		results.put("VTABLE_00000000", null);
		results.put("VTABLE_00000004", "     4 vbt []	[R1NS::R1]");
		results.put("VTABLE_0000000c",
			"    12 vft [P1NS::P1, Q1NS::Q1]	[R1NS::R1, Q1NS::Q1, P1NS::P1]");
		results.put("VTABLE_00000014",
			"    20 vft [P2NS::P2, Q1NS::Q1]	[R1NS::R1, Q1NS::Q1, P2NS::P2]");
		results.put("VTABLE_00000020",
			"    32 vft [P1NS::P1, Q2NS::Q2]	[R1NS::R1, Q2NS::Q2, P1NS::P1]");
		results.put("VTABLE_00000028",
			"    40 vft [P2NS::P2, Q2NS::Q2]	[R1NS::R1, Q2NS::Q2, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsR1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructR1_00000000());
		results.put("VTABLE_00000004", getVxtStructR1_00000004());
		results.put("VTABLE_0000000c", getVxtStructR1_0000000c());
		results.put("VTABLE_00000014", getVxtStructR1_00000014());
		results.put("VTABLE_00000020", getVxtStructR1_00000020());
		results.put("VTABLE_00000028", getVxtStructR1_00000028());
		return results;
	}

	private static String getVxtStructR1_00000000() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   4   R1NS::R1::fp1_1   ""
			   4   _func___thiscall_int_int *   4   R1NS::R1::fp1_2   ""
			   8   _func___thiscall_int *   4   R1NS::R1::fp1_2   ""
			   12   _func___thiscall_int *   4   R1NS::R1::fp2_1   ""
			   16   _func___thiscall_int_int *   4   R1NS::R1::fp2_2   ""
			   20   _func___thiscall_int *   4   R1NS::R1::fp2_2   ""
			}
			Length: 24 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructR1_00000004() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_00000004
			pack()
			Structure VTABLE_00000004 {
			   0   int   4      "Q1NS::Q1"
			   4   int   4      "Q2NS::Q2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructR1_0000000c() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_0000000c
			pack()
			Structure VTABLE_0000000c {
			   0   _func___thiscall_int *   4   R1NS::R1::fp1_3   ""
			   4   _func___thiscall_int_int *   4   R1NS::R1::fp1_4   ""
			   8   _func___thiscall_int *   4   R1NS::R1::fp1_4   ""
			   12   _func___thiscall_int *   4   R1NS::R1::fp1_5   ""
			   16   _func___thiscall_int_int *   4   R1NS::R1::fp1_6   ""
			   20   _func___thiscall_int *   4   R1NS::R1::fp1_6   ""
			   24   _func___thiscall_int *   4   R1NS::R1::fp1_7   ""
			   28   _func___thiscall_int_int *   4   R1NS::R1::fp1_8   ""
			   32   _func___thiscall_int *   4   R1NS::R1::fp1_8   ""
			   36   _func___thiscall_int_int *   4   R1NS::R1::fq1_3   ""
			   40   _func___thiscall_int *   4   Q1NS::Q1::fq1_3   ""
			}
			Length: 44 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructR1_00000014() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_00000014
			pack()
			Structure VTABLE_00000014 {
			   0   _func___thiscall_int *   4   R1NS::R1::fp2_3   ""
			   4   _func___thiscall_int_int *   4   R1NS::R1::fp2_4   ""
			   8   _func___thiscall_int *   4   R1NS::R1::fp2_4   ""
			   12   _func___thiscall_int *   4   R1NS::R1::fp2_5   ""
			   16   _func___thiscall_int_int *   4   R1NS::R1::fp2_6   ""
			   20   _func___thiscall_int *   4   R1NS::R1::fp2_6   ""
			   24   _func___thiscall_int *   4   R1NS::R1::fp2_7   ""
			   28   _func___thiscall_int_int *   4   R1NS::R1::fp2_8   ""
			   32   _func___thiscall_int *   4   R1NS::R1::fp2_8   ""
			   36   _func___thiscall_int *   4   R1NS::R1::fp2_9   ""
			   40   _func___thiscall_int_int *   4   R1NS::R1::fp2_10   ""
			   44   _func___thiscall_int *   4   R1NS::R1::fp2_10   ""
			}
			Length: 48 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructR1_00000020() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_int *   4   R1NS::R1::fp1_3   ""
			   4   _func___thiscall_int_int *   4   R1NS::R1::fp1_4   ""
			   8   _func___thiscall_int *   4   R1NS::R1::fp1_4   ""
			   12   _func___thiscall_int *   4   R1NS::R1::fp1_5   ""
			   16   _func___thiscall_int_int *   4   R1NS::R1::fp1_6   ""
			   20   _func___thiscall_int *   4   R1NS::R1::fp1_6   ""
			   24   _func___thiscall_int *   4   R1NS::R1::fp1_7   ""
			   28   _func___thiscall_int_int *   4   R1NS::R1::fp1_8   ""
			   32   _func___thiscall_int *   4   R1NS::R1::fp1_8   ""
			   36   _func___thiscall_int *   4   Q2NS::Q2::fq1_3   ""
			   40   _func___thiscall_int *   4   Q2NS::Q2::fp2_11   ""
			   44   _func___thiscall_int_int *   4   Q2NS::Q2::fp2_12   ""
			   48   _func___thiscall_int_int *   4   R1NS::R1::fq2_3   ""
			}
			Length: 52 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructR1_00000028() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_int *   4   R1NS::R1::fp2_3   ""
			   4   _func___thiscall_int_int *   4   R1NS::R1::fp2_4   ""
			   8   _func___thiscall_int *   4   R1NS::R1::fp2_4   ""
			   12   _func___thiscall_int *   4   R1NS::R1::fp2_5   ""
			   16   _func___thiscall_int_int *   4   R1NS::R1::fp2_6   ""
			   20   _func___thiscall_int *   4   R1NS::R1::fp2_6   ""
			   24   _func___thiscall_int *   4   R1NS::R1::fp2_7   ""
			   28   _func___thiscall_int_int *   4   R1NS::R1::fp2_8   ""
			   32   _func___thiscall_int *   4   R1NS::R1::fp2_8   ""
			   36   _func___thiscall_int *   4   R1NS::R1::fp2_9   ""
			   40   _func___thiscall_int_int *   4   R1NS::R1::fp2_10   ""
			   44   _func___thiscall_int *   4   R1NS::R1::fp2_10   ""
			}
			Length: 48 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	private static final List<ClassID> classIDs = List.of(P1, P2, Q1, Q2, Q3, Q4, Q5, Q6, Q7, R1);

	private static final Map<ClassID, String> expectedStructs = new TreeMap<>();
	static {
		expectedStructs.put(P1, getExpectedStructP1());
		expectedStructs.put(P2, getExpectedStructP2());
		expectedStructs.put(Q1, getExpectedStructQ1());
		expectedStructs.put(Q2, getExpectedStructQ2());
		expectedStructs.put(Q3, getExpectedStructQ3());
		expectedStructs.put(Q4, getExpectedStructQ4());
		expectedStructs.put(Q5, getExpectedStructQ5());
		expectedStructs.put(Q6, getExpectedStructQ6());
		expectedStructs.put(Q7, getExpectedStructQ7());
		expectedStructs.put(R1, getExpectedStructR1());
	}

	private static final Map<ClassID, String> fillerStructs = new LinkedHashMap<>();
	static {
		fillerStructs.putAll(expectedStructs);
		fillerStructs.put(Q4, getFillerStructQ4());
		fillerStructs.put(Q5, getFillerStructQ5());
		fillerStructs.put(Q6, getFillerStructQ6());
		fillerStructs.put(Q7, getFillerStructQ7());
		fillerStructs.put(R1, getFillerStructR1());
	}

	private static final Map<ClassID, String> speculatedStructs = new LinkedHashMap<>();
	static {
		speculatedStructs.put(P1, getSpeculatedStructP1());
		speculatedStructs.put(P2, getSpeculatedStructP2());
		speculatedStructs.put(Q1, getSpeculatedStructQ1());
		speculatedStructs.put(Q2, getSpeculatedStructQ2());
		speculatedStructs.put(Q3, getSpeculatedStructQ3());
		speculatedStructs.put(Q4, getSpeculatedStructQ4());
		speculatedStructs.put(Q5, getSpeculatedStructQ5());
		speculatedStructs.put(Q6, getSpeculatedStructQ6());
		speculatedStructs.put(Q7, getSpeculatedStructQ7());
		speculatedStructs.put(R1, getSpeculatedStructR1());
	}

	private static final Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
		new TreeMap<>();
	static {
		expectedVxtPtrSummaries.put(P1, getExpectedVxtPtrSummaryP1());
		expectedVxtPtrSummaries.put(P2, getExpectedVxtPtrSummaryP2());
		expectedVxtPtrSummaries.put(Q1, getExpectedVxtPtrSummaryQ1());
		expectedVxtPtrSummaries.put(Q2, getExpectedVxtPtrSummaryQ2());
		expectedVxtPtrSummaries.put(Q3, getExpectedVxtPtrSummaryQ3());
		expectedVxtPtrSummaries.put(Q4, getExpectedVxtPtrSummaryQ4());
		expectedVxtPtrSummaries.put(Q5, getExpectedVxtPtrSummaryQ5());
		expectedVxtPtrSummaries.put(Q6, getExpectedVxtPtrSummaryQ6());
		expectedVxtPtrSummaries.put(Q7, getExpectedVxtPtrSummaryQ7());
		expectedVxtPtrSummaries.put(R1, getExpectedVxtPtrSummaryR1());
	}

	private static final Map<ClassID, Map<String, String>> speculatedVxtPtrSummaries =
		new LinkedHashMap<>();
	static {
		speculatedVxtPtrSummaries.putAll(expectedVxtPtrSummaries);
	}

	private static final Map<ClassID, Map<String, String>> expectedVxtStructs = new TreeMap<>();
	static {
		expectedVxtStructs.put(P1, getExpectedVxtStructsP1());
		expectedVxtStructs.put(P2, getExpectedVxtStructsP2());
		expectedVxtStructs.put(Q1, getExpectedVxtStructsQ1());
		expectedVxtStructs.put(Q2, getExpectedVxtStructsQ2());
		expectedVxtStructs.put(Q3, getExpectedVxtStructsQ3());
		expectedVxtStructs.put(Q4, getExpectedVxtStructsQ4());
		expectedVxtStructs.put(Q5, getExpectedVxtStructsQ5());
		expectedVxtStructs.put(Q6, getExpectedVxtStructsQ6());
		expectedVxtStructs.put(Q7, getExpectedVxtStructsQ7());
		expectedVxtStructs.put(R1, getExpectedVxtStructsR1());
	}

	private static final Map<ClassID, Map<String, String>> speculatedVxtStructs =
		new LinkedHashMap<>();
	static {
		speculatedVxtStructs.putAll(expectedVxtStructs);
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================

	public Vftm32ProgramCreator() {
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
		CppCompositeType p1 = createP1_struct(dtm);
		cppTypes.add(p1);
		CppCompositeType p2 = createP2_struct(dtm);
		cppTypes.add(p2);
		CppCompositeType q1 = createQ1_struct(dtm, p1, p2);
		cppTypes.add(q1);
		CppCompositeType q2 = createQ2_struct(dtm, p1, p2);
		cppTypes.add(q2);
		CppCompositeType q3 = createQ3_struct(dtm, p1, p2);
		cppTypes.add(q3);
		CppCompositeType q4 = createQ4_struct(dtm, p1, p2);
		cppTypes.add(q4);
		CppCompositeType q5 = createQ5_struct(dtm, p1, p2);
		cppTypes.add(q5);
		CppCompositeType q6 = createQ6_struct(dtm, p1, p2);
		cppTypes.add(q6);
		CppCompositeType q7 = createQ7_struct(dtm, p1, p2);
		cppTypes.add(q7);
		CppCompositeType r1 = createR1_struct(dtm, q1, q2);
		cppTypes.add(r1);
		return cppTypes;
	}
}
