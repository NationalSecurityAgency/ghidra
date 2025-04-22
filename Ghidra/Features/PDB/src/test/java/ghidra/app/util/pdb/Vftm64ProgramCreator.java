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
 * Class to create the vftm 64-bit program and mock PDB
 */
public class Vftm64ProgramCreator extends ProgramCreator {

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

	private static String PROGRAM_NAME = "vftm64.exe";
	private static String LANGUAGE_ID = ProgramBuilder._X64;
	private static String COMPILER_SPEC_ID = "windows";
	private static AddressNameLength SECTIONS[] = {
		new AddressNameLength("140001000", ".text", 0x60a00),
		new AddressNameLength("140062000", ".rdata", 0x13200)
	};

	private static AddressNameBytes vbTableInfo[] = {
		new AddressNameBytes("1400627d0", "??_8Q4@Q4NS@@7B@",
			"f0 ff ff ff 10 00 00 00 80 da 06 40 01 00 00 00"),
		new AddressNameBytes("140062898", "??_8Q5@Q5NS@@7B@",
			"f0 ff ff ff 10 00 00 00 58 db 06 40 01 00 00 00"),
		new AddressNameBytes("140062960", "??_8Q6@Q6NS@@7B@",
			"f0 ff ff ff 10 00 00 00 08 dc 06 40 01 00 00 00"),
		new AddressNameBytes("140062a30", "??_8Q7@Q7NS@@7B@",
			"f8 ff ff ff 10 00 00 00 20 00 00 00 00 00 00 00 30 dd 06 40 01 00 00 00"),
		new AddressNameBytes("140062c18", "??_8R1@R1NS@@7B@",
			"f8 ff ff ff 10 00 00 00 38 00 00 00 00 00 00 00 68 df 06 40 01 00 00 00")
	};

	private static AddressNameBytes vfTableInfo[] = {
		new AddressNameBytes("140062400", "??_7P1@P1NS@@6B@",
			"60 4f 00 40 01 00 00 00 80 50 00 40 01 00 00 00 a0 50 00 40 01 00 00 00 d0 52 00 40 01 00 00 00 f0 53 00 40 01 00 00 00 10 54 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 f8 d6 06 40 01 00 00 00"),
		new AddressNameBytes("140062450", "??_7P2@P2NS@@6B@",
			"00 5c 00 40 01 00 00 00 e0 5c 00 40 01 00 00 00 00 5d 00 40 01 00 00 00 b0 5e 00 40 01 00 00 00 90 5f 00 40 01 00 00 00 b0 5f 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 70 d7 06 40 01 00 00 00"),
		new AddressNameBytes("1400624b8", "??_7Q1@Q1NS@@6BP1@P1NS@@@",
			"80 4f 00 40 01 00 00 00 c0 50 00 40 01 00 00 00 e0 50 00 40 01 00 00 00 f0 52 00 40 01 00 00 00 30 54 00 40 01 00 00 00 50 54 00 40 01 00 00 00 40 56 00 40 01 00 00 00 40 57 00 40 01 00 00 00 60 57 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 d0 64 00 40 01 00 00 00 20 d8 06 40 01 00 00 00"),
		new AddressNameBytes("140062518", "??_7Q1@Q1NS@@6BP2@P2NS@@@",
			"00 5c 00 40 01 00 00 00 e0 5c 00 40 01 00 00 00 00 5d 00 40 01 00 00 00 b0 5e 00 40 01 00 00 00 90 5f 00 40 01 00 00 00 b0 5f 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 48 d8 06 40 01 00 00 00"),
		new AddressNameBytes("140062580", "??_7Q2@Q2NS@@6BP1@P1NS@@@",
			"a0 4f 00 40 01 00 00 00 00 51 00 40 01 00 00 00 20 51 00 40 01 00 00 00 10 53 00 40 01 00 00 00 70 54 00 40 01 00 00 00 90 54 00 40 01 00 00 00 60 56 00 40 01 00 00 00 80 57 00 40 01 00 00 00 a0 57 00 40 01 00 00 00 f0 64 00 40 01 00 00 00 00 5b 00 40 01 00 00 00 20 5b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 d0 d8 06 40 01 00 00 00"),
		new AddressNameBytes("1400625f0", "??_7Q2@Q2NS@@6BP2@P2NS@@@",
			"00 5c 00 40 01 00 00 00 e0 5c 00 40 01 00 00 00 00 5d 00 40 01 00 00 00 b0 5e 00 40 01 00 00 00 90 5f 00 40 01 00 00 00 b0 5f 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 38 7b 00 40 01 00 00 00 50 59 00 40 01 00 00 00 f8 d8 06 40 01 00 00 00"),
		new AddressNameBytes("140062658", "??_7Q3@Q3NS@@6BP1@P1NS@@@",
			"c0 4f 00 40 01 00 00 00 40 51 00 40 01 00 00 00 60 51 00 40 01 00 00 00 30 53 00 40 01 00 00 00 b0 54 00 40 01 00 00 00 d0 54 00 40 01 00 00 00 80 56 00 40 01 00 00 00 c0 57 00 40 01 00 00 00 e0 57 00 40 01 00 00 00 10 65 00 40 01 00 00 00 80 d9 06 40 01 00 00 00"),
		new AddressNameBytes("1400626b0", "??_7Q3@Q3NS@@6BP2@P2NS@@@",
			"20 5c 00 40 01 00 00 00 20 5d 00 40 01 00 00 00 40 5d 00 40 01 00 00 00 d0 5e 00 40 01 00 00 00 d0 5f 00 40 01 00 00 00 f0 5f 00 40 01 00 00 00 60 61 00 40 01 00 00 00 20 62 00 40 01 00 00 00 40 62 00 40 01 00 00 00 b0 63 00 40 01 00 00 00 70 59 00 40 01 00 00 00 90 59 00 40 01 00 00 00 a8 d9 06 40 01 00 00 00"),
		new AddressNameBytes("140062718", "??_7Q4@Q4NS@@6BP2@P2NS@@@",
			"40 5c 00 40 01 00 00 00 60 5d 00 40 01 00 00 00 80 5d 00 40 01 00 00 00 f0 5e 00 40 01 00 00 00 10 60 00 40 01 00 00 00 30 60 00 40 01 00 00 00 80 61 00 40 01 00 00 00 60 62 00 40 01 00 00 00 80 62 00 40 01 00 00 00 d0 63 00 40 01 00 00 00 b0 59 00 40 01 00 00 00 d0 59 00 40 01 00 00 00 30 65 00 40 01 00 00 00 58 da 06 40 01 00 00 00"),
		new AddressNameBytes("140062788", "??_7Q4@Q4NS@@6BP1@P1NS@@@",
			"e0 4f 00 40 01 00 00 00 80 51 00 40 01 00 00 00 a0 51 00 40 01 00 00 00 50 53 00 40 01 00 00 00 f0 54 00 40 01 00 00 00 10 55 00 40 01 00 00 00 a0 56 00 40 01 00 00 00 00 58 00 40 01 00 00 00 20 58 00 40 01 00 00 00"),
		new AddressNameBytes("1400627e0", "??_7Q5@Q5NS@@6BP1@P1NS@@@",
			"00 50 00 40 01 00 00 00 c0 51 00 40 01 00 00 00 e0 51 00 40 01 00 00 00 70 53 00 40 01 00 00 00 30 55 00 40 01 00 00 00 50 55 00 40 01 00 00 00 c0 56 00 40 01 00 00 00 40 58 00 40 01 00 00 00 60 58 00 40 01 00 00 00 50 65 00 40 01 00 00 00 30 db 06 40 01 00 00 00"),
		new AddressNameBytes("140062838", "??_7Q5@Q5NS@@6BP2@P2NS@@@",
			"60 5c 00 40 01 00 00 00 a0 5d 00 40 01 00 00 00 c0 5d 00 40 01 00 00 00 10 5f 00 40 01 00 00 00 50 60 00 40 01 00 00 00 70 60 00 40 01 00 00 00 a0 61 00 40 01 00 00 00 a0 62 00 40 01 00 00 00 c0 62 00 40 01 00 00 00 f0 63 00 40 01 00 00 00 f0 59 00 40 01 00 00 00 10 5a 00 40 01 00 00 00"),
		new AddressNameBytes("1400628a8", "??_7Q6@Q6NS@@6BP1@P1NS@@@",
			"20 50 00 40 01 00 00 00 00 52 00 40 01 00 00 00 20 52 00 40 01 00 00 00 90 53 00 40 01 00 00 00 70 55 00 40 01 00 00 00 90 55 00 40 01 00 00 00 e0 56 00 40 01 00 00 00 80 58 00 40 01 00 00 00 a0 58 00 40 01 00 00 00 70 65 00 40 01 00 00 00 e0 db 06 40 01 00 00 00"),
		new AddressNameBytes("140062900", "??_7Q6@Q6NS@@6BP2@P2NS@@@",
			"80 5c 00 40 01 00 00 00 e0 5d 00 40 01 00 00 00 00 5e 00 40 01 00 00 00 30 5f 00 40 01 00 00 00 90 60 00 40 01 00 00 00 b0 60 00 40 01 00 00 00 c0 61 00 40 01 00 00 00 e0 62 00 40 01 00 00 00 00 63 00 40 01 00 00 00 10 64 00 40 01 00 00 00 30 5a 00 40 01 00 00 00 50 5a 00 40 01 00 00 00"),
		new AddressNameBytes("140062970", "??_7Q7@Q7NS@@6B01@@",
			"90 65 00 40 01 00 00 00 e0 dc 06 40 01 00 00 00"),
		new AddressNameBytes("140062980", "??_7Q7@Q7NS@@6BP1@P1NS@@@",
			"40 50 00 40 01 00 00 00 40 52 00 40 01 00 00 00 60 52 00 40 01 00 00 00 b0 53 00 40 01 00 00 00 b0 55 00 40 01 00 00 00 d0 55 00 40 01 00 00 00 00 57 00 40 01 00 00 00 c0 58 00 40 01 00 00 00 e0 58 00 40 01 00 00 00 08 dd 06 40 01 00 00 00"),
		new AddressNameBytes("1400629d0", "??_7Q7@Q7NS@@6BP2@P2NS@@@",
			"a0 5c 00 40 01 00 00 00 20 5e 00 40 01 00 00 00 40 5e 00 40 01 00 00 00 50 5f 00 40 01 00 00 00 d0 60 00 40 01 00 00 00 f0 60 00 40 01 00 00 00 e0 61 00 40 01 00 00 00 20 63 00 40 01 00 00 00 40 63 00 40 01 00 00 00 30 64 00 40 01 00 00 00 70 5a 00 40 01 00 00 00 90 5a 00 40 01 00 00 00"),
		new AddressNameBytes("140062a48", "??_7R1@R1NS@@6B@",
			"c0 4e 00 40 01 00 00 00 20 4f 00 40 01 00 00 00 40 4f 00 40 01 00 00 00 60 5b 00 40 01 00 00 00 c0 5b 00 40 01 00 00 00 e0 5b 00 40 01 00 00 00 c8 de 06 40 01 00 00 00"),
		new AddressNameBytes("140062a80", "??_7R1@R1NS@@6BP1@P1NS@@Q1@Q1NS@@@",
			"60 50 00 40 01 00 00 00 80 52 00 40 01 00 00 00 a0 52 00 40 01 00 00 00 d0 53 00 40 01 00 00 00 f0 55 00 40 01 00 00 00 10 56 00 40 01 00 00 00 20 57 00 40 01 00 00 00 00 59 00 40 01 00 00 00 20 59 00 40 01 00 00 00 b0 65 00 40 01 00 00 00 d0 64 00 40 01 00 00 00 f0 de 06 40 01 00 00 00"),
		new AddressNameBytes("140062ae0", "??_7R1@R1NS@@6BP2@P2NS@@Q1@Q1NS@@@",
			"c0 5c 00 40 01 00 00 00 60 5e 00 40 01 00 00 00 80 5e 00 40 01 00 00 00 70 5f 00 40 01 00 00 00 10 61 00 40 01 00 00 00 30 61 00 40 01 00 00 00 00 62 00 40 01 00 00 00 60 63 00 40 01 00 00 00 80 63 00 40 01 00 00 00 50 64 00 40 01 00 00 00 b0 5a 00 40 01 00 00 00 d0 5a 00 40 01 00 00 00 18 df 06 40 01 00 00 00"),
		new AddressNameBytes("140062b48", "??_7R1@R1NS@@6BP1@P1NS@@Q2@Q2NS@@@",
			"74 50 00 40 01 00 00 00 b4 52 00 40 01 00 00 00 c0 52 00 40 01 00 00 00 e4 53 00 40 01 00 00 00 24 56 00 40 01 00 00 00 30 56 00 40 01 00 00 00 34 57 00 40 01 00 00 00 34 59 00 40 01 00 00 00 40 59 00 40 01 00 00 00 f0 64 00 40 01 00 00 00 00 5b 00 40 01 00 00 00 20 5b 00 40 01 00 00 00 30 66 00 40 01 00 00 00 40 df 06 40 01 00 00 00"),
		new AddressNameBytes("140062bb8", "??_7R1@R1NS@@6BP2@P2NS@@Q2@Q2NS@@@",
			"d4 5c 00 40 01 00 00 00 94 5e 00 40 01 00 00 00 a0 5e 00 40 01 00 00 00 84 5f 00 40 01 00 00 00 44 61 00 40 01 00 00 00 50 61 00 40 01 00 00 00 14 62 00 40 01 00 00 00 94 63 00 40 01 00 00 00 a0 63 00 40 01 00 00 00 64 64 00 40 01 00 00 00 e4 5a 00 40 01 00 00 00 f0 5a 00 40 01 00 00 00"),
		new AddressNameBytes("140062c30", "??_7type_info@@6B@",
			"a4 69 00 40 01 00 00 00 00 00 00 00 00 00 00 00")
	};

	private static AddressNameBytes functionInfo[] = {
		new AddressNameBytes("140004ec0", "R1NS::R1::fp1_1",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 0a 83 c0 04"),
		new AddressNameBytes("140004f20", "R1NS::R1::fp1_2",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 10 0a 8b 4c 24 10 8d 44 08 06"),
		new AddressNameBytes("140004f40", "R1NS::R1::fp1_2",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 0a 83 c0 05"),
		new AddressNameBytes("140004f60", "P1NS::P1::fp1_3",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 83 c0 04"),
		new AddressNameBytes("140004f80", "Q1NS::Q1::fp1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 03 83 c0 05"),
		new AddressNameBytes("140004fa0", "Q2NS::Q2::fp1_3",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 20 8d 04 85 05 00 00 00"),
		new AddressNameBytes("140004fc0", "Q3NS::Q3::fp1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 05 83 c0 05"),
		new AddressNameBytes("140004fe0", "Q4NS::Q4::fp1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 06 83 c0 05"),
		new AddressNameBytes("140005000", "Q5NS::Q5::fp1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 07 83 c0 05"),
		new AddressNameBytes("140005020", "Q6NS::Q6::fp1_3",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 18 8d 04 c5 05 00 00 00"),
		new AddressNameBytes("140005040", "Q7NS::Q7::fp1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 09 83 c0 05"),
		new AddressNameBytes("140005060", "R1NS::R1::fp1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 0a 83 c0 07"),
		new AddressNameBytes("140005074", "[thunk]:R1NS::R1::fp1_3`adjustor{40}'",
			"48 83 e9 28 e9 e3 ff ff"),
		new AddressNameBytes("140005080", "P1NS::P1::fp1_4",
			"89 54 24 10 48 89 4c 24 08 6b 44 24 10 06 48 8b 4c 24 08 03 41 08"),
		new AddressNameBytes("1400050a0", "P1NS::P1::fp1_4",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 83 c0 05"),
		new AddressNameBytes("1400050c0", "Q1NS::Q1::fp1_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 20 03 6b 4c 24 10 07 03 c1"),
		new AddressNameBytes("1400050e0", "Q1NS::Q1::fp1_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 03 83 c0 06"),
		new AddressNameBytes("140005100", "Q2NS::Q2::fp1_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 20 6b 4c 24 10 07 8d 04 81"),
		new AddressNameBytes("140005120", "Q2NS::Q2::fp1_4",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 20 8d 04 85 06 00 00 00"),
		new AddressNameBytes("140005140", "Q3NS::Q3::fp1_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 20 05 6b 4c 24 10 07 03 c1"),
		new AddressNameBytes("140005160", "Q3NS::Q3::fp1_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 05 83 c0 06"),
		new AddressNameBytes("140005180", "Q4NS::Q4::fp1_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 06 6b 4c 24 10 07 03 c1"),
		new AddressNameBytes("1400051a0", "Q4NS::Q4::fp1_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 06 83 c0 06"),
		new AddressNameBytes("1400051c0", "Q5NS::Q5::fp1_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 18 07 6b 4c 24 10 07 03 c1"),
		new AddressNameBytes("1400051e0", "Q5NS::Q5::fp1_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 07 83 c0 06"),
		new AddressNameBytes("140005200", "Q6NS::Q6::fp1_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 18 6b 4c 24 10 07 8d 04 c1"),
		new AddressNameBytes("140005220", "Q6NS::Q6::fp1_4",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 18 8d 04 c5 06 00 00 00"),
		new AddressNameBytes("140005240", "Q7NS::Q7::fp1_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 09 6b 4c 24 10 07 03 c1"),
		new AddressNameBytes("140005260", "Q7NS::Q7::fp1_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 09 83 c0 06"),
		new AddressNameBytes("140005280", "R1NS::R1::fp1_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 0a 8b 4c 24 10 8d 44 08 09"),
		new AddressNameBytes("1400052a0", "R1NS::R1::fp1_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 0a 83 c0 08"),
		new AddressNameBytes("1400052b4", "[thunk]:R1NS::R1::fp1_4`adjustor{40}'",
			"48 83 e9 28 e9 c3 ff ff"),
		new AddressNameBytes("1400052c0", "[thunk]:R1NS::R1::fp1_4`adjustor{40}'",
			"48 83 e9 28 e9 d7 ff ff"),
		new AddressNameBytes("1400052d0", "P1NS::P1::fp1_5",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 83 c0 07"),
		new AddressNameBytes("1400052f0", "Q1NS::Q1::fp1_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 03 83 c0 08"),
		new AddressNameBytes("140005310", "Q2NS::Q2::fp1_5",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 20 8d 04 85 08 00 00 00"),
		new AddressNameBytes("140005330", "Q3NS::Q3::fp1_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 05 83 c0 08"),
		new AddressNameBytes("140005350", "Q4NS::Q4::fp1_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 06 83 c0 08"),
		new AddressNameBytes("140005370", "Q5NS::Q5::fp1_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 07 83 c0 08"),
		new AddressNameBytes("140005390", "Q6NS::Q6::fp1_5",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 18 8d 04 c5 08 00 00 00"),
		new AddressNameBytes("1400053b0", "Q7NS::Q7::fp1_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 09 83 c0 08"),
		new AddressNameBytes("1400053d0", "R1NS::R1::fp1_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 0a 83 c0 0a"),
		new AddressNameBytes("1400053e4", "[thunk]:R1NS::R1::fp1_5`adjustor{40}'",
			"48 83 e9 28 e9 e3 ff ff"),
		new AddressNameBytes("1400053f0", "P1NS::P1::fp1_6",
			"89 54 24 10 48 89 4c 24 08 6b 44 24 10 09 48 8b 4c 24 08 03 41 08"),
		new AddressNameBytes("140005410", "P1NS::P1::fp1_6",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 83 c0 08"),
		new AddressNameBytes("140005430", "Q1NS::Q1::fp1_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 20 03 6b 4c 24 10 0a 03 c1"),
		new AddressNameBytes("140005450", "Q1NS::Q1::fp1_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 03 83 c0 09"),
		new AddressNameBytes("140005470", "Q2NS::Q2::fp1_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 20 6b 4c 24 10 0a 8d 04 81"),
		new AddressNameBytes("140005490", "Q2NS::Q2::fp1_6",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 20 8d 04 85 09 00 00 00"),
		new AddressNameBytes("1400054b0", "Q3NS::Q3::fp1_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 20 05 6b 4c 24 10 0a 03 c1"),
		new AddressNameBytes("1400054d0", "Q3NS::Q3::fp1_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 05 83 c0 09"),
		new AddressNameBytes("1400054f0", "Q4NS::Q4::fp1_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 06 6b 4c 24 10 0a 03 c1"),
		new AddressNameBytes("140005510", "Q4NS::Q4::fp1_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 06 83 c0 09"),
		new AddressNameBytes("140005530", "Q5NS::Q5::fp1_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 18 07 6b 4c 24 10 0a 03 c1"),
		new AddressNameBytes("140005550", "Q5NS::Q5::fp1_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 07 83 c0 09"),
		new AddressNameBytes("140005570", "Q6NS::Q6::fp1_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 18 6b 4c 24 10 0a 8d 04 c1"),
		new AddressNameBytes("140005590", "Q6NS::Q6::fp1_6",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 18 8d 04 c5 09 00 00 00"),
		new AddressNameBytes("1400055b0", "Q7NS::Q7::fp1_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 09 6b 4c 24 10 0a 03 c1"),
		new AddressNameBytes("1400055d0", "Q7NS::Q7::fp1_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 09 83 c0 09"),
		new AddressNameBytes("1400055f0", "R1NS::R1::fp1_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 0a 8b 4c 24 10 8d 44 08 0c"),
		new AddressNameBytes("140005610", "R1NS::R1::fp1_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 0a 83 c0 0b"),
		new AddressNameBytes("140005624", "[thunk]:R1NS::R1::fp1_6`adjustor{40}'",
			"48 83 e9 28 e9 c3 ff ff"),
		new AddressNameBytes("140005630", "[thunk]:R1NS::R1::fp1_6`adjustor{40}'",
			"48 83 e9 28 e9 d7 ff ff"),
		new AddressNameBytes("140005640", "Q1NS::Q1::fp1_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 03 83 c0 0b"),
		new AddressNameBytes("140005660", "Q2NS::Q2::fp1_7",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 20 8d 04 85 0b 00 00 00"),
		new AddressNameBytes("140005680", "Q3NS::Q3::fp1_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 05 83 c0 0b"),
		new AddressNameBytes("1400056a0", "Q4NS::Q4::fp1_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 06 83 c0 0b"),
		new AddressNameBytes("1400056c0", "Q5NS::Q5::fp1_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 07 83 c0 0b"),
		new AddressNameBytes("1400056e0", "Q6NS::Q6::fp1_7",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 18 8d 04 c5 0b 00 00 00"),
		new AddressNameBytes("140005700", "Q7NS::Q7::fp1_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 09 83 c0 0b"),
		new AddressNameBytes("140005720", "R1NS::R1::fp1_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 0a 83 c0 0d"),
		new AddressNameBytes("140005734", "[thunk]:R1NS::R1::fp1_7`adjustor{40}'",
			"48 83 e9 28 e9 e3 ff ff"),
		new AddressNameBytes("140005740", "Q1NS::Q1::fp1_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 20 03 6b 4c 24 10 0d 03 c1"),
		new AddressNameBytes("140005760", "Q1NS::Q1::fp1_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 03 83 c0 0c"),
		new AddressNameBytes("140005780", "Q2NS::Q2::fp1_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 20 6b 4c 24 10 0d 8d 04 81"),
		new AddressNameBytes("1400057a0", "Q2NS::Q2::fp1_8",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 20 8d 04 85 0c 00 00 00"),
		new AddressNameBytes("1400057c0", "Q3NS::Q3::fp1_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 20 05 6b 4c 24 10 0d 03 c1"),
		new AddressNameBytes("1400057e0", "Q3NS::Q3::fp1_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 05 83 c0 0c"),
		new AddressNameBytes("140005800", "Q4NS::Q4::fp1_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 06 6b 4c 24 10 0d 03 c1"),
		new AddressNameBytes("140005820", "Q4NS::Q4::fp1_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 06 83 c0 0c"),
		new AddressNameBytes("140005840", "Q5NS::Q5::fp1_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 18 07 6b 4c 24 10 0d 03 c1"),
		new AddressNameBytes("140005860", "Q5NS::Q5::fp1_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 07 83 c0 0c"),
		new AddressNameBytes("140005880", "Q6NS::Q6::fp1_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 18 6b 4c 24 10 0d 8d 04 c1"),
		new AddressNameBytes("1400058a0", "Q6NS::Q6::fp1_8",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 18 8d 04 c5 0c 00 00 00"),
		new AddressNameBytes("1400058c0", "Q7NS::Q7::fp1_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 09 6b 4c 24 10 0d 03 c1"),
		new AddressNameBytes("1400058e0", "Q7NS::Q7::fp1_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 09 83 c0 0c"),
		new AddressNameBytes("140005900", "R1NS::R1::fp1_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 0a 8b 4c 24 10 8d 44 08 0f"),
		new AddressNameBytes("140005920", "R1NS::R1::fp1_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 0a 83 c0 0e"),
		new AddressNameBytes("140005934", "[thunk]:R1NS::R1::fp1_8`adjustor{40}'",
			"48 83 e9 28 e9 c3 ff ff"),
		new AddressNameBytes("140005940", "[thunk]:R1NS::R1::fp1_8`adjustor{40}'",
			"48 83 e9 28 e9 d7 ff ff"),
		new AddressNameBytes("140005950", "Q2NS::Q2::fp2_10",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 10 8d 04 85 0e 00 00 00"),
		new AddressNameBytes("140005970", "Q3NS::Q3::fp2_10",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 6b 4c 24 10 19 03 c1"),
		new AddressNameBytes("140005990", "Q3NS::Q3::fp2_10",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 83 c0 18"),
		new AddressNameBytes("1400059b0", "Q4NS::Q4::fp2_10",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 6b 4c 24 10 19 03 c1"),
		new AddressNameBytes("1400059d0", "Q4NS::Q4::fp2_10",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 83 c0 18"),
		new AddressNameBytes("1400059f0", "Q5NS::Q5::fp2_10",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 6b 4c 24 10 19 03 c1"),
		new AddressNameBytes("140005a10", "Q5NS::Q5::fp2_10",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 83 c0 18"),
		new AddressNameBytes("140005a30", "Q6NS::Q6::fp2_10",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 6b 4c 24 10 19 8d 04 c1"),
		new AddressNameBytes("140005a50", "Q6NS::Q6::fp2_10",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 8d 04 c5 18 00 00 00"),
		new AddressNameBytes("140005a70", "Q7NS::Q7::fp2_10",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 6b 4c 24 10 19 03 c1"),
		new AddressNameBytes("140005a90", "Q7NS::Q7::fp2_10",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 83 c0 18"),
		new AddressNameBytes("140005ab0", "R1NS::R1::fp2_10",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 8b 4c 24 10 8d 44 08 1f"),
		new AddressNameBytes("140005ad0", "R1NS::R1::fp2_10",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 83 c0 1e"),
		new AddressNameBytes("140005ae4", "[thunk]:R1NS::R1::fp2_10`adjustor{40}'",
			"48 83 e9 28 e9 c3 ff ff"),
		new AddressNameBytes("140005af0", "[thunk]:R1NS::R1::fp2_10`adjustor{40}'",
			"48 83 e9 28 e9 d7 ff ff"),
		new AddressNameBytes("140005b00", "Q2NS::Q2::fp2_11",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 20 8d 04 85 0f 00 00 00"),
		new AddressNameBytes("140005b20", "Q2NS::Q2::fp2_12",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 20 6b 4c 24 10 10 8d 04 81"),
		new AddressNameBytes("140005b60", "R1NS::R1::fp2_1",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 0a 83 c0 11"),
		new AddressNameBytes("140005bc0", "R1NS::R1::fp2_2",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 10 0a 8b 4c 24 10 8d 44 08 13"),
		new AddressNameBytes("140005be0", "R1NS::R1::fp2_2",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 0a 83 c0 12"),
		new AddressNameBytes("140005c00", "P2NS::P2::fp2_3",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 8d 44 00 04"),
		new AddressNameBytes("140005c20", "Q3NS::Q3::fp2_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 83 c0 0e"),
		new AddressNameBytes("140005c40", "Q4NS::Q4::fp2_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 83 c0 0e"),
		new AddressNameBytes("140005c60", "Q5NS::Q5::fp2_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 83 c0 0e"),
		new AddressNameBytes("140005c80", "Q6NS::Q6::fp2_3",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 8d 04 c5 0e 00 00 00"),
		new AddressNameBytes("140005ca0", "Q7NS::Q7::fp2_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 83 c0 0e"),
		new AddressNameBytes("140005cc0", "R1NS::R1::fp2_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 83 c0 14"),
		new AddressNameBytes("140005cd4", "[thunk]:R1NS::R1::fp2_3`adjustor{40}'",
			"48 83 e9 28 e9 e3 ff ff"),
		new AddressNameBytes("140005ce0", "P2NS::P2::fp2_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 08 6b 4c 24 10 06 8d 04 41"),
		new AddressNameBytes("140005d00", "P2NS::P2::fp2_4",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 8d 44 00 05"),
		new AddressNameBytes("140005d20", "Q3NS::Q3::fp2_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 6b 4c 24 10 10 03 c1"),
		new AddressNameBytes("140005d40", "Q3NS::Q3::fp2_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 83 c0 0f"),
		new AddressNameBytes("140005d60", "Q4NS::Q4::fp2_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 6b 4c 24 10 10 03 c1"),
		new AddressNameBytes("140005d80", "Q4NS::Q4::fp2_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 83 c0 0f"),
		new AddressNameBytes("140005da0", "Q5NS::Q5::fp2_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 6b 4c 24 10 10 03 c1"),
		new AddressNameBytes("140005dc0", "Q5NS::Q5::fp2_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 83 c0 0f"),
		new AddressNameBytes("140005de0", "Q6NS::Q6::fp2_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 6b 4c 24 10 10 8d 04 c1"),
		new AddressNameBytes("140005e00", "Q6NS::Q6::fp2_4",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 8d 04 c5 0f 00 00 00"),
		new AddressNameBytes("140005e20", "Q7NS::Q7::fp2_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 6b 4c 24 10 10 03 c1"),
		new AddressNameBytes("140005e40", "Q7NS::Q7::fp2_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 83 c0 0f"),
		new AddressNameBytes("140005e60", "R1NS::R1::fp2_4",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 8b 4c 24 10 8d 44 08 16"),
		new AddressNameBytes("140005e80", "R1NS::R1::fp2_4",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 83 c0 15"),
		new AddressNameBytes("140005e94", "[thunk]:R1NS::R1::fp2_4`adjustor{40}'",
			"48 83 e9 28 e9 c3 ff ff"),
		new AddressNameBytes("140005ea0", "[thunk]:R1NS::R1::fp2_4`adjustor{40}'",
			"48 83 e9 28 e9 d7 ff ff"),
		new AddressNameBytes("140005eb0", "P2NS::P2::fp2_5",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 8d 44 00 07"),
		new AddressNameBytes("140005ed0", "Q3NS::Q3::fp2_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 83 c0 11"),
		new AddressNameBytes("140005ef0", "Q4NS::Q4::fp2_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 83 c0 11"),
		new AddressNameBytes("140005f10", "Q5NS::Q5::fp2_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 83 c0 11"),
		new AddressNameBytes("140005f30", "Q6NS::Q6::fp2_5",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 8d 04 c5 11 00 00 00"),
		new AddressNameBytes("140005f50", "Q7NS::Q7::fp2_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 83 c0 11"),
		new AddressNameBytes("140005f70", "R1NS::R1::fp2_5",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 83 c0 17"),
		new AddressNameBytes("140005f84", "[thunk]:R1NS::R1::fp2_5`adjustor{40}'",
			"48 83 e9 28 e9 e3 ff ff"),
		new AddressNameBytes("140005f90", "P2NS::P2::fp2_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 08 6b 4c 24 10 09 8d 04 41"),
		new AddressNameBytes("140005fb0", "P2NS::P2::fp2_6",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 8d 44 00 08"),
		new AddressNameBytes("140005fd0", "Q3NS::Q3::fp2_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 6b 4c 24 10 13 03 c1"),
		new AddressNameBytes("140005ff0", "Q3NS::Q3::fp2_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 83 c0 12"),
		new AddressNameBytes("140006010", "Q4NS::Q4::fp2_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 6b 4c 24 10 13 03 c1"),
		new AddressNameBytes("140006030", "Q4NS::Q4::fp2_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 83 c0 12"),
		new AddressNameBytes("140006050", "Q5NS::Q5::fp2_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 6b 4c 24 10 13 03 c1"),
		new AddressNameBytes("140006070", "Q5NS::Q5::fp2_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 83 c0 12"),
		new AddressNameBytes("140006090", "Q6NS::Q6::fp2_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 6b 4c 24 10 13 8d 04 c1"),
		new AddressNameBytes("1400060b0", "Q6NS::Q6::fp2_6",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 8d 04 c5 12 00 00 00"),
		new AddressNameBytes("1400060d0", "Q7NS::Q7::fp2_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 6b 4c 24 10 13 03 c1"),
		new AddressNameBytes("1400060f0", "Q7NS::Q7::fp2_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 83 c0 12"),
		new AddressNameBytes("140006110", "R1NS::R1::fp2_6",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 8b 4c 24 10 8d 44 08 19"),
		new AddressNameBytes("140006130", "R1NS::R1::fp2_6",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 83 c0 18"),
		new AddressNameBytes("140006144", "[thunk]:R1NS::R1::fp2_6`adjustor{40}'",
			"48 83 e9 28 e9 c3 ff ff"),
		new AddressNameBytes("140006150", "[thunk]:R1NS::R1::fp2_6`adjustor{40}'",
			"48 83 e9 28 e9 d7 ff ff"),
		new AddressNameBytes("140006160", "Q3NS::Q3::fp2_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 83 c0 14"),
		new AddressNameBytes("140006180", "Q4NS::Q4::fp2_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 83 c0 14"),
		new AddressNameBytes("1400061a0", "Q5NS::Q5::fp2_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 83 c0 14"),
		new AddressNameBytes("1400061c0", "Q6NS::Q6::fp2_7",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 8d 04 c5 14 00 00 00"),
		new AddressNameBytes("1400061e0", "Q7NS::Q7::fp2_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 83 c0 14"),
		new AddressNameBytes("140006200", "R1NS::R1::fp2_7",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 83 c0 1a"),
		new AddressNameBytes("140006214", "[thunk]:R1NS::R1::fp2_7`adjustor{40}'",
			"48 83 e9 28 e9 e3 ff ff"),
		new AddressNameBytes("140006220", "Q3NS::Q3::fp2_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 6b 4c 24 10 16 03 c1"),
		new AddressNameBytes("140006240", "Q3NS::Q3::fp2_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 83 c0 15"),
		new AddressNameBytes("140006260", "Q4NS::Q4::fp2_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 6b 4c 24 10 16 03 c1"),
		new AddressNameBytes("140006280", "Q4NS::Q4::fp2_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 83 c0 15"),
		new AddressNameBytes("1400062a0", "Q5NS::Q5::fp2_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 6b 4c 24 10 16 03 c1"),
		new AddressNameBytes("1400062c0", "Q5NS::Q5::fp2_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 83 c0 15"),
		new AddressNameBytes("1400062e0", "Q6NS::Q6::fp2_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 6b 4c 24 10 16 8d 04 c1"),
		new AddressNameBytes("140006300", "Q6NS::Q6::fp2_8",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 8d 04 c5 15 00 00 00"),
		new AddressNameBytes("140006320", "Q7NS::Q7::fp2_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 6b 4c 24 10 16 03 c1"),
		new AddressNameBytes("140006340", "Q7NS::Q7::fp2_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 83 c0 15"),
		new AddressNameBytes("140006360", "R1NS::R1::fp2_8",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 8b 4c 24 10 8d 44 08 1c"),
		new AddressNameBytes("140006380", "R1NS::R1::fp2_8",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 83 c0 1b"),
		new AddressNameBytes("140006394", "[thunk]:R1NS::R1::fp2_8`adjustor{40}'",
			"48 83 e9 28 e9 c3 ff ff"),
		new AddressNameBytes("1400063a0", "[thunk]:R1NS::R1::fp2_8`adjustor{40}'",
			"48 83 e9 28 e9 d7 ff ff"),
		new AddressNameBytes("1400063b0", "Q3NS::Q3::fp2_9",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 05 83 c0 17"),
		new AddressNameBytes("1400063d0", "Q4NS::Q4::fp2_9",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 83 c0 17"),
		new AddressNameBytes("1400063f0", "Q5NS::Q5::fp2_9",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 07 83 c0 17"),
		new AddressNameBytes("140006410", "Q6NS::Q6::fp2_9",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 f8 8d 04 c5 17 00 00 00"),
		new AddressNameBytes("140006430", "Q7NS::Q7::fp2_9",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 09 83 c0 17"),
		new AddressNameBytes("140006450", "R1NS::R1::fp2_9",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 e8 0a 83 c0 1d"),
		new AddressNameBytes("140006464", "[thunk]:R1NS::R1::fp2_9`adjustor{40}'",
			"48 83 e9 28 e9 e3 ff ff"),
		new AddressNameBytes("1400064d0", "Q1NS::Q1::fq1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 03 83 c0 04"),
		new AddressNameBytes("1400064f0", "Q2NS::Q2::fq1_3",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 20 8d 04 85 04 00 00 00"),
		new AddressNameBytes("140006510", "Q3NS::Q3::fq1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 20 05 83 c0 04"),
		new AddressNameBytes("140006530", "Q4NS::Q4::fq1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 06 83 c0 04"),
		new AddressNameBytes("140006550", "Q5NS::Q5::fq1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 18 07 83 c0 04"),
		new AddressNameBytes("140006570", "Q6NS::Q6::fq1_3",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 18 8d 04 c5 04 00 00 00"),
		new AddressNameBytes("140006590", "Q7NS::Q7::fq1_3",
			"48 89 4c 24 08 48 8b 44 24 08 6b 40 10 09 83 c0 04"),
		new AddressNameBytes("1400065b0", "R1NS::R1::fq1_3",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 f8 0a 8b 4c 24 10 8d 44 08 20"),
		new AddressNameBytes("140006630", "R1NS::R1::fq2_3",
			"89 54 24 10 48 89 4c 24 08 48 8b 44 24 08 6b 40 d0 0a 8b 4c 24 10 8d 44 08 21"),
		new AddressNameBytes("1400069a4", "type_info::`scalar_deleting_destructor'",
			"40 53 48 83 ec 20 48 8d 05 7f c2 05 00 48 8b d9 48 89 01 f6 c2 01 74 0a ba 18 00 00 00 e8 22 03 00 00 48 8b c3 48 83 c4 20 5b"),
		new AddressNameBytes("140007b38", "_purecall",
			"48 83 ec 28 e8 eb ff ff ff 48 85 c0 74 06 ff 15 94 a7 05 00 e8 8f 9c 03")
	};

	private static CppCompositeType createP1_struct(DataTypeManager dtm) {
		String name = "P1NS::P1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("p1", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(0, 24, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(0, 32, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(0, 40, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(0, 48, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(0, 56, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(0, 64, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createP2_struct(DataTypeManager dtm) {
		String name = "P2NS::P2";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("p2", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(0, 24, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(0, 32, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(0, 40, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(0, 48, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(0, 56, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(0, 64, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(0, 72, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(0, 80, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(0, 88, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createQ1_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q1NS::Q1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(P1_struct.getComposite(), P1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(P2_struct.getComposite(), P2_struct, publicDirectAttributes, 16);
		struct.addMember("q1", intT, false, publicDirectAttributes, 32, null);
		struct.addVirtualMethod(0, 72, new SymbolPath(classSp, "fq1_3"), fintintT);
		struct.addVirtualMethod(0, 80, new SymbolPath(classSp, "fq1_3"), fintvoidT);
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
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(P1_struct.getComposite(), P1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(P2_struct.getComposite(), P2_struct, publicDirectAttributes, 16);
		struct.addMember("q2", intT, false, publicDirectAttributes, 32, null);
		struct.addVirtualMethod(0, 72, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		struct.addVirtualMethod(0, 80, new SymbolPath(classSp, "fp2_11"), fintvoidT);
		struct.addVirtualMethod(0, 88, new SymbolPath(classSp, "fp2_12"), fintintT);
		struct.addVirtualMethod(0, 96, new SymbolPath(classSp, "fq2_3"), fintintT);
		return struct;
	}

	private static CppCompositeType createQ3_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q3NS::Q3";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(P1_struct.getComposite(), P1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(P2_struct.getComposite(), P2_struct, publicDirectAttributes, 16);
		struct.addMember("q3", intT, false, publicDirectAttributes, 32, null);
		struct.addVirtualMethod(0, 72, new SymbolPath(classSp, "fq1_3"), fintvoidT);
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

	// Note P2/P1 reversed args from others
	private static CppCompositeType createQ4_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q4NS::Q4";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addDirectBaseClass(P2_struct.getComposite(), P2_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(P1_struct.getComposite(), P1_struct,
			publicDirectAttributes, 16, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("q4", intT, false, publicDirectAttributes, 24, null);
		struct.addVirtualMethod(0, 96, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
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
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addDirectBaseClass(P1_struct.getComposite(), P1_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(P2_struct.getComposite(), P2_struct,
			publicDirectAttributes, 16, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("q5", intT, false, publicDirectAttributes, 24, null);
		struct.addVirtualMethod(0, 72, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createQ6_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q6NS::Q6";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addDirectBaseClass(P1_struct.getComposite(), P1_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(P2_struct.getComposite(), P2_struct,
			publicDirectAttributes, 16, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("q6", intT, false, publicDirectAttributes, 24, null);
		struct.addVirtualMethod(0, 72, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createQ7_struct(DataTypeManager dtm, CppCompositeType P1_struct,
			CppCompositeType P2_struct) throws PdbException {
		String name = "Q7NS::Q7";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 56);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(P1_struct.getComposite(), P1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(P2_struct.getComposite(), P2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("q7", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fq1_3"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		return struct;
	}

	private static CppCompositeType createR1_struct(DataTypeManager dtm, CppCompositeType Q1_struct,
			CppCompositeType Q2_struct) throws PdbException {
		String name = "R1NS::R1";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 104);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(Q1_struct.getComposite(), Q1_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(Q2_struct.getComposite(), Q2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("r1", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "fp1_1"), fintvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "fp1_2"), fintintT);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "fp1_2"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_3"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_4"), fintintT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_4"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_5"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_6"), fintintT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_6"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_7"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_8"), fintintT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fp1_8"), fintvoidT);
		struct.addVirtualMethod(0, 24, new SymbolPath(classSp, "fp2_1"), fintvoidT);
		struct.addVirtualMethod(0, 32, new SymbolPath(classSp, "fp2_2"), fintintT);
		struct.addVirtualMethod(0, 40, new SymbolPath(classSp, "fp2_2"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_3"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_4"), fintintT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_4"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_5"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_6"), fintintT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_6"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_7"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_8"), fintintT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_8"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_9"), fintvoidT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_10"), fintintT);
		struct.addVirtualMethod(40, -1, new SymbolPath(classSp, "fp2_10"), fintvoidT);
		struct.addVirtualMethod(24, -1, new SymbolPath(classSp, "fq1_3"), fintintT);
		struct.addVirtualMethod(64, -1, new SymbolPath(classSp, "fq2_3"), fintintT);
		return struct;
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================

	//@formatter:off
	/*
	class P1NS::P1	size(16):
		+---
	 0	| {vfptr}
	 8	| p1
	  	| <alignment member> (size=4)
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
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8""";
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
			   0   _func___thiscall_int *   8   P1NS::P1::fp1_3   ""
			   8   _func___thiscall_int_int *   8   P1NS::P1::fp1_4   ""
			   16   _func___thiscall_int *   8   P1NS::P1::fp1_4   ""
			   24   _func___thiscall_int *   8   P1NS::P1::fp1_5   ""
			   32   _func___thiscall_int_int *   8   P1NS::P1::fp1_6   ""
			   40   _func___thiscall_int *   8   P1NS::P1::fp1_6   ""
			   48   _func___thiscall_int *   8   P1NS::P1::fp1_7   ""
			   56   _func___thiscall_int_int *   8   P1NS::P1::fp1_8   ""
			   64   _func___thiscall_int *   8   P1NS::P1::fp1_8   ""
			}
			Length: 72 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class P2NS::P2	size(16):
		+---
	 0	| {vfptr}
	 8	| p2
	  	| <alignment member> (size=4)
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
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p2   ""
			}
			Length: 16 Alignment: 8""";
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
			   0   _func___thiscall_int *   8   P2NS::P2::fp2_3   ""
			   8   _func___thiscall_int_int *   8   P2NS::P2::fp2_4   ""
			   16   _func___thiscall_int *   8   P2NS::P2::fp2_4   ""
			   24   _func___thiscall_int *   8   P2NS::P2::fp2_5   ""
			   32   _func___thiscall_int_int *   8   P2NS::P2::fp2_6   ""
			   40   _func___thiscall_int *   8   P2NS::P2::fp2_6   ""
			   48   _func___thiscall_int *   8   P2NS::P2::fp2_7   ""
			   56   _func___thiscall_int_int *   8   P2NS::P2::fp2_8   ""
			   64   _func___thiscall_int *   8   P2NS::P2::fp2_8   ""
			   72   _func___thiscall_int *   8   P2NS::P2::fp2_9   ""
			   80   _func___thiscall_int_int *   8   P2NS::P2::fp2_10   ""
			   88   _func___thiscall_int *   8   P2NS::P2::fp2_10   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q1NS::Q1	size(40):
		+---
	 0	| +--- (base class P1NS::P1)
	 0	| | {vfptr}
	 8	| | p1
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class P2NS::P2)
	16	| | {vfptr}
	24	| | p2
	  	| | <alignment member> (size=4)
		| +---
	32	| q1
	  	| <alignment member> (size=4)
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
		| -16
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
			   0   P1NS::P1   16      "Base"
			   16   P2NS::P2   16      "Base"
			   32   int   4   q1   ""
			}
			Length: 40 Alignment: 8
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ1() {
		return convertCommentsToSpeculative(getExpectedStructQ1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P1NS::P1]	[Q1NS::Q1, P1NS::P1]");
		results.put("VTABLE_00000010", "    16 vft [P2NS::P2]	[Q1NS::Q1, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ1_00000000());
		results.put("VTABLE_00000010", getVxtStructQ1_00000010());
		return results;
	}

	private static String getVxtStructQ1_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q1NS/Q1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   Q1NS::Q1::fp1_3   ""
			   8   _func___thiscall_int_int *   8   Q1NS::Q1::fp1_4   ""
			   16   _func___thiscall_int *   8   Q1NS::Q1::fp1_4   ""
			   24   _func___thiscall_int *   8   Q1NS::Q1::fp1_5   ""
			   32   _func___thiscall_int_int *   8   Q1NS::Q1::fp1_6   ""
			   40   _func___thiscall_int *   8   Q1NS::Q1::fp1_6   ""
			   48   _func___thiscall_int *   8   Q1NS::Q1::fp1_7   ""
			   56   _func___thiscall_int_int *   8   Q1NS::Q1::fp1_8   ""
			   64   _func___thiscall_int *   8   Q1NS::Q1::fp1_8   ""
			   72   _func___thiscall_int_int *   8   Q1NS::Q1::fq1_3   ""
			   80   _func___thiscall_int *   8   Q1NS::Q1::fq1_3   ""
			}
			Length: 88 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ1_00000010() {
		String expected =
		//@formatter:off
			"""
			/Q1NS/Q1/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   8   P2NS::P2::fp2_3   ""
			   8   _func___thiscall_int_int *   8   P2NS::P2::fp2_4   ""
			   16   _func___thiscall_int *   8   P2NS::P2::fp2_4   ""
			   24   _func___thiscall_int *   8   P2NS::P2::fp2_5   ""
			   32   _func___thiscall_int_int *   8   P2NS::P2::fp2_6   ""
			   40   _func___thiscall_int *   8   P2NS::P2::fp2_6   ""
			   48   _func___thiscall_int *   8   P2NS::P2::fp2_7   ""
			   56   _func___thiscall_int_int *   8   P2NS::P2::fp2_8   ""
			   64   _func___thiscall_int *   8   P2NS::P2::fp2_8   ""
			   72   _func___thiscall_int *   8   P2NS::P2::fp2_9   ""
			   80   _func___thiscall_int_int *   8   P2NS::P2::fp2_10   ""
			   88   _func___thiscall_int *   8   P2NS::P2::fp2_10   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}
	//==============================================================================================

	//@formatter:off
	/*
	class Q2NS::Q2	size(40):
		+---
	 0	| +--- (base class P1NS::P1)
	 0	| | {vfptr}
	 8	| | p1
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class P2NS::P2)
	16	| | {vfptr}
	24	| | p2
	  	| | <alignment member> (size=4)
		| +---
	32	| q2
	  	| <alignment member> (size=4)
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
		| -16
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
	Q2NS::Q2::fp2_10 this adjustor: 16
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
			   0   P1NS::P1   16      "Base"
			   16   P2NS::P2   16      "Base"
			   32   int   4   q2   ""
			}
			Length: 40 Alignment: 8
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ2() {
		return convertCommentsToSpeculative(getExpectedStructQ2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P1NS::P1]	[Q2NS::Q2, P1NS::P1]");
		results.put("VTABLE_00000010", "    16 vft [P2NS::P2]	[Q2NS::Q2, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ2_00000000());
		results.put("VTABLE_00000010", getVxtStructQ2_00000010());
		return results;
	}

	private static String getVxtStructQ2_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q2NS/Q2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   Q2NS::Q2::fp1_3   ""
			   8   _func___thiscall_int_int *   8   Q2NS::Q2::fp1_4   ""
			   16   _func___thiscall_int *   8   Q2NS::Q2::fp1_4   ""
			   24   _func___thiscall_int *   8   Q2NS::Q2::fp1_5   ""
			   32   _func___thiscall_int_int *   8   Q2NS::Q2::fp1_6   ""
			   40   _func___thiscall_int *   8   Q2NS::Q2::fp1_6   ""
			   48   _func___thiscall_int *   8   Q2NS::Q2::fp1_7   ""
			   56   _func___thiscall_int_int *   8   Q2NS::Q2::fp1_8   ""
			   64   _func___thiscall_int *   8   Q2NS::Q2::fp1_8   ""
			   72   _func___thiscall_int *   8   Q2NS::Q2::fq1_3   ""
			   80   _func___thiscall_int *   8   Q2NS::Q2::fp2_11   ""
			   88   _func___thiscall_int_int *   8   Q2NS::Q2::fp2_12   ""
			   96   _func___thiscall_int_int *   8   Q2NS::Q2::fq2_3   ""
			}
			Length: 104 Alignment: 8
			""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ2_00000010() {
		String expected =
		//@formatter:off
			"""
			/Q2NS/Q2/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   8   P2NS::P2::fp2_3   ""
			   8   _func___thiscall_int_int *   8   P2NS::P2::fp2_4   ""
			   16   _func___thiscall_int *   8   P2NS::P2::fp2_4   ""
			   24   _func___thiscall_int *   8   P2NS::P2::fp2_5   ""
			   32   _func___thiscall_int_int *   8   P2NS::P2::fp2_6   ""
			   40   _func___thiscall_int *   8   P2NS::P2::fp2_6   ""
			   48   _func___thiscall_int *   8   P2NS::P2::fp2_7   ""
			   56   _func___thiscall_int_int *   8   P2NS::P2::fp2_8   ""
			   64   _func___thiscall_int *   8   P2NS::P2::fp2_8   ""
			   72   _func___thiscall_int *   8   P2NS::P2::fp2_9   ""
			   80   _func___thiscall_int_int *   8   P2NS::P2::fp2_10   ""
			   88   _func___thiscall_int *   8   Q2NS::Q2::fp2_10   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q3NS::Q3	size(40):
		+---
	 0	| +--- (base class P1NS::P1)
	 0	| | {vfptr}
	 8	| | p1
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class P2NS::P2)
	16	| | {vfptr}
	24	| | p2
	  	| | <alignment member> (size=4)
		| +---
	32	| q3
	  	| <alignment member> (size=4)
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
		| -16
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
	Q3NS::Q3::fp2_3 this adjustor: 16
	Q3NS::Q3::fp2_4 this adjustor: 16
	Q3NS::Q3::fp2_4 this adjustor: 16
	Q3NS::Q3::fp2_5 this adjustor: 16
	Q3NS::Q3::fp2_6 this adjustor: 16
	Q3NS::Q3::fp2_6 this adjustor: 16
	Q3NS::Q3::fp2_7 this adjustor: 16
	Q3NS::Q3::fp2_8 this adjustor: 16
	Q3NS::Q3::fp2_8 this adjustor: 16
	Q3NS::Q3::fp2_9 this adjustor: 16
	Q3NS::Q3::fp2_10 this adjustor: 16
	Q3NS::Q3::fp2_10 this adjustor: 16
	 */
	//@formatter:on
	private static String getExpectedStructQ3() {
		String expected =
		//@formatter:off
			"""
			/Q3NS::Q3
			pack()
			Structure Q3NS::Q3 {
			   0   P1NS::P1   16      "Base"
			   16   P2NS::P2   16      "Base"
			   32   int   4   q3   ""
			}
			Length: 40 Alignment: 8
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ3() {
		return convertCommentsToSpeculative(getExpectedStructQ3());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P1NS::P1]	[Q3NS::Q3, P1NS::P1]");
		results.put("VTABLE_00000010", "    16 vft [P2NS::P2]	[Q3NS::Q3, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ3_00000000());
		results.put("VTABLE_00000010", getVxtStructQ3_00000010());
		return results;
	}

	private static String getVxtStructQ3_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q3NS/Q3/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   Q3NS::Q3::fp1_3   ""
			   8   _func___thiscall_int_int *   8   Q3NS::Q3::fp1_4   ""
			   16   _func___thiscall_int *   8   Q3NS::Q3::fp1_4   ""
			   24   _func___thiscall_int *   8   Q3NS::Q3::fp1_5   ""
			   32   _func___thiscall_int_int *   8   Q3NS::Q3::fp1_6   ""
			   40   _func___thiscall_int *   8   Q3NS::Q3::fp1_6   ""
			   48   _func___thiscall_int *   8   Q3NS::Q3::fp1_7   ""
			   56   _func___thiscall_int_int *   8   Q3NS::Q3::fp1_8   ""
			   64   _func___thiscall_int *   8   Q3NS::Q3::fp1_8   ""
			   72   _func___thiscall_int *   8   Q3NS::Q3::fq1_3   ""
			}
			Length: 80 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ3_00000010() {
		String expected =
		//@formatter:off
			"""
			/Q3NS/Q3/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_int *   8   Q3NS::Q3::fp2_3   ""
			   8   _func___thiscall_int_int *   8   Q3NS::Q3::fp2_4   ""
			   16   _func___thiscall_int *   8   Q3NS::Q3::fp2_4   ""
			   24   _func___thiscall_int *   8   Q3NS::Q3::fp2_5   ""
			   32   _func___thiscall_int_int *   8   Q3NS::Q3::fp2_6   ""
			   40   _func___thiscall_int *   8   Q3NS::Q3::fp2_6   ""
			   48   _func___thiscall_int *   8   Q3NS::Q3::fp2_7   ""
			   56   _func___thiscall_int_int *   8   Q3NS::Q3::fp2_8   ""
			   64   _func___thiscall_int *   8   Q3NS::Q3::fp2_8   ""
			   72   _func___thiscall_int *   8   Q3NS::Q3::fp2_9   ""
			   80   _func___thiscall_int_int *   8   Q3NS::Q3::fp2_10   ""
			   88   _func___thiscall_int *   8   Q3NS::Q3::fp2_10   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q4NS::Q4	size(48):
		+---
	 0	| +--- (base class P2NS::P2)
	 0	| | {vfptr}
	 8	| | p2
	  	| | <alignment member> (size=4)
		| +---
	16	| {vbptr}
	24	| q4
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base P1NS::P1)
	32	| {vfptr}
	40	| p1
	  	| <alignment member> (size=4)
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
	 0	| -16
	 1	| 16 (Q4d(Q4+16)P1)

	Q4NS::Q4::$vftable@P1@:
		| -32
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
	Q4NS::Q4::fp1_3 this adjustor: 32
	Q4NS::Q4::fp1_4 this adjustor: 32
	Q4NS::Q4::fp1_4 this adjustor: 32
	Q4NS::Q4::fp1_5 this adjustor: 32
	Q4NS::Q4::fp1_6 this adjustor: 32
	Q4NS::Q4::fp1_6 this adjustor: 32
	Q4NS::Q4::fp1_7 this adjustor: 32
	Q4NS::Q4::fp1_8 this adjustor: 32
	Q4NS::Q4::fp1_8 this adjustor: 32
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
	        P1NS::P1      32      16       4 0
	 */
	//@formatter:on
	private static String getExpectedStructQ4() {
		String expected =
		//@formatter:off
			"""
			/Q4NS::Q4
			pack()
			Structure Q4NS::Q4 {
			   0   Q4NS::Q4   32      "Self Base"
			   32   P1NS::P1   16      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p2   ""
			}
			Length: 16 Alignment: 8
			/Q4NS::Q4/!internal/Q4NS::Q4
			pack()
			Structure Q4NS::Q4 {
			   0   P2NS::P2   16      "Base"
			   16   pointer   8   {vbptr}   ""
			   24   int   4   q4   ""
			}
			Length: 32 Alignment: 8""";
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
			   0   Q4NS::Q4   32      "Self Base"
			   32   char[16]   16      "Filler for 1 Unplaceable Virtual Base: P1NS::P1"
			}
			Length: 48 Alignment: 8
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p2   ""
			}
			Length: 16 Alignment: 8
			/Q4NS::Q4/!internal/Q4NS::Q4
			pack()
			Structure Q4NS::Q4 {
			   0   P2NS::P2   16      "Base"
			   16   pointer   8   {vbptr}   ""
			   24   int   4   q4   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ4() {
		return convertCommentsToSpeculative(getExpectedStructQ4());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P2NS::P2]	[Q4NS::Q4, P2NS::P2]");
		results.put("VTABLE_00000010", "    16 vbt []	[Q4NS::Q4]");
		results.put("VTABLE_00000020", "    32 vft [P1NS::P1]	[Q4NS::Q4, P1NS::P1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ4_00000000());
		results.put("VTABLE_00000010", getVxtStructQ4_00000010());
		results.put("VTABLE_00000020", getVxtStructQ4_00000020());
		return results;
	}

	private static String getVxtStructQ4_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q4NS/Q4/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   Q4NS::Q4::fp2_3   ""
			   8   _func___thiscall_int_int *   8   Q4NS::Q4::fp2_4   ""
			   16   _func___thiscall_int *   8   Q4NS::Q4::fp2_4   ""
			   24   _func___thiscall_int *   8   Q4NS::Q4::fp2_5   ""
			   32   _func___thiscall_int_int *   8   Q4NS::Q4::fp2_6   ""
			   40   _func___thiscall_int *   8   Q4NS::Q4::fp2_6   ""
			   48   _func___thiscall_int *   8   Q4NS::Q4::fp2_7   ""
			   56   _func___thiscall_int_int *   8   Q4NS::Q4::fp2_8   ""
			   64   _func___thiscall_int *   8   Q4NS::Q4::fp2_8   ""
			   72   _func___thiscall_int *   8   Q4NS::Q4::fp2_9   ""
			   80   _func___thiscall_int_int *   8   Q4NS::Q4::fp2_10   ""
			   88   _func___thiscall_int *   8   Q4NS::Q4::fp2_10   ""
			   96   _func___thiscall_int *   8   Q4NS::Q4::fq1_3   ""
			}
			Length: 104 Alignment: 8""";
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
			   0   int   4      "P1NS::P1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ4_00000020() {
		String expected =
		//@formatter:off
			"""
			/Q4NS/Q4/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_int *   8   Q4NS::Q4::fp1_3   ""
			   8   _func___thiscall_int_int *   8   Q4NS::Q4::fp1_4   ""
			   16   _func___thiscall_int *   8   Q4NS::Q4::fp1_4   ""
			   24   _func___thiscall_int *   8   Q4NS::Q4::fp1_5   ""
			   32   _func___thiscall_int_int *   8   Q4NS::Q4::fp1_6   ""
			   40   _func___thiscall_int *   8   Q4NS::Q4::fp1_6   ""
			   48   _func___thiscall_int *   8   Q4NS::Q4::fp1_7   ""
			   56   _func___thiscall_int_int *   8   Q4NS::Q4::fp1_8   ""
			   64   _func___thiscall_int *   8   Q4NS::Q4::fp1_8   ""
			}
			Length: 72 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q5NS::Q5	size(48):
		+---
	 0	| +--- (base class P1NS::P1)
	 0	| | {vfptr}
	 8	| | p1
	  	| | <alignment member> (size=4)
		| +---
	16	| {vbptr}
	24	| q5
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base P2NS::P2)
	32	| {vfptr}
	40	| p2
	  	| <alignment member> (size=4)
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
	 0	| -16
	 1	| 16 (Q5d(Q5+16)P2)

	Q5NS::Q5::$vftable@P2@:
		| -32
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
	Q5NS::Q5::fp2_3 this adjustor: 32
	Q5NS::Q5::fp2_4 this adjustor: 32
	Q5NS::Q5::fp2_4 this adjustor: 32
	Q5NS::Q5::fp2_5 this adjustor: 32
	Q5NS::Q5::fp2_6 this adjustor: 32
	Q5NS::Q5::fp2_6 this adjustor: 32
	Q5NS::Q5::fp2_7 this adjustor: 32
	Q5NS::Q5::fp2_8 this adjustor: 32
	Q5NS::Q5::fp2_8 this adjustor: 32
	Q5NS::Q5::fp2_9 this adjustor: 32
	Q5NS::Q5::fp2_10 this adjustor: 32
	Q5NS::Q5::fp2_10 this adjustor: 32
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        P2NS::P2      32      16       4 0
	 */
	//@formatter:on
	private static String getExpectedStructQ5() {
		String expected =
		//@formatter:off
			"""
			/Q5NS::Q5
			pack()
			Structure Q5NS::Q5 {
			   0   Q5NS::Q5   32      "Self Base"
			   32   P2NS::P2   16      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p2   ""
			}
			Length: 16 Alignment: 8
			/Q5NS::Q5/!internal/Q5NS::Q5
			pack()
			Structure Q5NS::Q5 {
			   0   P1NS::P1   16      "Base"
			   16   pointer   8   {vbptr}   ""
			   24   int   4   q5   ""
			}
			Length: 32 Alignment: 8""";
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
			   0   Q5NS::Q5   32      "Self Base"
			   32   char[16]   16      "Filler for 1 Unplaceable Virtual Base: P2NS::P2"
			}
			Length: 48 Alignment: 8
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/Q5NS::Q5/!internal/Q5NS::Q5
			pack()
			Structure Q5NS::Q5 {
			   0   P1NS::P1   16      "Base"
			   16   pointer   8   {vbptr}   ""
			   24   int   4   q5   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ5() {
		return convertCommentsToSpeculative(getExpectedStructQ5());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ5() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P1NS::P1]	[Q5NS::Q5, P1NS::P1]");
		results.put("VTABLE_00000010", "    16 vbt []	[Q5NS::Q5]");
		results.put("VTABLE_00000020", "    32 vft [P2NS::P2]	[Q5NS::Q5, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ5() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ5_00000000());
		results.put("VTABLE_00000010", getVxtStructQ5_00000010());
		results.put("VTABLE_00000020", getVxtStructQ5_00000020());
		return results;
	}

	private static String getVxtStructQ5_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q5NS/Q5/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   Q5NS::Q5::fp1_3   ""
			   8   _func___thiscall_int_int *   8   Q5NS::Q5::fp1_4   ""
			   16   _func___thiscall_int *   8   Q5NS::Q5::fp1_4   ""
			   24   _func___thiscall_int *   8   Q5NS::Q5::fp1_5   ""
			   32   _func___thiscall_int_int *   8   Q5NS::Q5::fp1_6   ""
			   40   _func___thiscall_int *   8   Q5NS::Q5::fp1_6   ""
			   48   _func___thiscall_int *   8   Q5NS::Q5::fp1_7   ""
			   56   _func___thiscall_int_int *   8   Q5NS::Q5::fp1_8   ""
			   64   _func___thiscall_int *   8   Q5NS::Q5::fp1_8   ""
			   72   _func___thiscall_int *   8   Q5NS::Q5::fq1_3   ""
			}
			Length: 80 Alignment: 8""";
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
			   0   int   4      "P2NS::P2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ5_00000020() {
		String expected =
		//@formatter:off
			"""
			/Q5NS/Q5/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_int *   8   Q5NS::Q5::fp2_3   ""
			   8   _func___thiscall_int_int *   8   Q5NS::Q5::fp2_4   ""
			   16   _func___thiscall_int *   8   Q5NS::Q5::fp2_4   ""
			   24   _func___thiscall_int *   8   Q5NS::Q5::fp2_5   ""
			   32   _func___thiscall_int_int *   8   Q5NS::Q5::fp2_6   ""
			   40   _func___thiscall_int *   8   Q5NS::Q5::fp2_6   ""
			   48   _func___thiscall_int *   8   Q5NS::Q5::fp2_7   ""
			   56   _func___thiscall_int_int *   8   Q5NS::Q5::fp2_8   ""
			   64   _func___thiscall_int *   8   Q5NS::Q5::fp2_8   ""
			   72   _func___thiscall_int *   8   Q5NS::Q5::fp2_9   ""
			   80   _func___thiscall_int_int *   8   Q5NS::Q5::fp2_10   ""
			   88   _func___thiscall_int *   8   Q5NS::Q5::fp2_10   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q6NS::Q6	size(48):
		+---
	 0	| +--- (base class P1NS::P1)
	 0	| | {vfptr}
	 8	| | p1
	  	| | <alignment member> (size=4)
		| +---
	16	| {vbptr}
	24	| q6
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base P2NS::P2)
	32	| {vfptr}
	40	| p2
	  	| <alignment member> (size=4)
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
	 0	| -16
	 1	| 16 (Q6d(Q6+16)P2)

	Q6NS::Q6::$vftable@P2@:
		| -32
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
	Q6NS::Q6::fp2_3 this adjustor: 32
	Q6NS::Q6::fp2_4 this adjustor: 32
	Q6NS::Q6::fp2_4 this adjustor: 32
	Q6NS::Q6::fp2_5 this adjustor: 32
	Q6NS::Q6::fp2_6 this adjustor: 32
	Q6NS::Q6::fp2_6 this adjustor: 32
	Q6NS::Q6::fp2_7 this adjustor: 32
	Q6NS::Q6::fp2_8 this adjustor: 32
	Q6NS::Q6::fp2_8 this adjustor: 32
	Q6NS::Q6::fp2_9 this adjustor: 32
	Q6NS::Q6::fp2_10 this adjustor: 32
	Q6NS::Q6::fp2_10 this adjustor: 32
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        P2NS::P2      32      16       4 0
	 */
	//@formatter:on
	private static String getExpectedStructQ6() {
		String expected =
		//@formatter:off
			"""
			/Q6NS::Q6
			pack()
			Structure Q6NS::Q6 {
			   0   Q6NS::Q6   32      "Self Base"
			   32   P2NS::P2   16      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p2   ""
			}
			Length: 16 Alignment: 8
			/Q6NS::Q6/!internal/Q6NS::Q6
			pack()
			Structure Q6NS::Q6 {
			   0   P1NS::P1   16      "Base"
			   16   pointer   8   {vbptr}   ""
			   24   int   4   q6   ""
			}
			Length: 32 Alignment: 8""";
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
			   0   Q6NS::Q6   32      "Self Base"
			   32   char[16]   16      "Filler for 1 Unplaceable Virtual Base: P2NS::P2"
			}
			Length: 48 Alignment: 8
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/Q6NS::Q6/!internal/Q6NS::Q6
			pack()
			Structure Q6NS::Q6 {
			   0   P1NS::P1   16      "Base"
			   16   pointer   8   {vbptr}   ""
			   24   int   4   q6   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ6() {
		return convertCommentsToSpeculative(getExpectedStructQ6());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ6() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P1NS::P1]	[Q6NS::Q6, P1NS::P1]");
		results.put("VTABLE_00000010", "    16 vbt []	[Q6NS::Q6]");
		results.put("VTABLE_00000020", "    32 vft [P2NS::P2]	[Q6NS::Q6, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ6() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ6_00000000());
		results.put("VTABLE_00000010", getVxtStructQ6_00000010());
		results.put("VTABLE_00000020", getVxtStructQ6_00000020());
		return results;
	}

	private static String getVxtStructQ6_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q6NS/Q6/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   Q6NS::Q6::fp1_3   ""
			   8   _func___thiscall_int_int *   8   Q6NS::Q6::fp1_4   ""
			   16   _func___thiscall_int *   8   Q6NS::Q6::fp1_4   ""
			   24   _func___thiscall_int *   8   Q6NS::Q6::fp1_5   ""
			   32   _func___thiscall_int_int *   8   Q6NS::Q6::fp1_6   ""
			   40   _func___thiscall_int *   8   Q6NS::Q6::fp1_6   ""
			   48   _func___thiscall_int *   8   Q6NS::Q6::fp1_7   ""
			   56   _func___thiscall_int_int *   8   Q6NS::Q6::fp1_8   ""
			   64   _func___thiscall_int *   8   Q6NS::Q6::fp1_8   ""
			   72   _func___thiscall_int *   8   Q6NS::Q6::fq1_3   ""
			}
			Length: 80 Alignment: 8""";
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
			   0   int   4      "P2NS::P2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ6_00000020() {
		String expected =
		//@formatter:off
			"""
			/Q6NS/Q6/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_int *   8   Q6NS::Q6::fp2_3   ""
			   8   _func___thiscall_int_int *   8   Q6NS::Q6::fp2_4   ""
			   16   _func___thiscall_int *   8   Q6NS::Q6::fp2_4   ""
			   24   _func___thiscall_int *   8   Q6NS::Q6::fp2_5   ""
			   32   _func___thiscall_int_int *   8   Q6NS::Q6::fp2_6   ""
			   40   _func___thiscall_int *   8   Q6NS::Q6::fp2_6   ""
			   48   _func___thiscall_int *   8   Q6NS::Q6::fp2_7   ""
			   56   _func___thiscall_int_int *   8   Q6NS::Q6::fp2_8   ""
			   64   _func___thiscall_int *   8   Q6NS::Q6::fp2_8   ""
			   72   _func___thiscall_int *   8   Q6NS::Q6::fp2_9   ""
			   80   _func___thiscall_int_int *   8   Q6NS::Q6::fp2_10   ""
			   88   _func___thiscall_int *   8   Q6NS::Q6::fp2_10   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q7NS::Q7	size(56):
		+---
	 0	| {vfptr}
	 8	| {vbptr}
	16	| q7
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base P1NS::P1)
	24	| {vfptr}
	32	| p1
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base P2NS::P2)
	40	| {vfptr}
	48	| p2
	  	| <alignment member> (size=4)
		+---

	Q7NS::Q7::$vftable@Q7@:
		| &Q7_meta
		|  0
	 0	| &Q7NS::Q7::fq1_3

	Q7NS::Q7::$vbtable@:
	 0	| -8
	 1	| 16 (Q7d(Q7+8)P1)
	 2	| 32 (Q7d(Q7+8)P2)

	Q7NS::Q7::$vftable@P1@:
		| -24
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
		| -40
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
	Q7NS::Q7::fp1_3 this adjustor: 24
	Q7NS::Q7::fp1_4 this adjustor: 24
	Q7NS::Q7::fp1_4 this adjustor: 24
	Q7NS::Q7::fp1_5 this adjustor: 24
	Q7NS::Q7::fp1_6 this adjustor: 24
	Q7NS::Q7::fp1_6 this adjustor: 24
	Q7NS::Q7::fp1_7 this adjustor: 24
	Q7NS::Q7::fp1_8 this adjustor: 24
	Q7NS::Q7::fp1_8 this adjustor: 24
	Q7NS::Q7::fp2_3 this adjustor: 40
	Q7NS::Q7::fp2_4 this adjustor: 40
	Q7NS::Q7::fp2_4 this adjustor: 40
	Q7NS::Q7::fp2_5 this adjustor: 40
	Q7NS::Q7::fp2_6 this adjustor: 40
	Q7NS::Q7::fp2_6 this adjustor: 40
	Q7NS::Q7::fp2_7 this adjustor: 40
	Q7NS::Q7::fp2_8 this adjustor: 40
	Q7NS::Q7::fp2_8 this adjustor: 40
	Q7NS::Q7::fp2_9 this adjustor: 40
	Q7NS::Q7::fp2_10 this adjustor: 40
	Q7NS::Q7::fp2_10 this adjustor: 40
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
        	P1NS::P1      24       8       4 0
	        P2NS::P2      40       8       8 0
	 */
	//@formatter:on
	private static String getExpectedStructQ7() {
		String expected =
		//@formatter:off
			"""
			/Q7NS::Q7
			pack()
			Structure Q7NS::Q7 {
			   0   Q7NS::Q7   24      "Self Base"
			   24   P1NS::P1   16      "Virtual Base"
			   40   P2NS::P2   16      "Virtual Base"
			}
			Length: 56 Alignment: 8
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p2   ""
			}
			Length: 16 Alignment: 8
			/Q7NS::Q7/!internal/Q7NS::Q7
			pack()
			Structure Q7NS::Q7 {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   q7   ""
			}
			Length: 24 Alignment: 8""";
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
			   0   Q7NS::Q7   24      "Self Base"
			   24   char[32]   32      "Filler for 2 Unplaceable Virtual Bases: P1NS::P1; P2NS::P2"
			}
			Length: 56 Alignment: 8
			/Q7NS::Q7/!internal/Q7NS::Q7
			pack()
			Structure Q7NS::Q7 {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   q7   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ7() {
		return convertCommentsToSpeculative(getExpectedStructQ7());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ7() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [Q7NS::Q7]	[Q7NS::Q7]");
		results.put("VTABLE_00000008", "     8 vbt []	[Q7NS::Q7]");
		results.put("VTABLE_00000018", "    24 vft [P1NS::P1]	[Q7NS::Q7, P1NS::P1]");
		results.put("VTABLE_00000028", "    40 vft [P2NS::P2]	[Q7NS::Q7, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ7() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ7_00000000());
		results.put("VTABLE_00000008", getVxtStructQ7_00000008());
		results.put("VTABLE_00000018", getVxtStructQ7_00000018());
		results.put("VTABLE_00000028", getVxtStructQ7_00000028());
		return results;
	}

	private static String getVxtStructQ7_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q7NS/Q7/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   Q7NS::Q7::fq1_3   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ7_00000008() {
		String expected =
		//@formatter:off
			"""
			/Q7NS/Q7/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "P1NS::P1"
			   4   int   4      "P2NS::P2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ7_00000018() {
		String expected =
		//@formatter:off
			"""
			/Q7NS/Q7/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   Q7NS::Q7::fp1_3   ""
			   8   _func___thiscall_int_int *   8   Q7NS::Q7::fp1_4   ""
			   16   _func___thiscall_int *   8   Q7NS::Q7::fp1_4   ""
			   24   _func___thiscall_int *   8   Q7NS::Q7::fp1_5   ""
			   32   _func___thiscall_int_int *   8   Q7NS::Q7::fp1_6   ""
			   40   _func___thiscall_int *   8   Q7NS::Q7::fp1_6   ""
			   48   _func___thiscall_int *   8   Q7NS::Q7::fp1_7   ""
			   56   _func___thiscall_int_int *   8   Q7NS::Q7::fp1_8   ""
			   64   _func___thiscall_int *   8   Q7NS::Q7::fp1_8   ""
			}
			Length: 72 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructQ7_00000028() {
		String expected =
		//@formatter:off
			"""
			/Q7NS/Q7/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_int *   8   Q7NS::Q7::fp2_3   ""
			   8   _func___thiscall_int_int *   8   Q7NS::Q7::fp2_4   ""
			   16   _func___thiscall_int *   8   Q7NS::Q7::fp2_4   ""
			   24   _func___thiscall_int *   8   Q7NS::Q7::fp2_5   ""
			   32   _func___thiscall_int_int *   8   Q7NS::Q7::fp2_6   ""
			   40   _func___thiscall_int *   8   Q7NS::Q7::fp2_6   ""
			   48   _func___thiscall_int *   8   Q7NS::Q7::fp2_7   ""
			   56   _func___thiscall_int_int *   8   Q7NS::Q7::fp2_8   ""
			   64   _func___thiscall_int *   8   Q7NS::Q7::fp2_8   ""
			   72   _func___thiscall_int *   8   Q7NS::Q7::fp2_9   ""
			   80   _func___thiscall_int_int *   8   Q7NS::Q7::fp2_10   ""
			   88   _func___thiscall_int *   8   Q7NS::Q7::fp2_10   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class R1NS::R1	size(104):
		+---
	 0	| {vfptr}
	 8	| {vbptr}
	16	| r1
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base Q1NS::Q1)
	24	| +--- (base class P1NS::P1)
	24	| | {vfptr}
	32	| | p1
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class P2NS::P2)
	40	| | {vfptr}
	48	| | p2
	  	| | <alignment member> (size=4)
		| +---
	56	| q1
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base Q2NS::Q2)
	64	| +--- (base class P1NS::P1)
	64	| | {vfptr}
	72	| | p1
	  	| | <alignment member> (size=4)
		| +---
	80	| +--- (base class P2NS::P2)
	80	| | {vfptr}
	88	| | p2
	  	| | <alignment member> (size=4)
		| +---
	96	| q2
	  	| <alignment member> (size=4)
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
	 0	| -8
	 1	| 16 (R1d(R1+8)Q1)
	 2	| 56 (R1d(R1+8)Q2)

	R1NS::R1::$vftable@P1@Q1@:
		| -24
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
		| -40
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
		| -64
	 0	| &thunk: this-=40; goto R1NS::R1::fp1_3
	 1	| &thunk: this-=40; goto R1NS::R1::fp1_4
	 2	| &thunk: this-=40; goto R1NS::R1::fp1_4
	 3	| &thunk: this-=40; goto R1NS::R1::fp1_5
	 4	| &thunk: this-=40; goto R1NS::R1::fp1_6
	 5	| &thunk: this-=40; goto R1NS::R1::fp1_6
	 6	| &thunk: this-=40; goto R1NS::R1::fp1_7
	 7	| &thunk: this-=40; goto R1NS::R1::fp1_8
	 8	| &thunk: this-=40; goto R1NS::R1::fp1_8
	 9	| &Q2NS::Q2::fq1_3
	10	| &Q2NS::Q2::fp2_11
	11	| &Q2NS::Q2::fp2_12
	12	| &R1NS::R1::fq2_3

	R1NS::R1::$vftable@P2@Q2@:
		| -80
	 0	| &thunk: this-=40; goto R1NS::R1::fp2_3
	 1	| &thunk: this-=40; goto R1NS::R1::fp2_4
	 2	| &thunk: this-=40; goto R1NS::R1::fp2_4
	 3	| &thunk: this-=40; goto R1NS::R1::fp2_5
	 4	| &thunk: this-=40; goto R1NS::R1::fp2_6
	 5	| &thunk: this-=40; goto R1NS::R1::fp2_6
	 6	| &thunk: this-=40; goto R1NS::R1::fp2_7
	 7	| &thunk: this-=40; goto R1NS::R1::fp2_8
	 8	| &thunk: this-=40; goto R1NS::R1::fp2_8
	 9	| &thunk: this-=40; goto R1NS::R1::fp2_9
	10	| &thunk: this-=40; goto R1NS::R1::fp2_10
	11	| &thunk: this-=40; goto R1NS::R1::fp2_10

	R1NS::R1::fp1_1 this adjustor: 0
	R1NS::R1::fp1_2 this adjustor: 0
	R1NS::R1::fp1_2 this adjustor: 0
	R1NS::R1::fp1_3 this adjustor: 24
	R1NS::R1::fp1_4 this adjustor: 24
	R1NS::R1::fp1_4 this adjustor: 24
	R1NS::R1::fp1_5 this adjustor: 24
	R1NS::R1::fp1_6 this adjustor: 24
	R1NS::R1::fp1_6 this adjustor: 24
	R1NS::R1::fp1_7 this adjustor: 24
	R1NS::R1::fp1_8 this adjustor: 24
	R1NS::R1::fp1_8 this adjustor: 24
	R1NS::R1::fp2_1 this adjustor: 0
	R1NS::R1::fp2_2 this adjustor: 0
	R1NS::R1::fp2_2 this adjustor: 0
	R1NS::R1::fp2_3 this adjustor: 40
	R1NS::R1::fp2_4 this adjustor: 40
	R1NS::R1::fp2_4 this adjustor: 40
	R1NS::R1::fp2_5 this adjustor: 40
	R1NS::R1::fp2_6 this adjustor: 40
	R1NS::R1::fp2_6 this adjustor: 40
	R1NS::R1::fp2_7 this adjustor: 40
	R1NS::R1::fp2_8 this adjustor: 40
	R1NS::R1::fp2_8 this adjustor: 40
	R1NS::R1::fp2_9 this adjustor: 40
	R1NS::R1::fp2_10 this adjustor: 40
	R1NS::R1::fp2_10 this adjustor: 40
	R1NS::R1::fq1_3 this adjustor: 24
	R1NS::R1::fq2_3 this adjustor: 64
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	        Q1NS::Q1      24       8       4 0
	        Q2NS::Q2      64       8       8 0
     */
	//@formatter:on
	private static String getExpectedStructR1() {
		String expected =
		//@formatter:off
			"""
			/R1NS::R1
			pack()
			Structure R1NS::R1 {
			   0   R1NS::R1   24      "Self Base"
			   24   Q1NS::Q1   40      "Virtual Base"
			   64   Q2NS::Q2   40      "Virtual Base"
			}
			Length: 104 Alignment: 8
			/P1NS::P1
			pack()
			Structure P1NS::P1 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/P2NS::P2
			pack()
			Structure P2NS::P2 {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p2   ""
			}
			Length: 16 Alignment: 8
			/Q1NS::Q1
			pack()
			Structure Q1NS::Q1 {
			   0   P1NS::P1   16      "Base"
			   16   P2NS::P2   16      "Base"
			   32   int   4   q1   ""
			}
			Length: 40 Alignment: 8
			/Q2NS::Q2
			pack()
			Structure Q2NS::Q2 {
			   0   P1NS::P1   16      "Base"
			   16   P2NS::P2   16      "Base"
			   32   int   4   q2   ""
			}
			Length: 40 Alignment: 8
			/R1NS::R1/!internal/R1NS::R1
			pack()
			Structure R1NS::R1 {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   r1   ""
			}
			Length: 24 Alignment: 8""";
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
			   0   R1NS::R1   24      "Self Base"
			   24   char[80]   80      "Filler for 2 Unplaceable Virtual Bases: Q1NS::Q1; Q2NS::Q2"
			}
			Length: 104 Alignment: 8
			/R1NS::R1/!internal/R1NS::R1
			pack()
			Structure R1NS::R1 {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   r1   ""
			}
			Length: 24 Alignment: 8""";
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
		results.put("VTABLE_00000008", "     8 vbt []	[R1NS::R1]");
		results.put("VTABLE_00000018",
			"    24 vft [P1NS::P1, Q1NS::Q1]	[R1NS::R1, Q1NS::Q1, P1NS::P1]");
		results.put("VTABLE_00000028",
			"    40 vft [P2NS::P2, Q1NS::Q1]	[R1NS::R1, Q1NS::Q1, P2NS::P2]");
		results.put("VTABLE_00000040",
			"    64 vft [P1NS::P1, Q2NS::Q2]	[R1NS::R1, Q2NS::Q2, P1NS::P1]");
		results.put("VTABLE_00000050",
			"    80 vft [P2NS::P2, Q2NS::Q2]	[R1NS::R1, Q2NS::Q2, P2NS::P2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsR1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructR1_00000000());
		results.put("VTABLE_00000008", getVxtStructR1_00000008());
		results.put("VTABLE_00000018", getVxtStructR1_00000018());
		results.put("VTABLE_00000028", getVxtStructR1_00000028());
		results.put("VTABLE_00000040", getVxtStructR1_00000040());
		results.put("VTABLE_00000050", getVxtStructR1_00000050());
		return results;
	}

	private static String getVxtStructR1_00000000() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_int *   8   R1NS::R1::fp1_1   ""
			   8   _func___thiscall_int_int *   8   R1NS::R1::fp1_2   ""
			   16   _func___thiscall_int *   8   R1NS::R1::fp1_2   ""
			   24   _func___thiscall_int *   8   R1NS::R1::fp2_1   ""
			   32   _func___thiscall_int_int *   8   R1NS::R1::fp2_2   ""
			   40   _func___thiscall_int *   8   R1NS::R1::fp2_2   ""
			}
			Length: 48 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructR1_00000008() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "Q1NS::Q1"
			   4   int   4      "Q2NS::Q2"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructR1_00000018() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_int *   8   R1NS::R1::fp1_3   ""
			   8   _func___thiscall_int_int *   8   R1NS::R1::fp1_4   ""
			   16   _func___thiscall_int *   8   R1NS::R1::fp1_4   ""
			   24   _func___thiscall_int *   8   R1NS::R1::fp1_5   ""
			   32   _func___thiscall_int_int *   8   R1NS::R1::fp1_6   ""
			   40   _func___thiscall_int *   8   R1NS::R1::fp1_6   ""
			   48   _func___thiscall_int *   8   R1NS::R1::fp1_7   ""
			   56   _func___thiscall_int_int *   8   R1NS::R1::fp1_8   ""
			   64   _func___thiscall_int *   8   R1NS::R1::fp1_8   ""
			   72   _func___thiscall_int_int *   8   R1NS::R1::fq1_3   ""
			   80   _func___thiscall_int *   8   Q1NS::Q1::fq1_3   ""
			}
			Length: 88 Alignment: 8""";
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
			   0   _func___thiscall_int *   8   R1NS::R1::fp2_3   ""
			   8   _func___thiscall_int_int *   8   R1NS::R1::fp2_4   ""
			   16   _func___thiscall_int *   8   R1NS::R1::fp2_4   ""
			   24   _func___thiscall_int *   8   R1NS::R1::fp2_5   ""
			   32   _func___thiscall_int_int *   8   R1NS::R1::fp2_6   ""
			   40   _func___thiscall_int *   8   R1NS::R1::fp2_6   ""
			   48   _func___thiscall_int *   8   R1NS::R1::fp2_7   ""
			   56   _func___thiscall_int_int *   8   R1NS::R1::fp2_8   ""
			   64   _func___thiscall_int *   8   R1NS::R1::fp2_8   ""
			   72   _func___thiscall_int *   8   R1NS::R1::fp2_9   ""
			   80   _func___thiscall_int_int *   8   R1NS::R1::fp2_10   ""
			   88   _func___thiscall_int *   8   R1NS::R1::fp2_10   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructR1_00000040() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_00000040
			pack()
			Structure VTABLE_00000040 {
			   0   _func___thiscall_int *   8   R1NS::R1::fp1_3   ""
			   8   _func___thiscall_int_int *   8   R1NS::R1::fp1_4   ""
			   16   _func___thiscall_int *   8   R1NS::R1::fp1_4   ""
			   24   _func___thiscall_int *   8   R1NS::R1::fp1_5   ""
			   32   _func___thiscall_int_int *   8   R1NS::R1::fp1_6   ""
			   40   _func___thiscall_int *   8   R1NS::R1::fp1_6   ""
			   48   _func___thiscall_int *   8   R1NS::R1::fp1_7   ""
			   56   _func___thiscall_int_int *   8   R1NS::R1::fp1_8   ""
			   64   _func___thiscall_int *   8   R1NS::R1::fp1_8   ""
			   72   _func___thiscall_int *   8   Q2NS::Q2::fq1_3   ""
			   80   _func___thiscall_int *   8   Q2NS::Q2::fp2_11   ""
			   88   _func___thiscall_int_int *   8   Q2NS::Q2::fp2_12   ""
			   96   _func___thiscall_int_int *   8   R1NS::R1::fq2_3   ""
			}
			Length: 104 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructR1_00000050() {
		String expected =
		//@formatter:off
			"""
			/R1NS/R1/!internal/VTABLE_00000050
			pack()
			Structure VTABLE_00000050 {
			   0   _func___thiscall_int *   8   R1NS::R1::fp2_3   ""
			   8   _func___thiscall_int_int *   8   R1NS::R1::fp2_4   ""
			   16   _func___thiscall_int *   8   R1NS::R1::fp2_4   ""
			   24   _func___thiscall_int *   8   R1NS::R1::fp2_5   ""
			   32   _func___thiscall_int_int *   8   R1NS::R1::fp2_6   ""
			   40   _func___thiscall_int *   8   R1NS::R1::fp2_6   ""
			   48   _func___thiscall_int *   8   R1NS::R1::fp2_7   ""
			   56   _func___thiscall_int_int *   8   R1NS::R1::fp2_8   ""
			   64   _func___thiscall_int *   8   R1NS::R1::fp2_8   ""
			   72   _func___thiscall_int *   8   R1NS::R1::fp2_9   ""
			   80   _func___thiscall_int_int *   8   R1NS::R1::fp2_10   ""
			   88   _func___thiscall_int *   8   R1NS::R1::fp2_10   ""
			}
			Length: 96 Alignment: 8""";
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

	public Vftm64ProgramCreator() {
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
