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
 * Class to create the egray8 64-bit program and mock PDB.
 * <p>
 * This class implementation is not complete... many more classes' expected results need
 * codified
 */
public class Egray864ProgramCreator extends ProgramCreator {

	public static final CategoryPath MAIN_CATEGORY_PATH = CategoryPath.ROOT;

	public static final ClassID A = new ClassID(MAIN_CATEGORY_PATH, sp("A"));
	public static final ClassID B = new ClassID(MAIN_CATEGORY_PATH, sp("B"));
	public static final ClassID C = new ClassID(MAIN_CATEGORY_PATH, sp("C"));
	public static final ClassID CC1 = new ClassID(MAIN_CATEGORY_PATH, sp("CC1"));
	public static final ClassID CC2 = new ClassID(MAIN_CATEGORY_PATH, sp("CC2"));
	public static final ClassID CC3 = new ClassID(MAIN_CATEGORY_PATH, sp("CC3"));
	public static final ClassID D = new ClassID(MAIN_CATEGORY_PATH, sp("D"));
	public static final ClassID E = new ClassID(MAIN_CATEGORY_PATH, sp("E"));
	public static final ClassID F = new ClassID(MAIN_CATEGORY_PATH, sp("F"));
	public static final ClassID G = new ClassID(MAIN_CATEGORY_PATH, sp("G"));
	public static final ClassID H = new ClassID(MAIN_CATEGORY_PATH, sp("H"));
	public static final ClassID GG1 = new ClassID(MAIN_CATEGORY_PATH, sp("GG1"));
	public static final ClassID GG2 = new ClassID(MAIN_CATEGORY_PATH, sp("GG2"));
	public static final ClassID GG3 = new ClassID(MAIN_CATEGORY_PATH, sp("GG3"));
	public static final ClassID GG4 = new ClassID(MAIN_CATEGORY_PATH, sp("GG4"));
	public static final ClassID I = new ClassID(MAIN_CATEGORY_PATH, sp("I"));
	public static final ClassID GX1 = new ClassID(MAIN_CATEGORY_PATH, sp("GX1"));
	public static final ClassID HX1 = new ClassID(MAIN_CATEGORY_PATH, sp("HX1"));
	public static final ClassID IX1 = new ClassID(MAIN_CATEGORY_PATH, sp("IX1"));
	public static final ClassID G1 = new ClassID(MAIN_CATEGORY_PATH, sp("G1"));
	public static final ClassID H1 = new ClassID(MAIN_CATEGORY_PATH, sp("H1"));
	public static final ClassID I1 = new ClassID(MAIN_CATEGORY_PATH, sp("I1"));
	public static final ClassID I2 = new ClassID(MAIN_CATEGORY_PATH, sp("I2"));
	public static final ClassID I3 = new ClassID(MAIN_CATEGORY_PATH, sp("I3"));
	public static final ClassID I4 = new ClassID(MAIN_CATEGORY_PATH, sp("I4"));
	public static final ClassID I5 = new ClassID(MAIN_CATEGORY_PATH, sp("I5"));
	public static final ClassID J1 = new ClassID(MAIN_CATEGORY_PATH, sp("J1"));
	public static final ClassID J2 = new ClassID(MAIN_CATEGORY_PATH, sp("J2"));
	public static final ClassID J3 = new ClassID(MAIN_CATEGORY_PATH, sp("J3"));
	public static final ClassID J4 = new ClassID(MAIN_CATEGORY_PATH, sp("J4"));
	public static final ClassID J5 = new ClassID(MAIN_CATEGORY_PATH, sp("J5"));
	public static final ClassID J6 = new ClassID(MAIN_CATEGORY_PATH, sp("J6"));
	public static final ClassID P = new ClassID(MAIN_CATEGORY_PATH, sp("P"));
	public static final ClassID Q = new ClassID(MAIN_CATEGORY_PATH, sp("Q"));
	public static final ClassID R = new ClassID(MAIN_CATEGORY_PATH, sp("R"));
	public static final ClassID S = new ClassID(MAIN_CATEGORY_PATH, sp("S"));
	public static final ClassID T = new ClassID(MAIN_CATEGORY_PATH, sp("T"));
	public static final ClassID U = new ClassID(MAIN_CATEGORY_PATH, sp("U"));
	public static final ClassID V = new ClassID(MAIN_CATEGORY_PATH, sp("V"));
	public static final ClassID W = new ClassID(MAIN_CATEGORY_PATH, sp("W"));
	public static final ClassID WW = new ClassID(MAIN_CATEGORY_PATH, sp("WW"));
	public static final ClassID X = new ClassID(MAIN_CATEGORY_PATH, sp("X"));
	public static final ClassID Z = new ClassID(MAIN_CATEGORY_PATH, sp("Z"));
	public static final ClassID AA1a = new ClassID(MAIN_CATEGORY_PATH, sp("AA1a"));
	public static final ClassID AA1b = new ClassID(MAIN_CATEGORY_PATH, sp("AA1b"));
	public static final ClassID AA1 = new ClassID(MAIN_CATEGORY_PATH, sp("AA1"));
	public static final ClassID AA2a = new ClassID(MAIN_CATEGORY_PATH, sp("AA2a"));
	public static final ClassID AA2b = new ClassID(MAIN_CATEGORY_PATH, sp("AA2b"));
	public static final ClassID AA2 = new ClassID(MAIN_CATEGORY_PATH, sp("AA2"));
	public static final ClassID AA3a = new ClassID(MAIN_CATEGORY_PATH, sp("AA3a"));
	public static final ClassID AA3b = new ClassID(MAIN_CATEGORY_PATH, sp("AA3b"));
	public static final ClassID AA3c = new ClassID(MAIN_CATEGORY_PATH, sp("AA3c"));
	public static final ClassID AA3d = new ClassID(MAIN_CATEGORY_PATH, sp("AA3d"));
	public static final ClassID AA3e = new ClassID(MAIN_CATEGORY_PATH, sp("AA3e"));
	public static final ClassID AA3f = new ClassID(MAIN_CATEGORY_PATH, sp("AA3f"));
	public static final ClassID AA3g = new ClassID(MAIN_CATEGORY_PATH, sp("AA3g"));
	public static final ClassID AA4a = new ClassID(MAIN_CATEGORY_PATH, sp("AA4a"));
	public static final ClassID AA4b = new ClassID(MAIN_CATEGORY_PATH, sp("AA4b"));
	public static final ClassID AA4c = new ClassID(MAIN_CATEGORY_PATH, sp("AA4c"));
	public static final ClassID AA4d = new ClassID(MAIN_CATEGORY_PATH, sp("AA4d"));
	public static final ClassID AA4e = new ClassID(MAIN_CATEGORY_PATH, sp("AA4e"));
	public static final ClassID AA4f = new ClassID(MAIN_CATEGORY_PATH, sp("AA4f"));
	public static final ClassID AA4g = new ClassID(MAIN_CATEGORY_PATH, sp("AA4g"));
	public static final ClassID AA4h = new ClassID(MAIN_CATEGORY_PATH, sp("AA4h"));
	public static final ClassID AA4j = new ClassID(MAIN_CATEGORY_PATH, sp("AA4j"));
	public static final ClassID AA4k = new ClassID(MAIN_CATEGORY_PATH, sp("AA4k"));
	public static final ClassID AA4m = new ClassID(MAIN_CATEGORY_PATH, sp("AA4m"));
	public static final ClassID AA4n = new ClassID(MAIN_CATEGORY_PATH, sp("AA4n"));
	public static final ClassID AA4p = new ClassID(MAIN_CATEGORY_PATH, sp("AA4p"));
	public static final ClassID AA4q = new ClassID(MAIN_CATEGORY_PATH, sp("AA4q"));
	public static final ClassID AA5a = new ClassID(MAIN_CATEGORY_PATH, sp("AA5a"));
	public static final ClassID AA5b = new ClassID(MAIN_CATEGORY_PATH, sp("AA5b"));
	public static final ClassID AA5c = new ClassID(MAIN_CATEGORY_PATH, sp("AA5c"));
	public static final ClassID AA5d = new ClassID(MAIN_CATEGORY_PATH, sp("AA5d"));
	public static final ClassID AA5e = new ClassID(MAIN_CATEGORY_PATH, sp("AA5e"));
	public static final ClassID AA5f = new ClassID(MAIN_CATEGORY_PATH, sp("AA5f"));
	public static final ClassID AA5g = new ClassID(MAIN_CATEGORY_PATH, sp("AA5g"));
	public static final ClassID AA5h = new ClassID(MAIN_CATEGORY_PATH, sp("AA5h"));
	public static final ClassID AA5j = new ClassID(MAIN_CATEGORY_PATH, sp("AA5j"));
	public static final ClassID AA6a = new ClassID(MAIN_CATEGORY_PATH, sp("AA6a"));
	public static final ClassID AA6b = new ClassID(MAIN_CATEGORY_PATH, sp("AA6b"));
	public static final ClassID AA6c = new ClassID(MAIN_CATEGORY_PATH, sp("AA6c"));
	public static final ClassID AA6d = new ClassID(MAIN_CATEGORY_PATH, sp("AA6d"));
	public static final ClassID AA6e = new ClassID(MAIN_CATEGORY_PATH, sp("AA6e"));
	public static final ClassID AA6f = new ClassID(MAIN_CATEGORY_PATH, sp("AA6f"));
	public static final ClassID AA6g = new ClassID(MAIN_CATEGORY_PATH, sp("AA6g"));
	public static final ClassID AA6h = new ClassID(MAIN_CATEGORY_PATH, sp("AA6h"));
	public static final ClassID AA6j = new ClassID(MAIN_CATEGORY_PATH, sp("AA6j"));
	public static final ClassID AA7a = new ClassID(MAIN_CATEGORY_PATH, sp("AA7a"));
	public static final ClassID AA7b = new ClassID(MAIN_CATEGORY_PATH, sp("AA7b"));
	public static final ClassID AA7c = new ClassID(MAIN_CATEGORY_PATH, sp("AA7c"));
	public static final ClassID AA7d = new ClassID(MAIN_CATEGORY_PATH, sp("AA7d"));
	public static final ClassID BB1a = new ClassID(MAIN_CATEGORY_PATH, sp("BB1a"));
	public static final ClassID BB1b = new ClassID(MAIN_CATEGORY_PATH, sp("BB1b"));
	public static final ClassID BB1c = new ClassID(MAIN_CATEGORY_PATH, sp("BB1c"));
	public static final ClassID BB1d = new ClassID(MAIN_CATEGORY_PATH, sp("BB1d"));
	public static final ClassID BB2z = new ClassID(MAIN_CATEGORY_PATH, sp("BB2z"));
	public static final ClassID BB2a = new ClassID(MAIN_CATEGORY_PATH, sp("BB2a"));
	public static final ClassID BB2b = new ClassID(MAIN_CATEGORY_PATH, sp("BB2b"));
	public static final ClassID BB2c = new ClassID(MAIN_CATEGORY_PATH, sp("BB2c"));
	public static final ClassID BB2d = new ClassID(MAIN_CATEGORY_PATH, sp("BB2d"));
	public static final ClassID BB2e = new ClassID(MAIN_CATEGORY_PATH, sp("BB2e"));
	public static final ClassID BB3a = new ClassID(MAIN_CATEGORY_PATH, sp("BB3a"));
	public static final ClassID BB3b = new ClassID(MAIN_CATEGORY_PATH, sp("BB3b"));
	public static final ClassID BB3c = new ClassID(MAIN_CATEGORY_PATH, sp("BB3c"));
	public static final ClassID BB3d = new ClassID(MAIN_CATEGORY_PATH, sp("BB3d"));
	public static final ClassID BB3e = new ClassID(MAIN_CATEGORY_PATH, sp("BB3e"));
	public static final ClassID BB3f = new ClassID(MAIN_CATEGORY_PATH, sp("BB3f"));
	public static final ClassID BB3g = new ClassID(MAIN_CATEGORY_PATH, sp("BB3g"));
	public static final ClassID CC1a = new ClassID(MAIN_CATEGORY_PATH, sp("CC1a"));
	public static final ClassID CC1b = new ClassID(MAIN_CATEGORY_PATH, sp("CC1b"));
	public static final ClassID CC1c = new ClassID(MAIN_CATEGORY_PATH, sp("CC1c"));
	public static final ClassID CC1d = new ClassID(MAIN_CATEGORY_PATH, sp("CC1d"));
	public static final ClassID CC1e = new ClassID(MAIN_CATEGORY_PATH, sp("CC1e"));
	public static final ClassID CC1f = new ClassID(MAIN_CATEGORY_PATH, sp("CC1f"));
	public static final ClassID CC1g = new ClassID(MAIN_CATEGORY_PATH, sp("CC1g"));
	public static final ClassID CC1h = new ClassID(MAIN_CATEGORY_PATH, sp("CC1h"));
	public static final ClassID CC1g_counterpoint =
		new ClassID(MAIN_CATEGORY_PATH, sp("CC1g_counterpoint"));
	public static final ClassID CC1h_counterpoint =
		new ClassID(MAIN_CATEGORY_PATH, sp("CC1h_counterpoint"));
	public static final ClassID CC1g_counterpoint2 =
		new ClassID(MAIN_CATEGORY_PATH, sp("CC1g_counterpoint2"));
	public static final ClassID CC1h_counterpoint2 =
		new ClassID(MAIN_CATEGORY_PATH, sp("CC1h_counterpoint2"));
	public static final ClassID CC2a = new ClassID(MAIN_CATEGORY_PATH, sp("CC2a"));
	public static final ClassID CC2b = new ClassID(MAIN_CATEGORY_PATH, sp("CC2b"));
	public static final ClassID CC2c = new ClassID(MAIN_CATEGORY_PATH, sp("CC2c"));
	public static final ClassID CC2d = new ClassID(MAIN_CATEGORY_PATH, sp("CC2d"));
	public static final ClassID CC2e = new ClassID(MAIN_CATEGORY_PATH, sp("CC2e"));
	public static final ClassID CC2f = new ClassID(MAIN_CATEGORY_PATH, sp("CC2f"));
	public static final ClassID CC2g = new ClassID(MAIN_CATEGORY_PATH, sp("CC2g"));
	public static final ClassID CC2h = new ClassID(MAIN_CATEGORY_PATH, sp("CC2h"));
	public static final ClassID CC2j = new ClassID(MAIN_CATEGORY_PATH, sp("CC2j"));
	public static final ClassID DD1a = new ClassID(MAIN_CATEGORY_PATH, sp("DD1a"));
	public static final ClassID DD1b = new ClassID(MAIN_CATEGORY_PATH, sp("DD1b"));
	public static final ClassID DD1c = new ClassID(MAIN_CATEGORY_PATH, sp("DD1c"));
	public static final ClassID DD1d = new ClassID(MAIN_CATEGORY_PATH, sp("DD1d"));
	public static final ClassID DD2a = new ClassID(MAIN_CATEGORY_PATH, sp("DD2a"));
	public static final ClassID DD2b = new ClassID(MAIN_CATEGORY_PATH, sp("DD2b"));
	public static final ClassID DD2c = new ClassID(MAIN_CATEGORY_PATH, sp("DD2c"));
	public static final ClassID DD2d = new ClassID(MAIN_CATEGORY_PATH, sp("DD2d"));
	public static final ClassID DD2e = new ClassID(MAIN_CATEGORY_PATH, sp("DD2e"));

	private static String PROGRAM_NAME = "egray864.exe";
	private static String LANGUAGE_ID = ProgramBuilder._X64;
	private static String COMPILER_SPEC_ID = "windows";
	private static AddressNameLength SECTIONS[] = {
		new AddressNameLength("140001000", ".text", 0x54c00),
		new AddressNameLength("140056000", ".rdata", 0x12400)
	};

	private static AddressNameBytes vbTableInfo[] = {
		new AddressNameBytes("140056370", "??_8G@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056378", "??_8H@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056380", "??_8GG1@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056388", "??_8GG2@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056390", "??_8GG3@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056398", "??_8GG4@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("1400563a0", "??_8I@@7BG@@@", "00 00 00 00 28 00 00 00"),
		new AddressNameBytes("1400563a8", "??_8I@@7BH@@@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("1400563b0", "??_8GX1@@7B@", "00 00 00 00 08 00 00 00"),
		new AddressNameBytes("1400563b8", "??_8HX1@@7B@", "00 00 00 00 08 00 00 00"),
		new AddressNameBytes("1400563c0", "??_8IX1@@7BGX1@@@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("1400563c8", "??_8IX1@@7BHX1@@@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("1400563d0", "??_8G1@@7B@",
			"00 00 00 00 10 00 00 00 14 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400563e0", "??_8H1@@7B@",
			"00 00 00 00 10 00 00 00 14 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400563f0", "??_8I1@@7BG1@@@",
			"00 00 00 00 28 00 00 00 2c 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056400", "??_8I1@@7BH@@@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("140056408", "??_8I2@@7BG@@@",
			"00 00 00 00 28 00 00 00 2c 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056418", "??_8I2@@7BH1@@@",
			"00 00 00 00 1c 00 00 00 18 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056428", "??_8I3@@7BG1@@@",
			"00 00 00 00 28 00 00 00 2c 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056438", "??_8I3@@7BH1@@@",
			"00 00 00 00 1c 00 00 00 18 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056448", "??_8I4@@7B@",
			"00 00 00 00 18 00 00 00 1c 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056458", "??_8I5@@7B@",
			"00 00 00 00 1c 00 00 00 18 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056468", "??_8J1@@7BG1@@@",
			"00 00 00 00 58 00 00 00 5c 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056478", "??_8J1@@7BH@@@", "00 00 00 00 48 00 00 00"),
		new AddressNameBytes("140056480", "??_8J1@@7BG@@@",
			"00 00 00 00 30 00 00 00 34 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056490", "??_8J1@@7BH1@@@",
			"00 00 00 00 24 00 00 00 20 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400564a0", "??_8J2@@7BG@@@",
			"00 00 00 00 58 00 00 00 5c 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400564b0", "??_8J2@@7BH1@@@",
			"00 00 00 00 4c 00 00 00 48 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400564c0", "??_8J2@@7BG1@@@",
			"00 00 00 00 30 00 00 00 34 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400564d0", "??_8J2@@7BH@@@", "00 00 00 00 20 00 00 00"),
		new AddressNameBytes("1400564d8", "??_8J3@@7BG@@@",
			"00 00 00 00 60 00 00 00 64 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400564e8", "??_8J3@@7BH1@@@",
			"00 00 00 00 54 00 00 00 50 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400564f8", "??_8J3@@7BG1@@@",
			"00 00 00 00 38 00 00 00 3c 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056508", "??_8J3@@7BH@@@", "00 00 00 00 28 00 00 00"),
		new AddressNameBytes("140056510", "??_8J4@@7BG1@@@",
			"00 00 00 00 70 00 00 00 74 00 00 00 78 00 00 00 7c 00 00 00 80 00 00 00 90 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056530", "??_8J4@@7BH1@@@",
			"00 00 00 00 64 00 00 00 60 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056540", "??_8J4@@7BGG1@@@", "00 00 00 00 50 00 00 00"),
		new AddressNameBytes("140056548", "??_8J4@@7BG@@@", "00 00 00 00 38 00 00 00"),
		new AddressNameBytes("140056550", "??_8J4@@7BH@@@", "00 00 00 00 28 00 00 00"),
		new AddressNameBytes("140056558", "??_8J4@@7BGG2@@@", "00 00 00 00 fc ff ff ff"),
		new AddressNameBytes("140056560", "??_8J4@@7BGG3@@@", "00 00 00 00 ec ff ff ff"),
		new AddressNameBytes("140056568", "??_8J5@@7BG1@@@",
			"00 00 00 00 98 00 00 00 9c 00 00 00 70 00 00 00 78 00 00 00 88 00 00 00 a0 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056588", "??_8J5@@7BH1@@@",
			"00 00 00 00 8c 00 00 00 88 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056598", "??_8J5@@7BGG1@@@", "00 00 00 00 78 00 00 00"),
		new AddressNameBytes("1400565a0", "??_8J5@@7BG@@@", "00 00 00 00 60 00 00 00"),
		new AddressNameBytes("1400565a8", "??_8J5@@7BH@@@", "00 00 00 00 50 00 00 00"),
		new AddressNameBytes("1400565b0", "??_8J5@@7BGG2@@@", "00 00 00 00 f8 ff ff ff"),
		new AddressNameBytes("1400565b8", "??_8J5@@7BGG3@@@", "00 00 00 00 e8 ff ff ff"),
		new AddressNameBytes("1400565c0", "??_8J6@@7B0@@",
			"f8 ff ff ff 10 00 00 00 10 00 00 00 20 00 00 00 28 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400565d8", "??_8J6@@7BGG4@@@", "00 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400565e0", "??_8J6@@7BGG3@@@", "00 00 00 00 f8 ff ff ff"),
		new AddressNameBytes("140056670", "??_8T@@7B@", "f8 ff ff ff 18 00 00 00"),
		new AddressNameBytes("140056698", "??_8U@@7B@", "f8 ff ff ff 20 00 00 00"),
		new AddressNameBytes("1400566d0", "??_8AA3a@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("1400566d8", "??_8AA3b@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("1400566e0", "??_8AA3c@@7BAA3a@@@",
			"00 00 00 00 34 00 00 00 28 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400566f0", "??_8AA3c@@7BAA3b@@@", "00 00 00 00 24 00 00 00"),
		new AddressNameBytes("1400566f8", "??_8AA3d@@7B0@@",
			"00 00 00 00 10 00 00 00 1c 00 00 00 28 00 00 00 38 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056710", "??_8AA3d@@7BAA3a@@@", "00 00 00 00 f4 ff ff ff"),
		new AddressNameBytes("140056718", "??_8AA3d@@7BAA3b@@@", "00 00 00 00 e4 ff ff ff"),
		new AddressNameBytes("140056720", "??_8AA3g@@7B@",
			"00 00 00 00 10 00 00 00 20 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056730", "??_8AA4a@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056738", "??_8AA4b@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056740", "??_8AA4c@@7BAA4a@@@", "00 00 00 00 28 00 00 00"),
		new AddressNameBytes("140056748", "??_8AA4c@@7BAA4b@@@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("140056750", "??_8AA4d@@7BAA4b@@@",
			"00 00 00 00 18 00 00 00 28 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056760", "??_8AA4d@@7BAA4a@@@", "00 00 00 00 f0 ff ff ff"),
		new AddressNameBytes("140056768", "??_8AA4e@@7BAA4a@@@",
			"00 00 00 00 18 00 00 00 28 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056778", "??_8AA4e@@7BAA4b@@@", "00 00 00 00 f0 ff ff ff"),
		new AddressNameBytes("140056780", "??_8AA4f@@7B0@@",
			"00 00 00 00 10 00 00 00 20 00 00 00 30 00 00 00"),
		new AddressNameBytes("140056790", "??_8AA4f@@7BAA4a@@@", "00 00 00 00 f0 ff ff ff"),
		new AddressNameBytes("140056798", "??_8AA4f@@7BAA4b@@@", "00 00 00 00 e0 ff ff ff"),
		new AddressNameBytes("1400567a0", "??_8AA4g@@7B@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("1400567a8", "??_8AA4j@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("1400567b0", "??_8AA4k@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("1400567b8", "??_8AA4m@@7B@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("1400567c0", "??_8AA4n@@7B@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("1400567c8", "??_8AA4p@@7B@", "00 00 00 00 20 00 00 00"),
		new AddressNameBytes("1400567d0", "??_8AA4q@@7BAA4n@@@", "00 00 00 00 38 00 00 00"),
		new AddressNameBytes("1400567d8", "??_8AA4q@@7BAA4m@@@", "00 00 00 00 20 00 00 00"),
		new AddressNameBytes("1400567e0", "??_8AA5e@@7B@", "f8 ff ff ff 10 00 00 00"),
		new AddressNameBytes("1400567e8", "??_8AA5f@@7B@", "f8 ff ff ff 10 00 00 00"),
		new AddressNameBytes("1400567f0", "??_8AA5g@@7B0@@",
			"f8 ff ff ff 10 00 00 00 18 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056800", "??_8AA5g@@7BAA5e@@@", "f8 ff ff ff f0 ff ff ff"),
		new AddressNameBytes("140056808", "??_8AA5h@@7B0@@",
			"f8 ff ff ff 10 00 00 00 18 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056818", "??_8AA5h@@7BAA5f@@@", "f8 ff ff ff f0 ff ff ff"),
		new AddressNameBytes("140056820", "??_8AA5j@@7BAA5g@@@",
			"f8 ff ff ff 30 00 00 00 38 00 00 00 50 00 00 00 58 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056838", "??_8AA5j@@7BAA5h@@@",
			"f8 ff ff ff 38 00 00 00 40 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056848", "??_8AA5j@@7BAA5e@@@", "f8 ff ff ff f0 ff ff ff"),
		new AddressNameBytes("140056850", "??_8AA5j@@7BAA5f@@@", "f8 ff ff ff f0 ff ff ff"),
		new AddressNameBytes("140056858", "??_8AA6c@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056860", "??_8AA6g@@7B@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("140056868", "??_8AA6h@@7B0@@",
			"00 00 00 00 10 00 00 00 18 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056878", "??_8AA6h@@7BAA6c@@@", "00 00 00 00 f8 ff ff ff"),
		new AddressNameBytes("140056880", "??_8AA6j@@7B0@@",
			"00 00 00 00 18 00 00 00 20 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056890", "??_8AA6j@@7BAA6c@@@", "00 00 00 00 f8 ff ff ff"),
		new AddressNameBytes("140056940", "??_8AA7d@@7B@",
			"f8 ff ff ff 10 00 00 00 20 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056950", "??_8BB1c@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056958", "??_8BB1d@@7B@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("140056960", "??_8BB2a@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056968", "??_8BB2b@@7B@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("140056970", "??_8BB2c@@7B0@@",
			"00 00 00 00 10 00 00 00 18 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056980", "??_8BB2c@@7BBB2a@@@", "00 00 00 00 f8 ff ff ff"),
		new AddressNameBytes("140056988", "??_8BB2d@@7B@",
			"00 00 00 00 30 00 00 00 38 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056998", "??_8BB2d@@7BBB2c@@@",
			"00 00 00 00 18 00 00 00 20 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400569a8", "??_8BB2d@@7BBB2a@@@", "00 00 00 00 f8 ff ff ff"),
		new AddressNameBytes("1400569b0", "??_8BB2e@@7B@", "00 00 00 00 20 00 00 00"),
		new AddressNameBytes("1400569b8", "??_8BB3d@@7B@", "f8 ff ff ff 10 00 00 00"),
		new AddressNameBytes("1400569c0", "??_8BB3e@@7B@",
			"f8 ff ff ff 10 00 00 00 14 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400569d0", "??_8BB3f@@7BBB3d@@@",
			"f8 ff ff ff 30 00 00 00 34 00 00 00 38 00 00 00"),
		new AddressNameBytes("1400569e0", "??_8BB3f@@7BBB3e@@@",
			"f8 ff ff ff 1c 00 00 00 20 00 00 00 00 00 00 00"),
		new AddressNameBytes("1400569f0", "??_8BB3g@@7BBB3e@@@",
			"f8 ff ff ff 30 00 00 00 34 00 00 00 38 00 00 00"),
		new AddressNameBytes("140056a00", "??_8BB3g@@7BBB3d@@@", "f8 ff ff ff 20 00 00 00"),
		new AddressNameBytes("140056a08", "??_8CC1h@@7B@",
			"00 00 00 00 10 00 00 00 14 00 00 00 18 00 00 00 1c 00 00 00 20 00 00 00 28 00 00 00 00 00 00 00"),
		new AddressNameBytes("140056a28", "??_8DD1b@@7B@", "00 00 00 00 10 00 00 00"),
		new AddressNameBytes("140056a30", "??_8DD1c@@7B@", "00 00 00 00 18 00 00 00"),
		new AddressNameBytes("140056a38", "??_8DD1d@@7B@", "00 00 00 00 18 00 00 00")
	};

	private static AddressNameBytes vfTableInfo[] = {
		new AddressNameBytes("1400565f0", "??_7P@@6B@", "f0 22 00 40 01 00 00 00"),
		new AddressNameBytes("140056600", "??_7Q@@6B@",
			"b0 23 00 40 01 00 00 00 e0 23 00 40 01 00 00 00"),
		new AddressNameBytes("140056618", "??_7R@@6B@",
			"40 24 00 40 01 00 00 00 70 24 00 40 01 00 00 00"),
		new AddressNameBytes("140056630", "??_7S@@6BP@@@", "00 25 00 40 01 00 00 00"),
		new AddressNameBytes("140056640", "??_7S@@6BR@@@",
			"14 84 00 40 01 00 00 00 30 25 00 40 01 00 00 00"),
		new AddressNameBytes("140056658", "??_7T@@6B0@@", "80 26 00 40 01 00 00 00"),
		new AddressNameBytes("140056668", "??_7T@@6BP@@@", "30 84 00 40 01 00 00 00"),
		new AddressNameBytes("140056680", "??_7U@@6BT@@@", "80 26 00 40 01 00 00 00"),
		new AddressNameBytes("140056690", "??_7U@@6BP@@@", "20 84 00 40 01 00 00 00"),
		new AddressNameBytes("1400566a8", "??_7V@@6B@", "70 83 00 40 01 00 00 00"),
		new AddressNameBytes("1400566b8", "??_7W@@6B@", "f0 81 00 40 01 00 00 00"),
		new AddressNameBytes("1400566c8", "??_7WW@@6B@", "b0 82 00 40 01 00 00 00"),
		new AddressNameBytes("1400568a0", "??_7AA7a@@6B@",
			"30 38 00 40 01 00 00 00 60 38 00 40 01 00 00 00"),
		new AddressNameBytes("1400568b8", "??_7AA7b@@6B@",
			"90 38 00 40 01 00 00 00 c0 38 00 40 01 00 00 00"),
		new AddressNameBytes("1400568d0", "??_7AA7c@@6BAA7a@@@",
			"30 38 00 40 01 00 00 00 60 38 00 40 01 00 00 00 f0 38 00 40 01 00 00 00"),
		new AddressNameBytes("1400568f0", "??_7AA7c@@6BAA7b@@@",
			"90 38 00 40 01 00 00 00 c0 38 00 40 01 00 00 00"),
		new AddressNameBytes("140056908", "??_7AA7d@@6B0@@", "20 39 00 40 01 00 00 00"),
		new AddressNameBytes("140056918", "??_7AA7d@@6BAA7a@@@",
			"30 38 00 40 01 00 00 00 60 38 00 40 01 00 00 00"),
		new AddressNameBytes("140056930", "??_7AA7d@@6BAA7b@@@",
			"90 38 00 40 01 00 00 00 c0 38 00 40 01 00 00 00"),
		new AddressNameBytes("140056a60", "??_7type_info@@6B@", "f0 86 00 40 01 00 00 00")
	};

	private static AddressNameBytes functionInfo[] = {
		new AddressNameBytes("1400022f0", "P::pvf",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 05 0a 10 00 00 48 8b 4c 24 08 89 41 08"),
		new AddressNameBytes("1400023b0", "Q::pvf",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 05 0b 10 00 00 48 8b 4c 24 08 89 41 08"),
		new AddressNameBytes("1400023e0", "Q::qvf",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 10 05 0b 30 00 00 48 8b 4c 24 08 89 41 10"),
		new AddressNameBytes("140002440", "R::pvf",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 05 0c 20 00 00 48 8b 4c 24 08 89 41 08"),
		new AddressNameBytes("140002470", "R::rvf",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 05 0c 10 00 00 48 8b 4c 24 08 89 41 08"),
		new AddressNameBytes("140002500", "S::pvf",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 05 0d 10 00 00 48 8b 4c 24 08 89 41 08"),
		new AddressNameBytes("140002530", "S::rvf",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 05 0d 20 00 00 48 8b 4c 24 08 89 41 08"),
		new AddressNameBytes("140002680", "T::tvf",
			"48 89 4c 24 08 48 8b 44 24 08 48 8b 40 08 48 63 40 04 48 8b 4c 24 08 8b 44 01 10 83 c0 10 48 8b 4c 24 08 48 8b 49 08 48 63 49 04 48 8b 54 24 08 89 44 0a 10 48 8b 44 24 08 8b 40 10 83 c0 10 48 8b 4c 24 08 89 41 10"),
		new AddressNameBytes("140003830", "AA7a::pvf1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 05 00 10 00 00 48 8b 4c 24 08 89 41 08"),
		new AddressNameBytes("140003860", "AA7a::pvf2",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 05 00 20 00 00 48 8b 4c 24 08 89 41 08"),
		new AddressNameBytes("140003890", "AA7b::pvf1",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 05 00 10 00 00 48 8b 4c 24 08 89 41 08"),
		new AddressNameBytes("1400038c0", "AA7b::pvf3",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 08 05 00 30 00 00 48 8b 4c 24 08 89 41 08"),
		new AddressNameBytes("1400038f0", "AA7c::pvf4",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 20 05 00 40 00 00 48 8b 4c 24 08 89 41 20"),
		new AddressNameBytes("140003920", "AA7d::pvf5",
			"48 89 4c 24 08 48 8b 44 24 08 8b 40 10 05 00 50 00 00 48 8b 4c 24 08 89 41 10"),
		new AddressNameBytes("1400081f0", "W::`vector_deleting_destructor'",
			"89 54 24 10 48 89 4c 24 08 48 83 ec 28 8b 44 24 38 83 e0 02 85 c0 74 57 4c 8d 0d a1 ff ff ff 48 8b 44 24 30 4c 8b 40 f8 ba 08 00 00 00 48 8b 4c 24 30 e8 49 03 00 00 8b 44 24 38 83 e0 01 85 c0 74 22 48 8b 44 24 30 48 8b 40 f8 48 8d 04 c5 08 00 00 00 48 8b 4c 24 30 48 83 e9 08 48 8b d0 e8 88 04 00 00 48 8b 44 24 30 48 83 e8 08 eb 40 48 8b 4c 24 30 e8 47 ff ff ff 8b 44 24 38 83 e0 01 85 c0 74 26 8b 44 24 38 83 e0 04 85 c0 75 0c 48 8b 4c 24 30 e8 a7 a5 ff ff eb 0f ba 08 00 00 00 48 8b 4c 24 30 e8 56 01 00 00 48 8b 44 24 30 48 83 c4 28"),
		new AddressNameBytes("1400082b0", "WW::`vector_deleting_destructor'",
			"89 54 24 10 48 89 4c 24 08 48 83 ec 28 8b 44 24 38 83 e0 02 85 c0 74 54 4c 8d 0d 01 ff ff ff 48 8b 44 24 30 4c 8b 40 f8 ba 10 00 00 00 48 8b 4c 24 30 e8 89 02 00 00 8b 44 24 38 83 e0 01 85 c0 74 1f 48 8b 44 24 30 48 6b 40 f8 10 48 83 c0 08 48 8b 4c 24 30 48 83 e9 08 48 8b d0 e8 cb 03 00 00 48 8b 44 24 30 48 83 e8 08 eb 40 48 8b 4c 24 30 e8 aa fe ff ff 8b 44 24 38 83 e0 01 85 c0 74 26 8b 44 24 38 83 e0 04 85 c0 75 0c 48 8b 4c 24 30 e8 ea a4 ff ff eb 0f ba 10 00 00 00 48 8b 4c 24 30 e8 99 00 00 00 48 8b 44 24 30 48 83 c4 28"),
		new AddressNameBytes("140008370", "V::`scalar_deleting_destructor'",
			"89 54 24 10 48 89 4c 24 08 48 83 ec 28 48 8b 4c 24 30 e8 29 a4 ff ff 8b 44 24 38 83 e0 01 85 c0 74 0f ba 08 00 00 00 48 8b 4c 24 30 e8 2b 03 00 00 48 8b 44 24 30 48 83 c4 28"),
		new AddressNameBytes("140008414", "[thunk]:S::pvf`adjustor{16}'",
			"48 83 e9 10 e9 e3 a0 ff"),
		new AddressNameBytes("140008420", "T::pvf", "48 63 41 fc 48 2b c8 48 83 e9 08 e9 00 a2 ff"),
		new AddressNameBytes("140008430", "T::pvf", "48 63 41 fc 48 2b c8 e9 f4 a1 ff"),
		new AddressNameBytes("1400086f0", "type_info::`scalar_deleting_destructor'",
			"40 53 48 83 ec 20 48 8d 05 63 e3 04 00 48 8b d9 48 89 01 f6 c2 01 74 0a ba 18 00 00 00 e8 ba ff ff ff 48 8b c3 48 83 c4 20 5b"),
		new AddressNameBytes("1400181ac", "_purecall",
			"48 83 ec 28 e8 ef ff ff ff 48 85 c0 74 06 ff 15 f8 e0 03 00 e8 f7 d6 01")
	};

	private static CppCompositeType createA_struct(DataTypeManager dtm) {
		String name = "A";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addMember("c", charT, false, publicDirectAttributes, 0, null);
		struct.addMember("i", intT, false, publicDirectAttributes, 4, null);
		return struct;
	}

	private static CppCompositeType createB_struct(DataTypeManager dtm) {
		String name = "B";
		CppCompositeType struct = createStruct(dtm, name, 12);
		struct.addMember("bm1", intT, false, publicDirectAttributes, 0, null);
		struct.addMember("bm2", intT, false, protectedDirectAttributes, 4, null);
		struct.addMember("bm3", intT, false, privateDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createC_struct(DataTypeManager dtm) {
		String name = "C";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("c1", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createCC1_struct(DataTypeManager dtm) {
		String name = "CC1";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("cc11", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createCC2_struct(DataTypeManager dtm) {
		String name = "CC2";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("cc21", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createCC3_struct(DataTypeManager dtm) {
		String name = "CC3";
		CppCompositeType struct = createStruct(dtm, name, 1); // OR IS IT ZERO?
		return struct;
	}

	private static CppCompositeType createD_struct(DataTypeManager dtm,
			CppCompositeType C_struct) throws PdbException {
		String name = "D";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addDirectBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes, 0);
		struct.addMember("d1", intT, false, publicDirectAttributes, 4, null);
		return struct;
	}

	private static CppCompositeType createE_struct(DataTypeManager dtm) {
		String name = "E";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("e1", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createF_struct(DataTypeManager dtm,
			CppCompositeType C_struct, CppCompositeType E_struct) throws PdbException {
		String name = "F";
		CppCompositeType struct = createStruct(dtm, name, 12);
		struct.addDirectBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(E_struct.getComposite(), E_struct, publicDirectAttributes, 4);
		struct.addMember("f1", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createG_struct(DataTypeManager dtm,
			CppCompositeType C_struct) throws PdbException {
		String name = "G";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("g1", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createH_struct(DataTypeManager dtm,
			CppCompositeType C_struct) throws PdbException {
		String name = "H";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("h1", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createGG1_struct(DataTypeManager dtm,
			CppCompositeType CC1_struct) throws PdbException {
		String name = "GG1";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(CC1_struct.getComposite(), CC1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("gg11", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createGG2_struct(DataTypeManager dtm,
			CppCompositeType CC2_struct) throws PdbException {
		String name = "GG2";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("gg21", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createGG3_struct(DataTypeManager dtm,
			CppCompositeType CC2_struct) throws PdbException {
		String name = "GG3";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("gg31", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createGG4_struct(DataTypeManager dtm,
			CppCompositeType CC3_struct) throws PdbException {
		String name = "GG4";
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addDirectVirtualBaseClass(CC3_struct.getComposite(), CC3_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("gg41", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createI_struct(DataTypeManager dtm,
			CppCompositeType G_struct, CppCompositeType H_struct, CppCompositeType C_struct)
			throws PdbException {
		String name = "I";
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addDirectBaseClass(G_struct.getComposite(), G_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(H_struct.getComposite(), H_struct, publicDirectAttributes, 16);
		struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("i1", intT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createGX1_struct(DataTypeManager dtm,
			CppCompositeType C_struct) throws PdbException {
		String name = "GX1";
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 1);
		return struct;
	}

	private static CppCompositeType createHX1_struct(DataTypeManager dtm,
			CppCompositeType C_struct) throws PdbException {
		String name = "HX1";
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 1);
		return struct;
	}

	private static CppCompositeType createIX1_struct(DataTypeManager dtm,
			CppCompositeType GX1_struct, CppCompositeType HX1_struct, CppCompositeType C_struct)
			throws PdbException {
		String name = "IX1";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(GX1_struct.getComposite(), GX1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(HX1_struct.getComposite(), HX1_struct, publicDirectAttributes, 8);
		struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("ix11", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createG1_struct(DataTypeManager dtm,
			CppCompositeType C_struct, CppCompositeType E_struct) throws PdbException {
		String name = "G1";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(E_struct.getComposite(), E_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("g11", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createH1_struct(DataTypeManager dtm,
			CppCompositeType C_struct, CppCompositeType E_struct) throws PdbException {
		String name = "H1";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(E_struct.getComposite(), E_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("h11", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createI1_struct(DataTypeManager dtm,
			CppCompositeType G1_struct, CppCompositeType H_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) throws PdbException {
		String name = "I1";
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(H_struct.getComposite(), H_struct, publicDirectAttributes, 16);
		struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("i11", intT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createI2_struct(DataTypeManager dtm,
			CppCompositeType G_struct, CppCompositeType H1_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) throws PdbException {
		String name = "I2";
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addDirectBaseClass(G_struct.getComposite(), G_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(H1_struct.getComposite(), H1_struct, publicDirectAttributes, 16);
		struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("i21", intT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createI3_struct(DataTypeManager dtm,
			CppCompositeType G1_struct, CppCompositeType H1_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) throws PdbException {
		String name = "I3";
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(H1_struct.getComposite(), H1_struct, publicDirectAttributes, 16);
		struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("i31", intT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createI4_struct(DataTypeManager dtm,
			CppCompositeType G1_struct, CppCompositeType C_struct, CppCompositeType E_struct)
			throws PdbException {
		String name = "I4";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(E_struct.getComposite(), E_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 2);
		struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("i41", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createI5_struct(DataTypeManager dtm,
			CppCompositeType G1_struct, CppCompositeType E_struct, CppCompositeType C_struct)
			throws PdbException {
		String name = "I5";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(E_struct.getComposite(), E_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 2);
		struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, publicDirectAttributes,
			0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("i51", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createJ1_struct(DataTypeManager dtm,
			CppCompositeType I1_struct, CppCompositeType I2_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) throws PdbException {
		String name = "J1";
		CppCompositeType struct = createStruct(dtm, name, 96);
		struct.addDirectBaseClass(I1_struct.getComposite(), I1_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(I2_struct.getComposite(), I2_struct, publicDirectAttributes, 40);
		struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("j11", intT, false, publicDirectAttributes, 80, null);
		return struct;
	}

	private static CppCompositeType createJ2_struct(DataTypeManager dtm,
			CppCompositeType I2_struct, CppCompositeType I1_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) throws PdbException {
		String name = "J2";
		CppCompositeType struct = createStruct(dtm, name, 96);
		struct.addDirectBaseClass(I2_struct.getComposite(), I2_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(I1_struct.getComposite(), I1_struct, publicDirectAttributes, 40);
		struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("j21", intT, false, publicDirectAttributes, 80, null);
		return struct;
	}

	private static CppCompositeType createJ3_struct(DataTypeManager dtm,
			CppCompositeType I2_struct, CppCompositeType I1_struct, CppCompositeType A_struct,
			CppCompositeType C_struct, CppCompositeType E_struct) throws PdbException {
		String name = "J3";
		CppCompositeType struct = createStruct(dtm, name, 104);
		struct.addDirectBaseClass(I2_struct.getComposite(), I2_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(I1_struct.getComposite(), I1_struct, publicDirectAttributes, 40);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 80);
		struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("j31", intT, false, publicDirectAttributes, 88, null);
		return struct;
	}

	private static CppCompositeType createJ4_struct(DataTypeManager dtm,
			CppCompositeType I3_struct, CppCompositeType GG1_struct, CppCompositeType I_struct,
			CppCompositeType A_struct, CppCompositeType C_struct, CppCompositeType E_struct,
			CppCompositeType CC1_struct, CppCompositeType CC2_struct, CppCompositeType GG2_struct,
			CppCompositeType GG3_struct) throws PdbException {
		String name = "J4";
		CppCompositeType struct = createStruct(dtm, name, 160);
		struct.addDirectBaseClass(I3_struct.getComposite(), I3_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(GG1_struct.getComposite(), GG1_struct, publicDirectAttributes,
			40);
		struct.addDirectBaseClass(I_struct.getComposite(), I_struct, publicDirectAttributes, 56);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 96);
		struct.addDirectVirtualBaseClass(GG2_struct.getComposite(), GG2_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 5);
		struct.addDirectVirtualBaseClass(GG3_struct.getComposite(), GG3_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 6);
		struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(CC1_struct.getComposite(), CC1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("j41", intT, false, publicDirectAttributes, 104, null);
		return struct;
	}

	private static CppCompositeType createJ5_struct(DataTypeManager dtm,
			CppCompositeType I3_struct, CppCompositeType GG1_struct, CppCompositeType I_struct,
			CppCompositeType A_struct, CppCompositeType CC2_struct, CppCompositeType GG2_struct,
			CppCompositeType GG3_struct, CppCompositeType C_struct, CppCompositeType E_struct,
			CppCompositeType CC1_struct) throws PdbException {
		String name = "J5";
		CppCompositeType struct = createStruct(dtm, name, 168);
		struct.addDirectBaseClass(I3_struct.getComposite(), I3_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(GG1_struct.getComposite(), GG1_struct, publicDirectAttributes,
			40);
		struct.addDirectBaseClass(I_struct.getComposite(), I_struct, publicDirectAttributes, 56);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 96);
		struct.addDirectVirtualBaseClass(GG2_struct.getComposite(), GG2_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 4);
		struct.addDirectVirtualBaseClass(GG3_struct.getComposite(), GG3_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 5);
		struct.addIndirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(CC1_struct.getComposite(), CC1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 6);
		struct.addMember("j51", intT, false, publicDirectAttributes, 104, null);
		return struct;
	}

	private static CppCompositeType createJ6_struct(DataTypeManager dtm,
			CppCompositeType A_struct, CppCompositeType CC3_struct, CppCompositeType GG4_struct,
			CppCompositeType CC2_struct, CppCompositeType GG3_struct) throws PdbException {
		String name = "J6";
		CppCompositeType struct = createStruct(dtm, name, 64);
		struct.addDirectBaseClass(A_struct.getComposite(), A_struct, publicDirectAttributes, 0);
		struct.addDirectVirtualBaseClass(GG4_struct.getComposite(), GG4_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addDirectVirtualBaseClass(GG3_struct.getComposite(), GG3_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addIndirectVirtualBaseClass(CC3_struct.getComposite(), CC3_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addMember("j61", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createP_struct(DataTypeManager dtm) {
		String name = "P";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("p1", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "pvf"), fvoidvoidT);
		return struct;
	}

	private static CppCompositeType createQ_struct(DataTypeManager dtm,
			CppCompositeType P_struct) throws PdbException {
		String name = "Q";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectBaseClass(P_struct.getComposite(), P_struct, publicDirectAttributes, 0);
		struct.addMember("q1", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "pvf"), fvoidvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "qvf"), fvoidvoidT);
		return struct;
	}

	private static CppCompositeType createR_struct(DataTypeManager dtm) {
		String name = "R";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("r1", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "pvf"), fvoidvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "rvf"), fvoidvoidT);
		return struct;
	}

	private static CppCompositeType createS_struct(DataTypeManager dtm,
			CppCompositeType P_struct, CppCompositeType R_struct) throws PdbException {
		String name = "S";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(P_struct.getComposite(), P_struct, publicDirectAttributes, 0);
		struct.addDirectBaseClass(R_struct.getComposite(), R_struct, publicDirectAttributes, 16);
		struct.addMember("s1", intT, false, publicDirectAttributes, 32, null);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "pvf"), fvoidvoidT);
		struct.addVirtualMethod(16, -1, new SymbolPath(classSp, "rvf"), fvoidvoidT);
		return struct;
	}

	private static CppCompositeType createT_struct(DataTypeManager dtm,
			CppCompositeType P_struct) throws PdbException {
		String name = "T";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(P_struct.getComposite(), P_struct, publicDirectAttributes,
			8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("t1", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(32, -1, new SymbolPath(classSp, "pvf"), fvoidvoidT);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "tvf"), fvoidvoidT);
		return struct;
	}

	private static CppCompositeType createU_struct(DataTypeManager dtm,
			CppCompositeType T_struct, CppCompositeType P_struct) throws PdbException {
		String name = "U";
		CppCompositeType struct = createStruct(dtm, name, 56);
		struct.addDirectBaseClass(T_struct.getComposite(), T_struct, publicDirectAttributes, 0);
		struct.addIndirectVirtualBaseClass(P_struct.getComposite(), P_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("u1", intT, false, publicDirectAttributes, 24, null);
		return struct;
	}

	private static CppCompositeType createV_struct(DataTypeManager dtm) {
		String name = "V";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "~V"), fvoidvoidT);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "__vecDelDtor"), fpvoidunsignedT);
		return struct;
	}

	private static CppCompositeType createW_struct(DataTypeManager dtm,
			CppCompositeType V_struct) throws PdbException {
		String name = "W";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addDirectBaseClass(V_struct.getComposite(), V_struct, publicDirectAttributes, 0);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "~W"), fvoidvoidT);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "__vecDelDtor"), fpvoidunsignedT);
		return struct;
	}

	private static CppCompositeType createWW_struct(DataTypeManager dtm,
			CppCompositeType W_struct) throws PdbException {
		String name = "WW";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addDirectBaseClass(W_struct.getComposite(), W_struct, publicDirectAttributes, 0);
		struct.addMember("w1", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, -1, new SymbolPath(classSp, "~WW"), fvoidvoidT);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "__vecDelDtor"), fpvoidunsignedT);
		return struct;
	}

	private static CppCompositeType createX_struct(DataTypeManager dtm) {
		String name = "X";
		CppCompositeType struct = createStruct(dtm, name, 1);
		return struct;
	}

	private static CppCompositeType createZ_struct(DataTypeManager dtm) {
		String name = "Z";
		CppCompositeType struct = createStruct(dtm, name, 1);
		return struct;
	}

	private static CppCompositeType createAA1a_struct(DataTypeManager dtm) {
		String name = "AA1a";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("aa1ai", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createAA1b_struct(DataTypeManager dtm) {
		String name = "AA1b";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("aa1bi", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createAA1_struct(DataTypeManager dtm,
			CppCompositeType AA1a_struct, CppCompositeType AA1b_struct) throws PdbException {
		String name = "AA1";
		CppCompositeType struct = createStruct(dtm, name, 12);
		struct.addDirectBaseClass(AA1a_struct.getComposite(), AA1a_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(AA1b_struct.getComposite(), AA1b_struct, publicDirectAttributes,
			4);
		struct.addMember("aa1i", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA2a_struct(DataTypeManager dtm) {
		String name = "AA2a";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("aa2ai", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createAA2b_struct(DataTypeManager dtm) {
		String name = "AA2b";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("aa2bi", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createAA2_struct(DataTypeManager dtm,
			CppCompositeType AA2a_struct, CppCompositeType AA2b_struct) throws PdbException {
		String name = "AA2";
		CppCompositeType struct = createStruct(dtm, name, 12);
		struct.addDirectBaseClass(AA2a_struct.getComposite(), AA2a_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(AA2b_struct.getComposite(), AA2b_struct, publicDirectAttributes,
			4);
		struct.addMember("aa2i", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA3a_struct(DataTypeManager dtm,
			CppCompositeType AA2_struct) throws PdbException {
		String name = "AA3a";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectVirtualBaseClass(AA2_struct.getComposite(), AA2_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa3ai", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA3b_struct(DataTypeManager dtm,
			CppCompositeType AA2_struct) throws PdbException {
		String name = "AA3b";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectVirtualBaseClass(AA2_struct.getComposite(), AA2_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa3bi", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA3c_struct(DataTypeManager dtm,
			CppCompositeType AA3a_struct, CppCompositeType AA3b_struct, CppCompositeType AA1_struct,
			CppCompositeType AA2_struct) throws PdbException {
		String name = "AA3c";
		CppCompositeType struct = createStruct(dtm, name, 64);
		struct.addDirectBaseClass(AA3a_struct.getComposite(), AA3a_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(AA3b_struct.getComposite(), AA3b_struct, publicDirectAttributes,
			16);
		struct.addDirectVirtualBaseClass(AA1_struct.getComposite(), AA1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(AA2_struct.getComposite(), AA2_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa3ci", intT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createAA3d_struct(DataTypeManager dtm,
			CppCompositeType AA1_struct, CppCompositeType AA2_struct, CppCompositeType AA3a_struct,
			CppCompositeType AA3b_struct) throws PdbException {
		String name = "AA3d";
		CppCompositeType struct = createStruct(dtm, name, 72);
		struct.addDirectVirtualBaseClass(AA1_struct.getComposite(), AA1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(AA3a_struct.getComposite(), AA3a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 3);
		struct.addDirectVirtualBaseClass(AA3b_struct.getComposite(), AA3b_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 4);
		struct.addIndirectVirtualBaseClass(AA2_struct.getComposite(), AA2_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("aa3di", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA3e_struct(DataTypeManager dtm,
			CppCompositeType AA2_struct) throws PdbException {
		String name = "AA3e";
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addDirectBaseClass(AA2_struct.getComposite(), AA2_struct, publicDirectAttributes, 0);
		struct.addMember("aa3ei", intT, false, publicDirectAttributes, 12, null);
		return struct;
	}

	private static CppCompositeType createAA3f_struct(DataTypeManager dtm,
			CppCompositeType AA2_struct) throws PdbException {
		String name = "AA3f";
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addDirectBaseClass(AA2_struct.getComposite(), AA2_struct, publicDirectAttributes, 0);
		struct.addMember("aa3fi", intT, false, publicDirectAttributes, 12, null);
		return struct;
	}

	private static CppCompositeType createAA3g_struct(DataTypeManager dtm,
			CppCompositeType AA3e_struct, CppCompositeType AA3f_struct) throws PdbException {
		String name = "AA3g";
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addDirectVirtualBaseClass(AA3e_struct.getComposite(), AA3e_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(AA3f_struct.getComposite(), AA3f_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("aa3gi", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA4a_struct(DataTypeManager dtm,
			CppCompositeType AA1_struct) throws PdbException {
		String name = "AA4a";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectVirtualBaseClass(AA1_struct.getComposite(), AA1_struct,
			privateDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4ai", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA4b_struct(DataTypeManager dtm,
			CppCompositeType AA1_struct) throws PdbException {
		String name = "AA4b";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectVirtualBaseClass(AA1_struct.getComposite(), AA1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4bi", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA4c_struct(DataTypeManager dtm,
			CppCompositeType AA4a_struct, CppCompositeType AA4b_struct, CppCompositeType AA1_struct)
			throws PdbException {
		String name = "AA4c";
		CppCompositeType struct = createStruct(dtm, name, 56);
		struct.addDirectBaseClass(AA4a_struct.getComposite(), AA4a_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(AA4b_struct.getComposite(), AA4b_struct, publicDirectAttributes,
			16);
		struct.addIndirectVirtualBaseClass(AA1_struct.getComposite(), AA1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4ci", intT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createAA4d_struct(DataTypeManager dtm,
			CppCompositeType AA4b_struct, CppCompositeType AA1_struct, CppCompositeType AA4a_struct)
			throws PdbException {
		String name = "AA4d";
		CppCompositeType struct = createStruct(dtm, name, 56);
		struct.addDirectBaseClass(AA4b_struct.getComposite(), AA4b_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(AA4a_struct.getComposite(), AA4a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(AA1_struct.getComposite(), AA1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4di", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createAA4e_struct(DataTypeManager dtm,
			CppCompositeType AA4a_struct, CppCompositeType AA1_struct, CppCompositeType AA4b_struct)
			throws PdbException {
		String name = "AA4e";
		CppCompositeType struct = createStruct(dtm, name, 56);
		struct.addDirectBaseClass(AA4a_struct.getComposite(), AA4a_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(AA4b_struct.getComposite(), AA4b_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(AA1_struct.getComposite(), AA1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4ei", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createAA4f_struct(DataTypeManager dtm,
			CppCompositeType AA1_struct, CppCompositeType AA4a_struct, CppCompositeType AA4b_struct)
			throws PdbException {
		String name = "AA4f";
		CppCompositeType struct = createStruct(dtm, name, 64);
		struct.addDirectVirtualBaseClass(AA4a_struct.getComposite(), AA4a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addDirectVirtualBaseClass(AA4b_struct.getComposite(), AA4b_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(AA1_struct.getComposite(), AA1_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4fi", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA4g_struct(DataTypeManager dtm,
			CppCompositeType AA4b_struct, CppCompositeType AA1_struct) throws PdbException {
		String name = "AA4g";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(AA4b_struct.getComposite(), AA4b_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(AA1_struct.getComposite(), AA1_struct,
			privateDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4gi", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createAA4h_struct(DataTypeManager dtm) {
		String name = "AA4h";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("aa4hi", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createAA4j_struct(DataTypeManager dtm,
			CppCompositeType AA4h_struct) throws PdbException {
		String name = "AA4j";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(AA4h_struct.getComposite(), AA4h_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4ji", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA4k_struct(DataTypeManager dtm,
			CppCompositeType AA4h_struct) throws PdbException {
		String name = "AA4k";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(AA4h_struct.getComposite(), AA4h_struct,
			privateDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4ki", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA4m_struct(DataTypeManager dtm,
			CppCompositeType AA4j_struct, CppCompositeType AA4h_struct) throws PdbException {
		String name = "AA4m";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(AA4j_struct.getComposite(), AA4j_struct, privateDirectAttributes,
			0);
		struct.addIndirectVirtualBaseClass(AA4h_struct.getComposite(), AA4h_struct,
			privateDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4mi", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createAA4n_struct(DataTypeManager dtm,
			CppCompositeType AA4k_struct, CppCompositeType AA4h_struct) throws PdbException {
		String name = "AA4n";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(AA4k_struct.getComposite(), AA4k_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(AA4h_struct.getComposite(), AA4h_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4ni", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createAA4p_struct(DataTypeManager dtm,
			CppCompositeType AA4m_struct, CppCompositeType AA4h_struct) throws PdbException {
		String name = "AA4p";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(AA4m_struct.getComposite(), AA4m_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(AA4h_struct.getComposite(), AA4h_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4pi", intT, false, publicDirectAttributes, 24, null);
		return struct;
	}

	private static CppCompositeType createAA4q_struct(DataTypeManager dtm,
			CppCompositeType AA4n_struct, CppCompositeType AA4m_struct,
			CppCompositeType AA4h_struct) throws PdbException {
		String name = "AA4q";
		CppCompositeType struct = createStruct(dtm, name, 64);
		struct.addDirectBaseClass(AA4n_struct.getComposite(), AA4n_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(AA4m_struct.getComposite(), AA4m_struct, publicDirectAttributes,
			24);
		struct.addIndirectVirtualBaseClass(AA4h_struct.getComposite(), AA4h_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa4qi", intT, false, publicDirectAttributes, 48, null);
		return struct;
	}

	private static CppCompositeType createAA5a_struct(DataTypeManager dtm) {
		String name = "AA5a";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("aa5ai", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createAA5b_struct(DataTypeManager dtm) {
		String name = "AA5b";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("aa5bi", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createAA5c_struct(DataTypeManager dtm) {
		String name = "AA5c";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("aa5ci", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createAA5d_struct(DataTypeManager dtm) {
		String name = "AA5d";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("aa5di", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createAA5e_struct(DataTypeManager dtm,
			CppCompositeType AA5a_struct, CppCompositeType AA5b_struct) throws PdbException {
		String name = "AA5e";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(AA5a_struct.getComposite(), AA5a_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(AA5b_struct.getComposite(), AA5b_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa5ei", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createAA5f_struct(DataTypeManager dtm,
			CppCompositeType AA5c_struct, CppCompositeType AA5d_struct) throws PdbException {
		String name = "AA5f";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(AA5c_struct.getComposite(), AA5c_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(AA5d_struct.getComposite(), AA5d_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa5fi", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createAA5g_struct(DataTypeManager dtm,
			CppCompositeType AA5c_struct, CppCompositeType AA5b_struct,
			CppCompositeType AA5e_struct) throws PdbException {
		String name = "AA5g";
		CppCompositeType struct = createStruct(dtm, name, 56);
		struct.addDirectBaseClass(AA5c_struct.getComposite(), AA5c_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(AA5e_struct.getComposite(), AA5e_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(AA5b_struct.getComposite(), AA5b_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa5gi", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createAA5h_struct(DataTypeManager dtm,
			CppCompositeType AA5a_struct, CppCompositeType AA5d_struct,
			CppCompositeType AA5f_struct) throws PdbException {
		String name = "AA5h";
		CppCompositeType struct = createStruct(dtm, name, 56);
		struct.addDirectBaseClass(AA5a_struct.getComposite(), AA5a_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(AA5f_struct.getComposite(), AA5f_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(AA5d_struct.getComposite(), AA5d_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa5hi", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createAA5j_struct(DataTypeManager dtm,
			CppCompositeType AA5g_struct, CppCompositeType AA5h_struct,
			CppCompositeType AA5b_struct, CppCompositeType AA5e_struct,
			CppCompositeType AA5d_struct, CppCompositeType AA5f_struct) throws PdbException {
		String name = "AA5j";
		CppCompositeType struct = createStruct(dtm, name, 120);
		struct.addDirectBaseClass(AA5g_struct.getComposite(), AA5g_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(AA5h_struct.getComposite(), AA5h_struct, publicDirectAttributes,
			24);
		struct.addDirectVirtualBaseClass(AA5b_struct.getComposite(), AA5b_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(AA5e_struct.getComposite(), AA5e_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(AA5d_struct.getComposite(), AA5d_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addIndirectVirtualBaseClass(AA5f_struct.getComposite(), AA5f_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 4);
		struct.addMember("aa5ji", intT, false, publicDirectAttributes, 48, null);
		return struct;
	}

	private static CppCompositeType createAA6a_struct(DataTypeManager dtm) {
		String name = "AA6a";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("aa6ai", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createAA6b_struct(DataTypeManager dtm,
			CppCompositeType AA6a_struct) throws PdbException {
		String name = "AA6b";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addDirectBaseClass(AA6a_struct.getComposite(), AA6a_struct, publicDirectAttributes,
			0);
		struct.addMember("aa6bi", intT, false, publicDirectAttributes, 4, null);
		return struct;
	}

	private static CppCompositeType createAA6c_struct(DataTypeManager dtm,
			CppCompositeType AA6a_struct) throws PdbException {
		String name = "AA6c";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(AA6a_struct.getComposite(), AA6a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa6ci", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createAA6d_struct(DataTypeManager dtm,
			CppCompositeType AA6a_struct) {
		String name = "AA6d";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addMember("aa6di", intT, false, publicDirectAttributes, 0, null);
		struct.addMember("aa6a", AA6a_struct.getComposite(), false, publicDirectAttributes, 4,
			null);
		return struct;
	}

	private static CppCompositeType createAA6e_struct(DataTypeManager dtm,
			CppCompositeType AA6a_struct) throws PdbException {
		String name = "AA6e";
		CppCompositeType struct = createStruct(dtm, name, 12);
		struct.addDirectBaseClass(AA6a_struct.getComposite(), AA6a_struct, publicDirectAttributes,
			0);
		struct.addMember("aa6ei", intT, false, publicDirectAttributes, 4, null);
		struct.addMember("aa6a", AA6a_struct.getComposite(), false, publicDirectAttributes, 8,
			null);
		return struct;
	}

	private static CppCompositeType createAA6f_struct(DataTypeManager dtm,
			CppCompositeType AA6b_struct, CppCompositeType AA6a_struct) throws PdbException {
		String name = "AA6f";
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addDirectBaseClass(AA6b_struct.getComposite(), AA6b_struct, publicDirectAttributes,
			0);
		struct.addMember("aa6fi", intT, false, publicDirectAttributes, 8, null);
		struct.addMember("aa6a", AA6a_struct.getComposite(), false, publicDirectAttributes, 12,
			null);
		return struct;
	}

	private static CppCompositeType createAA6g_struct(DataTypeManager dtm,
			CppCompositeType AA6c_struct, CppCompositeType AA6a_struct) throws PdbException {
		String name = "AA6g";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(AA6c_struct.getComposite(), AA6c_struct, publicDirectAttributes,
			0);
		struct.addIndirectVirtualBaseClass(AA6a_struct.getComposite(), AA6a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa6gi", intT, false, publicDirectAttributes, 16, null);
		struct.addMember("aa6a", AA6a_struct.getComposite(), false, publicDirectAttributes, 20,
			null);
		return struct;
	}

	private static CppCompositeType createAA6h_struct(DataTypeManager dtm,
			CppCompositeType AA6a_struct, CppCompositeType AA6c_struct) throws PdbException {
		String name = "AA6h";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectVirtualBaseClass(AA6c_struct.getComposite(), AA6c_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(AA6a_struct.getComposite(), AA6a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("aa6hi", intT, false, publicDirectAttributes, 8, null);
		struct.addMember("aa6a", AA6a_struct.getComposite(), false, publicDirectAttributes, 12,
			null);
		return struct;
	}

	private static CppCompositeType createAA6j_struct(DataTypeManager dtm,
			CppCompositeType AA6a_struct, CppCompositeType AA6c_struct) throws PdbException {
		String name = "AA6j";
		CppCompositeType struct = createStruct(dtm, name, 48);
		PointerDataType paa6j = new PointerDataType(struct.getComposite());
		struct.addDirectVirtualBaseClass(AA6c_struct.getComposite(), AA6c_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(AA6a_struct.getComposite(), AA6a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		// aa6hj was intended to be aa6ji
		struct.addMember("aa6hj", intT, false, publicDirectAttributes, 8, null);
		struct.addMember("aa6a", AA6a_struct.getComposite(), false, publicDirectAttributes, 12,
			null);
		struct.addMember("paa6j", paa6j, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createAA7a_struct(DataTypeManager dtm) {
		String name = "AA7a";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("aa7ai", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "pvf1"), fvoidvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "pvf2"), fvoidvoidT);
		return struct;
	}

	private static CppCompositeType createAA7b_struct(DataTypeManager dtm) {
		String name = "AA7b";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addMember("aa7bi", intT, false, publicDirectAttributes, 8, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "pvf1"), fvoidvoidT);
		struct.addVirtualMethod(0, 8, new SymbolPath(classSp, "pvf3"), fvoidvoidT);
		return struct;
	}

	private static CppCompositeType createAA7c_struct(DataTypeManager dtm,
			CppCompositeType AA7a_struct, CppCompositeType AA7b_struct) throws PdbException {
		String name = "AA7c";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(AA7a_struct.getComposite(), AA7a_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(AA7b_struct.getComposite(), AA7b_struct, publicDirectAttributes,
			16);
		struct.addMember("aa7ci", intT, false, publicDirectAttributes, 32, null);
		struct.addVirtualMethod(0, 16, new SymbolPath(classSp, "pvf4"), fvoidvoidT);
		return struct;
	}

	private static CppCompositeType createAA7d_struct(DataTypeManager dtm,
			CppCompositeType AA7a_struct, CppCompositeType AA7b_struct) throws PdbException {
		String name = "AA7d";
		SymbolPath classSp = new SymbolPath(SymbolPathParser.parse(name));
		CppCompositeType struct = createStruct(dtm, name, 56);
		struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, 0);
		struct.addDirectVirtualBaseClass(AA7a_struct.getComposite(), AA7a_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(AA7b_struct.getComposite(), AA7b_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("aa7di", intT, false, publicDirectAttributes, 16, null);
		struct.addVirtualMethod(0, 0, new SymbolPath(classSp, "pvf5"), fvoidvoidT);
		return struct;
	}

	private static CppCompositeType createBB1a_struct(DataTypeManager dtm) {
		String name = "BB1a";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("bb1ai", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createBB1b_struct(DataTypeManager dtm,
			CppCompositeType BB1a_struct) throws PdbException {
		String name = "BB1b";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addDirectBaseClass(BB1a_struct.getComposite(), BB1a_struct, publicDirectAttributes,
			0);
		struct.addMember("bb1bi", intT, false, publicDirectAttributes, 4, null);
		return struct;
	}

	private static CppCompositeType createBB1c_struct(DataTypeManager dtm,
			CppCompositeType BB1a_struct) throws PdbException {
		String name = "BB1c";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(BB1a_struct.getComposite(), BB1a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("bb1ci", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createBB1d_struct(DataTypeManager dtm,
			CppCompositeType BB1b_struct, CppCompositeType BB1c_struct,
			CppCompositeType BB1a_struct) throws PdbException {
		String name = "BB1d";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(BB1b_struct.getComposite(), BB1b_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(BB1c_struct.getComposite(), BB1c_struct, publicDirectAttributes,
			8);
		struct.addIndirectVirtualBaseClass(BB1a_struct.getComposite(), BB1a_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("bb1di", intT, false, publicDirectAttributes, 24, null);
		return struct;
	}

	private static CppCompositeType createBB2z_struct(DataTypeManager dtm) {
		String name = "BB2z";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("bb2zi", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createBB2a_struct(DataTypeManager dtm,
			CppCompositeType BB2z_struct) throws PdbException {
		String name = "BB2a";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(BB2z_struct.getComposite(), BB2z_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("bb2ai", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createBB2b_struct(DataTypeManager dtm,
			CppCompositeType BB2a_struct, CppCompositeType BB2z_struct) throws PdbException {
		String name = "BB2b";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(BB2a_struct.getComposite(), BB2a_struct, publicDirectAttributes,
			0);
		struct.addIndirectVirtualBaseClass(BB2z_struct.getComposite(), BB2z_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("bb2bi", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createBB2c_struct(DataTypeManager dtm,
			CppCompositeType BB2z_struct, CppCompositeType BB2a_struct) throws PdbException {
		String name = "BB2c";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectVirtualBaseClass(BB2a_struct.getComposite(), BB2a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(BB2z_struct.getComposite(), BB2z_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("bb2ci", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createBB2d_struct(DataTypeManager dtm,
			CppCompositeType BB2b_struct, CppCompositeType BB2c_struct,
			CppCompositeType BB2z_struct, CppCompositeType BB2a_struct) throws PdbException {
		String name = "BB2d";
		CppCompositeType struct = createStruct(dtm, name, 72);
		struct.addDirectBaseClass(BB2b_struct.getComposite(), BB2b_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(BB2c_struct.getComposite(), BB2c_struct, publicDirectAttributes,
			24);
		struct.addIndirectVirtualBaseClass(BB2z_struct.getComposite(), BB2z_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(BB2a_struct.getComposite(), BB2a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("bb2di", intT, false, publicDirectAttributes, 40, null);
		return struct;
	}

	private static CppCompositeType createBB2e_struct(DataTypeManager dtm,
			CppCompositeType BB2b_struct, CppCompositeType BB2z_struct) throws PdbException {
		String name = "BB2e";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(BB2b_struct.getComposite(), BB2b_struct, publicDirectAttributes,
			0);
		struct.addIndirectVirtualBaseClass(BB2z_struct.getComposite(), BB2z_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("bb2ei", intT, false, publicDirectAttributes, 24, null);
		return struct;
	}

	private static CppCompositeType createBB3a_struct(DataTypeManager dtm) {
		String name = "BB3a";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("bb3ai", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createBB3b_struct(DataTypeManager dtm) {
		String name = "BB3b";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("bb3bi", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createBB3c_struct(DataTypeManager dtm) {
		String name = "BB3c";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("bb3ci", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createBB3d_struct(DataTypeManager dtm,
			CppCompositeType BB3a_struct, CppCompositeType BB3c_struct,
			CppCompositeType BB3b_struct) throws PdbException {
		String name = "BB3d";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(BB3a_struct.getComposite(), BB3a_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(BB3c_struct.getComposite(), BB3c_struct, publicDirectAttributes,
			4);
		struct.addDirectVirtualBaseClass(BB3b_struct.getComposite(), BB3b_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("bb3di", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createBB3e_struct(DataTypeManager dtm,
			CppCompositeType BB3b_struct, CppCompositeType BB3a_struct,
			CppCompositeType BB3c_struct) throws PdbException {
		String name = "BB3e";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(BB3b_struct.getComposite(), BB3b_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(BB3a_struct.getComposite(), BB3a_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(BB3c_struct.getComposite(), BB3c_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addMember("bb3ei", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createBB3f_struct(DataTypeManager dtm,
			CppCompositeType BB3d_struct, CppCompositeType BB3e_struct,
			CppCompositeType BB3b_struct, CppCompositeType BB3a_struct,
			CppCompositeType BB3c_struct) throws PdbException {
		String name = "BB3f";
		CppCompositeType struct = createStruct(dtm, name, 72);
		struct.addDirectBaseClass(BB3d_struct.getComposite(), BB3d_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(BB3e_struct.getComposite(), BB3e_struct, publicDirectAttributes,
			24);
		struct.addIndirectVirtualBaseClass(BB3b_struct.getComposite(), BB3b_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(BB3a_struct.getComposite(), BB3a_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(BB3c_struct.getComposite(), BB3c_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addMember("bb3fi", intT, false, publicDirectAttributes, 48, null);
		return struct;
	}

	private static CppCompositeType createBB3g_struct(DataTypeManager dtm,
			CppCompositeType BB3e_struct, CppCompositeType BB3d_struct,
			CppCompositeType BB3a_struct, CppCompositeType BB3c_struct,
			CppCompositeType BB3b_struct) throws PdbException {
		String name = "BB3g";
		CppCompositeType struct = createStruct(dtm, name, 72);
		struct.addDirectBaseClass(BB3e_struct.getComposite(), BB3e_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(BB3d_struct.getComposite(), BB3d_struct, publicDirectAttributes,
			24);
		struct.addIndirectVirtualBaseClass(BB3a_struct.getComposite(), BB3a_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 1);
		struct.addIndirectVirtualBaseClass(BB3c_struct.getComposite(), BB3c_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 2);
		struct.addIndirectVirtualBaseClass(BB3b_struct.getComposite(), BB3b_struct,
			publicDirectAttributes, 8, ClassUtils.VXPTR_TYPE, 3);
		struct.addMember("bb3gi", intT, false, publicDirectAttributes, 48, null);
		return struct;
	}

	private static CppCompositeType createCC1a_struct(DataTypeManager dtm) {
		String name = "CC1a";
		CppCompositeType struct = createStruct(dtm, name, 2);
		struct.addMember("cc1as", shortT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createCC1b_struct(DataTypeManager dtm) {
		String name = "CC1b";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("cc1bi", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createCC1c_struct(DataTypeManager dtm) {
		String name = "CC1c";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("cc1cl", longT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createCC1d_struct(DataTypeManager dtm) {
		String name = "CC1d";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("cc1df", floatT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createCC1e_struct(DataTypeManager dtm) {
		String name = "CC1e";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addMember("cc1ep", pcharT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createCC1f_struct(DataTypeManager dtm) {
		String name = "CC1f";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addMember("cc1fd", doubleT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createCC1g_struct(DataTypeManager dtm,
			CppCompositeType CC1a_struct, CppCompositeType CC1b_struct,
			CppCompositeType CC1c_struct, CppCompositeType CC1d_struct,
			CppCompositeType CC1e_struct, CppCompositeType CC1f_struct) throws PdbException {
		String name = "CC1g";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addDirectBaseClass(CC1a_struct.getComposite(), CC1a_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(CC1b_struct.getComposite(), CC1b_struct, publicDirectAttributes,
			4);
		struct.addDirectBaseClass(CC1c_struct.getComposite(), CC1c_struct, publicDirectAttributes,
			8);
		struct.addDirectBaseClass(CC1d_struct.getComposite(), CC1d_struct, publicDirectAttributes,
			12);
		struct.addDirectBaseClass(CC1e_struct.getComposite(), CC1e_struct, publicDirectAttributes,
			16);
		struct.addDirectBaseClass(CC1f_struct.getComposite(), CC1f_struct, publicDirectAttributes,
			24);
		struct.addMember("cc1gc", charT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createCC1h_struct(DataTypeManager dtm,
			CppCompositeType CC1a_struct, CppCompositeType CC1b_struct,
			CppCompositeType CC1c_struct, CppCompositeType CC1d_struct,
			CppCompositeType CC1e_struct, CppCompositeType CC1f_struct) throws PdbException {
		String name = "CC1h";
		CppCompositeType struct = createStruct(dtm, name, 48);
		struct.addDirectVirtualBaseClass(CC1a_struct.getComposite(), CC1a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addDirectVirtualBaseClass(CC1b_struct.getComposite(), CC1b_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 2);
		struct.addDirectVirtualBaseClass(CC1c_struct.getComposite(), CC1c_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 3);
		struct.addDirectVirtualBaseClass(CC1d_struct.getComposite(), CC1d_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 4);
		struct.addDirectVirtualBaseClass(CC1e_struct.getComposite(), CC1e_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 5);
		struct.addDirectVirtualBaseClass(CC1f_struct.getComposite(), CC1f_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 6);
		struct.addMember("cc1hc", charT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createCC1g_counterpoint_struct(DataTypeManager dtm) {
		String name = "CC1g_counterpoint";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addMember("cc1as", shortT, false, publicDirectAttributes, 0, null);
		struct.addMember("cc1bi", intT, false, publicDirectAttributes, 4, null);
		struct.addMember("cc1cl", longT, false, publicDirectAttributes, 8, null);
		struct.addMember("cc1df", floatT, false, publicDirectAttributes, 12, null);
		struct.addMember("cc1ep", pcharT, false, publicDirectAttributes, 16, null);
		struct.addMember("cc1fd", doubleT, false, publicDirectAttributes, 24, null);
		struct.addMember("cc1gc", charT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createCC1h_counterpoint_struct(DataTypeManager dtm) {
		String name = "CC1h_counterpoint";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addMember("p", pcharT, false, publicDirectAttributes, 0, null);
		struct.addMember("cc1hc", charT, false, publicDirectAttributes, 8, null);
		struct.addMember("cc1as", shortT, false, publicDirectAttributes, 10, null);
		struct.addMember("cc1bi", intT, false, publicDirectAttributes, 12, null);
		struct.addMember("cc1cl", longT, false, publicDirectAttributes, 16, null);
		struct.addMember("cc1df", floatT, false, publicDirectAttributes, 20, null);
		struct.addMember("cc1ep", pcharT, false, publicDirectAttributes, 24, null);
		struct.addMember("cc1fd", doubleT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createCC1g_counterpoint2_struct(DataTypeManager dtm) {
		String name = "CC1g_counterpoint2";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addMember("cc1as", shortT, false, publicDirectAttributes, 0, null);
		struct.addMember("cc1bi", intT, false, publicDirectAttributes, 4, null);
		struct.addMember("cc1cl", longT, false, publicDirectAttributes, 8, null);
		struct.addMember("cc1df", floatT, false, publicDirectAttributes, 12, null);
		struct.addMember("cc1ep", pcharT, false, publicDirectAttributes, 16, null);
		struct.addMember("cc1fd", doubleT, false, publicDirectAttributes, 24, null);
		struct.addMember("cc1gc", charT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createCC1h_counterpoint2_struct(DataTypeManager dtm) {
		String name = "CC1h_counterpoint2";
		CppCompositeType struct = createStruct(dtm, name, 40);
		struct.addMember("p", pcharT, false, publicDirectAttributes, 0, null);
		struct.addMember("cc1hc", charT, false, publicDirectAttributes, 8, null);
		struct.addMember("cc1as", shortT, false, publicDirectAttributes, 10, null);
		struct.addMember("cc1bi", intT, false, publicDirectAttributes, 12, null);
		struct.addMember("cc1cl", longT, false, publicDirectAttributes, 16, null);
		struct.addMember("cc1df", floatT, false, publicDirectAttributes, 20, null);
		struct.addMember("cc1ep", pcharT, false, publicDirectAttributes, 24, null);
		struct.addMember("cc1fd", doubleT, false, publicDirectAttributes, 32, null);
		return struct;
	}

	private static CppCompositeType createCC2a_struct(DataTypeManager dtm) {
		String name = "CC2a";
		CppCompositeType struct = createStruct(dtm, name, 2);
		struct.addMember("x", charT, false, publicDirectAttributes, 0, null);
		struct.addMember("c", charT, false, publicDirectAttributes, 1, null);
		return struct;
	}

	private static CppCompositeType createCC2b_struct(DataTypeManager dtm) {
		String name = "CC2b";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("x", charT, false, publicDirectAttributes, 0, null);
		struct.addMember("s", shortT, false, publicDirectAttributes, 2, null);
		return struct;
	}

	private static CppCompositeType createCC2c_struct(DataTypeManager dtm) {
		String name = "CC2c";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addMember("x", charT, false, publicDirectAttributes, 0, null);
		struct.addMember("i", intT, false, publicDirectAttributes, 4, null);
		return struct;
	}

	private static CppCompositeType createCC2d_struct(DataTypeManager dtm) {
		String name = "CC2d";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addMember("x", charT, false, publicDirectAttributes, 0, null);
		struct.addMember("l", longT, false, publicDirectAttributes, 4, null);
		return struct;
	}

	private static CppCompositeType createCC2e_struct(DataTypeManager dtm) {
		String name = "CC2e";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addMember("x", charT, false, publicDirectAttributes, 0, null);
		struct.addMember("f", floatT, false, publicDirectAttributes, 4, null);
		return struct;
	}

	private static CppCompositeType createCC2f_struct(DataTypeManager dtm) {
		String name = "CC2f";
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addMember("x", charT, false, publicDirectAttributes, 0, null);
		struct.addMember("d", doubleT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createCC2g_struct(DataTypeManager dtm) {
		String name = "CC2g";
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addMember("x", charT, false, publicDirectAttributes, 0, null);
		struct.addMember("p", pcharT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createCC2h_struct(DataTypeManager dtm) {
		String name = "CC2h";
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addMember("x", charT, false, publicDirectAttributes, 0, null);
		struct.addMember("ll", longlongT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createCC2j_struct(DataTypeManager dtm) {
		String name = "CC2j";
		CppCompositeType struct = createStruct(dtm, name, 16);
		struct.addMember("x", charT, false, publicDirectAttributes, 0, null);
		struct.addMember("ld", doubleT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createDD1a_struct(DataTypeManager dtm) {
		String name = "DD1a";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("dd1ai", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createDD1b_struct(DataTypeManager dtm,
			CppCompositeType DD1a_struct) throws PdbException {
		String name = "DD1b";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectVirtualBaseClass(DD1a_struct.getComposite(), DD1a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("dd1bi", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createDD1c_struct(DataTypeManager dtm,
			CppCompositeType DD1b_struct, CppCompositeType DD1a_struct) throws PdbException {
		String name = "DD1c";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(DD1b_struct.getComposite(), DD1b_struct, publicDirectAttributes,
			0);
		struct.addDirectVirtualBaseClass(DD1a_struct.getComposite(), DD1a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("dd1ci", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createDD1d_struct(DataTypeManager dtm,
			CppCompositeType DD1b_struct, CppCompositeType DD1a_struct) throws PdbException {
		String name = "DD1d";
		CppCompositeType struct = createStruct(dtm, name, 32);
		struct.addDirectBaseClass(DD1b_struct.getComposite(), DD1b_struct, publicDirectAttributes,
			0);
		struct.addIndirectVirtualBaseClass(DD1a_struct.getComposite(), DD1a_struct,
			publicDirectAttributes, 0, ClassUtils.VXPTR_TYPE, 1);
		struct.addMember("dd1di", intT, false, publicDirectAttributes, 16, null);
		return struct;
	}

	private static CppCompositeType createDD2a_struct(DataTypeManager dtm) {
		String name = "DD2a";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("dd2ai", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createDD2b_struct(DataTypeManager dtm) {
		String name = "DD2b";
		CppCompositeType struct = createStruct(dtm, name, 4);
		struct.addMember("dd2bi", intT, false, publicDirectAttributes, 0, null);
		return struct;
	}

	private static CppCompositeType createDD2c_struct(DataTypeManager dtm,
			CppCompositeType DD2a_struct) throws PdbException {
		String name = "DD2c";
		CppCompositeType struct = createStruct(dtm, name, 8);
		struct.addDirectBaseClass(DD2a_struct.getComposite(), DD2a_struct, publicDirectAttributes,
			0);
		struct.addMember("dd2ci", intT, false, publicDirectAttributes, 4, null);
		return struct;
	}

	private static CppCompositeType createDD2d_struct(DataTypeManager dtm,
			CppCompositeType DD2a_struct, CppCompositeType DD2b_struct) throws PdbException {
		String name = "DD2d";
		CppCompositeType struct = createStruct(dtm, name, 12);
		struct.addDirectBaseClass(DD2a_struct.getComposite(), DD2a_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(DD2b_struct.getComposite(), DD2b_struct, publicDirectAttributes,
			4);
		struct.addMember("dd2di", intT, false, publicDirectAttributes, 8, null);
		return struct;
	}

	private static CppCompositeType createDD2e_struct(DataTypeManager dtm,
			CppCompositeType DD2c_struct, CppCompositeType DD2d_struct) throws PdbException {
		String name = "DD2e";
		CppCompositeType struct = createStruct(dtm, name, 24);
		struct.addDirectBaseClass(DD2c_struct.getComposite(), DD2c_struct, publicDirectAttributes,
			0);
		struct.addDirectBaseClass(DD2d_struct.getComposite(), DD2d_struct, publicDirectAttributes,
			8);
		struct.addMember("dd2ei", intT, false, publicDirectAttributes, 20, null);
		return struct;
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================

	//@formatter:off
	/*
	struct A {
	  char c;
	  int i;
	};

	class A	size(8):
		+---
	 0	| c
	  	| <alignment member> (size=3)
	 4	| i
		+---
	 */
	//@formatter:on
	private static String getExpectedStructA() {
		String expected =
		//@formatter:off
			"""
			/A
			pack()
			Structure A {
			   0   char   1   c   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructA() {
		return convertCommentsToSpeculative(getExpectedStructA());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryA() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsA() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct B {
	public:
  		int bm1;
  		B();
	protected:
  		int bm2;
	private:
  		int bm3;
  		static int bsm;
  		void bf();
  		static void bsf();
  		typedef void* bpv;
	};

	class B	size(12):
		+---
 	 0	| bm1
 	 4	| bm2
 	 8	| bm3
		+---
	 */
	//@formatter:on
	private static String getExpectedStructB() {
		String expected =
		//@formatter:off
			"""
			/B
			pack()
			Structure B {
			   0   int   4   bm1   ""
			   4   int   4   bm2   ""
			   8   int   4   bm3   ""
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
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsB() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct C {
	  int c1;
	  void cf();
	};

	class C	size(4):
		+---
	 0	| c1
		+---
	 */
	//@formatter:on
	//@formatter:on
	private static String getExpectedStructC() {
		String expected =
		//@formatter:off
			"""
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructC() {
		return convertCommentsToSpeculative(getExpectedStructC());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryC() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsC() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct CC1 {
	  int cc11;
	  void cc1f();
	};

	class CC1	size(4):
		+---
 	0	| cc11
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1() {
		String expected =
		//@formatter:off
			"""
			/CC1
			pack()
			Structure CC1 {
			   0   int   4   cc11   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1() {
		return convertCommentsToSpeculative(getExpectedStructCC1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct CC2 {
	  int cc21;
	  void cc2f();
	};

	class CC2	size(4):
		+---
	 0	| cc21
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC2() {
		String expected =
		//@formatter:off
			"""
			/CC2
			pack()
			Structure CC2 {
			   0   int   4   cc21   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC2() {
		return convertCommentsToSpeculative(getExpectedStructCC2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC2() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC2() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct CC3 {
	  void cc3f();
	};

	class CC3	size(1):
		+---
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC3() {
		String expected =
		//@formatter:off
			"""
			/CC3
			pack(disabled)
			Structure CC3 {
			}
			Length: 1 Alignment: 1""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC3() {
		return convertCommentsToSpeculative(getExpectedStructCC3());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC3() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC3() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct D : C {
	  int d1;
	  void df();
	};

	class D	size(8):
		+---
	 0	| +--- (base class C)
	 0	| | c1
		| +---
	 4	| d1
		+---
	 */
	//@formatter:on
	private static String getExpectedStructD() {
		String expected =
		//@formatter:off
			"""
			/D
			pack()
			Structure D {
			   0   C   4      "Base"
			   4   int   4   d1   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructD() {
		return convertCommentsToSpeculative(getExpectedStructD());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryD() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsD() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct E {
	  int e1;
	  void ef();
	};

	class E	size(4):
		+---
	 0	| e1
		+---
	 */
	//@formatter:on
	private static String getExpectedStructE() {
		String expected =
		//@formatter:off
			"""
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructE() {
		return convertCommentsToSpeculative(getExpectedStructE());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryE() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsE() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct F : C, E {
	  int f1;
	  void ff();
	};

	class F	size(12):
		+---
	 0	| +--- (base class C)
	 0	| | c1
		| +---
	 4	| +--- (base class E)
	 4	| | e1
		| +---
	 8	| f1
		+---
	 */
	//@formatter:on
	private static String getExpectedStructF() {
		String expected =
		//@formatter:off
			"""
			/F
			pack()
			Structure F {
			   0   C   4      "Base"
			   4   E   4      "Base"
			   8   int   4   f1   ""
			}
			Length: 12 Alignment: 4
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructF() {
		return convertCommentsToSpeculative(getExpectedStructF());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryF() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsF() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct G : virtual C {
	  int g1;
	  void gf();
	};

	class G	size(20):
		+---
	 0	| {vbptr}
	 8	| g1
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	16	| c1
		+---

	G::$vbtable@:
	 0	| 0
	 1	| 16 (Gd(G+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructG() {
		String expected =
		//@formatter:off
			"""
			/G
			pack()
			Structure G {
			   0   G   16      "Self Base"
			   16   C   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructG() {
		String expected =
		//@formatter:off
			"""
			/G
			pack()
			Structure G {
			   0   G   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: C"
			}
			Length: 24 Alignment: 8
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructG() {
		return convertCommentsToSpeculative(getExpectedStructG());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryG() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[G]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsG() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructG_00000000());
		return results;
	}

	private static String getVxtStructG_00000000() {
		String expected =
		//@formatter:off
			"""
			/G/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct H : virtual C {
	  int h1;
	  void hf();
	};

	class H	size(20):
		+---
	 0	| {vbptr}
	 8	| h1
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	16	| c1
		+---

	H::$vbtable@:
	 0	| 0
	 1	| 16 (Hd(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructH() {
		String expected =
		//@formatter:off
			"""
			/H
			pack()
			Structure H {
			   0   H   16      "Self Base"
			   16   C   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructH() {
		String expected =
		//@formatter:off
			"""
			/H
			pack()
			Structure H {
			   0   H   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: C"
			}
			Length: 24 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructH() {
		return convertCommentsToSpeculative(getExpectedStructH());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryH() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[H]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsH() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructH_00000000());
		return results;
	}

	private static String getVxtStructH_00000000() {
		String expected =
		//@formatter:off
			"""
			/H/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct GG1 : virtual CC1 {
	  int gg11;
	  void gg1f();
	};

	class GG1	size(20):
		+---
	 0	| {vbptr}
	 8	| gg11
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC1)
	16	| cc11
		+---

	GG1::$vbtable@:
	 0	| 0
	 1	| 16 (GG1d(GG1+0)CC1)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC1      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructGG1() {
		String expected =
		//@formatter:off
			"""
			/GG1
			pack()
			Structure GG1 {
			   0   GG1   16      "Self Base"
			   16   CC1   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/CC1
			pack()
			Structure CC1 {
			   0   int   4   cc11   ""
			}
			Length: 4 Alignment: 4
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg11   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructGG1() {
		String expected =
		//@formatter:off
			"""
			/GG1
			pack()
			Structure GG1 {
			   0   GG1   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: CC1"
			}
			Length: 24 Alignment: 8
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg11   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructGG1() {
		return convertCommentsToSpeculative(getExpectedStructGG1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryGG1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[GG1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsGG1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructGG1_00000000());
		return results;
	}

	private static String getVxtStructGG1_00000000() {
		String expected =
		//@formatter:off
			"""
			/GG1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "CC1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct GG2 : virtual CC2 {
	  int gg21;
	  void gg2f();
	};

	class GG2	size(20):
		+---
	 0	| {vbptr}
	 8	| gg21
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC2)
	16	| cc21
		+---

	GG2::$vbtable@:
	 0	| 0
	 1	| 16 (GG2d(GG2+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC2      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructGG2() {
		String expected =
		//@formatter:off
			"""
			/GG2
			pack()
			Structure GG2 {
			   0   GG2   16      "Self Base"
			   16   CC2   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/CC2
			pack()
			Structure CC2 {
			   0   int   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg21   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructGG2() {
		String expected =
		//@formatter:off
			"""
			/GG2
			pack()
			Structure GG2 {
			   0   GG2   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: CC2"
			}
			Length: 24 Alignment: 8
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg21   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructGG2() {
		return convertCommentsToSpeculative(getExpectedStructGG2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryGG2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[GG2]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsGG2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructGG2_00000000());
		return results;
	}

	private static String getVxtStructGG2_00000000() {
		String expected =
		//@formatter:off
			"""
			/GG2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "CC2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct GG3 : virtual CC2 {
	  int gg31;
	  void gg3f();
	};

	class GG3	size(20):
		+---
	 0	| {vbptr}
	 8	| gg31
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC2)
	16	| cc21
		+---

	GG3::$vbtable@:
	 0	| 0
 	1	| 16 (GG3d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC2      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructGG3() {
		String expected =
		//@formatter:off
			"""
			/GG3
			pack()
			Structure GG3 {
			   0   GG3   16      "Self Base"
			   16   CC2   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/CC2
			pack()
			Structure CC2 {
			   0   int   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg31   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructGG3() {
		String expected =
		//@formatter:off
			"""
			/GG3
			pack()
			Structure GG3 {
			   0   GG3   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: CC2"
			}
			Length: 24 Alignment: 8
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg31   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructGG3() {
		return convertCommentsToSpeculative(getExpectedStructGG3());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryGG3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[GG3]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsGG3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructGG3_00000000());
		return results;
	}

	private static String getVxtStructGG3_00000000() {
		String expected =
		//@formatter:off
			"""
			/GG3/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "CC2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct GG4 : virtual CC3 {
	  int gg41;
	  void gg4f();
	};

	class GG4	size(16):
		+---
	 0	| {vbptr}
	 8	| gg41
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC3)
		+---

	GG4::$vbtable@:
	 0	| 0
	 1	| 16 (GG4d(GG4+0)CC3)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC3      16       0       4 0
	 */
	//@formatter:on
	// TODO: consider if we want to change the format on the output to provide information
	//  about zero-sized virtual structure components trailing at the end.  We currently let
	//  this information drop on the floor.  So in this case, our output does not show
	//  the fact that CC3 is a zero-sized virtual parent.
	private static String getExpectedStructGG4() {
		String expected =
		//@formatter:off
			"""
			/GG4
			pack()
			Structure GG4 {
			   0   GG4   16      "Self Base"
			}
			Length: 16 Alignment: 8
			/GG4/!internal/GG4
			pack()
			Structure GG4 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg41   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructGG4() {
		String expected =
		//@formatter:off
			"""
			/GG4
			pack()
			Structure GG4 {
			   0   GG4   16      "Self Base"
			   16   char[0]   0      "Filler for 1 Unplaceable Virtual Base: CC3"
			}
			Length: 16 Alignment: 8
			/GG4/!internal/GG4
			pack()
			Structure GG4 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg41   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructGG4() {
		return convertCommentsToSpeculative(getExpectedStructGG4());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryGG4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[GG4]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsGG4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructGG4_00000000());
		return results;
	}

	private static String getVxtStructGG4_00000000() {
		String expected =
		//@formatter:off
			"""
			/GG4/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "CC3"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct I : G, H {
	  int i1;
	  void _if();
	};

	class I	size(44):
		+---
	 0	| +--- (base class G)
	 0	| | {vbptr}
	 8	| | g1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class H)
	16	| | {vbptr}
	24	| | h1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	32	| i1
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	40	| c1
		+---

	I::$vbtable@G@:
	 0	| 0
 	1	| 40 (Id(G+0)C)

	I::$vbtable@H@:
	 0	| 0
	 1	| 24 (Id(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      40       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructI() {
		String expected =
		//@formatter:off
			"""
			/I
			pack()
			Structure I {
			   0   I   40      "Self Base"
			   40   C   4      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/I/!internal/I
			pack()
			Structure I {
			   0   G   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i1   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructI() {
		String expected =
		//@formatter:off
			"""
			/I
			pack()
			Structure I {
			   0   I   40      "Self Base"
			   40   char[8]   8      "Filler for 1 Unplaceable Virtual Base: C"
			}
			Length: 48 Alignment: 8
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/I/!internal/I
			pack()
			Structure I {
			   0   G   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i1   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructI() {
		return convertCommentsToSpeculative(getExpectedStructI());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryI() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [G]	[I, G]");
		results.put("VTABLE_00000010", "    16 vbt [H]	[I, H]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsI() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructI_00000000());
		results.put("VTABLE_00000010", getVxtStructI_00000010());
		return results;
	}

	private static String getVxtStructI_00000000() {
		String expected =
		//@formatter:off
			"""
			/I/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructI_00000010() {
		String expected =
		//@formatter:off
			"""
			/I/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct GX1 : virtual C { // No direct members
	  GX1();
	  void gx1f();
	};

	class GX1	size(12):
		+---
 	 0	| {vbptr}
		+---
		+--- (virtual base C)
 	 8	| c1
		+---

		GX1::$vbtable@:
 	 0	| 0
 	 1	| 8 (GX1d(GX1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C       8       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructGX1() {
		String expected =
		//@formatter:off
			"""
			/GX1
			pack()
			Structure GX1 {
			   0   GX1   8      "Self Base"
			   8   C   4      "Virtual Base"
			}
			Length: 16 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/GX1/!internal/GX1
			pack()
			Structure GX1 {
			   0   pointer   8   {vbptr}   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructGX1() {
		String expected =
		//@formatter:off
			"""
			/GX1
			pack()
			Structure GX1 {
			   0   GX1   8      "Self Base"
			   8   char[8]   8      "Filler for 1 Unplaceable Virtual Base: C"
			}
			Length: 16 Alignment: 8
			/GX1/!internal/GX1
			pack()
			Structure GX1 {
			   0   pointer   8   {vbptr}   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructGX1() {
		return convertCommentsToSpeculative(getExpectedStructGX1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryGX1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[GX1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsGX1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructGX1_00000000());
		return results;
	}

	private static String getVxtStructGX1_00000000() {
		String expected =
		//@formatter:off
			"""
			/GX1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct HX1 : virtual C { // No direct members
	 HX1();
	 void hx1f();
	};

	class HX1	size(12):
		+---
 	 0	| {vbptr}
		+---
		+--- (virtual base C)
 	 8	| c1
		+---

	HX1::$vbtable@:
 	 0	| 0
 	 1	| 8 (HX1d(HX1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C       8       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructHX1() {
		String expected =
		//@formatter:off
			"""
			/HX1
			pack()
			Structure HX1 {
			   0   HX1   8      "Self Base"
			   8   C   4      "Virtual Base"
			}
			Length: 16 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/HX1/!internal/HX1
			pack()
			Structure HX1 {
			   0   pointer   8   {vbptr}   ""
			}
			Length: 8 Alignment: 8
			""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructHX1() {
		String expected =
		//@formatter:off
			"""
			/HX1
			pack()
			Structure HX1 {
			   0   HX1   8      "Self Base"
			   8   char[8]   8      "Filler for 1 Unplaceable Virtual Base: C"
			}
			Length: 16 Alignment: 8
			/HX1/!internal/HX1
			pack()
			Structure HX1 {
			   0   pointer   8   {vbptr}   ""
			}
			Length: 8 Alignment: 8
			""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructHX1() {
		return convertCommentsToSpeculative(getExpectedStructHX1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryHX1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[HX1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsHX1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructHX1_00000000());
		return results;
	}

	private static String getVxtStructHX1_00000000() {
		String expected =
		//@formatter:off
			"""
			/HX1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct IX1 : GX1, HX1 {
	  int ix11;
	  IX1();
	  void _ix1f();
	};

	class IX1	size(28):
		+---
 	 0	| +--- (base class GX1)
 	 0	| | {vbptr}
  		| | <alignment member> (size=4)
		| +---
 	 8	| +--- (base class HX1)
 	 8	| | {vbptr}
  		| | <alignment member> (size=4)
		| +---
	16	| ix11
  		| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	24	| c1
		+---

	IX1::$vbtable@GX1@:
 	 0	| 0
 	 1	| 24 (IX1d(GX1+0)C)

	IX1::$vbtable@HX1@:
 	 0	| 0
 	 1	| 16 (IX1d(HX1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructIX1() {
		String expected =
		//@formatter:off
			"""
			/IX1
			pack()
			Structure IX1 {
			   0   IX1   24      "Self Base"
			   24   C   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/GX1/!internal/GX1
			pack()
			Structure GX1 {
			   0   pointer   8   {vbptr}   ""
			}
			Length: 8 Alignment: 8
			/HX1/!internal/HX1
			pack()
			Structure HX1 {
			   0   pointer   8   {vbptr}   ""
			}
			Length: 8 Alignment: 8
			/IX1/!internal/IX1
			pack()
			Structure IX1 {
			   0   GX1   8      "Base"
			   8   HX1   8      "Base"
			   16   int   4   ix11   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructIX1() {
		String expected =
		//@formatter:off
			"""
			/IX1
			pack()
			Structure IX1 {
			   0   IX1   24      "Self Base"
			   24   char[8]   8      "Filler for 1 Unplaceable Virtual Base: C"
			}
			Length: 32 Alignment: 8
			/GX1/!internal/GX1
			pack()
			Structure GX1 {
			   0   pointer   8   {vbptr}   ""
			}
			Length: 8 Alignment: 8
			/HX1/!internal/HX1
			pack()
			Structure HX1 {
			   0   pointer   8   {vbptr}   ""
			}
			Length: 8 Alignment: 8
			/IX1/!internal/IX1
			pack()
			Structure IX1 {
			   0   GX1   8      "Base"
			   8   HX1   8      "Base"
			   16   int   4   ix11   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructIX1() {
		return convertCommentsToSpeculative(getExpectedStructIX1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryIX1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [GX1]	[IX1, GX1]");
		results.put("VTABLE_00000008", "     8 vbt [HX1]	[IX1, HX1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsIX1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructIX1_00000000());
		results.put("VTABLE_00000008", getVxtStructIX1_00000008());
		return results;
	}

	private static String getVxtStructIX1_00000000() {
		String expected =
		//@formatter:off
			"""
			/IX1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructIX1_00000008() {
		String expected =
		//@formatter:off
			"""
			/IX1/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct G1 : virtual C, virtual E {
	  int g11;
	  void g1f();
	};

	class G1	size(24):
		+---
	 0	| {vbptr}
	 8	| g11
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	16	| c1
		+---
		+--- (virtual base E)
	20	| e1
		+---

	G1::$vbtable@:
	 0	| 0
	 1	| 16 (G1d(G1+0)C)
	 2	| 20 (G1d(G1+0)E)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      16       0       4 0
	               E      20       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructG1() {
		String expected =
		//@formatter:off
			"""
			/G1
			pack()
			Structure G1 {
			   0   G1   16      "Self Base"
			   16   C   4      "Virtual Base"
			   20   E   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructG1() {
		String expected =
		//@formatter:off
			"""
			/G1
			pack()
			Structure G1 {
			   0   G1   16      "Self Base"
			   16   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: C; E"
			}
			Length: 24 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructG1() {
		return convertCommentsToSpeculative(getExpectedStructG1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryG1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[G1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsG1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructG1_00000000());
		return results;
	}

	private static String getVxtStructG1_00000000() {
		String expected =
		//@formatter:off
			"""
			/G1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct H1 : virtual E, virtual C { //order reversed from G1
	  int h11;
	  void h1f();
	};

	class H1	size(24):
		+---
	 0	| {vbptr}
	 8	| h11
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base E)
	16	| e1
		+---
		+--- (virtual base C)
	20	| c1
		+---

	H1::$vbtable@:
	 0	| 0
	 1	| 16 (H1d(H1+0)E)
	 2	| 20 (H1d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               E      16       0       4 0
	               C      20       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructH1() {
		String expected =
		//@formatter:off
			"""
			/H1
			pack()
			Structure H1 {
			   0   H1   16      "Self Base"
			   16   E   4      "Virtual Base"
			   20   C   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructH1() {
		String expected =
		//@formatter:off
			"""
			/H1
			pack()
			Structure H1 {
			   0   H1   16      "Self Base"
			   16   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: E; C"
			}
			Length: 24 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructH1() {
		return convertCommentsToSpeculative(getExpectedStructH1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryH1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[H1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsH1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructH1_00000000());
		return results;
	}

	private static String getVxtStructH1_00000000() {
		String expected =
		//@formatter:off
			"""
			/H1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "E"
			   4   int   4      "C"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct I1 : G1, H {
	  int i11;
	  void _i1f();
	};

	class I1	size(48):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 8	| | g11
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class H)
	16	| | {vbptr}
	24	| | h1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	32	| i11
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	40	| c1
		+---
		+--- (virtual base E)
	44	| e1
		+---

	I1::$vbtable@G1@:
	 0	| 0
	 1	| 40 (I1d(G1+0)C)
	 2	| 44 (I1d(G1+0)E)

	I1::$vbtable@H@:
	 0	| 0
	 1	| 24 (I1d(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      40       0       4 0
	               E      44       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructI1() {
		String expected =
		//@formatter:off
			"""
			/I1
			pack()
			Structure I1 {
			   0   I1   40      "Self Base"
			   40   C   4      "Virtual Base"
			   44   E   4      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i11   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructI1() {
		String expected =
		//@formatter:off
			"""
			/I1
			pack()
			Structure I1 {
			   0   I1   40      "Self Base"
			   40   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: C; E"
			}
			Length: 48 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i11   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructI1() {
		return convertCommentsToSpeculative(getExpectedStructI1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryI1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [G1]	[I1, G1]");
		results.put("VTABLE_00000010", "    16 vbt [H]	[I1, H]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsI1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructI1_00000000());
		results.put("VTABLE_00000010", getVxtStructI1_00000010());
		return results;
	}

	private static String getVxtStructI1_00000000() {
		String expected =
		//@formatter:off
			"""
			/I1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructI1_00000010() {
		String expected =
		//@formatter:off
			"""
			/I1/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct I2 : G, H1 {
	  int i21;
	  void _i2f();
	};

	class I2	size(48):
		+---
	 0	| +--- (base class G)
	 0	| | {vbptr}
	 8	| | g1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class H1)
	16	| | {vbptr}
	24	| | h11
	  	| | <alignment member> (size=4)
		| +---
	32	| i21
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	40	| c1
		+---
		+--- (virtual base E)
	44	| e1
		+---

	I2::$vbtable@G@:
	 0	| 0
	 1	| 40 (I2d(G+0)C)
	 2	| 44 (I2d(I2+0)E)

	I2::$vbtable@H1@:
	 0	| 0
	 1	| 28 (I2d(H1+0)E)
	 2	| 24 (I2d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      40       0       4 0
	               E      44       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructI2() {
		String expected =
		//@formatter:off
			"""
			/I2
			pack()
			Structure I2 {
			   0   I2   40      "Self Base"
			   40   C   4      "Virtual Base"
			   44   E   4      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i21   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructI2() {
		String expected =
		//@formatter:off
			"""
			/I2
			pack()
			Structure I2 {
			   0   I2   40      "Self Base"
			   40   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: C; E"
			}
			Length: 48 Alignment: 8
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i21   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructI2() {
		return convertCommentsToSpeculative(getExpectedStructI2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryI2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [G]	[I2, G]");
		results.put("VTABLE_00000010", "    16 vbt [H1]	[I2, H1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsI2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructI2_00000000());
		results.put("VTABLE_00000010", getVxtStructI2_00000010());
		return results;
	}

	private static String getVxtStructI2_00000000() {
		String expected =
		//@formatter:off
			"""
			/I2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructI2_00000010() {
		String expected =
		//@formatter:off
			"""
			/I2/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "E"
			   4   int   4      "C"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct I3 : G1, H1 {
	  int i31;
	  void _i3f();
	};

	class I3	size(48):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 8	| | g11
	  	| | <alignment member> (size=4)
		| +---
	16	| +--- (base class H1)
	16	| | {vbptr}
	24	| | h11
	  	| | <alignment member> (size=4)
		| +---
	32	| i31
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	40	| c1
		+---
		+--- (virtual base E)
	44	| e1
		+---

	I3::$vbtable@G1@:
	 0	| 0
	 1	| 40 (I3d(G1+0)C)
	 2	| 44 (I3d(G1+0)E)

	I3::$vbtable@H1@:
	 0	| 0
	 1	| 28 (I3d(H1+0)E)
	 2	| 24 (I3d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      40       0       4 0
	               E      44       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructI3() {
		String expected =
		//@formatter:off
			"""
			/I3
			pack()
			Structure I3 {
			   0   I3   40      "Self Base"
			   40   C   4      "Virtual Base"
			   44   E   4      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i31   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructI3() {
		String expected =
		//@formatter:off
			"""
			/I3
			pack()
			Structure I3 {
			   0   I3   40      "Self Base"
			   40   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: C; E"
			}
			Length: 48 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i31   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructI3() {
		return convertCommentsToSpeculative(getExpectedStructI3());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryI3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [G1]	[I3, G1]");
		results.put("VTABLE_00000010", "    16 vbt [H1]	[I3, H1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsI3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructI3_00000000());
		results.put("VTABLE_00000010", getVxtStructI3_00000010());
		return results;
	}

	private static String getVxtStructI3_00000000() {
		String expected =
		//@formatter:off
			"""
			/I3/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructI3_00000010() {
		String expected =
		//@formatter:off
			"""
			/I3/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "E"
			   4   int   4      "C"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct I4 : G1, virtual E, virtual C {
	  int i41;
	  void _i4f();
	};

	class I4	size(32):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 8	| | g11
	  	| | <alignment member> (size=4)
		| +---
	16	| i41
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	24	| c1
		+---
		+--- (virtual base E)
	28	| e1
		+---

	I4::$vbtable@:
	 0	| 0
	 1	| 24 (I4d(G1+0)C)
	 2	| 28 (I4d(G1+0)E)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      24       0       4 0
	               E      28       0       8 0	 */
	//@formatter:on
	private static String getExpectedStructI4() {
		String expected =
		//@formatter:off
			"""
			/I4
			pack()
			Structure I4 {
			   0   I4   24      "Self Base"
			   24   C   4      "Virtual Base"
			   28   E   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/I4/!internal/I4
			pack()
			Structure I4 {
			   0   G1   16      "Base"
			   16   int   4   i41   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructI4() {
		String expected =
		//@formatter:off
			"""
			/I4
			pack()
			Structure I4 {
			   0   I4   24      "Self Base"
			   24   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: E; C"
			}
			Length: 32 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/I4/!internal/I4
			pack()
			Structure I4 {
			   0   G1   16      "Base"
			   16   int   4   i41   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructI4() {
		return convertCommentsToSpeculative(getExpectedStructI4());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryI4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[I4, G1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsI4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructI4_00000000());
		return results;
	}

	private static String getVxtStructI4_00000000() {
		String expected =
		//@formatter:off
			"""
			/I4/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct I5 : virtual E, virtual C, G1 {
	  int i51;
	  void _i5f();
	};

	class I5	size(32):
		+---
	 0	| +--- (base class G1)
	 0	| | {vbptr}
	 8	| | g11
	  	| | <alignment member> (size=4)
		| +---
	16	| i51
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base E)
	24	| e1
		+---
		+--- (virtual base C)
	28	| c1
		+---

	I5::$vbtable@:
	 0	| 0
	 1	| 28 (I5d(G1+0)C)
	 2	| 24 (I5d(G1+0)E)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               E      24       0       8 0
	               C      28       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructI5() {
		String expected =
		//@formatter:off
			"""
			/I5
			pack()
			Structure I5 {
			   0   I5   24      "Self Base"
			   24   E   4      "Virtual Base"
			   28   C   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/I5/!internal/I5
			pack()
			Structure I5 {
			   0   G1   16      "Base"
			   16   int   4   i51   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructI5() {
		String expected =
		//@formatter:off
			"""
			/I5
			pack()
			Structure I5 {
			   0   I5   24      "Self Base"
			   24   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: E; C"
			}
			Length: 32 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/I5/!internal/I5
			pack()
			Structure I5 {
			   0   G1   16      "Base"
			   16   int   4   i51   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	/**
	 * Test struct I5 - 64 - speculative placement.
	 * <p> THIS TEST STILL HAS PROBLEMS...
	 * <p> The expected output does not match what is the correct layout, but we do not have enough
	 * information (without using vbtable) to create the correct output.  So we are testing our
	 * incorrect result against the known incorrect expected result to cause the test to pass
	 */
	// NOTE: We know that this is an incorrect layout (it matches that of I4), but we are
	//  measuring our result against the best we can determine (C and E virtual bases are
	//  switched from the actual as the Base Class records in the PDB are given in the exact
	//  same order as for I4.  Using the VBT-based algorithm can produce the correct layout, but
	//  the speculative algorithm works without it.
	private static String getSpeculatedStructI5() {
		String expected =
		//@formatter:off
			"""
			/I5
			pack()
			Structure I5 {
			   0   I5   24      "Self Base"
			   24   C   4      \"Virtual Base - Speculative Placement\"
			   28   E   4      \"Virtual Base - Speculative Placement\"
			}
			Length: 32 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/I5/!internal/I5
			pack()
			Structure I5 {
			   0   G1   16      "Base"
			   16   int   4   i51   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static Map<String, String> getExpectedVxtPtrSummaryI5() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[I5, G1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsI5() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructI5_00000000());
		return results;
	}

	private static String getVxtStructI5_00000000() {
		String expected =
		//@formatter:off
			"""
			/I5/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct J1 : I1, I2 {
	  int j11;
	  void j1f();
	};

	class J1	size(96):
		+---
	 0	| +--- (base class I1)
	 0	| | +--- (base class G1)
	 0	| | | {vbptr}
	 8	| | | g11
	  	| | | <alignment member> (size=4)
		| | +---
	16	| | +--- (base class H)
	16	| | | {vbptr}
	24	| | | h1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	32	| | i11
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class I2)
	40	| | +--- (base class G)
	40	| | | {vbptr}
	48	| | | g1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	56	| | +--- (base class H1)
	56	| | | {vbptr}
	64	| | | h11
	  	| | | <alignment member> (size=4)
		| | +---
	72	| | i21
	  	| | <alignment member> (size=4)
		| +---
	80	| j11
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	88	| c1
		+---
		+--- (virtual base E)
	92	| e1
		+---

	J1::$vbtable@G1@:
	 0	| 0
	 1	| 88 (J1d(G1+0)C)
	 2	| 92 (J1d(G1+0)E)

	J1::$vbtable@H@:
	 0	| 0
	 1	| 72 (J1d(H+0)C)

	J1::$vbtable@G@:
	 0	| 0
	 1	| 48 (J1d(G+0)C)
	 2	| 52 (J1d(I2+0)E)

	J1::$vbtable@H1@:
	 0	| 0
	 1	| 36 (J1d(H1+0)E)
	 2	| 32 (J1d(H1+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      88       0       4 0
	               E      92       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructJ1() {
		String expected =
		//@formatter:off
			"""
			/J1
			pack()
			Structure J1 {
			   0   J1   88      "Self Base"
			   88   C   4      "Virtual Base"
			   92   E   4      "Virtual Base"
			}
			Length: 96 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i11   ""
			}
			Length: 40 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i21   ""
			}
			Length: 40 Alignment: 8
			/J1/!internal/J1
			pack()
			Structure J1 {
			   0   I1   40      "Base"
			   40   I2   40      "Base"
			   80   int   4   j11   ""
			}
			Length: 88 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructJ1() {
		String expected =
		//@formatter:off
			"""
			/J1
			pack()
			Structure J1 {
			   0   J1   88      "Self Base"
			   88   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: C; E"
			}
			Length: 96 Alignment: 8
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i11   ""
			}
			Length: 40 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i21   ""
			}
			Length: 40 Alignment: 8
			/J1/!internal/J1
			pack()
			Structure J1 {
			   0   I1   40      "Base"
			   40   I2   40      "Base"
			   80   int   4   j11   ""
			}
			Length: 88 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructJ1() {
		return convertCommentsToSpeculative(getExpectedStructJ1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryJ1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [G1]	[J1, I1, G1]");
		results.put("VTABLE_00000010", "    16 vbt [H]	[J1, I1, H]");
		results.put("VTABLE_00000028", "    40 vbt [G]	[J1, I2, G]");
		results.put("VTABLE_00000038", "    56 vbt [H1]	[J1, I2, H1]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsJ1() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructJ1_00000000());
		results.put("VTABLE_00000010", getVxtStructJ1_00000010());
		results.put("VTABLE_00000028", getVxtStructJ1_00000028());
		results.put("VTABLE_00000038", getVxtStructJ1_00000038());
		return results;
	}

	private static String getVxtStructJ1_00000000() {
		String expected =
		//@formatter:off
			"""
			/J1/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ1_00000010() {
		String expected =
		//@formatter:off
			"""
			/J1/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ1_00000028() {
		String expected =
		//@formatter:off
			"""
			/J1/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ1_00000038() {
		String expected =
		//@formatter:off
			"""
			/J1/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   int   4      "E"
			   4   int   4      "C"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct J2 : I2, I1 {
	  int j21;
	  void j2f();
	};

	class J2	size(96):
		+---
	 0	| +--- (base class I2)
	 0	| | +--- (base class G)
	 0	| | | {vbptr}
	 8	| | | g1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	16	| | +--- (base class H1)
	16	| | | {vbptr}
	24	| | | h11
	  	| | | <alignment member> (size=4)
		| | +---
	32	| | i21
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class I1)
	40	| | +--- (base class G1)
	40	| | | {vbptr}
	48	| | | g11
	  	| | | <alignment member> (size=4)
		| | +---
	56	| | +--- (base class H)
	56	| | | {vbptr}
	64	| | | h1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	72	| | i11
	  	| | <alignment member> (size=4)
		| +---
	80	| j21
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	88	| c1
		+---
		+--- (virtual base E)
	92	| e1
		+---

	J2::$vbtable@G@:
	 0	| 0
	 1	| 88 (J2d(G+0)C)
	 2	| 92 (J2d(I2+0)E)

	J2::$vbtable@H1@:
	 0	| 0
	 1	| 76 (J2d(H1+0)E)
	 2	| 72 (J2d(H1+0)C)

	J2::$vbtable@G1@:
	 0	| 0
	 1	| 48 (J2d(G1+0)C)
	 2	| 52 (J2d(G1+0)E)

	J2::$vbtable@H@:
	 0	| 0
 	1	| 32 (J2d(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      88       0       4 0
	               E      92       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructJ2() {
		String expected =
		//@formatter:off
			"""
			/J2
			pack()
			Structure J2 {
			   0   J2   88      "Self Base"
			   88   C   4      "Virtual Base"
			   92   E   4      "Virtual Base"
			}
			Length: 96 Alignment: 8
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i11   ""
			}
			Length: 40 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i21   ""
			}
			Length: 40 Alignment: 8
			/J2/!internal/J2
			pack()
			Structure J2 {
			   0   I2   40      "Base"
			   40   I1   40      "Base"
			   80   int   4   j21   ""
			}
			Length: 88 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructJ2() {
		String expected =
		//@formatter:off
			"""
			/J2
			pack()
			Structure J2 {
			   0   J2   88      "Self Base"
			   88   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: C; E"
			}
			Length: 96 Alignment: 8
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i11   ""
			}
			Length: 40 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i21   ""
			}
			Length: 40 Alignment: 8
			/J2/!internal/J2
			pack()
			Structure J2 {
			   0   I2   40      "Base"
			   40   I1   40      "Base"
			   80   int   4   j21   ""
			}
			Length: 88 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructJ2() {
		return convertCommentsToSpeculative(getExpectedStructJ2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryJ2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [G]	[J2, I2, G]");
		results.put("VTABLE_00000010", "    16 vbt [H1]	[J2, I2, H1]");
		results.put("VTABLE_00000028", "    40 vbt [G1]	[J2, I1, G1]");
		results.put("VTABLE_00000038", "    56 vbt [H]	[J2, I1, H]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsJ2() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructJ2_00000000());
		results.put("VTABLE_00000010", getVxtStructJ2_00000010());
		results.put("VTABLE_00000028", getVxtStructJ2_00000028());
		results.put("VTABLE_00000038", getVxtStructJ2_00000038());
		return results;
	}

	private static String getVxtStructJ2_00000000() {
		String expected =
		//@formatter:off
			"""
			/J2/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ2_00000010() {
		String expected =
		//@formatter:off
			"""
			/J2/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "E"
			   4   int   4      "C"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ2_00000028() {
		String expected =
		//@formatter:off
			"""
			/J2/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ2_00000038() {
		String expected =
		//@formatter:off
			"""
			/J2/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct J3 : I2, I1, A {
	  int j31;
	  void j3f();
	};

	class J3	size(104):
		+---
	 0	| +--- (base class I2)
	 0	| | +--- (base class G)
	 0	| | | {vbptr}
	 8	| | | g1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	16	| | +--- (base class H1)
	16	| | | {vbptr}
	24	| | | h11
	  	| | | <alignment member> (size=4)
		| | +---
	32	| | i21
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class I1)
	40	| | +--- (base class G1)
	40	| | | {vbptr}
	48	| | | g11
	  	| | | <alignment member> (size=4)
		| | +---
	56	| | +--- (base class H)
	56	| | | {vbptr}
	64	| | | h1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	72	| | i11
	  	| | <alignment member> (size=4)
		| +---
	80	| +--- (base class A)
	80	| | c
	  	| | <alignment member> (size=3)
	84	| | i
		| +---
	88	| j31
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	96	| c1
		+---
		+--- (virtual base E)
	100	| e1
		+---

	J3::$vbtable@G@:
	 0	| 0
	 1	| 96 (J3d(G+0)C)
	 2	| 100 (J3d(I2+0)E)

	J3::$vbtable@H1@:
	 0	| 0
	 1	| 84 (J3d(H1+0)E)
	 2	| 80 (J3d(H1+0)C)

	J3::$vbtable@G1@:
	 0	| 0
	 1	| 56 (J3d(G1+0)C)
	 2	| 60 (J3d(G1+0)E)

	J3::$vbtable@H@:
	 0	| 0
	 1	| 40 (J3d(H+0)C)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C      96       0       4 0
	               E     100       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructJ3() {
		String expected =
		//@formatter:off
			"""
			/J3
			pack()
			Structure J3 {
			   0   J3   96      "Self Base"
			   96   C   4      "Virtual Base"
			   100   E   4      "Virtual Base"
			}
			Length: 104 Alignment: 8
			/A
			pack()
			Structure A {
			   0   char   1   c   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i11   ""
			}
			Length: 40 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i21   ""
			}
			Length: 40 Alignment: 8
			/J3/!internal/J3
			pack()
			Structure J3 {
			   0   I2   40      "Base"
			   40   I1   40      "Base"
			   80   A   8      "Base"
			   88   int   4   j31   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructJ3() {
		String expected =
		//@formatter:off
			"""
			/J3
			pack()
			Structure J3 {
			   0   J3   96      "Self Base"
			   96   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: C; E"
			}
			Length: 104 Alignment: 8
			/A
			pack()
			Structure A {
			   0   char   1   c   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I1/!internal/I1
			pack()
			Structure I1 {
			   0   G1   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i11   ""
			}
			Length: 40 Alignment: 8
			/I2/!internal/I2
			pack()
			Structure I2 {
			   0   G   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i21   ""
			}
			Length: 40 Alignment: 8
			/J3/!internal/J3
			pack()
			Structure J3 {
			   0   I2   40      "Base"
			   40   I1   40      "Base"
			   80   A   8      "Base"
			   88   int   4   j31   ""
			}
			Length: 96 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructJ3() {
		return convertCommentsToSpeculative(getExpectedStructJ3());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryJ3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [G]	[J3, I2, G]");
		results.put("VTABLE_00000010", "    16 vbt [H1]	[J3, I2, H1]");
		results.put("VTABLE_00000028", "    40 vbt [G1]	[J3, I1, G1]");
		results.put("VTABLE_00000038", "    56 vbt [H]	[J3, I1, H]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsJ3() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructJ3_00000000());
		results.put("VTABLE_00000010", getVxtStructJ3_00000010());
		results.put("VTABLE_00000028", getVxtStructJ3_00000028());
		results.put("VTABLE_00000038", getVxtStructJ3_00000038());
		return results;
	}

	private static String getVxtStructJ3_00000000() {
		String expected =
		//@formatter:off
			"""
			/J3/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ3_00000010() {
		String expected =
		//@formatter:off
			"""
			/J3/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "E"
			   4   int   4      "C"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ3_00000028() {
		String expected =
		//@formatter:off
			"""
			/J3/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "C"
			   4   int   4      "E"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ3_00000038() {
		String expected =
		//@formatter:off
			"""
			/J3/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct J4 : I3, GG1, I, A, virtual GG2, virtual GG3 {
	  int j41;
	  void j4f();
	};

	class J4	size(160):
		+---
	 0	| +--- (base class I3)
	 0	| | +--- (base class G1)
	 0	| | | {vbptr}
	 8	| | | g11
	  	| | | <alignment member> (size=4)
		| | +---
	16	| | +--- (base class H1)
	16	| | | {vbptr}
	24	| | | h11
	  	| | | <alignment member> (size=4)
		| | +---
	32	| | i31
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class GG1)
	40	| | {vbptr}
	48	| | gg11
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	56	| +--- (base class I)
	56	| | +--- (base class G)
	56	| | | {vbptr}
	64	| | | g1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	72	| | +--- (base class H)
	72	| | | {vbptr}
	80	| | | h1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	88	| | i1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	96	| +--- (base class A)
	96	| | c
	  	| | <alignment member> (size=3)
	100	| | i
		| +---
	104	| j41
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	112	| c1
		+---
		+--- (virtual base E)
	116	| e1
		+---
		+--- (virtual base CC1)
	120	| cc11
		+---
		+--- (virtual base CC2)
	124	| cc21
		+---
		+--- (virtual base GG2)
	128	| {vbptr}
	136	| gg21
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base GG3)
	144	| {vbptr}
	152	| gg31
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---

	J4::$vbtable@G1@:
	 0	| 0
	 1	| 112 (J4d(G1+0)C)
	 2	| 116 (J4d(G1+0)E)
	 3	| 120 (J4d(J4+0)CC1)
	 4	| 124 (J4d(J4+0)CC2)
	 5	| 128 (J4d(J4+0)GG2)
	 6	| 144 (J4d(J4+0)GG3)

	J4::$vbtable@H1@:
	 0	| 0
	 1	| 100 (J4d(H1+0)E)
	 2	| 96 (J4d(H1+0)C)

	J4::$vbtable@GG1@:
	 0	| 0
	 1	| 80 (J4d(GG1+0)CC1)

	J4::$vbtable@G@:
	 0	| 0
	 1	| 56 (J4d(G+0)C)

	J4::$vbtable@H@:
	 0	| 0
	 1	| 40 (J4d(H+0)C)

	J4::$vbtable@GG2@:
	 0	| 0
	 1	| -4 (J4d(GG2+0)CC2)

	J4::$vbtable@GG3@:
	 0	| 0
	 1	| -20 (J4d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               C     112       0       4 0
	               E     116       0       8 0
	             CC1     120       0      12 0
	             CC2     124       0      16 0
	             GG2     128       0      20 0
	             GG3     144       0      24 0
	 */
	//@formatter:on
	private static String getExpectedStructJ4() {
		String expected =
		//@formatter:off
			"""
			/J4
			pack()
			Structure J4 {
			   0   J4   112      "Self Base"
			   112   C   4      "Virtual Base"
			   116   E   4      "Virtual Base"
			   120   CC1   4      "Virtual Base"
			   124   CC2   4      "Virtual Base"
			   128   GG2   16      "Virtual Base"
			   144   GG3   16      "Virtual Base"
			}
			Length: 160 Alignment: 8
			/A
			pack()
			Structure A {
			   0   char   1   c   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/CC1
			pack()
			Structure CC1 {
			   0   int   4   cc11   ""
			}
			Length: 4 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   int   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg11   ""
			}
			Length: 16 Alignment: 8
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg21   ""
			}
			Length: 16 Alignment: 8
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg31   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I/!internal/I
			pack()
			Structure I {
			   0   G   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i1   ""
			}
			Length: 40 Alignment: 8
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i31   ""
			}
			Length: 40 Alignment: 8
			/J4/!internal/J4
			pack()
			Structure J4 {
			   0   I3   40      "Base"
			   40   GG1   16      "Base"
			   56   I   40      "Base"
			   96   A   8      "Base"
			   104   int   4   j41   ""
			}
			Length: 112 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructJ4() {
		String expected =
		//@formatter:off
			"""
			/J4
			pack()
			Structure J4 {
			   0   J4   112      "Self Base"
			   112   char[48]   48      "Filler for 6 Unplaceable Virtual Bases: GG2; GG3; C; E; CC1; CC2"
			}
			Length: 160 Alignment: 8
			/A
			pack()
			Structure A {
			   0   char   1   c   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg11   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I/!internal/I
			pack()
			Structure I {
			   0   G   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i1   ""
			}
			Length: 40 Alignment: 8
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i31   ""
			}
			Length: 40 Alignment: 8
			/J4/!internal/J4
			pack()
			Structure J4 {
			   0   I3   40      "Base"
			   40   GG1   16      "Base"
			   56   I   40      "Base"
			   96   A   8      "Base"
			   104   int   4   j41   ""
			}
			Length: 112 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructJ4() {
		return convertCommentsToSpeculative(getExpectedStructJ4());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryJ4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [G1]	[J4, I3, G1]");
		results.put("VTABLE_00000010", "    16 vbt [H1]	[J4, I3, H1]");
		results.put("VTABLE_00000028", "    40 vbt [GG1]	[J4, GG1]");
		results.put("VTABLE_00000038", "    56 vbt [G]	[J4, I, G]");
		results.put("VTABLE_00000048", "    72 vbt [H]	[J4, I, H]");
		results.put("VTABLE_00000080", "   128 vbt [GG2]	[J4, GG2]");
		results.put("VTABLE_00000090", "   144 vbt [GG3]	[J4, GG3]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsJ4() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructJ4_00000000());
		results.put("VTABLE_00000010", getVxtStructJ4_00000010());
		results.put("VTABLE_00000028", getVxtStructJ4_00000028());
		results.put("VTABLE_00000038", getVxtStructJ4_00000038());
		results.put("VTABLE_00000048", getVxtStructJ4_00000048());
		results.put("VTABLE_00000080", getVxtStructJ4_00000080());
		results.put("VTABLE_00000090", getVxtStructJ4_00000090());
		return results;
	}

	private static String getVxtStructJ4_00000000() {
		String expected =
		//@formatter:off
			"""
			/J4/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			   8   int   4      "CC1"
			   12   int   4      "CC2"
			   16   int   4      "GG2"
			   20   int   4      "GG3"
			}
			Length: 24 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ4_00000010() {
		String expected =
		//@formatter:off
			"""
			/J4/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "E"
			   4   int   4      "C"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ4_00000028() {
		String expected =
		//@formatter:off
			"""
			/J4/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "CC1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ4_00000038() {
		String expected =
		//@formatter:off
			"""
			/J4/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ4_00000048() {
		String expected =
		//@formatter:off
			"""
			/J4/!internal/VTABLE_00000048
			pack()
			Structure VTABLE_00000048 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ4_00000080() {
		String expected =
		//@formatter:off
			"""
			/J4/!internal/VTABLE_00000080
			pack()
			Structure VTABLE_00000080 {
			   0   int   4      "CC2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ4_00000090() {
		String expected =
		//@formatter:off
			"""
			/J4/!internal/VTABLE_00000090
			pack()
			Structure VTABLE_00000090 {
			   0   int   4      "CC2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct J5 : virtual GG2, virtual GG3, I3, GG1, I, A {
	  int j51;
	  void j5f();
	};

	class J5	size(164):
		+---
	 0	| +--- (base class I3)
	 0	| | +--- (base class G1)
	 0	| | | {vbptr}
	 8	| | | g11
	  	| | | <alignment member> (size=4)
		| | +---
	16	| | +--- (base class H1)
	16	| | | {vbptr}
	24	| | | h11
	  	| | | <alignment member> (size=4)
		| | +---
	32	| | i31
	  	| | <alignment member> (size=4)
		| +---
	40	| +--- (base class GG1)
	40	| | {vbptr}
	48	| | gg11
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	56	| +--- (base class I)
	56	| | +--- (base class G)
	56	| | | {vbptr}
	64	| | | g1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	72	| | +--- (base class H)
	72	| | | {vbptr}
	80	| | | h1
	  	| | | <alignment member> (size=4)
	  	| | | <alignment member> (size=4)
		| | +---
	88	| | i1
	  	| | <alignment member> (size=4)
	  	| | <alignment member> (size=4)
		| +---
	96	| +--- (base class A)
	96	| | c
	  	| | <alignment member> (size=3)
	100	| | i
		| +---
	104	| j51
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC2)
	112	| cc21
		+---
		+--- (virtual base GG2)
	120	| {vbptr}
	128	| gg21
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base GG3)
	136	| {vbptr}
	144	| gg31
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base C)
	152	| c1
		+---
		+--- (virtual base E)
	156	| e1
		+---
		+--- (virtual base CC1)
	160	| cc11
		+---

	J5::$vbtable@G1@:
	 0	| 0
	 1	| 152 (J5d(G1+0)C)
	 2	| 156 (J5d(G1+0)E)
	 3	| 112 (J5d(J5+0)CC2)
	 4	| 120 (J5d(J5+0)GG2)
	 5	| 136 (J5d(J5+0)GG3)
	 6	| 160 (J5d(J5+0)CC1)

	J5::$vbtable@H1@:
	 0	| 0
	 1	| 140 (J5d(H1+0)E)
	 2	| 136 (J5d(H1+0)C)

	J5::$vbtable@GG1@:
	 0	| 0
	 1	| 120 (J5d(GG1+0)CC1)

	J5::$vbtable@G@:
	 0	| 0
	 1	| 96 (J5d(G+0)C)

	J5::$vbtable@H@:
	 0	| 0
	 1	| 80 (J5d(H+0)C)

	J5::$vbtable@GG2@:
	 0	| 0
	 1	| -8 (J5d(GG2+0)CC2)

	J5::$vbtable@GG3@:
	 0	| 0
	 1	| -24 (J5d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC2     112       0      12 0
	             GG2     120       0      16 0
	             GG3     136       0      20 0
	               C     152       0       4 0
	               E     156       0       8 0
	             CC1     160       0      24 0
	 */
	//@formatter:on
	private static String getExpectedStructJ5() {
		String expected =
		//@formatter:off
			"""
			/J5
			pack()
			Structure J5 {
			   0   J5   112      "Self Base"
			   112   CC2   4      "Virtual Base"
			   120   GG2   16      "Virtual Base"
			   136   GG3   16      "Virtual Base"
			   152   C   4      "Virtual Base"
			   156   E   4      "Virtual Base"
			   160   CC1   4      "Virtual Base"
			}
			Length: 168 Alignment: 8
			/A
			pack()
			Structure A {
			   0   char   1   c   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/CC1
			pack()
			Structure CC1 {
			   0   int   4   cc11   ""
			}
			Length: 4 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   int   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg11   ""
			}
			Length: 16 Alignment: 8
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg21   ""
			}
			Length: 16 Alignment: 8
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg31   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I/!internal/I
			pack()
			Structure I {
			   0   G   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i1   ""
			}
			Length: 40 Alignment: 8
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i31   ""
			}
			Length: 40 Alignment: 8
			/J5/!internal/J5
			pack()
			Structure J5 {
			   0   I3   40      "Base"
			   40   GG1   16      "Base"
			   56   I   40      "Base"
			   96   A   8      "Base"
			   104   int   4   j51   ""
			}
			Length: 112 Alignment: 8""";

		//@formatter:on
		return expected;
	}

	// TODO: Need to work on layout algorithm... believe we can do better, but don't have
	//  a decision on the best speculative results yet.
	private static String getSpeculatedStructJ5() {
		String expected =
		//@formatter:off
			"""
			/J5
			aligned(8) pack(disabled)
			Structure J5 {
			   0   J5   112      "Self Base"
			   112   C   4      "Virtual Base - Speculative Placement"
			   116   E   4      "Virtual Base - Speculative Placement"
			   120   CC1   4      "Virtual Base - Speculative Placement"
			   124   CC2   4      "Virtual Base - Speculative Placement"
			   128   GG2   16      "Virtual Base - Speculative Placement"
			   144   GG3   16      "Virtual Base - Speculative Placement"
			}
			Length: 168 Alignment: 8
			/A
			pack()
			Structure A {
			   0   char   1   c   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4
			/C
			pack()
			Structure C {
			   0   int   4   c1   ""
			}
			Length: 4 Alignment: 4
			/CC1
			pack()
			Structure CC1 {
			   0   int   4   cc11   ""
			}
			Length: 4 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   int   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/E
			pack()
			Structure E {
			   0   int   4   e1   ""
			}
			Length: 4 Alignment: 4
			/G/!internal/G
			pack()
			Structure G {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g1   ""
			}
			Length: 16 Alignment: 8
			/G1/!internal/G1
			pack()
			Structure G1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   g11   ""
			}
			Length: 16 Alignment: 8
			/GG1/!internal/GG1
			pack()
			Structure GG1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg11   ""
			}
			Length: 16 Alignment: 8
			/GG2/!internal/GG2
			pack()
			Structure GG2 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg21   ""
			}
			Length: 16 Alignment: 8
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg31   ""
			}
			Length: 16 Alignment: 8
			/H/!internal/H
			pack()
			Structure H {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h1   ""
			}
			Length: 16 Alignment: 8
			/H1/!internal/H1
			pack()
			Structure H1 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   h11   ""
			}
			Length: 16 Alignment: 8
			/I/!internal/I
			pack()
			Structure I {
			   0   G   16      "Base"
			   16   H   16      "Base"
			   32   int   4   i1   ""
			}
			Length: 40 Alignment: 8
			/I3/!internal/I3
			pack()
			Structure I3 {
			   0   G1   16      "Base"
			   16   H1   16      "Base"
			   32   int   4   i31   ""
			}
			Length: 40 Alignment: 8
			/J5/!internal/J5
			pack()
			Structure J5 {
			   0   I3   40      "Base"
			   40   GG1   16      "Base"
			   56   I   40      "Base"
			   96   A   8      "Base"
			   104   int   4   j51   ""
			}
			Length: 112 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static Map<String, String> getExpectedVxtPtrSummaryJ5() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [G1]	[J5, I3, G1]");
		results.put("VTABLE_00000010", "    16 vbt [H1]	[J5, I3, H1]");
		results.put("VTABLE_00000028", "    40 vbt [GG1]	[J5, GG1]");
		results.put("VTABLE_00000038", "    56 vbt [G]	[J5, I, G]");
		results.put("VTABLE_00000048", "    72 vbt [H]	[J5, I, H]");
		results.put("VTABLE_00000078", "   120 vbt [GG2]	[J5, GG2]");
		results.put("VTABLE_00000088", "   136 vbt [GG3]	[J5, GG3]");
		return results;
	}

	private static Map<String, String> getSpeculatedVxtPtrSummaryJ5() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [G1]	[J5, I3, G1]");
		results.put("VTABLE_00000010", "    16 vbt [H1]	[J5, I3, H1]");
		results.put("VTABLE_00000028", "    40 vbt [GG1]	[J5, GG1]");
		results.put("VTABLE_00000038", "    56 vbt [G]	[J5, I, G]");
		results.put("VTABLE_00000048", "    72 vbt [H]	[J5, I, H]");
		results.put("VTABLE_00000080", "   128 vbt [GG2]	[J5, GG2]");
		results.put("VTABLE_00000090", "   144 vbt [GG3]	[J5, GG3]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsJ5() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructJ5_00000000());
		results.put("VTABLE_00000010", getVxtStructJ5_00000010());
		results.put("VTABLE_00000028", getVxtStructJ5_00000028());
		results.put("VTABLE_00000038", getVxtStructJ5_00000038());
		results.put("VTABLE_00000048", getVxtStructJ5_00000048());
		results.put("VTABLE_00000078", getVxtStructJ5_00000078());
		results.put("VTABLE_00000088", getVxtStructJ5_00000088());
		return results;
	}

	private static Map<String, String> getSpeculatedVxtStructsJ5() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructJ5_00000000());
		results.put("VTABLE_00000010", getVxtStructJ5_00000010());
		results.put("VTABLE_00000028", getVxtStructJ5_00000028());
		results.put("VTABLE_00000038", getVxtStructJ5_00000038());
		results.put("VTABLE_00000048", getVxtStructJ5_00000048());
		results.put("VTABLE_00000080", getVxtStructJ5_00000080_speculated());
		results.put("VTABLE_00000090", getVxtStructJ5_00000090_speculated());
		return results;
	}

	private static String getVxtStructJ5_00000000() {
		String expected =
		//@formatter:off
			"""
			/J5/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "C"
			   4   int   4      "E"
			   8   int   4      "CC2"
			   12   int   4      "GG2"
			   16   int   4      "GG3"
			   20   int   4      "CC1"
			}
			Length: 24 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ5_00000010() {
		String expected =
		//@formatter:off
			"""
			/J5/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "E"
			   4   int   4      "C"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ5_00000028() {
		String expected =
		//@formatter:off
			"""
			/J5/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "CC1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ5_00000038() {
		String expected =
		//@formatter:off
			"""
			/J5/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ5_00000048() {
		String expected =
		//@formatter:off
			"""
			/J5/!internal/VTABLE_00000048
			pack()
			Structure VTABLE_00000048 {
			   0   int   4      "C"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ5_00000078() {
		String expected =
		//@formatter:off
			"""
			/J5/!internal/VTABLE_00000078
			pack()
			Structure VTABLE_00000078 {
			   0   int   4      "CC2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ5_00000088() {
		String expected =
		//@formatter:off
			"""
			/J5/!internal/VTABLE_00000088
			pack()
			Structure VTABLE_00000088 {
			   0   int   4      "CC2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ5_00000080_speculated() {
		String expected =
		//@formatter:off
			"""
			/J5/!internal/VTABLE_00000080
			pack()
			Structure VTABLE_00000080 {
			   0   int   4      "CC2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ5_00000090_speculated() {
		String expected =
		//@formatter:off
			"""
			/J5/!internal/VTABLE_00000090
			pack()
			Structure VTABLE_00000090 {
			   0   int   4      "CC2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	struct J6 : virtual GG4, virtual GG3, A { //GG4 contains CC3, which has no members
	  int j61;
	  void j6f();
	};

	class J6	size(64):
		+---
	 0	| +--- (base class A)
	 0	| | c
	  	| | <alignment member> (size=3)
	 4	| | i
		| +---
	 8	| {vbptr}
	16	| j61
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC3)
		+---
		+--- (virtual base GG4)
	24	| {vbptr}
	32	| gg41
	  	| <alignment member> (size=4)
		+---
		+--- (virtual base CC2)
	40	| cc21
		+---
		+--- (virtual base GG3)
	48	| {vbptr}
	56	| gg31
	  	| <alignment member> (size=4)
	  	| <alignment member> (size=4)
		+---

	J6::$vbtable@J6@:
	 0	| -8
	 1	| 16 (J6d(J6+8)CC3)
	 2	| 16 (J6d(J6+8)GG4)
	 3	| 32 (J6d(J6+8)CC2)
	 4	| 40 (J6d(J6+8)GG3)

	J6::$vbtable@GG4@:
	 0	| 0
	 1	| 0 (J6d(GG4+0)CC3)

	J6::$vbtable@GG3@:
	 0	| 0
	 1	| -8 (J6d(GG3+0)CC2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             CC3      24       8       4 0
	             GG4      24       8       8 0
	             CC2      40       8      12 0
	             GG3      48       8      16 0
	 */
	//@formatter:on
	private static String getExpectedStructJ6() {
		String expected =
		//@formatter:off
			"""
			/J6
			pack()
			Structure J6 {
			   0   J6   24      "Self Base"
			   24   GG4   16      "Virtual Base"
			   40   CC2   4      "Virtual Base and previous (Empty Virtual Base CC3)"
			   48   GG3   16      "Virtual Base"
			}
			Length: 64 Alignment: 8
			/A
			pack()
			Structure A {
			   0   char   1   c   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   int   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg31   ""
			}
			Length: 16 Alignment: 8
			/GG4/!internal/GG4
			pack()
			Structure GG4 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg41   ""
			}
			Length: 16 Alignment: 8
			/J6/!internal/J6
			pack()
			Structure J6 {
			   0   A   8      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   j61   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructJ6() {
		String expected =
		//@formatter:off
			"""
			/J6
			pack()
			Structure J6 {
			   0   J6   24      "Self Base"
			   24   char[40]   40      "Filler for 4 Unplaceable Virtual Bases: GG4; GG3; CC3; CC2"
			}
			Length: 64 Alignment: 8
			/A
			pack()
			Structure A {
			   0   char   1   c   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4
			/J6/!internal/J6
			pack()
			Structure J6 {
			   0   A   8      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   j61   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	// TODO: Need to work on layout algorithm... believe we can do better, but don't have
	//  a decision on the best speculative results yet.
	private static String getSpeculatedStructJ6() {
		String expected =
		//@formatter:off
			"""
			/J6
			pack()
			Structure J6 {
			   0   J6   24      "Self Base"
			   24   CC2   4      "Virtual Base - Speculative Placement and previous (Empty Virtual Base CC3)"
			   32   GG4   16      "Virtual Base - Speculative Placement"
			   48   GG3   16      "Virtual Base - Speculative Placement"
			}
			Length: 64 Alignment: 8
			/A
			pack()
			Structure A {
			   0   char   1   c   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4
			/CC2
			pack()
			Structure CC2 {
			   0   int   4   cc21   ""
			}
			Length: 4 Alignment: 4
			/GG3/!internal/GG3
			pack()
			Structure GG3 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg31   ""
			}
			Length: 16 Alignment: 8
			/GG4/!internal/GG4
			pack()
			Structure GG4 {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   gg41   ""
			}
			Length: 16 Alignment: 8
			/J6/!internal/J6
			pack()
			Structure J6 {
			   0   A   8      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   j61   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static Map<String, String> getExpectedVxtPtrSummaryJ6() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt [J6]	[J6]");
		results.put("VTABLE_00000018", "    24 vbt [GG4]	[J6, GG4]");
		results.put("VTABLE_00000030", "    48 vbt [GG3]	[J6, GG3]");
		return results;
	}

	private static Map<String, String> getSpeculatedVxtPtrSummaryJ6() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt [J6]	[J6]");
		results.put("VTABLE_00000020", "    32 vbt [GG4]	[J6, GG4]");
		results.put("VTABLE_00000030", "    48 vbt [GG3]	[J6, GG3]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsJ6() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructJ6_00000008());
		results.put("VTABLE_00000018", getVxtStructJ6_00000018());
		results.put("VTABLE_00000030", getVxtStructJ6_00000030());
		return results;
	}

	private static Map<String, String> getSpeculatedVxtStructsJ6() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructJ6_00000008());
		results.put("VTABLE_00000020", getVxtStructJ6_00000020_speculated());
		results.put("VTABLE_00000030", getVxtStructJ6_00000030_speculated());
		return results;
	}

	private static String getVxtStructJ6_00000008() {
		String expected =
		//@formatter:off
			"""
			/J6/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "CC3"
			   4   int   4      "GG4"
			   8   int   4      "CC2"
			   12   int   4      "GG3"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ6_00000018() {
		String expected =
		//@formatter:off
			"""
			/J6/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   int   4      "CC3"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ6_00000030() {
		String expected =
		//@formatter:off
			"""
			/J6/!internal/VTABLE_00000030
			pack()
			Structure VTABLE_00000030 {
			   0   int   4      "CC2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ6_00000020_speculated() {
		String expected =
		//@formatter:off
			"""
			/J6/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   int   4      "CC3"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructJ6_00000030_speculated() {
		String expected =
		//@formatter:off
			"""
			/J6/!internal/VTABLE_00000030
			pack()
			Structure VTABLE_00000030 {
			   0   int   4      "CC2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================
	//@formatter:off
	/*
	class P	size(16):
		+---
	 0	| {vfptr}
	 8	| p1
  		| <alignment member> (size=4)
		+---

	P::$vftable@:
		| &P_meta
		|  0
	 0	| &P::pvf

	P::pvf this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructP() {
		String expected =
		//@formatter:off
			"""
			/P
			pack()
			Structure P {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructP() {
		return convertCommentsToSpeculative(getExpectedStructP());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryP() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[P]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsP() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructP_00000000());
		return results;
	}

	private static String getVxtStructP_00000000() {
		String expected =
		//@formatter:off
			"""
			/P/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_undefined *   8   P::pvf   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Q	size(24):
		+---
	 0	| +--- (base class P)
	 0	| | {vfptr}
	 8	| | p1
  		| | <alignment member> (size=4)
		| +---
	16	| q1
	  	| <alignment member> (size=4)
		+---

	Q::$vftable@:
		| &Q_meta
		|  0
	 0	| &Q::pvf
	 1	| &Q::qvf

	Q::pvf this adjustor: 0
	Q::qvf this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructQ() {
		String expected =
		//@formatter:off
			"""
			/Q
			pack()
			Structure Q {
			   0   P   16      "Base"
			   16   int   4   q1   ""
			}
			Length: 24 Alignment: 8
			/P
			pack()
			Structure P {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructQ() {
		return convertCommentsToSpeculative(getExpectedStructQ());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryQ() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[Q, P]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsQ() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructQ_00000000());
		return results;
	}

	private static String getVxtStructQ_00000000() {
		String expected =
		//@formatter:off
			"""
			/Q/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_undefined *   8   Q::pvf   ""
			   8   _func___thiscall_undefined *   8   Q::qvf   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class R	size(16):
		+---
	 0	| {vfptr}
	 8	| r1
  		| <alignment member> (size=4)
		+---

	R::$vftable@:
		| &R_meta
		|  0
	 0	| &R::pvf
	 1	| &R::rvf

	R::pvf this adjustor: 0
	R::rvf this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructR() {
		String expected =
		//@formatter:off
			"""
			/R
			pack()
			Structure R {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   r1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructR() {
		return convertCommentsToSpeculative(getExpectedStructR());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryR() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[R]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsR() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000",

			getVxtStructR_00000000());
		return results;
	}

	private static String getVxtStructR_00000000() {
		String expected =
		//@formatter:off
			"""
			/R/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_undefined *   8   R::pvf   ""
			   8   _func___thiscall_undefined *   8   R::rvf   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class S	size(40):
		+---
	 0	| +--- (base class P)
	 0	| | {vfptr}
	 8	| | p1
  		| | <alignment member> (size=4)
		| +---
	16	| +--- (base class R)
	16	| | {vfptr}
	24	| | r1
  		| | <alignment member> (size=4)
		| +---
	32	| s1
  		| <alignment member> (size=4)
		+---

	S::$vftable@P@:
		| &S_meta
		|  0
	 0	| &S::pvf

	S::$vftable@R@:
		| -16
	 0	| &thunk: this-=16; goto S::pvf
	 1	| &S::rvf

	S::pvf this adjustor: 0
	S::rvf this adjustor: 16
	 */
	//@formatter:on
	private static String getExpectedStructS() {
		String expected =
		//@formatter:off
			"""
			/S
			pack()
			Structure S {
			   0   P   16      "Base"
			   16   R   16      "Base"
			   32   int   4   s1   ""
			}
			Length: 40 Alignment: 8
			/P
			pack()
			Structure P {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/R
			pack()
			Structure R {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   r1   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructS() {
		return convertCommentsToSpeculative(getExpectedStructS());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryS() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [P]	[S, P]");
		results.put("VTABLE_00000010", "    16 vft [R]	[S, R]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsS() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructS_00000000());
		results.put("VTABLE_00000010", getVxtStructS_00000010());
		return results;
	}

	private static String getVxtStructS_00000000() {
		String expected =
		//@formatter:off
			"""
			/S/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_undefined *   8   S::pvf   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructS_00000010() {
		String expected =
		//@formatter:off
			"""
			/S/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_undefined *   8   S::pvf   ""
			   8   _func___thiscall_undefined *   8   S::rvf   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class T	size(48):
		+---
	 0	| {vfptr}
	 8	| {vbptr}
	16	| t1
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
	28	| (vtordisp for vbase P)
		+--- (virtual base P)
	32	| {vfptr}
	40	| p1
  		| <alignment member> (size=4)
		+---

	T::$vftable@T@:
		| &T_meta
		|  0
	 0	| &T::tvf

	T::$vbtable@:
	 0	| -8
	 1	| 24 (Td(T+8)P)

	T::$vftable@P@:
		| -32
	 0	| &(vtordisp) T::pvf

	T::pvf this adjustor: 32
	T::tvf this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               P      32       8       4 1
	 */
	//@formatter:on
	private static String getExpectedStructT() {
		String expected =
		//@formatter:off
			"""
			/T
			pack()
			Structure T {
			   0   T   24      "Self Base"
			   24   longlong   8   _padding_   ""
			   32   P   16      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/P
			pack()
			Structure P {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/T/!internal/T
			pack()
			Structure T {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   t1   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructT() {
		String expected =
		//@formatter:off
			"""
			/T
			pack()
			Structure T {
			   0   T   24      "Self Base"
			   24   char[24]   24      "Filler for 1 Unplaceable Virtual Base: P"
			}
			Length: 48 Alignment: 8
			/T/!internal/T
			pack()
			Structure T {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   t1   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructT() {
		String expected =
		//@formatter:off
			"""
			/T
			aligned(8) pack(disabled)
			Structure T {
			   0   T   24      "Self Base"
			   24   P   16      "Virtual Base - Speculative Placement"
			}
			Length: 48 Alignment: 8
			/P
			pack()
			Structure P {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/T/!internal/T
			pack()
			Structure T {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   t1   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static Map<String, String> getExpectedVxtPtrSummaryT() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [T]	[T]");
		results.put("VTABLE_00000008", "     8 vbt []	[T]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000020", "    32 vft [P]	[T, P]");
		results.put("VTABLE_00000020", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsT() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructT_00000000());
		results.put("VTABLE_00000008", getVxtStructT_00000008());
		results.put("VTABLE_00000020", getVxtStructT_00000020());
		return results;
	}

	private static Map<String, String> getSpeculatedVxtStructsT() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructT_00000000());
		results.put("VTABLE_00000008", getVxtStructT_00000008());
		results.put("VTABLE_00000018", getVxtStructT_00000018_speculated());
		return results;
	}

	private static String getVxtStructT_00000000() {
		String expected =
		//@formatter:off
			"""
			/T/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_undefined *   8   T::tvf   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructT_00000008() {
		String expected =
		//@formatter:off
			"""
			/T/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "P"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructT_00000020() {
		String expected =
		//@formatter:off
			"""
			/T/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_undefined *   8   T::pvf   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructT_00000018_speculated() {
		String expected =
		//@formatter:off
			"""
			/T/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_undefined *   8   T::pvf   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class U	size(56):
		+---
	 0	| +--- (base class T)
	 0	| | {vfptr}
	 8	| | {vbptr}
	16	| | t1
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	24	| u1
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
	36	| (vtordisp for vbase P)
		+--- (virtual base P)
	40	| {vfptr}
	48	| p1
  		| <alignment member> (size=4)
		+---

	U::$vftable@T@:
		| &U_meta
		|  0
	 0	| &T::tvf

	U::$vbtable@:
	 0	| -8
	 1	| 32 (Ud(T+8)P)

	U::$vftable@P@:
		| -40
	 0	| &(vtordisp) thunk: this-=8; goto T::pvf
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	               P      40       8       4 1
	 */
	//@formatter:on
	private static String getExpectedStructU() {
		String expected =
		//@formatter:off
			"""
			/U
			pack()
			Structure U {
			   0   U   32      "Self Base"
			   32   longlong   8   _padding_   ""
			   40   P   16      "Virtual Base"
			}
			Length: 56 Alignment: 8
			/P
			pack()
			Structure P {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/T/!internal/T
			pack()
			Structure T {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   t1   ""
			}
			Length: 24 Alignment: 8
			/U/!internal/U
			pack()
			Structure U {
			   0   T   24      "Base"
			   24   int   4   u1   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructU() {
		String expected =
		//@formatter:off
			"""
			/U
			pack()
			Structure U {
			   0   U   32      "Self Base"
			   32   char[24]   24      "Filler for 1 Unplaceable Virtual Base: P"
			}
			Length: 56 Alignment: 8
			/T/!internal/T
			pack()
			Structure T {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   t1   ""
			}
			Length: 24 Alignment: 8
			/U/!internal/U
			pack()
			Structure U {
			   0   T   24      "Base"
			   24   int   4   u1   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructU() {
		String expected =
		//@formatter:off
			"""
			/U
			aligned(8) pack(disabled)
			Structure U {
			   0   U   32      "Self Base"
			   32   P   16      "Virtual Base - Speculative Placement"
			}
			Length: 56 Alignment: 8
			/P
			pack()
			Structure P {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   p1   ""
			}
			Length: 16 Alignment: 8
			/T/!internal/T
			pack()
			Structure T {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   t1   ""
			}
			Length: 24 Alignment: 8
			/U/!internal/U
			pack()
			Structure U {
			   0   T   24      "Base"
			   24   int   4   u1   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static Map<String, String> getExpectedVxtPtrSummaryU() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [T]	[U, T]");
		results.put("VTABLE_00000008", "     8 vbt []	[U, T]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000028", "    40 vft [P]	[U, T, P]");
		results.put("VTABLE_00000028", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsU() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructU_00000000());
		results.put("VTABLE_00000008", getVxtStructU_00000008());
		results.put("VTABLE_00000028", getVxtStructU_00000028());
		return results;
	}

	private static Map<String, String> getSpeculatedVxtStructsU() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructU_00000000());
		results.put("VTABLE_00000008", getVxtStructU_00000008());
		results.put("VTABLE_00000020", getVxtStructU_00000020_speculated());
		return results;
	}

	private static String getVxtStructU_00000000() {
		String expected =
		//@formatter:off
			"""
			/U/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_undefined *   8   T::tvf   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructU_00000008() {
		String expected =
		//@formatter:off
			"""
			/U/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "P"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructU_00000028() {
		String expected =
		//@formatter:off
			"""
			/U/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_undefined *   8   T::pvf   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructU_00000020_speculated() {
		String expected =
		//@formatter:off
			"""
			/U/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   _func___thiscall_undefined *   8   T::pvf   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class V	size(8):
		+---
	 0	| {vfptr}
		+---

	V::$vftable@:
		| &V_meta
		|  0
	 0	| &V::{dtor}

	V::{dtor} this adjustor: 0
	V::__delDtor this adjustor: 0
	V::__vecDelDtor this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructV() {
		String expected =
		//@formatter:off
			"""
			/V
			pack()
			Structure V {
			   0   pointer   8   {vfptr}   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructV() {
		return convertCommentsToSpeculative(getExpectedStructV());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryV() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[V]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsV() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructV_00000000());
		return results;
	}

	private static String getVxtStructV_00000000() {
		String expected =
		//@formatter:off
			"""
			/V/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_void_ptr *   8   V::__vecDelDtor   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class W	size(8):
		+---
	 0	| +--- (base class V)
	 0	| | {vfptr}
		| +---
		+---

	W::$vftable@:
		| &W_meta
		|  0
	 0	| &W::{dtor}

	W::{dtor} this adjustor: 0
	W::__delDtor this adjustor: 0
	W::__vecDelDtor this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructW() {
		String expected =
		//@formatter:off
			"""
			/W
			pack()
			Structure W {
			   0   V   8      "Base"
			}
			Length: 8 Alignment: 8
			/V
			pack()
			Structure V {
			   0   pointer   8   {vfptr}   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructW() {
		return convertCommentsToSpeculative(getExpectedStructW());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryW() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[W, V]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsW() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructW_00000000());
		return results;
	}

	private static String getVxtStructW_00000000() {
		String expected =
		//@formatter:off
			"""
			/W/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_void_ptr *   8   W::__vecDelDtor   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class WW	size(16):
		+---
	 0	| +--- (base class W)
	 0	| | +--- (base class V)
	 0	| | | {vfptr}
		| | +---
		| +---
	 8	| w1
  		| <alignment member> (size=4)
		+---

	WW::$vftable@:
		| &WW_meta
		|  0
	 0	| &WW::{dtor}

	WW::{dtor} this adjustor: 0
	WW::__delDtor this adjustor: 0
	WW::__vecDelDtor this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructWW() {
		String expected =
		//@formatter:off
			"""
			/WW
			pack()
			Structure WW {
			   0   W   8      "Base"
			   8   int   4   w1   ""
			}
			Length: 16 Alignment: 8
			/V
			pack()
			Structure V {
			   0   pointer   8   {vfptr}   ""
			}
			Length: 8 Alignment: 8
			/W
			pack()
			Structure W {
			   0   V   8      "Base"
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructWW() {
		return convertCommentsToSpeculative(getExpectedStructWW());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryWW() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[WW, W, V]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsWW() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructWW_00000000());
		return results;
	}

	private static String getVxtStructWW_00000000() {
		String expected =
		//@formatter:off
			"""
			/WW/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_void_ptr *   8   WW::__vecDelDtor   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class X	size(1):
		+---
		+---
	 */
	//@formatter:on
	private static String getExpectedStructX() {
		String expected =
		//@formatter:off
			"""
			/X
			pack(disabled)
			Structure X {
			}
			Length: 1 Alignment: 1""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructX() {
		return convertCommentsToSpeculative(getExpectedStructX());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryX() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsX() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class Z	size(1):
		+---
		+---
	 */
	//@formatter:on
	private static String getExpectedStructZ() {
		String expected =
		//@formatter:off
			"""
			/Z
			pack(disabled)
			Structure Z {
			}
			Length: 1 Alignment: 1""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructZ() {
		return convertCommentsToSpeculative(getExpectedStructZ());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryZ() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsZ() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA1a	size(4):
		+---
	 0	| aa1ai
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA1a() {
		String expected =
		//@formatter:off
			"""
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA1a() {
		return convertCommentsToSpeculative(getExpectedStructAA1a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA1a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA1a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA1b	size(4):
		+---
	 0	| aa1bi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA1b() {
		String expected =
		//@formatter:off
			"""
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA1b() {
		return convertCommentsToSpeculative(getExpectedStructAA1b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA1b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA1b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA1	size(12):
		+---
	 0	| +--- (base class AA1a)
	 0	| | aa1ai
		| +---
	 4	| +--- (base class AA1b)
	 4	| | aa1bi
		| +---
	 8	| aa1i
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA1() {
		String expected =
		//@formatter:off
			"""
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA1() {
		return convertCommentsToSpeculative(getExpectedStructAA1());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA1() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA1() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA2a	size(4):
		+---
	 0	| aa2ai
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA2a() {
		String expected =
		//@formatter:off
			"""
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA2a() {
		return convertCommentsToSpeculative(getExpectedStructAA2a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA2a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA2a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA2b	size(4):
		+---
	 0	| aa2bi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA2b() {
		String expected =
		//@formatter:off
			"""
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA2b() {
		return convertCommentsToSpeculative(getExpectedStructAA2b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA2b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA2b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA2	size(12):
		+---
	 0	| +--- (base class AA2a)
	 0	| | aa2ai
		| +---
	 4	| +--- (base class AA2b)
	 4	| | aa2bi
		| +---
	 8	| aa2i
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA2() {
		String expected =
		//@formatter:off
			"""
			/AA2
			pack()
			Structure AA2 {
			   0   AA2a   4      "Base"
			   4   AA2b   4      "Base"
			   8   int   4   aa2i   ""
			}
			Length: 12 Alignment: 4
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA2() {
		return convertCommentsToSpeculative(getExpectedStructAA2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA2() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA2() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA3a	size(28):
		+---
	 0	| {vbptr}
	 8	| aa3ai
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA2)
	16	| +--- (base class AA2a)
	16	| | aa2ai
		| +---
	20	| +--- (base class AA2b)
	20	| | aa2bi
		| +---
	24	| aa2i
		+---

	AA3a::$vbtable@:
	 0	| 0
	 1	| 16 (AA3ad(AA3a+0)AA2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA2      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA3a() {
		String expected =
		//@formatter:off
			"""
			/AA3a
			pack()
			Structure AA3a {
			   0   AA3a   16      "Self Base"
			   16   AA2   12      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/AA2
			pack()
			Structure AA2 {
			   0   AA2a   4      "Base"
			   4   AA2b   4      "Base"
			   8   int   4   aa2i   ""
			}
			Length: 12 Alignment: 4
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4
			/AA3a/!internal/AA3a
			pack()
			Structure AA3a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3ai   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA3a() {
		String expected =
		//@formatter:off
			"""
			/AA3a
			pack()
			Structure AA3a {
			   0   AA3a   16      "Self Base"
			   16   char[16]   16      "Filler for 1 Unplaceable Virtual Base: AA2"
			}
			Length: 32 Alignment: 8
			/AA3a/!internal/AA3a
			pack()
			Structure AA3a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3ai   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA3a() {
		return convertCommentsToSpeculative(getExpectedStructAA3a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA3a() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA3a]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA3a() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA3a_00000000());
		return results;
	}

	private static String getVxtStructAA3a_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA3a/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA3b	size(28):
		+---
	 0	| {vbptr}
	 8	| aa3bi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA2)
	16	| +--- (base class AA2a)
	16	| | aa2ai
		| +---
	20	| +--- (base class AA2b)
	20	| | aa2bi
		| +---
	24	| aa2i
		+---

	AA3b::$vbtable@:
	 0	| 0
	 1	| 16 (AA3bd(AA3b+0)AA2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA2      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA3b() {
		String expected =
		//@formatter:off
			"""
			/AA3b
			pack()
			Structure AA3b {
			   0   AA3b   16      "Self Base"
			   16   AA2   12      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/AA2
			pack()
			Structure AA2 {
			   0   AA2a   4      "Base"
			   4   AA2b   4      "Base"
			   8   int   4   aa2i   ""
			}
			Length: 12 Alignment: 4
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4
			/AA3b/!internal/AA3b
			pack()
			Structure AA3b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3bi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA3b() {
		String expected =
		//@formatter:off
			"""
			/AA3b
			pack()
			Structure AA3b {
			   0   AA3b   16      "Self Base"
			   16   char[16]   16      "Filler for 1 Unplaceable Virtual Base: AA2"
			}
			Length: 32 Alignment: 8
			/AA3b/!internal/AA3b
			pack()
			Structure AA3b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3bi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA3b() {
		return convertCommentsToSpeculative(getExpectedStructAA3b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA3b() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA3b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA3b() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA3b_00000000());
		return results;
	}

	private static String getVxtStructAA3b_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA3b/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA3c	size(64):
		+---
	 0	| +--- (base class AA3a)
	 0	| | {vbptr}
	 8	| | aa3ai
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| +--- (base class AA3b)
	16	| | {vbptr}
	24	| | aa3bi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	32	| aa3ci
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA1)
	40	| +--- (base class AA1a)
	40	| | aa1ai
		| +---
	44	| +--- (base class AA1b)
	44	| | aa1bi
		| +---
	48	| aa1i
		+---
		+--- (virtual base AA2)
	52	| +--- (base class AA2a)
	52	| | aa2ai
		| +---
	56	| +--- (base class AA2b)
	56	| | aa2bi
		| +---
	60	| aa2i
		+---

	AA3c::$vbtable@AA3a@:
	 0	| 0
	 1	| 52 (AA3cd(AA3a+0)AA2)
	 2	| 40 (AA3cd(AA3c+0)AA1)

	AA3c::$vbtable@AA3b@:
	 0	| 0
	 1	| 36 (AA3cd(AA3b+0)AA2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA1      40       0       8 0
	             AA2      52       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA3c() {
		String expected =
		//@formatter:off
			"""
			/AA3c
			pack()
			Structure AA3c {
			   0   AA3c   40      "Self Base"
			   40   AA1   12      "Virtual Base"
			   52   AA2   12      "Virtual Base"
			}
			Length: 64 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA2
			pack()
			Structure AA2 {
			   0   AA2a   4      "Base"
			   4   AA2b   4      "Base"
			   8   int   4   aa2i   ""
			}
			Length: 12 Alignment: 4
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4
			/AA3a/!internal/AA3a
			pack()
			Structure AA3a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3ai   ""
			}
			Length: 16 Alignment: 8
			/AA3b/!internal/AA3b
			pack()
			Structure AA3b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3bi   ""
			}
			Length: 16 Alignment: 8
			/AA3c/!internal/AA3c
			pack()
			Structure AA3c {
			   0   AA3a   16      "Base"
			   16   AA3b   16      "Base"
			   32   int   4   aa3ci   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA3c() {
		String expected =
		//@formatter:off
			"""
			/AA3c
			pack()
			Structure AA3c {
			   0   AA3c   40      "Self Base"
			   40   char[24]   24      "Filler for 2 Unplaceable Virtual Bases: AA1; AA2"
			}
			Length: 64 Alignment: 8
			/AA3a/!internal/AA3a
			pack()
			Structure AA3a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3ai   ""
			}
			Length: 16 Alignment: 8
			/AA3b/!internal/AA3b
			pack()
			Structure AA3b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3bi   ""
			}
			Length: 16 Alignment: 8
			/AA3c/!internal/AA3c
			pack()
			Structure AA3c {
			   0   AA3a   16      "Base"
			   16   AA3b   16      "Base"
			   32   int   4   aa3ci   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA3c() {
		String expected =
		//@formatter:off
			"""
			/AA3c
			pack()
			Structure AA3c {
			   0   AA3c   40      "Self Base"
			   40   AA2   12      "Virtual Base - Speculative Placement"
			   52   AA1   12      "Virtual Base - Speculative Placement"
			}
			Length: 64 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA2
			pack()
			Structure AA2 {
			   0   AA2a   4      "Base"
			   4   AA2b   4      "Base"
			   8   int   4   aa2i   ""
			}
			Length: 12 Alignment: 4
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4
			/AA3a/!internal/AA3a
			pack()
			Structure AA3a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3ai   ""
			}
			Length: 16 Alignment: 8
			/AA3b/!internal/AA3b
			pack()
			Structure AA3b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3bi   ""
			}
			Length: 16 Alignment: 8
			/AA3c/!internal/AA3c
			pack()
			Structure AA3c {
			   0   AA3a   16      "Base"
			   16   AA3b   16      "Base"
			   32   int   4   aa3ci   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA3c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [AA3a]	[AA3c, AA3a]");
		results.put("VTABLE_00000010", "    16 vbt [AA3b]	[AA3c, AA3b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA3c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA3c_00000000());
		results.put("VTABLE_00000010", getVxtStructAA3c_00000010());
		return results;
	}

	private static String getVxtStructAA3c_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA3c/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA2"
			   4   int   4      "AA1"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA3c_00000010() {
		String expected =
		//@formatter:off
			"""
			/AA3c/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "AA2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA3d	size(72):
		+---
	 0	| {vbptr}
	 8	| aa3di
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA1)
	16	| +--- (base class AA1a)
	16	| | aa1ai
		| +---
	20	| +--- (base class AA1b)
	20	| | aa1bi
		| +---
	24	| aa1i
		+---
		+--- (virtual base AA2)
	28	| +--- (base class AA2a)
	28	| | aa2ai
		| +---
	32	| +--- (base class AA2b)
	32	| | aa2bi
		| +---
	36	| aa2i
		+---
		+--- (virtual base AA3a)
	40	| {vbptr}
	48	| aa3ai
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA3b)
	56	| {vbptr}
	64	| aa3bi
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	AA3d::$vbtable@AA3d@:
	 0	| 0
	 1	| 16 (AA3dd(AA3d+0)AA1)
	 2	| 28 (AA3dd(AA3d+0)AA2)
	 3	| 40 (AA3dd(AA3d+0)AA3a)
	 4	| 56 (AA3dd(AA3d+0)AA3b)

	AA3d::$vbtable@AA3a@:
	 0	| 0
	 1	| -12 (AA3dd(AA3a+0)AA2)

	AA3d::$vbtable@AA3b@:
	 0	| 0
	 1	| -28 (AA3dd(AA3b+0)AA2)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA1      16       0       4 0
	             AA2      28       0       8 0
	            AA3a      40       0      12 0
	            AA3b      56       0      16 0
	 */
	//@formatter:on
	private static String getExpectedStructAA3d() {
		String expected =
		//@formatter:off
			"""
			/AA3d
			pack()
			Structure AA3d {
			   0   AA3d   16      "Self Base"
			   16   AA1   12      "Virtual Base"
			   28   AA2   12      "Virtual Base"
			   40   AA3a   16      "Virtual Base"
			   56   AA3b   16      "Virtual Base"
			}
			Length: 72 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA2
			pack()
			Structure AA2 {
			   0   AA2a   4      "Base"
			   4   AA2b   4      "Base"
			   8   int   4   aa2i   ""
			}
			Length: 12 Alignment: 4
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4
			/AA3a/!internal/AA3a
			pack()
			Structure AA3a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3ai   ""
			}
			Length: 16 Alignment: 8
			/AA3b/!internal/AA3b
			pack()
			Structure AA3b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3bi   ""
			}
			Length: 16 Alignment: 8
			/AA3d/!internal/AA3d
			pack()
			Structure AA3d {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3di   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA3d() {
		String expected =
		//@formatter:off
			"""
			/AA3d
			pack()
			Structure AA3d {
			   0   AA3d   16      "Self Base"
			   16   char[56]   56      "Filler for 4 Unplaceable Virtual Bases: AA1; AA3a; AA3b; AA2"
			}
			Length: 72 Alignment: 8
			/AA3d/!internal/AA3d
			pack()
			Structure AA3d {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3di   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA3d() {
		String expected =
		//@formatter:off
			"""
			/AA3d
			pack()
			Structure AA3d {
			   0   AA3d   16      "Self Base"
			   16   AA2   12      "Virtual Base - Speculative Placement"
			   28   AA1   12      "Virtual Base - Speculative Placement"
			   40   AA3a   16      "Virtual Base - Speculative Placement"
			   56   AA3b   16      "Virtual Base - Speculative Placement"
			}
			Length: 72 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA2
			pack()
			Structure AA2 {
			   0   AA2a   4      "Base"
			   4   AA2b   4      "Base"
			   8   int   4   aa2i   ""
			}
			Length: 12 Alignment: 4
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4
			/AA3a/!internal/AA3a
			pack()
			Structure AA3a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3ai   ""
			}
			Length: 16 Alignment: 8
			/AA3b/!internal/AA3b
			pack()
			Structure AA3b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3bi   ""
			}
			Length: 16 Alignment: 8
			/AA3d/!internal/AA3d
			pack()
			Structure AA3d {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3di   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA3d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [AA3d]	[AA3d]");
		results.put("VTABLE_00000028", "    40 vbt [AA3a]	[AA3d, AA3a]");
		results.put("VTABLE_00000038", "    56 vbt [AA3b]	[AA3d, AA3b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA3d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA3d_00000000());
		results.put("VTABLE_00000028", getVxtStructAA3d_00000028());
		results.put("VTABLE_00000038", getVxtStructAA3d_00000038());
		return results;
	}

	private static String getVxtStructAA3d_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA3d/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA1"
			   4   int   4      "AA2"
			   8   int   4      "AA3a"
			   12   int   4      "AA3b"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA3d_00000028() {
		String expected =
		//@formatter:off
			"""
			/AA3d/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "AA2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA3d_00000038() {
		String expected =
		//@formatter:off
			"""
			/AA3d/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   int   4      "AA2"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA3e	size(16):
		+---
	 0	| +--- (base class AA2)
	 0	| | +--- (base class AA2a)
	 0	| | | aa2ai
		| | +---
	 4	| | +--- (base class AA2b)
	 4	| | | aa2bi
		| | +---
	 8	| | aa2i
		| +---
	12	| aa3ei
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA3e() {
		String expected =
		//@formatter:off
			"""
			/AA3e
			pack()
			Structure AA3e {
			   0   AA2   12      "Base"
			   12   int   4   aa3ei   ""
			}
			Length: 16 Alignment: 4
			/AA2
			pack()
			Structure AA2 {
			   0   AA2a   4      "Base"
			   4   AA2b   4      "Base"
			   8   int   4   aa2i   ""
			}
			Length: 12 Alignment: 4
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA3e() {
		return convertCommentsToSpeculative(getExpectedStructAA3e());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA3e() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA3e() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA3f	size(16):
		+---
	 0	| +--- (base class AA2)
	 0	| | +--- (base class AA2a)
	 0	| | | aa2ai
		| | +---
	 4	| | +--- (base class AA2b)
	 4	| | | aa2bi
		| | +---
	 8	| | aa2i
		| +---
	12	| aa3fi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA3f() {
		String expected =
		//@formatter:off
			"""
			/AA3f
			pack()
			Structure AA3f {
			   0   AA2   12      "Base"
			   12   int   4   aa3fi   ""
			}
			Length: 16 Alignment: 4
			/AA2
			pack()
			Structure AA2 {
			   0   AA2a   4      "Base"
			   4   AA2b   4      "Base"
			   8   int   4   aa2i   ""
			}
			Length: 12 Alignment: 4
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA3f() {
		return convertCommentsToSpeculative(getExpectedStructAA3f());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA3f() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA3f() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA3g	size(48):
		+---
	 0	| {vbptr}
	 8	| aa3gi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA3e)
	16	| +--- (base class AA2)
	16	| | +--- (base class AA2a)
	16	| | | aa2ai
		| | +---
	20	| | +--- (base class AA2b)
	20	| | | aa2bi
		| | +---
	24	| | aa2i
		| +---
	28	| aa3ei
		+---
		+--- (virtual base AA3f)
	32	| +--- (base class AA2)
	32	| | +--- (base class AA2a)
	32	| | | aa2ai
		| | +---
	36	| | +--- (base class AA2b)
	36	| | | aa2bi
		| | +---
	40	| | aa2i
		| +---
	44	| aa3fi
		+---

	AA3g::$vbtable@:
	 0	| 0
	 1	| 16 (AA3gd(AA3g+0)AA3e)
	 2	| 32 (AA3gd(AA3g+0)AA3f)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA3e      16       0       4 0
	            AA3f      32       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructAA3g() {
		String expected =
		//@formatter:off
			"""
			/AA3g
			pack()
			Structure AA3g {
			   0   AA3g   16      "Self Base"
			   16   AA3e   16      "Virtual Base"
			   32   AA3f   16      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/AA2
			pack()
			Structure AA2 {
			   0   AA2a   4      "Base"
			   4   AA2b   4      "Base"
			   8   int   4   aa2i   ""
			}
			Length: 12 Alignment: 4
			/AA2a
			pack()
			Structure AA2a {
			   0   int   4   aa2ai   ""
			}
			Length: 4 Alignment: 4
			/AA2b
			pack()
			Structure AA2b {
			   0   int   4   aa2bi   ""
			}
			Length: 4 Alignment: 4
			/AA3e
			pack()
			Structure AA3e {
			   0   AA2   12      "Base"
			   12   int   4   aa3ei   ""
			}
			Length: 16 Alignment: 4
			/AA3f
			pack()
			Structure AA3f {
			   0   AA2   12      "Base"
			   12   int   4   aa3fi   ""
			}
			Length: 16 Alignment: 4
			/AA3g/!internal/AA3g
			pack()
			Structure AA3g {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3gi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA3g() {
		String expected =
		//@formatter:off
			"""
			/AA3g
			pack()
			Structure AA3g {
			   0   AA3g   16      "Self Base"
			   16   char[32]   32      "Filler for 2 Unplaceable Virtual Bases: AA3e; AA3f"
			}
			Length: 48 Alignment: 8
			/AA3g/!internal/AA3g
			pack()
			Structure AA3g {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa3gi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA3g() {
		return convertCommentsToSpeculative(getExpectedStructAA3g());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA3g() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA3g]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA3g() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA3g_00000000());
		return results;
	}

	private static String getVxtStructAA3g_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA3g/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA3e"
			   4   int   4      "AA3f"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4a	size(28):
		+---
	 0	| {vbptr}
	 8	| aa4ai
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA1)
	16	| +--- (base class AA1a)
	16	| | aa1ai
		| +---
	20	| +--- (base class AA1b)
	20	| | aa1bi
		| +---
	24	| aa1i
		+---

	AA4a::$vbtable@:
	 0	| 0
	 1	| 16 (AA4ad(AA4a+0)AA1)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA1      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4a() {
		String expected =
		//@formatter:off
			"""
			/AA4a
			pack()
			Structure AA4a {
			   0   AA4a   16      "Self Base"
			   16   AA1   12      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA4a/!internal/AA4a
			pack()
			Structure AA4a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ai   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4a() {
		String expected =
		//@formatter:off
			"""
			/AA4a
			pack()
			Structure AA4a {
			   0   AA4a   16      "Self Base"
			   16   char[16]   16      "Filler for 1 Unplaceable Virtual Base: AA1"
			}
			Length: 32 Alignment: 8
			/AA4a/!internal/AA4a
			pack()
			Structure AA4a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ai   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4a() {
		return convertCommentsToSpeculative(getExpectedStructAA4a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4a() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA4a]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4a() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4a_00000000());
		return results;
	}

	private static String getVxtStructAA4a_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4a/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4b	size(28):
		+---
	 0	| {vbptr}
	 8	| aa4bi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA1)
	16	| +--- (base class AA1a)
	16	| | aa1ai
		| +---
	20	| +--- (base class AA1b)
	20	| | aa1bi
		| +---
	24	| aa1i
		+---

	AA4b::$vbtable@:
	 0	| 0
	 1	| 16 (AA4bd(AA4b+0)AA1)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA1      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4b() {
		String expected =
		//@formatter:off
			"""
			/AA4b
			pack()
			Structure AA4b {
			   0   AA4b   16      "Self Base"
			   16   AA1   12      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA4b/!internal/AA4b
			pack()
			Structure AA4b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4bi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4b() {
		String expected =
		//@formatter:off
			"""
			/AA4b
			pack()
			Structure AA4b {
			   0   AA4b   16      "Self Base"
			   16   char[16]   16      "Filler for 1 Unplaceable Virtual Base: AA1"
			}
			Length: 32 Alignment: 8
			/AA4b/!internal/AA4b
			pack()
			Structure AA4b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4bi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4b() {
		return convertCommentsToSpeculative(getExpectedStructAA4b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4b() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA4b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4b() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4b_00000000());
		return results;
	}

	private static String getVxtStructAA4b_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4b/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4c	size(52):
		+---
	 0	| +--- (base class AA4a)
	 0	| | {vbptr}
	 8	| | aa4ai
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| +--- (base class AA4b)
	16	| | {vbptr}
	24	| | aa4bi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	32	| aa4ci
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA1)
	40	| +--- (base class AA1a)
	40	| | aa1ai
		| +---
	44	| +--- (base class AA1b)
	44	| | aa1bi
		| +---
	48	| aa1i
		+---

	AA4c::$vbtable@AA4a@:
	 0	| 0
	 1	| 40 (AA4cd(AA4a+0)AA1)

	AA4c::$vbtable@AA4b@:
	 0	| 0
	 1	| 24 (AA4cd(AA4b+0)AA1)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA1      40       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4c() {
		String expected =
		//@formatter:off
			"""
			/AA4c
			pack()
			Structure AA4c {
			   0   AA4c   40      "Self Base"
			   40   AA1   12      "Virtual Base"
			}
			Length: 56 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA4a/!internal/AA4a
			pack()
			Structure AA4a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ai   ""
			}
			Length: 16 Alignment: 8
			/AA4b/!internal/AA4b
			pack()
			Structure AA4b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4bi   ""
			}
			Length: 16 Alignment: 8
			/AA4c/!internal/AA4c
			pack()
			Structure AA4c {
			   0   AA4a   16      "Base"
			   16   AA4b   16      "Base"
			   32   int   4   aa4ci   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4c() {
		String expected =
		//@formatter:off
			"""
			/AA4c
			pack()
			Structure AA4c {
			   0   AA4c   40      "Self Base"
			   40   char[16]   16      "Filler for 1 Unplaceable Virtual Base: AA1"
			}
			Length: 56 Alignment: 8
			/AA4a/!internal/AA4a
			pack()
			Structure AA4a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ai   ""
			}
			Length: 16 Alignment: 8
			/AA4b/!internal/AA4b
			pack()
			Structure AA4b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4bi   ""
			}
			Length: 16 Alignment: 8
			/AA4c/!internal/AA4c
			pack()
			Structure AA4c {
			   0   AA4a   16      "Base"
			   16   AA4b   16      "Base"
			   32   int   4   aa4ci   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4c() {
		return convertCommentsToSpeculative(getExpectedStructAA4c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [AA4a]	[AA4c, AA4a]");
		results.put("VTABLE_00000010", "    16 vbt [AA4b]	[AA4c, AA4b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4c_00000000());
		results.put("VTABLE_00000010", getVxtStructAA4c_00000010());
		return results;
	}

	private static String getVxtStructAA4c_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4c/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA4c_00000010() {
		String expected =
		//@formatter:off
			"""
			/AA4c/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   int   4      "AA1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4d	size(56):
		+---
	 0	| +--- (base class AA4b)
	 0	| | {vbptr}
	 8	| | aa4bi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| aa4di
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA1)
	24	| +--- (base class AA1a)
	24	| | aa1ai
		| +---
	28	| +--- (base class AA1b)
	28	| | aa1bi
		| +---
	32	| aa1i
		+---
		+--- (virtual base AA4a)
	40	| {vbptr}
	48	| aa4ai
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	AA4d::$vbtable@AA4b@:
	 0	| 0
	 1	| 24 (AA4dd(AA4b+0)AA1)
	 2	| 40 (AA4dd(AA4d+0)AA4a)

	AA4d::$vbtable@AA4a@:
	 0	| 0
	 1	| -16 (AA4dd(AA4a+0)AA1)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA1      24       0       4 0
	            AA4a      40       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4d() {
		String expected =
		//@formatter:off
			"""
			/AA4d
			pack()
			Structure AA4d {
			   0   AA4d   24      "Self Base"
			   24   AA1   12      "Virtual Base"
			   40   AA4a   16      "Virtual Base"
			}
			Length: 56 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA4a/!internal/AA4a
			pack()
			Structure AA4a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ai   ""
			}
			Length: 16 Alignment: 8
			/AA4b/!internal/AA4b
			pack()
			Structure AA4b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4bi   ""
			}
			Length: 16 Alignment: 8
			/AA4d/!internal/AA4d
			pack()
			Structure AA4d {
			   0   AA4b   16      "Base"
			   16   int   4   aa4di   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4d() {
		String expected =
		//@formatter:off
			"""
			/AA4d
			pack()
			Structure AA4d {
			   0   AA4d   24      "Self Base"
			   24   char[32]   32      "Filler for 2 Unplaceable Virtual Bases: AA4a; AA1"
			}
			Length: 56 Alignment: 8
			/AA4b/!internal/AA4b
			pack()
			Structure AA4b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4bi   ""
			}
			Length: 16 Alignment: 8
			/AA4d/!internal/AA4d
			pack()
			Structure AA4d {
			   0   AA4b   16      "Base"
			   16   int   4   aa4di   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4d() {
		return convertCommentsToSpeculative(getExpectedStructAA4d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [AA4b]	[AA4d, AA4b]");
		results.put("VTABLE_00000028", "    40 vbt [AA4a]	[AA4d, AA4a]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4d_00000000());
		results.put("VTABLE_00000028", getVxtStructAA4d_00000028());
		return results;
	}

	private static String getVxtStructAA4d_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4d/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA1"
			   4   int   4      "AA4a"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA4d_00000028() {
		String expected =
		//@formatter:off
			"""
			/AA4d/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "AA1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4e	size(56):
		+---
	 0	| +--- (base class AA4a)
	 0	| | {vbptr}
	 8	| | aa4ai
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| aa4ei
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA1)
	24	| +--- (base class AA1a)
	24	| | aa1ai
		| +---
	28	| +--- (base class AA1b)
	28	| | aa1bi
		| +---
	32	| aa1i
		+---
		+--- (virtual base AA4b)
	40	| {vbptr}
	48	| aa4bi
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	AA4e::$vbtable@AA4a@:
	 0	| 0
	 1	| 24 (AA4ed(AA4a+0)AA1)
	 2	| 40 (AA4ed(AA4e+0)AA4b)

	AA4e::$vbtable@AA4b@:
	 0	| 0
	 1	| -16 (AA4ed(AA4b+0)AA1)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA1      24       0       4 0
	            AA4b      40       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4e() {
		String expected =
		//@formatter:off
			"""
			/AA4e
			pack()
			Structure AA4e {
			   0   AA4e   24      "Self Base"
			   24   AA1   12      "Virtual Base"
			   40   AA4b   16      "Virtual Base"
			}
			Length: 56 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA4a/!internal/AA4a
			pack()
			Structure AA4a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ai   ""
			}
			Length: 16 Alignment: 8
			/AA4b/!internal/AA4b
			pack()
			Structure AA4b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4bi   ""
			}
			Length: 16 Alignment: 8
			/AA4e/!internal/AA4e
			pack()
			Structure AA4e {
			   0   AA4a   16      "Base"
			   16   int   4   aa4ei   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4e() {
		String expected =
		//@formatter:off
			"""
			/AA4e
			pack()
			Structure AA4e {
			   0   AA4e   24      "Self Base"
			   24   char[32]   32      "Filler for 2 Unplaceable Virtual Bases: AA4b; AA1"
			}
			Length: 56 Alignment: 8
			/AA4a/!internal/AA4a
			pack()
			Structure AA4a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ai   ""
			}
			Length: 16 Alignment: 8
			/AA4e/!internal/AA4e
			pack()
			Structure AA4e {
			   0   AA4a   16      "Base"
			   16   int   4   aa4ei   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4e() {
		return convertCommentsToSpeculative(getExpectedStructAA4e());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4e() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [AA4a]	[AA4e, AA4a]");
		results.put("VTABLE_00000028", "    40 vbt [AA4b]	[AA4e, AA4b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4e() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4e_00000000());
		results.put("VTABLE_00000028", getVxtStructAA4e_00000028());
		return results;
	}

	private static String getVxtStructAA4e_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4e/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA1"
			   4   int   4      "AA4b"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA4e_00000028() {
		String expected =
		//@formatter:off
			"""
			/AA4e/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "AA1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4f	size(64):
		+---
	 0	| {vbptr}
	 8	| aa4fi
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA1)
	16	| +--- (base class AA1a)
	16	| | aa1ai
		| +---
	20	| +--- (base class AA1b)
	20	| | aa1bi
		| +---
	24	| aa1i
		+---
		+--- (virtual base AA4a)
	32	| {vbptr}
	40	| aa4ai
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA4b)
	48	| {vbptr}
	56	| aa4bi
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	AA4f::$vbtable@AA4f@:
	 0	| 0
	 1	| 16 (AA4fd(AA4f+0)AA1)
	 2	| 32 (AA4fd(AA4f+0)AA4a)
	 3	| 48 (AA4fd(AA4f+0)AA4b)

	AA4f::$vbtable@AA4a@:
	 0	| 0
	 1	| -16 (AA4fd(AA4a+0)AA1)

	AA4f::$vbtable@AA4b@:
	 0	| 0
	 1	| -32 (AA4fd(AA4b+0)AA1)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA1      16       0       4 0
	            AA4a      32       0       8 0
	            AA4b      48       0      12 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4f() {
		String expected =
		//@formatter:off
			"""
			/AA4f
			pack()
			Structure AA4f {
			   0   AA4f   16      "Self Base"
			   16   AA1   12      "Virtual Base"
			   32   AA4a   16      "Virtual Base"
			   48   AA4b   16      "Virtual Base"
			}
			Length: 64 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA4a/!internal/AA4a
			pack()
			Structure AA4a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ai   ""
			}
			Length: 16 Alignment: 8
			/AA4b/!internal/AA4b
			pack()
			Structure AA4b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4bi   ""
			}
			Length: 16 Alignment: 8
			/AA4f/!internal/AA4f
			pack()
			Structure AA4f {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4fi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4f() {
		String expected =
		//@formatter:off
			"""
			/AA4f
			pack()
			Structure AA4f {
			   0   AA4f   16      "Self Base"
			   16   char[48]   48      "Filler for 3 Unplaceable Virtual Bases: AA4a; AA4b; AA1"
			}
			Length: 64 Alignment: 8
			/AA4f/!internal/AA4f
			pack()
			Structure AA4f {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4fi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4f() {
		return convertCommentsToSpeculative(getExpectedStructAA4f());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4f() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [AA4f]	[AA4f]");
		results.put("VTABLE_00000020", "    32 vbt [AA4a]	[AA4f, AA4a]");
		results.put("VTABLE_00000030", "    48 vbt [AA4b]	[AA4f, AA4b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4f() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4f_00000000());
		results.put("VTABLE_00000020", getVxtStructAA4f_00000020());
		results.put("VTABLE_00000030", getVxtStructAA4f_00000030());
		return results;
	}

	private static String getVxtStructAA4f_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4f/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA1"
			   4   int   4      "AA4a"
			   8   int   4      "AA4b"
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA4f_00000020() {
		String expected =
		//@formatter:off
			"""
			/AA4f/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   int   4      "AA1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA4f_00000030() {
		String expected =
		//@formatter:off
			"""
			/AA4f/!internal/VTABLE_00000030
			pack()
			Structure VTABLE_00000030 {
			   0   int   4      "AA1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4g	size(36):
		+---
	 0	| +--- (base class AA4b)
	 0	| | {vbptr}
	 8	| | aa4bi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| aa4gi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA1)
	24	| +--- (base class AA1a)
	24	| | aa1ai
		| +---
	28	| +--- (base class AA1b)
	28	| | aa1bi
		| +---
	32	| aa1i
		+---

	AA4g::$vbtable@:
	 0	| 0
	 1	| 24 (AA4gd(AA4b+0)AA1)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	             AA1      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4g() {
		String expected =
		//@formatter:off
			"""
			/AA4g
			pack()
			Structure AA4g {
			   0   AA4g   24      "Self Base"
			   24   AA1   12      "Virtual Base"
			}
			Length: 40 Alignment: 8
			/AA1
			pack()
			Structure AA1 {
			   0   AA1a   4      "Base"
			   4   AA1b   4      "Base"
			   8   int   4   aa1i   ""
			}
			Length: 12 Alignment: 4
			/AA1a
			pack()
			Structure AA1a {
			   0   int   4   aa1ai   ""
			}
			Length: 4 Alignment: 4
			/AA1b
			pack()
			Structure AA1b {
			   0   int   4   aa1bi   ""
			}
			Length: 4 Alignment: 4
			/AA4b/!internal/AA4b
			pack()
			Structure AA4b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4bi   ""
			}
			Length: 16 Alignment: 8
			/AA4g/!internal/AA4g
			pack()
			Structure AA4g {
			   0   AA4b   16      "Base"
			   16   int   4   aa4gi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4g() {
		String expected =
		//@formatter:off
			"""
			/AA4g
			pack()
			Structure AA4g {
			   0   AA4g   24      "Self Base"
			   24   char[16]   16      "Filler for 1 Unplaceable Virtual Base: AA1"
			}
			Length: 40 Alignment: 8
			/AA4b/!internal/AA4b
			pack()
			Structure AA4b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4bi   ""
			}
			Length: 16 Alignment: 8
			/AA4g/!internal/AA4g
			pack()
			Structure AA4g {
			   0   AA4b   16      "Base"
			   16   int   4   aa4gi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4g() {
		return convertCommentsToSpeculative(getExpectedStructAA4g());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4g() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA4g, AA4b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4g() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4g_00000000());
		return results;
	}

	private static String getVxtStructAA4g_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4g/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA1"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4h	size(4):
		+---
	 0	| aa4hi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA4h() {
		String expected =
		//@formatter:off
			"""
			/AA4h
			pack()
			Structure AA4h {
			   0   int   4   aa4hi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4h() {
		return convertCommentsToSpeculative(getExpectedStructAA4h());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4h() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4h() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4j	size(20):
		+---
	 0	| {vbptr}
	 8	| aa4ji
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA4h)
	16	| aa4hi
		+---

	AA4j::$vbtable@:
	 0	| 0
	 1	| 16 (AA4jd(AA4j+0)AA4h)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA4h      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4j() {
		String expected =
		//@formatter:off
			"""
			/AA4j
			pack()
			Structure AA4j {
			   0   AA4j   16      "Self Base"
			   16   AA4h   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/AA4h
			pack()
			Structure AA4h {
			   0   int   4   aa4hi   ""
			}
			Length: 4 Alignment: 4
			/AA4j/!internal/AA4j
			pack()
			Structure AA4j {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ji   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4j() {
		String expected =
		//@formatter:off
			"""
			/AA4j
			pack()
			Structure AA4j {
			   0   AA4j   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: AA4h"
			}
			Length: 24 Alignment: 8
			/AA4j/!internal/AA4j
			pack()
			Structure AA4j {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ji   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4j() {
		return convertCommentsToSpeculative(getExpectedStructAA4j());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4j() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA4j]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4j() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4j_00000000());
		return results;
	}

	private static String getVxtStructAA4j_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4j/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA4h"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4k	size(20):
		+---
	 0	| {vbptr}
	 8	| aa4ki
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA4h)
	16	| aa4hi
		+---

	AA4k::$vbtable@:
	 0	| 0
	 1	| 16 (AA4kd(AA4k+0)AA4h)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA4h      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4k() {
		String expected =
		//@formatter:off
			"""
			/AA4k
			pack()
			Structure AA4k {
			   0   AA4k   16      "Self Base"
			   16   AA4h   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/AA4h
			pack()
			Structure AA4h {
			   0   int   4   aa4hi   ""
			}
			Length: 4 Alignment: 4
			/AA4k/!internal/AA4k
			pack()
			Structure AA4k {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ki   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4k() {
		String expected =
		//@formatter:off
			"""
			/AA4k
			pack()
			Structure AA4k {
			   0   AA4k   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: AA4h"
			}
			Length: 24 Alignment: 8
			/AA4k/!internal/AA4k
			pack()
			Structure AA4k {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ki   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4k() {
		return convertCommentsToSpeculative(getExpectedStructAA4k());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4k() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA4k]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4k() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4k_00000000());
		return results;
	}

	private static String getVxtStructAA4k_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4k/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA4h"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4m	size(28):
		+---
	 0	| +--- (base class AA4j)
	 0	| | {vbptr}
	 8	| | aa4ji
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| aa4mi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA4h)
	24	| aa4hi
		+---

	AA4m::$vbtable@:
	 0	| 0
	 1	| 24 (AA4md(AA4j+0)AA4h)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA4h      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4m() {
		String expected =
		//@formatter:off
			"""
			/AA4m
			pack()
			Structure AA4m {
			   0   AA4m   24      "Self Base"
			   24   AA4h   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/AA4h
			pack()
			Structure AA4h {
			   0   int   4   aa4hi   ""
			}
			Length: 4 Alignment: 4
			/AA4j/!internal/AA4j
			pack()
			Structure AA4j {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ji   ""
			}
			Length: 16 Alignment: 8
			/AA4m/!internal/AA4m
			pack()
			Structure AA4m {
			   0   AA4j   16      "Base"
			   16   int   4   aa4mi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4m() {
		String expected =
		//@formatter:off
			"""
			/AA4m
			pack()
			Structure AA4m {
			   0   AA4m   24      "Self Base"
			   24   char[8]   8      "Filler for 1 Unplaceable Virtual Base: AA4h"
			}
			Length: 32 Alignment: 8
			/AA4j/!internal/AA4j
			pack()
			Structure AA4j {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ji   ""
			}
			Length: 16 Alignment: 8
			/AA4m/!internal/AA4m
			pack()
			Structure AA4m {
			   0   AA4j   16      "Base"
			   16   int   4   aa4mi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4m() {
		return convertCommentsToSpeculative(getExpectedStructAA4m());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4m() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA4m, AA4j]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4m() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4m_00000000());
		return results;
	}

	private static String getVxtStructAA4m_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4m/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA4h"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4n	size(28):
		+---
	 0	| +--- (base class AA4k)
	 0	| | {vbptr}
	 8	| | aa4ki
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| aa4ni
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA4h)
	24	| aa4hi
		+---

	AA4n::$vbtable@:
	 0	| 0
	 1	| 24 (AA4nd(AA4k+0)AA4h)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA4h      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4n() {
		String expected =
		//@formatter:off
			"""
			/AA4n
			pack()
			Structure AA4n {
			   0   AA4n   24      "Self Base"
			   24   AA4h   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/AA4h
			pack()
			Structure AA4h {
			   0   int   4   aa4hi   ""
			}
			Length: 4 Alignment: 4
			/AA4k/!internal/AA4k
			pack()
			Structure AA4k {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ki   ""
			}
			Length: 16 Alignment: 8
			/AA4n/!internal/AA4n
			pack()
			Structure AA4n {
			   0   AA4k   16      "Base"
			   16   int   4   aa4ni   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4n() {
		String expected =
		//@formatter:off
			"""
			/AA4n
			pack()
			Structure AA4n {
			   0   AA4n   24      "Self Base"
			   24   char[8]   8      "Filler for 1 Unplaceable Virtual Base: AA4h"
			}
			Length: 32 Alignment: 8
			/AA4k/!internal/AA4k
			pack()
			Structure AA4k {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ki   ""
			}
			Length: 16 Alignment: 8
			/AA4n/!internal/AA4n
			pack()
			Structure AA4n {
			   0   AA4k   16      "Base"
			   16   int   4   aa4ni   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4n() {
		return convertCommentsToSpeculative(getExpectedStructAA4n());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4n() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA4n, AA4k]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4n() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4n_00000000());
		return results;
	}

	private static String getVxtStructAA4n_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4n/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA4h"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4p	size(36):
		+---
	 0	| +--- (base class AA4m)
	 0	| | +--- (base class AA4j)
	 0	| | | {vbptr}
	 8	| | | aa4ji
  		| | | <alignment member> (size=4)
  		| | | <alignment member> (size=4)
		| | +---
	16	| | aa4mi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	24	| aa4pi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA4h)
	32	| aa4hi
		+---

	AA4p::$vbtable@:
	 0	| 0
	 1	| 32 (AA4pd(AA4j+0)AA4h)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA4h      32       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4p() {
		String expected =
		//@formatter:off
			"""
			/AA4p
			pack()
			Structure AA4p {
			   0   AA4p   32      "Self Base"
			   32   AA4h   4      "Virtual Base"
			}
			Length: 40 Alignment: 8
			/AA4h
			pack()
			Structure AA4h {
			   0   int   4   aa4hi   ""
			}
			Length: 4 Alignment: 4
			/AA4j/!internal/AA4j
			pack()
			Structure AA4j {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ji   ""
			}
			Length: 16 Alignment: 8
			/AA4m/!internal/AA4m
			pack()
			Structure AA4m {
			   0   AA4j   16      "Base"
			   16   int   4   aa4mi   ""
			}
			Length: 24 Alignment: 8
			/AA4p/!internal/AA4p
			pack()
			Structure AA4p {
			   0   AA4m   24      "Base"
			   24   int   4   aa4pi   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4p() {
		String expected =
		//@formatter:off
			"""
			/AA4p
			pack()
			Structure AA4p {
			   0   AA4p   32      "Self Base"
			   32   char[8]   8      "Filler for 1 Unplaceable Virtual Base: AA4h"
			}
			Length: 40 Alignment: 8
			/AA4j/!internal/AA4j
			pack()
			Structure AA4j {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ji   ""
			}
			Length: 16 Alignment: 8
			/AA4m/!internal/AA4m
			pack()
			Structure AA4m {
			   0   AA4j   16      "Base"
			   16   int   4   aa4mi   ""
			}
			Length: 24 Alignment: 8
			/AA4p/!internal/AA4p
			pack()
			Structure AA4p {
			   0   AA4m   24      "Base"
			   24   int   4   aa4pi   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4p() {
		return convertCommentsToSpeculative(getExpectedStructAA4p());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4p() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA4p, AA4m, AA4j]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4p() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4p_00000000());
		return results;
	}

	private static String getVxtStructAA4p_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4p/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA4h"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA4q	size(60):
		+---
	 0	| +--- (base class AA4n)
	 0	| | +--- (base class AA4k)
	 0	| | | {vbptr}
	 8	| | | aa4ki
  		| | | <alignment member> (size=4)
  		| | | <alignment member> (size=4)
		| | +---
	16	| | aa4ni
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	24	| +--- (base class AA4m)
	24	| | +--- (base class AA4j)
	24	| | | {vbptr}
	32	| | | aa4ji
  		| | | <alignment member> (size=4)
  		| | | <alignment member> (size=4)
		| | +---
	40	| | aa4mi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	48	| aa4qi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA4h)
	56	| aa4hi
		+---

	AA4q::$vbtable@AA4n@:
	 0	| 0
	 1	| 56 (AA4qd(AA4k+0)AA4h)

	AA4q::$vbtable@AA4m@:
	 0	| 0
	 1	| 32 (AA4qd(AA4j+0)AA4h)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA4h      56       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA4q() {
		String expected =
		//@formatter:off
			"""
			/AA4q
			pack()
			Structure AA4q {
			   0   AA4q   56      "Self Base"
			   56   AA4h   4      "Virtual Base"
			}
			Length: 64 Alignment: 8
			/AA4h
			pack()
			Structure AA4h {
			   0   int   4   aa4hi   ""
			}
			Length: 4 Alignment: 4
			/AA4j/!internal/AA4j
			pack()
			Structure AA4j {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ji   ""
			}
			Length: 16 Alignment: 8
			/AA4k/!internal/AA4k
			pack()
			Structure AA4k {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ki   ""
			}
			Length: 16 Alignment: 8
			/AA4m/!internal/AA4m
			pack()
			Structure AA4m {
			   0   AA4j   16      "Base"
			   16   int   4   aa4mi   ""
			}
			Length: 24 Alignment: 8
			/AA4n/!internal/AA4n
			pack()
			Structure AA4n {
			   0   AA4k   16      "Base"
			   16   int   4   aa4ni   ""
			}
			Length: 24 Alignment: 8
			/AA4q/!internal/AA4q
			pack()
			Structure AA4q {
			   0   AA4n   24      "Base"
			   24   AA4m   24      "Base"
			   48   int   4   aa4qi   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA4q() {
		String expected =
		//@formatter:off
			"""
			/AA4q
			pack()
			Structure AA4q {
			   0   AA4q   56      "Self Base"
			   56   char[8]   8      "Filler for 1 Unplaceable Virtual Base: AA4h"
			}
			Length: 64 Alignment: 8
			/AA4j/!internal/AA4j
			pack()
			Structure AA4j {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ji   ""
			}
			Length: 16 Alignment: 8
			/AA4k/!internal/AA4k
			pack()
			Structure AA4k {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa4ki   ""
			}
			Length: 16 Alignment: 8
			/AA4m/!internal/AA4m
			pack()
			Structure AA4m {
			   0   AA4j   16      "Base"
			   16   int   4   aa4mi   ""
			}
			Length: 24 Alignment: 8
			/AA4n/!internal/AA4n
			pack()
			Structure AA4n {
			   0   AA4k   16      "Base"
			   16   int   4   aa4ni   ""
			}
			Length: 24 Alignment: 8
			/AA4q/!internal/AA4q
			pack()
			Structure AA4q {
			   0   AA4n   24      "Base"
			   24   AA4m   24      "Base"
			   48   int   4   aa4qi   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA4q() {
		return convertCommentsToSpeculative(getExpectedStructAA4q());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA4q() {
		Map<String, String> results = new TreeMap<>();
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000000", "     0 vbt [AA4n]	[AA4q, AA4n, AA4k]");
		results.put("VTABLE_00000000", null);
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000018", "    24 vbt [AA4m]	[AA4q, AA4m, AA4j]");
		results.put("VTABLE_00000018", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA4q() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA4q_00000000());
		results.put("VTABLE_00000018", getVxtStructAA4q_00000018());
		return results;
	}

	private static String getVxtStructAA4q_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA4q/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA4h"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA4q_00000018() {
		String expected =
		//@formatter:off
			"""
			/AA4q/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   int   4      "AA4h"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA5a	size(4):
		+---
	 0	| aa5ai
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA5a() {
		String expected =
		//@formatter:off
			"""
			/AA5a
			pack()
			Structure AA5a {
			   0   int   4   aa5ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA5a() {
		return convertCommentsToSpeculative(getExpectedStructAA5a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA5a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA5a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA5b	size(4):
		+---
	 0	| aa5bi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA5b() {
		String expected =
		//@formatter:off
			"""
			/AA5b
			pack()
			Structure AA5b {
			   0   int   4   aa5bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA5b() {
		return convertCommentsToSpeculative(getExpectedStructAA5b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA5b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA5b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA5c	size(4):
		+---
	 0	| aa5ci
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA5c() {
		String expected =
		//@formatter:off
			"""
			/AA5c
			pack()
			Structure AA5c {
			   0   int   4   aa5ci   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA5c() {
		return convertCommentsToSpeculative(getExpectedStructAA5c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA5c() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA5c() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA5d	size(4):
		+---
	 0	| aa5di
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA5d() {
		String expected =
		//@formatter:off
			"""
			/AA5d
			pack()
			Structure AA5d {
			   0   int   4   aa5di   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA5d() {
		return convertCommentsToSpeculative(getExpectedStructAA5d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA5d() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA5d() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA5e	size(28):
		+---
	 0	| +--- (base class AA5a)
	 0	| | aa5ai
		| +---
	 8	| {vbptr}
	16	| aa5ei
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA5b)
	24	| aa5bi
		+---

	AA5e::$vbtable@:
	 0	| -8
	 1	| 16 (AA5ed(AA5e+8)AA5b)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA5b      24       8       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA5e() {
		String expected =
		//@formatter:off
			"""
			/AA5e
			pack()
			Structure AA5e {
			   0   AA5e   24      "Self Base"
			   24   AA5b   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/AA5a
			pack()
			Structure AA5a {
			   0   int   4   aa5ai   ""
			}
			Length: 4 Alignment: 4
			/AA5b
			pack()
			Structure AA5b {
			   0   int   4   aa5bi   ""
			}
			Length: 4 Alignment: 4
			/AA5e/!internal/AA5e
			pack()
			Structure AA5e {
			   0   AA5a   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5ei   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA5e() {
		String expected =
		//@formatter:off
			"""
			/AA5e
			pack()
			Structure AA5e {
			   0   AA5e   24      "Self Base"
			   24   char[8]   8      "Filler for 1 Unplaceable Virtual Base: AA5b"
			}
			Length: 32 Alignment: 8
			/AA5a
			pack()
			Structure AA5a {
			   0   int   4   aa5ai   ""
			}
			Length: 4 Alignment: 4
			/AA5e/!internal/AA5e
			pack()
			Structure AA5e {
			   0   AA5a   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5ei   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA5e() {
		return convertCommentsToSpeculative(getExpectedStructAA5e());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA5e() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt []	[AA5e]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA5e() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructAA5e_00000008());
		return results;
	}

	private static String getVxtStructAA5e_00000008() {
		String expected =
		//@formatter:off
			"""
			/AA5e/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "AA5b"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA5f	size(28):
		+---
	 0	| +--- (base class AA5c)
	 0	| | aa5ci
		| +---
	 8	| {vbptr}
	16	| aa5fi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA5d)
	24	| aa5di
		+---

	AA5f::$vbtable@:
	 0	| -8
	 1	| 16 (AA5fd(AA5f+8)AA5d)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA5d      24       8       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA5f() {
		String expected =
		//@formatter:off
			"""
			/AA5f
			pack()
			Structure AA5f {
			   0   AA5f   24      "Self Base"
			   24   AA5d   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/AA5c
			pack()
			Structure AA5c {
			   0   int   4   aa5ci   ""
			}
			Length: 4 Alignment: 4
			/AA5d
			pack()
			Structure AA5d {
			   0   int   4   aa5di   ""
			}
			Length: 4 Alignment: 4
			/AA5f/!internal/AA5f
			pack()
			Structure AA5f {
			   0   AA5c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5fi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA5f() {
		String expected =
		//@formatter:off
			"""
			/AA5f
			pack()
			Structure AA5f {
			   0   AA5f   24      "Self Base"
			   24   char[8]   8      "Filler for 1 Unplaceable Virtual Base: AA5d"
			}
			Length: 32 Alignment: 8
			/AA5c
			pack()
			Structure AA5c {
			   0   int   4   aa5ci   ""
			}
			Length: 4 Alignment: 4
			/AA5f/!internal/AA5f
			pack()
			Structure AA5f {
			   0   AA5c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5fi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA5f() {
		return convertCommentsToSpeculative(getExpectedStructAA5f());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA5f() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt []	[AA5f]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA5f() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructAA5f_00000008());
		return results;
	}

	private static String getVxtStructAA5f_00000008() {
		String expected =
		//@formatter:off
			"""
			/AA5f/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "AA5d"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA5g	size(56):
		+---
	 0	| +--- (base class AA5c)
	 0	| | aa5ci
		| +---
	 8	| {vbptr}
	16	| aa5gi
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA5b)
	24	| aa5bi
		+---
		+--- (virtual base AA5e)
	32	| +--- (base class AA5a)
	32	| | aa5ai
		| +---
	40	| {vbptr}
	48	| aa5ei
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	AA5g::$vbtable@AA5g@:
	 0	| -8
	 1	| 16 (AA5gd(AA5g+8)AA5b)
	 2	| 24 (AA5gd(AA5g+8)AA5e)

	AA5g::$vbtable@AA5e@:
	 0	| -8
	 1	| -16 (AA5gd(AA5e+8)AA5b)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA5b      24       8       4 0
	            AA5e      32       8       8 0
	 */
	//@formatter:on
	private static String getExpectedStructAA5g() {
		String expected =
		//@formatter:off
			"""
			/AA5g
			pack()
			Structure AA5g {
			   0   AA5g   24      "Self Base"
			   24   AA5b   4      "Virtual Base"
			   32   AA5e   24      "Virtual Base"
			}
			Length: 56 Alignment: 8
			/AA5a
			pack()
			Structure AA5a {
			   0   int   4   aa5ai   ""
			}
			Length: 4 Alignment: 4
			/AA5b
			pack()
			Structure AA5b {
			   0   int   4   aa5bi   ""
			}
			Length: 4 Alignment: 4
			/AA5c
			pack()
			Structure AA5c {
			   0   int   4   aa5ci   ""
			}
			Length: 4 Alignment: 4
			/AA5e/!internal/AA5e
			pack()
			Structure AA5e {
			   0   AA5a   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5ei   ""
			}
			Length: 24 Alignment: 8
			/AA5g/!internal/AA5g
			pack()
			Structure AA5g {
			   0   AA5c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5gi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA5g() {
		String expected =
		//@formatter:off
			"""
			/AA5g
			pack()
			Structure AA5g {
			   0   AA5g   24      "Self Base"
			   24   char[32]   32      "Filler for 2 Unplaceable Virtual Bases: AA5e; AA5b"
			}
			Length: 56 Alignment: 8
			/AA5c
			pack()
			Structure AA5c {
			   0   int   4   aa5ci   ""
			}
			Length: 4 Alignment: 4
			/AA5g/!internal/AA5g
			pack()
			Structure AA5g {
			   0   AA5c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5gi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA5g() {
		return convertCommentsToSpeculative(getExpectedStructAA5g());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA5g() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt [AA5g]	[AA5g]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000028", "    40 vbt [AA5e]	[AA5g, AA5e]");
		results.put("VTABLE_00000028", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA5g() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructAA5g_00000008());
		results.put("VTABLE_00000028", getVxtStructAA5g_00000028());
		return results;
	}

	private static String getVxtStructAA5g_00000008() {
		String expected =
		//@formatter:off
			"""
			/AA5g/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "AA5b"
			   4   int   4      "AA5e"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA5g_00000028() {
		String expected =
		//@formatter:off
			"""
			/AA5g/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "AA5b"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA5h	size(56):
		+---
	 0	| +--- (base class AA5a)
	 0	| | aa5ai
		| +---
	 8	| {vbptr}
	16	| aa5hi
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA5d)
	24	| aa5di
		+---
		+--- (virtual base AA5f)
	32	| +--- (base class AA5c)
	32	| | aa5ci
		| +---
	40	| {vbptr}
	48	| aa5fi
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	AA5h::$vbtable@AA5h@:
	 0	| -8
	 1	| 16 (AA5hd(AA5h+8)AA5d)
	 2	| 24 (AA5hd(AA5h+8)AA5f)

	AA5h::$vbtable@AA5f@:
	 0	| -8
	 1	| -16 (AA5hd(AA5f+8)AA5d)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA5d      24       8       4 0
	            AA5f      32       8       8 0
	 */
	//@formatter:on
	private static String getExpectedStructAA5h() {
		String expected =
		//@formatter:off
			"""
			/AA5h
			pack()
			Structure AA5h {
			   0   AA5h   24      "Self Base"
			   24   AA5d   4      "Virtual Base"
			   32   AA5f   24      "Virtual Base"
			}
			Length: 56 Alignment: 8
			/AA5a
			pack()
			Structure AA5a {
			   0   int   4   aa5ai   ""
			}
			Length: 4 Alignment: 4
			/AA5c
			pack()
			Structure AA5c {
			   0   int   4   aa5ci   ""
			}
			Length: 4 Alignment: 4
			/AA5d
			pack()
			Structure AA5d {
			   0   int   4   aa5di   ""
			}
			Length: 4 Alignment: 4
			/AA5f/!internal/AA5f
			pack()
			Structure AA5f {
			   0   AA5c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5fi   ""
			}
			Length: 24 Alignment: 8
			/AA5h/!internal/AA5h
			pack()
			Structure AA5h {
			   0   AA5a   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5hi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA5h() {
		String expected =
		//@formatter:off
			"""
			/AA5h
			pack()
			Structure AA5h {
			   0   AA5h   24      "Self Base"
			   24   char[32]   32      "Filler for 2 Unplaceable Virtual Bases: AA5f; AA5d"
			}
			Length: 56 Alignment: 8
			/AA5a
			pack()
			Structure AA5a {
			   0   int   4   aa5ai   ""
			}
			Length: 4 Alignment: 4
			/AA5h/!internal/AA5h
			pack()
			Structure AA5h {
			   0   AA5a   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5hi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA5h() {
		return convertCommentsToSpeculative(getExpectedStructAA5h());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA5h() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt [AA5h]	[AA5h]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000028", "    40 vbt [AA5f]	[AA5h, AA5f]");
		results.put("VTABLE_00000028", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA5h() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructAA5h_00000008());
		results.put("VTABLE_00000028", getVxtStructAA5h_00000028());
		return results;
	}

	private static String getVxtStructAA5h_00000008() {
		String expected =
		//@formatter:off
			"""
			/AA5h/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "AA5d"
			   4   int   4      "AA5f"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA5h_00000028() {
		String expected =
		//@formatter:off
			"""
			/AA5h/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   int   4      "AA5d"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA5j	size(120):
		+---
	 0	| +--- (base class AA5g)
	 0	| | +--- (base class AA5c)
	 0	| | | aa5ci
		| | +---
	 8	| | {vbptr}
	16	| | aa5gi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	24	| +--- (base class AA5h)
	24	| | +--- (base class AA5a)
	24	| | | aa5ai
		| | +---
	32	| | {vbptr}
	40	| | aa5hi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	48	| aa5ji
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA5b)
	56	| aa5bi
		+---
		+--- (virtual base AA5e)
	64	| +--- (base class AA5a)
	64	| | aa5ai
		| +---
	72	| {vbptr}
	80	| aa5ei
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA5d)
	88	| aa5di
		+---
		+--- (virtual base AA5f)
	96	| +--- (base class AA5c)
	96	| | aa5ci
		| +---
	104	| {vbptr}
	112	| aa5fi
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	AA5j::$vbtable@AA5g@:
	 0	| -8
	 1	| 48 (AA5jd(AA5g+8)AA5b)
	 2	| 56 (AA5jd(AA5g+8)AA5e)
	 3	| 80 (AA5jd(AA5j+8)AA5d)
	 4	| 88 (AA5jd(AA5j+8)AA5f)

	AA5j::$vbtable@AA5h@:
	 0	| -8
	 1	| 56 (AA5jd(AA5h+8)AA5d)
	 2	| 64 (AA5jd(AA5h+8)AA5f)

	AA5j::$vbtable@AA5e@:
	 0	| -8
	 1	| -16 (AA5jd(AA5e+8)AA5b)

	AA5j::$vbtable@AA5f@:
	 0	| -8
	 1	| -16 (AA5jd(AA5f+8)AA5d)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA5b      56       8       4 0
	            AA5e      64       8       8 0
	            AA5d      88       8      12 0
	            AA5f      96       8      16 0
	 */
	//@formatter:on
	private static String getExpectedStructAA5j() {
		String expected =
		//@formatter:off
			"""
			/AA5j
			pack()
			Structure AA5j {
			   0   AA5j   56      "Self Base"
			   56   AA5b   4      "Virtual Base"
			   64   AA5e   24      "Virtual Base"
			   88   AA5d   4      "Virtual Base"
			   96   AA5f   24      "Virtual Base"
			}
			Length: 120 Alignment: 8
			/AA5a
			pack()
			Structure AA5a {
			   0   int   4   aa5ai   ""
			}
			Length: 4 Alignment: 4
			/AA5b
			pack()
			Structure AA5b {
			   0   int   4   aa5bi   ""
			}
			Length: 4 Alignment: 4
			/AA5c
			pack()
			Structure AA5c {
			   0   int   4   aa5ci   ""
			}
			Length: 4 Alignment: 4
			/AA5d
			pack()
			Structure AA5d {
			   0   int   4   aa5di   ""
			}
			Length: 4 Alignment: 4
			/AA5e/!internal/AA5e
			pack()
			Structure AA5e {
			   0   AA5a   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5ei   ""
			}
			Length: 24 Alignment: 8
			/AA5f/!internal/AA5f
			pack()
			Structure AA5f {
			   0   AA5c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5fi   ""
			}
			Length: 24 Alignment: 8
			/AA5g/!internal/AA5g
			pack()
			Structure AA5g {
			   0   AA5c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5gi   ""
			}
			Length: 24 Alignment: 8
			/AA5h/!internal/AA5h
			pack()
			Structure AA5h {
			   0   AA5a   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5hi   ""
			}
			Length: 24 Alignment: 8
			/AA5j/!internal/AA5j
			pack()
			Structure AA5j {
			   0   AA5g   24      "Base"
			   24   AA5h   24      "Base"
			   48   int   4   aa5ji   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA5j() {
		String expected =
		//@formatter:off
			"""
			/AA5j
			pack()
			Structure AA5j {
			   0   AA5j   56      "Self Base"
			   56   char[64]   64      "Filler for 4 Unplaceable Virtual Bases: AA5b; AA5e; AA5d; AA5f"
			}
			Length: 120 Alignment: 8
			/AA5a
			pack()
			Structure AA5a {
			   0   int   4   aa5ai   ""
			}
			Length: 4 Alignment: 4
			/AA5c
			pack()
			Structure AA5c {
			   0   int   4   aa5ci   ""
			}
			Length: 4 Alignment: 4
			/AA5g/!internal/AA5g
			pack()
			Structure AA5g {
			   0   AA5c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5gi   ""
			}
			Length: 24 Alignment: 8
			/AA5h/!internal/AA5h
			pack()
			Structure AA5h {
			   0   AA5a   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa5hi   ""
			}
			Length: 24 Alignment: 8
			/AA5j/!internal/AA5j
			pack()
			Structure AA5j {
			   0   AA5g   24      "Base"
			   24   AA5h   24      "Base"
			   48   int   4   aa5ji   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA5j() {
		return convertCommentsToSpeculative(getExpectedStructAA5j());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA5j() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt [AA5g]	[AA5j, AA5g]");
		results.put("VTABLE_00000020", "    32 vbt [AA5h]	[AA5j, AA5h]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000048", "    72 vbt [AA5e]	[AA5j, AA5g, AA5e]");
		results.put("VTABLE_00000048", null);
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000068", "   104 vbt [AA5f]	[AA5j, AA5h, AA5f]");
		results.put("VTABLE_00000068", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA5j() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructAA5j_00000008());
		results.put("VTABLE_00000020", getVxtStructAA5j_00000020());
		results.put("VTABLE_00000048", getVxtStructAA5j_00000048());
		results.put("VTABLE_00000068", getVxtStructAA5j_00000068());
		return results;
	}

	private static String getVxtStructAA5j_00000008() {
		String expected =
		//@formatter:off
			"""
			/AA5j/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "AA5b"
			   4   int   4      "AA5e"
			   8   int   4      "AA5d"
			   12   int   4      "AA5f"
			}
			Length: 16 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA5j_00000020() {
		String expected =
		//@formatter:off
			"""
			/AA5j/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   int   4      "AA5d"
			   4   int   4      "AA5f"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA5j_00000048() {
		String expected =
		//@formatter:off
			"""
			/AA5j/!internal/VTABLE_00000048
			pack()
			Structure VTABLE_00000048 {
			   0   int   4      "AA5b"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA5j_00000068() {
		String expected =
		//@formatter:off
			"""
			/AA5j/!internal/VTABLE_00000068
			pack()
			Structure VTABLE_00000068 {
			   0   int   4      "AA5d"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA6a	size(4):
		+---
	 0	| aa6ai
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA6a() {
		String expected =
		//@formatter:off
			"""
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA6a() {
		return convertCommentsToSpeculative(getExpectedStructAA6a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA6a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA6a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA6b	size(8):
		+---
	 0	| +--- (base class AA6a)
	 0	| | aa6ai
		| +---
	 4	| aa6bi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA6b() {
		String expected =
		//@formatter:off
			"""
			/AA6b
			pack()
			Structure AA6b {
			   0   AA6a   4      "Base"
			   4   int   4   aa6bi   ""
			}
			Length: 8 Alignment: 4
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA6b() {
		return convertCommentsToSpeculative(getExpectedStructAA6b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA6b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA6b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA6c	size(20):
		+---
	 0	| {vbptr}
	 8	| aa6ci
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA6a)
	16	| aa6ai
		+---

	AA6c::$vbtable@:
	 0	| 0
	 1	| 16 (AA6cd(AA6c+0)AA6a)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA6a      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA6c() {
		String expected =
		//@formatter:off
			"""
			/AA6c
			pack()
			Structure AA6c {
			   0   AA6c   16      "Self Base"
			   16   AA6a   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4
			/AA6c/!internal/AA6c
			pack()
			Structure AA6c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa6ci   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA6c() {
		String expected =
		//@formatter:off
			"""
			/AA6c
			pack()
			Structure AA6c {
			   0   AA6c   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: AA6a"
			}
			Length: 24 Alignment: 8
			/AA6c/!internal/AA6c
			pack()
			Structure AA6c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa6ci   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA6c() {
		return convertCommentsToSpeculative(getExpectedStructAA6c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA6c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA6c]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA6c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA6c_00000000());
		return results;
	}

	private static String getVxtStructAA6c_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA6c/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA6a"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA6d	size(8):
		+---
	 0	| aa6di
	 4	| AA6a aa6a
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA6d() {
		String expected =
		//@formatter:off
			"""
			/AA6d
			pack()
			Structure AA6d {
			   0   int   4   aa6di   ""
			   4   AA6a   4   aa6a   ""
			}
			Length: 8 Alignment: 4
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA6d() {
		return convertCommentsToSpeculative(getExpectedStructAA6d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA6d() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA6d() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA6e	size(12):
		+---
	 0	| +--- (base class AA6a)
	 0	| | aa6ai
		| +---
	 4	| aa6ei
	 8	| AA6a aa6a
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA6e() {
		String expected =
		//@formatter:off
			"""
			/AA6e
			pack()
			Structure AA6e {
			   0   AA6a   4      "Base"
			   4   int   4   aa6ei   ""
			   8   AA6a   4   aa6a   ""
			}
			Length: 12 Alignment: 4
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA6e() {
		return convertCommentsToSpeculative(getExpectedStructAA6e());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA6e() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA6e() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA6f	size(16):
		+---
	 0	| +--- (base class AA6b)
	 0	| | +--- (base class AA6a)
	 0	| | | aa6ai
		| | +---
	 4	| | aa6bi
		| +---
	 8	| aa6fi
	12	| AA6a aa6a
		+---
	 */
	//@formatter:on
	private static String getExpectedStructAA6f() {
		String expected =
		//@formatter:off
			"""
			/AA6f
			pack()
			Structure AA6f {
			   0   AA6b   8      "Base"
			   8   int   4   aa6fi   ""
			   12   AA6a   4   aa6a   ""
			}
			Length: 16 Alignment: 4
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4
			/AA6b
			pack()
			Structure AA6b {
			   0   AA6a   4      "Base"
			   4   int   4   aa6bi   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA6f() {
		return convertCommentsToSpeculative(getExpectedStructAA6f());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA6f() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA6f() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA6g	size(28):
		+---
	 0	| +--- (base class AA6c)
	 0	| | {vbptr}
	 8	| | aa6ci
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| aa6gi
	20	| AA6a aa6a
		+---
		+--- (virtual base AA6a)
	24	| aa6ai
		+---

	AA6g::$vbtable@:
	 0	| 0
	 1	| 24 (AA6gd(AA6c+0)AA6a)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA6a      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructAA6g() {
		String expected =
		//@formatter:off
			"""
			/AA6g
			pack()
			Structure AA6g {
			   0   AA6g   24      "Self Base"
			   24   AA6a   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4
			/AA6c/!internal/AA6c
			pack()
			Structure AA6c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa6ci   ""
			}
			Length: 16 Alignment: 8
			/AA6g/!internal/AA6g
			pack()
			Structure AA6g {
			   0   AA6c   16      "Base"
			   16   int   4   aa6gi   ""
			   20   AA6a   4   aa6a   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA6g() {
		String expected =
		//@formatter:off
			"""
			/AA6g
			pack()
			Structure AA6g {
			   0   AA6g   24      "Self Base"
			   24   char[8]   8      "Filler for 1 Unplaceable Virtual Base: AA6a"
			}
			Length: 32 Alignment: 8
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4
			/AA6c/!internal/AA6c
			pack()
			Structure AA6c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa6ci   ""
			}
			Length: 16 Alignment: 8
			/AA6g/!internal/AA6g
			pack()
			Structure AA6g {
			   0   AA6c   16      "Base"
			   16   int   4   aa6gi   ""
			   20   AA6a   4   aa6a   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA6g() {
		return convertCommentsToSpeculative(getExpectedStructAA6g());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA6g() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[AA6g, AA6c]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA6g() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA6g_00000000());
		return results;
	}

	private static String getVxtStructAA6g_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA6g/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA6a"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA6h	size(40):
		+---
	 0	| {vbptr}
	 8	| aa6hi
	12	| AA6a aa6a
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA6a)
	16	| aa6ai
		+---
		+--- (virtual base AA6c)
	24	| {vbptr}
	32	| aa6ci
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	AA6h::$vbtable@AA6h@:
	 0	| 0
	 1	| 16 (AA6hd(AA6h+0)AA6a)
	 2	| 24 (AA6hd(AA6h+0)AA6c)

	AA6h::$vbtable@AA6c@:
	 0	| 0
	 1	| -8 (AA6hd(AA6c+0)AA6a)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA6a      16       0       4 0
	            AA6c      24       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructAA6h() {
		String expected =
		//@formatter:off
			"""
			/AA6h
			pack()
			Structure AA6h {
			   0   AA6h   16      "Self Base"
			   16   AA6a   4      "Virtual Base"
			   24   AA6c   16      "Virtual Base"
			}
			Length: 40 Alignment: 8
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4
			/AA6c/!internal/AA6c
			pack()
			Structure AA6c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa6ci   ""
			}
			Length: 16 Alignment: 8
			/AA6h/!internal/AA6h
			pack()
			Structure AA6h {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa6hi   ""
			   12   AA6a   4   aa6a   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA6h() {
		String expected =
		//@formatter:off
			"""
			/AA6h
			pack()
			Structure AA6h {
			   0   AA6h   16      "Self Base"
			   16   char[24]   24      "Filler for 2 Unplaceable Virtual Bases: AA6c; AA6a"
			}
			Length: 40 Alignment: 8
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4
			/AA6h/!internal/AA6h
			pack()
			Structure AA6h {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa6hi   ""
			   12   AA6a   4   aa6a   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA6h() {
		return convertCommentsToSpeculative(getExpectedStructAA6h());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA6h() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [AA6h]	[AA6h]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000018", "    24 vbt [AA6c]	[AA6h, AA6c]");
		results.put("VTABLE_00000018", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA6h() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA6h_00000000());
		results.put("VTABLE_00000018", getVxtStructAA6h_00000018());
		return results;
	}

	private static String getVxtStructAA6h_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA6h/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA6a"
			   4   int   4      "AA6c"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA6h_00000018() {
		String expected =
		//@formatter:off
			"""
			/AA6h/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   int   4      "AA6a"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA6j	size(48):
		+---
	 0	| {vbptr}
	 8	| aa6hj
	12	| AA6a aa6a
	16	| paa6j
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA6a)
	24	| aa6ai
		+---
		+--- (virtual base AA6c)
	32	| {vbptr}
	40	| aa6ci
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	AA6j::$vbtable@AA6j@:
	 0	| 0
	 1	| 24 (AA6jd(AA6j+0)AA6a)
	 2	| 32 (AA6jd(AA6j+0)AA6c)

	AA6j::$vbtable@AA6c@:
	 0	| 0
	 1	| -8 (AA6jd(AA6c+0)AA6a)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA6a      24       0       4 0
	            AA6c      32       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructAA6j() {
		String expected =
		//@formatter:off
			"""
			/AA6j
			pack()
			Structure AA6j {
			   0   AA6j   24      "Self Base"
			   24   AA6a   4      "Virtual Base"
			   32   AA6c   16      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4
			/AA6c/!internal/AA6c
			pack()
			Structure AA6c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa6ci   ""
			}
			Length: 16 Alignment: 8
			/AA6j/!internal/AA6j
			pack()
			Structure AA6j {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa6hj   ""
			   12   AA6a   4   aa6a   ""
			   16   AA6j *   8   paa6j   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA6j() {
		String expected =
		//@formatter:off
			"""
			/AA6j
			pack()
			Structure AA6j {
			   0   AA6j   24      "Self Base"
			   24   char[24]   24      "Filler for 2 Unplaceable Virtual Bases: AA6c; AA6a"
			}
			Length: 48 Alignment: 8
			/AA6a
			pack()
			Structure AA6a {
			   0   int   4   aa6ai   ""
			}
			Length: 4 Alignment: 4
			/AA6j/!internal/AA6j
			pack()
			Structure AA6j {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   aa6hj   ""
			   12   AA6a   4   aa6a   ""
			   16   AA6j *   8   paa6j   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA6j() {
		return convertCommentsToSpeculative(getExpectedStructAA6j());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA6j() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [AA6j]	[AA6j]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000020", "    32 vbt [AA6c]	[AA6j, AA6c]");
		results.put("VTABLE_00000020", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA6j() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA6j_00000000());
		results.put("VTABLE_00000020", getVxtStructAA6j_00000020());
		return results;
	}

	private static String getVxtStructAA6j_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA6j/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "AA6a"
			   4   int   4      "AA6c"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA6j_00000020() {
		String expected =
		//@formatter:off
			"""
			/AA6j/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   int   4      "AA6a"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA7a	size(16):
		+---
	 0	| {vfptr}
	 8	| aa7ai
  		| <alignment member> (size=4)
		+---

	AA7a::$vftable@:
		| &AA7a_meta
		|  0
	 0	| &AA7a::pvf1
	 1	| &AA7a::pvf2

	AA7a::pvf1 this adjustor: 0
	AA7a::pvf2 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructAA7a() {
		String expected =
		//@formatter:off
			"""
			/AA7a
			pack()
			Structure AA7a {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   aa7ai   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA7a() {
		return convertCommentsToSpeculative(getExpectedStructAA7a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA7a() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[AA7a]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA7a() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA7a_00000000());
		return results;
	}

	private static String getVxtStructAA7a_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA7a/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_undefined *   8   AA7a::pvf1   ""
			   8   _func___thiscall_undefined *   8   AA7a::pvf2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA7b	size(16):
		+---
	 0	| {vfptr}
	 8	| aa7bi
  		| <alignment member> (size=4)
		+---

	AA7b::$vftable@:
		| &AA7b_meta
		|  0
	 0	| &AA7b::pvf1
	 1	| &AA7b::pvf3

	AA7b::pvf1 this adjustor: 0
	AA7b::pvf3 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructAA7b() {
		String expected =
		//@formatter:off
			"""
			/AA7b
			pack()
			Structure AA7b {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   aa7bi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA7b() {
		return convertCommentsToSpeculative(getExpectedStructAA7b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA7b() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft []	[AA7b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA7b() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA7b_00000000());
		return results;
	}

	private static String getVxtStructAA7b_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA7b/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_undefined *   8   AA7b::pvf1   ""
			   8   _func___thiscall_undefined *   8   AA7b::pvf3   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA7c	size(40):
		+---
	 0	| +--- (base class AA7a)
	 0	| | {vfptr}
	 8	| | aa7ai
  		| | <alignment member> (size=4)
		| +---
	16	| +--- (base class AA7b)
	16	| | {vfptr}
	24	| | aa7bi
  		| | <alignment member> (size=4)
		| +---
	32	| aa7ci
  		| <alignment member> (size=4)
		+---

	AA7c::$vftable@AA7a@:
		| &AA7c_meta
		|  0
	 0	| &AA7a::pvf1
	 1	| &AA7a::pvf2
	 2	| &AA7c::pvf4

	AA7c::$vftable@AA7b@:
		| -16
	 0	| &AA7b::pvf1
	 1	| &AA7b::pvf3

	AA7c::pvf4 this adjustor: 0
	 */
	//@formatter:on
	private static String getExpectedStructAA7c() {
		String expected =
		//@formatter:off
			"""
			/AA7c
			pack()
			Structure AA7c {
			   0   AA7a   16      "Base"
			   16   AA7b   16      "Base"
			   32   int   4   aa7ci   ""
			}
			Length: 40 Alignment: 8
			/AA7a
			pack()
			Structure AA7a {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   aa7ai   ""
			}
			Length: 16 Alignment: 8
			/AA7b
			pack()
			Structure AA7b {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   aa7bi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA7c() {
		return convertCommentsToSpeculative(getExpectedStructAA7c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA7c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [AA7a]	[AA7c, AA7a]");
		results.put("VTABLE_00000010", "    16 vft [AA7b]	[AA7c, AA7b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA7c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA7c_00000000());
		results.put("VTABLE_00000010", getVxtStructAA7c_00000010());
		return results;
	}

	private static String getVxtStructAA7c_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA7c/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_undefined *   8   AA7a::pvf1   ""
			   8   _func___thiscall_undefined *   8   AA7a::pvf2   ""
			   16   _func___thiscall_undefined *   8   AA7c::pvf4   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA7c_00000010() {
		String expected =
		//@formatter:off
			"""
			/AA7c/!internal/VTABLE_00000010
			pack()
			Structure VTABLE_00000010 {
			   0   _func___thiscall_undefined *   8   AA7b::pvf1   ""
			   8   _func___thiscall_undefined *   8   AA7b::pvf3   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class AA7d	size(56):
		+---
	 0	| {vfptr}
	 8	| {vbptr}
	16	| aa7di
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA7a)
	24	| {vfptr}
	32	| aa7ai
  		| <alignment member> (size=4)
		+---
		+--- (virtual base AA7b)
	40	| {vfptr}
	48	| aa7bi
  		| <alignment member> (size=4)
		+---

	AA7d::$vftable@AA7d@:
		| &AA7d_meta
		|  0
	 0	| &AA7d::pvf5

	AA7d::$vbtable@:
	 0	| -8
	 1	| 16 (AA7dd(AA7d+8)AA7a)
	 2	| 32 (AA7dd(AA7d+8)AA7b)

	AA7d::$vftable@AA7a@:
		| -24
	 0	| &AA7a::pvf1
	 1	| &AA7a::pvf2

	AA7d::$vftable@AA7b@:
		| -40
	 0	| &AA7b::pvf1
	 1	| &AA7b::pvf3

	AA7d::pvf5 this adjustor: 0
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            AA7a      24       8       4 0
	            AA7b      40       8       8 0
	 */
	//@formatter:on
	private static String getExpectedStructAA7d() {
		String expected =
		//@formatter:off
			"""
			/AA7d
			pack()
			Structure AA7d {
			   0   AA7d   24      "Self Base"
			   24   AA7a   16      "Virtual Base"
			   40   AA7b   16      "Virtual Base"
			}
			Length: 56 Alignment: 8
			/AA7a
			pack()
			Structure AA7a {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   aa7ai   ""
			}
			Length: 16 Alignment: 8
			/AA7b
			pack()
			Structure AA7b {
			   0   pointer   8   {vfptr}   ""
			   8   int   4   aa7bi   ""
			}
			Length: 16 Alignment: 8
			/AA7d/!internal/AA7d
			pack()
			Structure AA7d {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa7di   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructAA7d() {
		String expected =
		//@formatter:off
			"""
			/AA7d
			pack()
			Structure AA7d {
			   0   AA7d   24      "Self Base"
			   24   char[32]   32      "Filler for 2 Unplaceable Virtual Bases: AA7a; AA7b"
			}
			Length: 56 Alignment: 8
			/AA7d/!internal/AA7d
			pack()
			Structure AA7d {
			   0   pointer   8   {vfptr}   ""
			   8   pointer   8   {vbptr}   ""
			   16   int   4   aa7di   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructAA7d() {
		return convertCommentsToSpeculative(getExpectedStructAA7d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryAA7d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vft [AA7d]	[AA7d]");
		results.put("VTABLE_00000008", "     8 vbt []	[AA7d]");
		results.put("VTABLE_00000018", "    24 vft [AA7a]	[AA7d, AA7a]");
		results.put("VTABLE_00000028", "    40 vft [AA7b]	[AA7d, AA7b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsAA7d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructAA7d_00000000());
		results.put("VTABLE_00000008", getVxtStructAA7d_00000008());
		results.put("VTABLE_00000018", getVxtStructAA7d_00000018());
		results.put("VTABLE_00000028", getVxtStructAA7d_00000028());
		return results;
	}

	private static String getVxtStructAA7d_00000000() {
		String expected =
		//@formatter:off
			"""
			/AA7d/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   _func___thiscall_undefined *   8   AA7d::pvf5   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA7d_00000008() {
		String expected =
		//@formatter:off
			"""
			/AA7d/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "AA7a"
			   4   int   4      "AA7b"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA7d_00000018() {
		String expected =
		//@formatter:off
			"""
			/AA7d/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   _func___thiscall_undefined *   8   AA7a::pvf1   ""
			   8   _func___thiscall_undefined *   8   AA7a::pvf2   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructAA7d_00000028() {
		String expected =
		//@formatter:off
			"""
			/AA7d/!internal/VTABLE_00000028
			pack()
			Structure VTABLE_00000028 {
			   0   _func___thiscall_undefined *   8   AA7b::pvf1   ""
			   8   _func___thiscall_undefined *   8   AA7b::pvf3   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB1a	size(4):
		+---
	 0	| bb1ai
		+---
	 */
	//@formatter:on
	private static String getExpectedStructBB1a() {
		String expected =
		//@formatter:off
			"""
			/BB1a
			pack()
			Structure BB1a {
			   0   int   4   bb1ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB1a() {
		return convertCommentsToSpeculative(getExpectedStructBB1a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB1a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB1a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB1b	size(8):
		+---
	 0	| +--- (base class BB1a)
	 0	| | bb1ai
		| +---
	 4	| bb1bi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructBB1b() {
		String expected =
		//@formatter:off
			"""
			/BB1b
			pack()
			Structure BB1b {
			   0   BB1a   4      "Base"
			   4   int   4   bb1bi   ""
			}
			Length: 8 Alignment: 4
			/BB1a
			pack()
			Structure BB1a {
			   0   int   4   bb1ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB1b() {
		return convertCommentsToSpeculative(getExpectedStructBB1b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB1b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB1b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB1c	size(20):
		+---
	 0	| {vbptr}
	 8	| bb1ci
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB1a)
	16	| bb1ai
		+---

	BB1c::$vbtable@:
	 0	| 0
	 1	| 16 (BB1cd(BB1c+0)BB1a)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            BB1a      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructBB1c() {
		String expected =
		//@formatter:off
			"""
			/BB1c
			pack()
			Structure BB1c {
			   0   BB1c   16      "Self Base"
			   16   BB1a   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/BB1a
			pack()
			Structure BB1a {
			   0   int   4   bb1ai   ""
			}
			Length: 4 Alignment: 4
			/BB1c/!internal/BB1c
			pack()
			Structure BB1c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb1ci   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB1c() {
		String expected =
		//@formatter:off
			"""
			/BB1c
			pack()
			Structure BB1c {
			   0   BB1c   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: BB1a"
			}
			Length: 24 Alignment: 8
			/BB1c/!internal/BB1c
			pack()
			Structure BB1c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb1ci   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB1c() {
		return convertCommentsToSpeculative(getExpectedStructBB1c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB1c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[BB1c]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB1c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructBB1c_00000000());
		return results;
	}

	private static String getVxtStructBB1c_00000000() {
		String expected =
		//@formatter:off
			"""
			/BB1c/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "BB1a"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB1d	size(36):
		+---
	 0	| +--- (base class BB1b)
	 0	| | +--- (base class BB1a)
	 0	| | | bb1ai
		| | +---
	 4	| | bb1bi
		| +---
	 8	| +--- (base class BB1c)
	 8	| | {vbptr}
	16	| | bb1ci
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	24	| bb1di
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB1a)
	32	| bb1ai
		+---

	BB1d::$vbtable@:
	 0	| 0
	 1	| 24 (BB1dd(BB1c+0)BB1a)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            BB1a      32       8       4 0
	 */
	//@formatter:on
	private static String getExpectedStructBB1d() {
		String expected =
		//@formatter:off
			"""
			/BB1d
			pack()
			Structure BB1d {
			   0   BB1d   32      "Self Base"
			   32   BB1a   4      "Virtual Base"
			}
			Length: 40 Alignment: 8
			/BB1a
			pack()
			Structure BB1a {
			   0   int   4   bb1ai   ""
			}
			Length: 4 Alignment: 4
			/BB1b
			pack()
			Structure BB1b {
			   0   BB1a   4      "Base"
			   4   int   4   bb1bi   ""
			}
			Length: 8 Alignment: 4
			/BB1c/!internal/BB1c
			pack()
			Structure BB1c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb1ci   ""
			}
			Length: 16 Alignment: 8
			/BB1d/!internal/BB1d
			pack()
			Structure BB1d {
			   0   BB1b   8      "Base"
			   8   BB1c   16      "Base"
			   24   int   4   bb1di   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB1d() {
		String expected =
		//@formatter:off
			"""
			/BB1d
			pack()
			Structure BB1d {
			   0   BB1d   32      "Self Base"
			   32   char[8]   8      "Filler for 1 Unplaceable Virtual Base: BB1a"
			}
			Length: 40 Alignment: 8
			/BB1a
			pack()
			Structure BB1a {
			   0   int   4   bb1ai   ""
			}
			Length: 4 Alignment: 4
			/BB1b
			pack()
			Structure BB1b {
			   0   BB1a   4      "Base"
			   4   int   4   bb1bi   ""
			}
			Length: 8 Alignment: 4
			/BB1c/!internal/BB1c
			pack()
			Structure BB1c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb1ci   ""
			}
			Length: 16 Alignment: 8
			/BB1d/!internal/BB1d
			pack()
			Structure BB1d {
			   0   BB1b   8      "Base"
			   8   BB1c   16      "Base"
			   24   int   4   bb1di   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB1d() {
		return convertCommentsToSpeculative(getExpectedStructBB1d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB1d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt []	[BB1d, BB1c]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB1d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructBB1d_00000008());
		return results;
	}

	private static String getVxtStructBB1d_00000008() {
		String expected =
		//@formatter:off
			"""
			/BB1d/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "BB1a"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB2z	size(4):
		+---
	 0	| bb2zi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructBB2z() {
		String expected =
		//@formatter:off
			"""
			/BB2z
			pack()
			Structure BB2z {
			   0   int   4   bb2zi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB2z() {
		return convertCommentsToSpeculative(getExpectedStructBB2z());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB2z() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB2z() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB2a	size(20):
		+---
	 0	| {vbptr}
	 8	| bb2ai
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB2z)
	16	| bb2zi
		+---

	BB2a::$vbtable@:
	 0	| 0
	 1	| 16 (BB2ad(BB2a+0)BB2z)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
            	            BB2z      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructBB2a() {
		String expected =
		//@formatter:off
			"""
			/BB2a
			pack()
			Structure BB2a {
			   0   BB2a   16      "Self Base"
			   16   BB2z   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/BB2a/!internal/BB2a
			pack()
			Structure BB2a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ai   ""
			}
			Length: 16 Alignment: 8
			/BB2z
			pack()
			Structure BB2z {
			   0   int   4   bb2zi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB2a() {
		String expected =
		//@formatter:off
			"""
			/BB2a
			pack()
			Structure BB2a {
			   0   BB2a   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: BB2z"
			}
			Length: 24 Alignment: 8
			/BB2a/!internal/BB2a
			pack()
			Structure BB2a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ai   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB2a() {
		return convertCommentsToSpeculative(getExpectedStructBB2a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB2a() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[BB2a]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB2a() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructBB2a_00000000());
		return results;
	}

	private static String getVxtStructBB2a_00000000() {
		String expected =
		//@formatter:off
			"""
			/BB2a/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "BB2z"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB2b	size(28):
		+---
	 0	| +--- (base class BB2a)
	 0	| | {vbptr}
	 8	| | bb2ai
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| bb2bi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB2z)
	24	| bb2zi
		+---

	BB2b::$vbtable@:
	 0	| 0
	 1	| 24 (BB2bd(BB2a+0)BB2z)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            BB2z      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructBB2b() {
		String expected =
		//@formatter:off
			"""
			/BB2b
			pack()
			Structure BB2b {
			   0   BB2b   24      "Self Base"
			   24   BB2z   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/BB2a/!internal/BB2a
			pack()
			Structure BB2a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ai   ""
			}
			Length: 16 Alignment: 8
			/BB2b/!internal/BB2b
			pack()
			Structure BB2b {
			   0   BB2a   16      "Base"
			   16   int   4   bb2bi   ""
			}
			Length: 24 Alignment: 8
			/BB2z
			pack()
			Structure BB2z {
			   0   int   4   bb2zi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB2b() {
		String expected =
		//@formatter:off
			"""
			/BB2b
			pack()
			Structure BB2b {
			   0   BB2b   24      "Self Base"
			   24   char[8]   8      "Filler for 1 Unplaceable Virtual Base: BB2z"
			}
			Length: 32 Alignment: 8
			/BB2a/!internal/BB2a
			pack()
			Structure BB2a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ai   ""
			}
			Length: 16 Alignment: 8
			/BB2b/!internal/BB2b
			pack()
			Structure BB2b {
			   0   BB2a   16      "Base"
			   16   int   4   bb2bi   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB2b() {
		return convertCommentsToSpeculative(getExpectedStructBB2b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB2b() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[BB2b, BB2a]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB2b() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructBB2b_00000000());
		return results;
	}

	private static String getVxtStructBB2b_00000000() {
		String expected =
		//@formatter:off
			"""
			/BB2b/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "BB2z"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB2c	size(40):
		+---
	 0	| {vbptr}
	 8	| bb2ci
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB2z)
	16	| bb2zi
		+---
		+--- (virtual base BB2a)
	24	| {vbptr}
	32	| bb2ai
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	BB2c::$vbtable@BB2c@:
	 0	| 0
	 1	| 16 (BB2cd(BB2c+0)BB2z)
	 2	| 24 (BB2cd(BB2c+0)BB2a)

	BB2c::$vbtable@BB2a@:
	 0	| 0
	 1	| -8 (BB2cd(BB2a+0)BB2z)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            BB2z      16       0       4 0
	            BB2a      24       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructBB2c() {
		String expected =
		//@formatter:off
			"""
			/BB2c
			pack()
			Structure BB2c {
			   0   BB2c   16      "Self Base"
			   16   BB2z   4      "Virtual Base"
			   24   BB2a   16      "Virtual Base"
			}
			Length: 40 Alignment: 8
			/BB2a/!internal/BB2a
			pack()
			Structure BB2a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ai   ""
			}
			Length: 16 Alignment: 8
			/BB2c/!internal/BB2c
			pack()
			Structure BB2c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ci   ""
			}
			Length: 16 Alignment: 8
			/BB2z
			pack()
			Structure BB2z {
			   0   int   4   bb2zi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB2c() {
		String expected =
		//@formatter:off
			"""
			/BB2c
			pack()
			Structure BB2c {
			   0   BB2c   16      "Self Base"
			   16   char[24]   24      "Filler for 2 Unplaceable Virtual Bases: BB2a; BB2z"
			}
			Length: 40 Alignment: 8
			/BB2c/!internal/BB2c
			pack()
			Structure BB2c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ci   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB2c() {
		return convertCommentsToSpeculative(getExpectedStructBB2c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB2c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt [BB2c]	[BB2c]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000018", "    24 vbt [BB2a]	[BB2c, BB2a]");
		results.put("VTABLE_00000018", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB2c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructBB2c_00000000());
		results.put("VTABLE_00000018", getVxtStructBB2c_00000018());
		return results;
	}

	private static String getVxtStructBB2c_00000000() {
		String expected =
		//@formatter:off
			"""
			/BB2c/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "BB2z"
			   4   int   4      "BB2a"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructBB2c_00000018() {
		String expected =
		//@formatter:off
			"""
			/BB2c/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   int   4      "BB2z"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB2d	size(72):
		+---
	 0	| +--- (base class BB2b)
	 0	| | +--- (base class BB2a)
	 0	| | | {vbptr}
	 8	| | | bb2ai
  		| | | <alignment member> (size=4)
  		| | | <alignment member> (size=4)
		| | +---
	16	| | bb2bi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	24	| +--- (base class BB2c)
	24	| | {vbptr}
	32	| | bb2ci
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	40	| bb2di
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB2z)
	48	| bb2zi
		+---
		+--- (virtual base BB2a)
	56	| {vbptr}
	64	| bb2ai
  		| <alignment member> (size=4)
  		| <alignment member> (size=4)
		+---

	BB2d::$vbtable@:
	 0	| 0
	 1	| 48 (BB2dd(BB2a+0)BB2z)
	 2	| 56 (BB2dd(BB2d+0)BB2a)

	BB2d::$vbtable@BB2c@:
	 0	| 0
	 1	| 24 (BB2dd(BB2c+0)BB2z)
	 2	| 32 (BB2dd(BB2c+0)BB2a)

	BB2d::$vbtable@BB2a@:
	 0	| 0
	 1	| -8 (BB2dd(BB2a+0)BB2z)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            BB2z      48       0       4 0
	            BB2a      56       0       8 0
	 */
	//@formatter:on
	private static String getExpectedStructBB2d() {
		String expected =
		//@formatter:off
			"""
			/BB2d
			pack()
			Structure BB2d {
			   0   BB2d   48      "Self Base"
			   48   BB2z   4      "Virtual Base"
			   56   BB2a   16      "Virtual Base"
			}
			Length: 72 Alignment: 8
			/BB2a/!internal/BB2a
			pack()
			Structure BB2a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ai   ""
			}
			Length: 16 Alignment: 8
			/BB2b/!internal/BB2b
			pack()
			Structure BB2b {
			   0   BB2a   16      "Base"
			   16   int   4   bb2bi   ""
			}
			Length: 24 Alignment: 8
			/BB2c/!internal/BB2c
			pack()
			Structure BB2c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ci   ""
			}
			Length: 16 Alignment: 8
			/BB2d/!internal/BB2d
			pack()
			Structure BB2d {
			   0   BB2b   24      "Base"
			   24   BB2c   16      "Base"
			   40   int   4   bb2di   ""
			}
			Length: 48 Alignment: 8
			/BB2z
			pack()
			Structure BB2z {
			   0   int   4   bb2zi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB2d() {
		String expected =
		//@formatter:off
			"""
			/BB2d
			pack()
			Structure BB2d {
			   0   BB2d   48      "Self Base"
			   48   char[24]   24      "Filler for 2 Unplaceable Virtual Bases: BB2z; BB2a"
			}
			Length: 72 Alignment: 8
			/BB2a/!internal/BB2a
			pack()
			Structure BB2a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ai   ""
			}
			Length: 16 Alignment: 8
			/BB2b/!internal/BB2b
			pack()
			Structure BB2b {
			   0   BB2a   16      "Base"
			   16   int   4   bb2bi   ""
			}
			Length: 24 Alignment: 8
			/BB2c/!internal/BB2c
			pack()
			Structure BB2c {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ci   ""
			}
			Length: 16 Alignment: 8
			/BB2d/!internal/BB2d
			pack()
			Structure BB2d {
			   0   BB2b   24      "Base"
			   24   BB2c   16      "Base"
			   40   int   4   bb2di   ""
			}
			Length: 48 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB2d() {
		return convertCommentsToSpeculative(getExpectedStructBB2d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB2d() {
		Map<String, String> results = new TreeMap<>();
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000000", "     0 vbt []	[BB2d, BB2b, BB2a]");
		results.put("VTABLE_00000000", null);
		results.put("VTABLE_00000018", "    24 vbt [BB2c]	[BB2d, BB2c]");
		// This is the real expected result, but passing null tells the test to skip doing the
		//  check... causing the test not to fail,
		//  but it will issue a warning that the summary value is skipped.
		//results.put("VTABLE_00000038", "    56 vbt [BB2a]	[BB2d, BB2c, BB2a]");
		results.put("VTABLE_00000038", null);
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB2d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructBB2d_00000000());
		results.put("VTABLE_00000018", getVxtStructBB2d_00000018());
		results.put("VTABLE_00000038", getVxtStructBB2d_00000038());
		return results;
	}

	private static String getVxtStructBB2d_00000000() {
		String expected =
		//@formatter:off
			"""
			/BB2d/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "BB2z"
			   4   int   4      "BB2a"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructBB2d_00000018() {
		String expected =
		//@formatter:off
			"""
			/BB2d/!internal/VTABLE_00000018
			pack()
			Structure VTABLE_00000018 {
			   0   int   4      "BB2z"
			   4   int   4      "BB2a"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructBB2d_00000038() {
		String expected =
		//@formatter:off
			"""
			/BB2d/!internal/VTABLE_00000038
			pack()
			Structure VTABLE_00000038 {
			   0   int   4      "BB2z"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB2e	size(36):
		+---
	 0	| +--- (base class BB2b)
	 0	| | +--- (base class BB2a)
	 0	| | | {vbptr}
	 8	| | | bb2ai
  		| | | <alignment member> (size=4)
  		| | | <alignment member> (size=4)
		| | +---
	16	| | bb2bi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	24	| bb2ei
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB2z)
	32	| bb2zi
		+---

	BB2e::$vbtable@:
	 0	| 0
	 1	| 32 (BB2ed(BB2a+0)BB2z)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            BB2z      32       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructBB2e() {
		String expected =
		//@formatter:off
			"""
			/BB2e
			pack()
			Structure BB2e {
			   0   BB2e   32      "Self Base"
			   32   BB2z   4      "Virtual Base"
			}
			Length: 40 Alignment: 8
			/BB2a/!internal/BB2a
			pack()
			Structure BB2a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ai   ""
			}
			Length: 16 Alignment: 8
			/BB2b/!internal/BB2b
			pack()
			Structure BB2b {
			   0   BB2a   16      "Base"
			   16   int   4   bb2bi   ""
			}
			Length: 24 Alignment: 8
			/BB2e/!internal/BB2e
			pack()
			Structure BB2e {
			   0   BB2b   24      "Base"
			   24   int   4   bb2ei   ""
			}
			Length: 32 Alignment: 8
			/BB2z
			pack()
			Structure BB2z {
			   0   int   4   bb2zi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB2e() {
		String expected =
		//@formatter:off
			"""
			/BB2e
			pack()
			Structure BB2e {
			   0   BB2e   32      "Self Base"
			   32   char[8]   8      "Filler for 1 Unplaceable Virtual Base: BB2z"
			}
			Length: 40 Alignment: 8
			/BB2a/!internal/BB2a
			pack()
			Structure BB2a {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   bb2ai   ""
			}
			Length: 16 Alignment: 8
			/BB2b/!internal/BB2b
			pack()
			Structure BB2b {
			   0   BB2a   16      "Base"
			   16   int   4   bb2bi   ""
			}
			Length: 24 Alignment: 8
			/BB2e/!internal/BB2e
			pack()
			Structure BB2e {
			   0   BB2b   24      "Base"
			   24   int   4   bb2ei   ""
			}
			Length: 32 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB2e() {
		return convertCommentsToSpeculative(getExpectedStructBB2e());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB2e() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[BB2e, BB2b, BB2a]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB2e() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructBB2e_00000000());
		return results;
	}

	private static String getVxtStructBB2e_00000000() {
		String expected =
		//@formatter:off
			"""
			/BB2e/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "BB2z"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB3a	size(4):
		+---
	 0	| bb3ai
		+---
	 */
	//@formatter:on
	private static String getExpectedStructBB3a() {
		String expected =
		//@formatter:off
			"""
			/BB3a
			pack()
			Structure BB3a {
			   0   int   4   bb3ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB3a() {
		return convertCommentsToSpeculative(getExpectedStructBB3a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB3a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB3a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB3b	size(4):
		+---
	 0	| bb3bi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructBB3b() {
		String expected =
		//@formatter:off
			"""
			/BB3b
			pack()
			Structure BB3b {
			   0   int   4   bb3bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB3b() {
		return convertCommentsToSpeculative(getExpectedStructBB3b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB3b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB3b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB3c	size(4):
		+---
	 0	| bb3ci
		+---
	 */
	//@formatter:on
	private static String getExpectedStructBB3c() {
		String expected =
		//@formatter:off
			"""
			/BB3c
			pack()
			Structure BB3c {
			   0   int   4   bb3ci   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB3c() {
		return convertCommentsToSpeculative(getExpectedStructBB3c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB3c() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB3c() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB3d	size(28):
		+---
	 0	| +--- (base class BB3a)
	 0	| | bb3ai
		| +---
	 4	| +--- (base class BB3c)
	 4	| | bb3ci
		| +---
	 8	| {vbptr}
	16	| bb3di
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB3b)
	24	| bb3bi
		+---

	BB3d::$vbtable@:
	 0	| -8
	 1	| 16 (BB3dd(BB3d+8)BB3b)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            BB3b      24       8       4 0
	 */
	//@formatter:on
	private static String getExpectedStructBB3d() {
		String expected =
		//@formatter:off
			"""
			/BB3d
			pack()
			Structure BB3d {
			   0   BB3d   24      "Self Base"
			   24   BB3b   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/BB3a
			pack()
			Structure BB3a {
			   0   int   4   bb3ai   ""
			}
			Length: 4 Alignment: 4
			/BB3b
			pack()
			Structure BB3b {
			   0   int   4   bb3bi   ""
			}
			Length: 4 Alignment: 4
			/BB3c
			pack()
			Structure BB3c {
			   0   int   4   bb3ci   ""
			}
			Length: 4 Alignment: 4
			/BB3d/!internal/BB3d
			pack()
			Structure BB3d {
			   0   BB3a   4      "Base"
			   4   BB3c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3di   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB3d() {
		String expected =
		//@formatter:off
			"""
			/BB3d
			pack()
			Structure BB3d {
			   0   BB3d   24      "Self Base"
			   24   char[8]   8      "Filler for 1 Unplaceable Virtual Base: BB3b"
			}
			Length: 32 Alignment: 8
			/BB3a
			pack()
			Structure BB3a {
			   0   int   4   bb3ai   ""
			}
			Length: 4 Alignment: 4
			/BB3c
			pack()
			Structure BB3c {
			   0   int   4   bb3ci   ""
			}
			Length: 4 Alignment: 4
			/BB3d/!internal/BB3d
			pack()
			Structure BB3d {
			   0   BB3a   4      "Base"
			   4   BB3c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3di   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB3d() {
		return convertCommentsToSpeculative(getExpectedStructBB3d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB3d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt []	[BB3d]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB3d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructBB3d_00000008());
		return results;
	}

	private static String getVxtStructBB3d_00000008() {
		String expected =
		//@formatter:off
			"""
			/BB3d/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "BB3b"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB3e	size(32):
		+---
	 0	| +--- (base class BB3b)
	 0	| | bb3bi
		| +---
	 8	| {vbptr}
	16	| bb3ei
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB3a)
	24	| bb3ai
		+---
		+--- (virtual base BB3c)
	28	| bb3ci
		+---

	BB3e::$vbtable@:
	 0	| -8
	 1	| 16 (BB3ed(BB3e+8)BB3a)
	 2	| 20 (BB3ed(BB3e+8)BB3c)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            BB3a      24       8       4 0
	            BB3c      28       8       8 0
	 */
	//@formatter:on
	private static String getExpectedStructBB3e() {
		String expected =
		//@formatter:off
			"""
			/BB3e
			pack()
			Structure BB3e {
			   0   BB3e   24      "Self Base"
			   24   BB3a   4      "Virtual Base"
			   28   BB3c   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/BB3a
			pack()
			Structure BB3a {
			   0   int   4   bb3ai   ""
			}
			Length: 4 Alignment: 4
			/BB3b
			pack()
			Structure BB3b {
			   0   int   4   bb3bi   ""
			}
			Length: 4 Alignment: 4
			/BB3c
			pack()
			Structure BB3c {
			   0   int   4   bb3ci   ""
			}
			Length: 4 Alignment: 4
			/BB3e/!internal/BB3e
			pack()
			Structure BB3e {
			   0   BB3b   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3ei   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB3e() {
		String expected =
		//@formatter:off
			"""
			/BB3e
			pack()
			Structure BB3e {
			   0   BB3e   24      "Self Base"
			   24   char[8]   8      "Filler for 2 Unplaceable Virtual Bases: BB3a; BB3c"
			}
			Length: 32 Alignment: 8
			/BB3b
			pack()
			Structure BB3b {
			   0   int   4   bb3bi   ""
			}
			Length: 4 Alignment: 4
			/BB3e/!internal/BB3e
			pack()
			Structure BB3e {
			   0   BB3b   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3ei   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB3e() {
		return convertCommentsToSpeculative(getExpectedStructBB3e());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB3e() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt []	[BB3e]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB3e() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructBB3e_00000008());
		return results;
	}

	private static String getVxtStructBB3e_00000008() {
		String expected =
		//@formatter:off
			"""
			/BB3e/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "BB3a"
			   4   int   4      "BB3c"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB3f	size(68):
		+---
	 0	| +--- (base class BB3d)
	 0	| | +--- (base class BB3a)
	 0	| | | bb3ai
		| | +---
	 4	| | +--- (base class BB3c)
	 4	| | | bb3ci
		| | +---
	 8	| | {vbptr}
	16	| | bb3di
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	24	| +--- (base class BB3e)
	24	| | +--- (base class BB3b)
	24	| | | bb3bi
		| | +---
	32	| | {vbptr}
	40	| | bb3ei
  		| | <alignment member> (size=4)
		| +---
	48	| bb3fi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB3b)
	56	| bb3bi
		+---
		+--- (virtual base BB3a)
	60	| bb3ai
		+---
		+--- (virtual base BB3c)
	64	| bb3ci
		+---

	BB3f::$vbtable@BB3d@:
	 0	| -8
	 1	| 48 (BB3fd(BB3d+8)BB3b)
	 2	| 52 (BB3fd(BB3f+8)BB3a)
	 3	| 56 (BB3fd(BB3f+8)BB3c)

	BB3f::$vbtable@BB3e@:
	 0	| -8
	 1	| 28 (BB3fd(BB3e+8)BB3a)
	 2	| 32 (BB3fd(BB3e+8)BB3c)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            BB3b      56       8       4 0
	            BB3a      60       8       8 0
	            BB3c      64       8      12 0
	 */
	//@formatter:on
	private static String getExpectedStructBB3f() {
		String expected =
		//@formatter:off
			"""
			/BB3f
			pack()
			Structure BB3f {
			   0   BB3f   56      "Self Base"
			   56   BB3b   4      "Virtual Base"
			   60   BB3a   4      "Virtual Base"
			   64   BB3c   4      "Virtual Base"
			}
			Length: 72 Alignment: 8
			/BB3a
			pack()
			Structure BB3a {
			   0   int   4   bb3ai   ""
			}
			Length: 4 Alignment: 4
			/BB3b
			pack()
			Structure BB3b {
			   0   int   4   bb3bi   ""
			}
			Length: 4 Alignment: 4
			/BB3c
			pack()
			Structure BB3c {
			   0   int   4   bb3ci   ""
			}
			Length: 4 Alignment: 4
			/BB3d/!internal/BB3d
			pack()
			Structure BB3d {
			   0   BB3a   4      "Base"
			   4   BB3c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3di   ""
			}
			Length: 24 Alignment: 8
			/BB3e/!internal/BB3e
			pack()
			Structure BB3e {
			   0   BB3b   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3ei   ""
			}
			Length: 24 Alignment: 8
			/BB3f/!internal/BB3f
			pack()
			Structure BB3f {
			   0   BB3d   24      "Base"
			   24   BB3e   24      "Base"
			   48   int   4   bb3fi   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB3f() {
		String expected =
		//@formatter:off
			"""
			/BB3f
			pack()
			Structure BB3f {
			   0   BB3f   56      "Self Base"
			   56   char[16]   16      "Filler for 3 Unplaceable Virtual Bases: BB3b; BB3a; BB3c"
			}
			Length: 72 Alignment: 8
			/BB3a
			pack()
			Structure BB3a {
			   0   int   4   bb3ai   ""
			}
			Length: 4 Alignment: 4
			/BB3b
			pack()
			Structure BB3b {
			   0   int   4   bb3bi   ""
			}
			Length: 4 Alignment: 4
			/BB3c
			pack()
			Structure BB3c {
			   0   int   4   bb3ci   ""
			}
			Length: 4 Alignment: 4
			/BB3d/!internal/BB3d
			pack()
			Structure BB3d {
			   0   BB3a   4      "Base"
			   4   BB3c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3di   ""
			}
			Length: 24 Alignment: 8
			/BB3e/!internal/BB3e
			pack()
			Structure BB3e {
			   0   BB3b   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3ei   ""
			}
			Length: 24 Alignment: 8
			/BB3f/!internal/BB3f
			pack()
			Structure BB3f {
			   0   BB3d   24      "Base"
			   24   BB3e   24      "Base"
			   48   int   4   bb3fi   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB3f() {
		return convertCommentsToSpeculative(getExpectedStructBB3f());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB3f() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt [BB3d]	[BB3f, BB3d]");
		results.put("VTABLE_00000020", "    32 vbt [BB3e]	[BB3f, BB3e]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB3f() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructBB3f_00000008());
		results.put("VTABLE_00000020", getVxtStructBB3f_00000020());
		return results;
	}

	private static String getVxtStructBB3f_00000008() {
		String expected =
		//@formatter:off
			"""
			/BB3f/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "BB3b"
			   4   int   4      "BB3a"
			   8   int   4      "BB3c"
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructBB3f_00000020() {
		String expected =
		//@formatter:off
			"""
			/BB3f/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   int   4      "BB3a"
			   4   int   4      "BB3c"
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class BB3g	size(68):
		+---
	 0	| +--- (base class BB3e)
	 0	| | +--- (base class BB3b)
	 0	| | | bb3bi
		| | +---
	 8	| | {vbptr}
	16	| | bb3ei
  		| | <alignment member> (size=4)
		| +---
	24	| +--- (base class BB3d)
	24	| | +--- (base class BB3a)
	24	| | | bb3ai
		| | +---
	28	| | +--- (base class BB3c)
	28	| | | bb3ci
		| | +---
	32	| | {vbptr}
	40	| | bb3di
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	48	| bb3gi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base BB3a)
	56	| bb3ai
		+---
		+--- (virtual base BB3c)
	60	| bb3ci
		+---
		+--- (virtual base BB3b)
	64	| bb3bi
		+---

	BB3g::$vbtable@BB3e@:
	 0	| -8
	 1	| 48 (BB3gd(BB3e+8)BB3a)
	 2	| 52 (BB3gd(BB3e+8)BB3c)
	 3	| 56 (BB3gd(BB3g+8)BB3b)

	BB3g::$vbtable@BB3d@:
	 0	| -8
	 1	| 32 (BB3gd(BB3d+8)BB3b)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            BB3a      56       8       4 0
	            BB3c      60       8       8 0
	            BB3b      64       8      12 0
	 */
	//@formatter:on
	private static String getExpectedStructBB3g() {
		String expected =
		//@formatter:off
			"""
			/BB3g
			pack()
			Structure BB3g {
			   0   BB3g   56      "Self Base"
			   56   BB3a   4      "Virtual Base"
			   60   BB3c   4      "Virtual Base"
			   64   BB3b   4      "Virtual Base"
			}
			Length: 72 Alignment: 8
			/BB3a
			pack()
			Structure BB3a {
			   0   int   4   bb3ai   ""
			}
			Length: 4 Alignment: 4
			/BB3b
			pack()
			Structure BB3b {
			   0   int   4   bb3bi   ""
			}
			Length: 4 Alignment: 4
			/BB3c
			pack()
			Structure BB3c {
			   0   int   4   bb3ci   ""
			}
			Length: 4 Alignment: 4
			/BB3d/!internal/BB3d
			pack()
			Structure BB3d {
			   0   BB3a   4      "Base"
			   4   BB3c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3di   ""
			}
			Length: 24 Alignment: 8
			/BB3e/!internal/BB3e
			pack()
			Structure BB3e {
			   0   BB3b   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3ei   ""
			}
			Length: 24 Alignment: 8
			/BB3g/!internal/BB3g
			pack()
			Structure BB3g {
			   0   BB3e   24      "Base"
			   24   BB3d   24      "Base"
			   48   int   4   bb3gi   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructBB3g() {
		String expected =
		//@formatter:off
			"""
			/BB3g
			pack()
			Structure BB3g {
			   0   BB3g   56      "Self Base"
			   56   char[16]   16      "Filler for 3 Unplaceable Virtual Bases: BB3a; BB3c; BB3b"
			}
			Length: 72 Alignment: 8
			/BB3a
			pack()
			Structure BB3a {
			   0   int   4   bb3ai   ""
			}
			Length: 4 Alignment: 4
			/BB3b
			pack()
			Structure BB3b {
			   0   int   4   bb3bi   ""
			}
			Length: 4 Alignment: 4
			/BB3c
			pack()
			Structure BB3c {
			   0   int   4   bb3ci   ""
			}
			Length: 4 Alignment: 4
			/BB3d/!internal/BB3d
			pack()
			Structure BB3d {
			   0   BB3a   4      "Base"
			   4   BB3c   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3di   ""
			}
			Length: 24 Alignment: 8
			/BB3e/!internal/BB3e
			pack()
			Structure BB3e {
			   0   BB3b   4      "Base"
			   8   pointer   8   {vbptr}   ""
			   16   int   4   bb3ei   ""
			}
			Length: 24 Alignment: 8
			/BB3g/!internal/BB3g
			pack()
			Structure BB3g {
			   0   BB3e   24      "Base"
			   24   BB3d   24      "Base"
			   48   int   4   bb3gi   ""
			}
			Length: 56 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructBB3g() {
		return convertCommentsToSpeculative(getExpectedStructBB3g());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryBB3g() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", "     8 vbt [BB3e]	[BB3g, BB3e]");
		results.put("VTABLE_00000020", "    32 vbt [BB3d]	[BB3g, BB3d]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsBB3g() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000008", getVxtStructBB3g_00000008());
		results.put("VTABLE_00000020", getVxtStructBB3g_00000020());
		return results;
	}

	private static String getVxtStructBB3g_00000008() {
		String expected =
		//@formatter:off
			"""
			/BB3g/!internal/VTABLE_00000008
			pack()
			Structure VTABLE_00000008 {
			   0   int   4      "BB3a"
			   4   int   4      "BB3c"
			   8   int   4      "BB3b"
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getVxtStructBB3g_00000020() {
		String expected =
		//@formatter:off
			"""
			/BB3g/!internal/VTABLE_00000020
			pack()
			Structure VTABLE_00000020 {
			   0   int   4      "BB3b"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1a	size(2):
		+---
	 0	| cc1as
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1a() {
		String expected =
		//@formatter:off
			"""
			/CC1a
			pack()
			Structure CC1a {
			   0   short   2   cc1as   ""
			}
			Length: 2 Alignment: 2""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1a() {
		return convertCommentsToSpeculative(getExpectedStructCC1a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1b	size(4):
		+---
	 0	| cc1bi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1b() {
		String expected =
		//@formatter:off
			"""
			/CC1b
			pack()
			Structure CC1b {
			   0   int   4   cc1bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1b() {
		return convertCommentsToSpeculative(getExpectedStructCC1b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1c	size(4):
		+---
	 0	| cc1cl
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1c() {
		String expected =
		//@formatter:off
			"""
			/CC1c
			pack()
			Structure CC1c {
			   0   long   4   cc1cl   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1c() {
		return convertCommentsToSpeculative(getExpectedStructCC1c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1c() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1c() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1d	size(4):
		+---
	 0	| cc1df
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1d() {
		String expected =
		//@formatter:off
			"""
			/CC1d
			pack()
			Structure CC1d {
			   0   float   4   cc1df   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1d() {
		return convertCommentsToSpeculative(getExpectedStructCC1d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1d() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1d() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1e	size(8):
		+---
	 0	| cc1ep
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1e() {
		String expected =
		//@formatter:off
			"""
			/CC1e
			pack()
			Structure CC1e {
			   0   char *   8   cc1ep   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1e() {
		return convertCommentsToSpeculative(getExpectedStructCC1e());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1e() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1e() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1f	size(8):
		+---
	 0	| cc1fd
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1f() {
		String expected =
		//@formatter:off
			"""
			/CC1f
			pack()
			Structure CC1f {
			   0   double   8   cc1fd   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1f() {
		return convertCommentsToSpeculative(getExpectedStructCC1f());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1f() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1f() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1g	size(40):
		+---
	 0	| +--- (base class CC1a)
	 0	| | cc1as
		| +---
	 4	| +--- (base class CC1b)
	 4	| | cc1bi
		| +---
	 8	| +--- (base class CC1c)
	 8	| | cc1cl
		| +---
	12	| +--- (base class CC1d)
	12	| | cc1df
		| +---
	16	| +--- (base class CC1e)
	16	| | cc1ep
		| +---
	24	| +--- (base class CC1f)
	24	| | cc1fd
		| +---
	32	| cc1gc
  		| <alignment member> (size=7)
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1g() {
		String expected =
		//@formatter:off
			"""
			/CC1g
			pack()
			Structure CC1g {
			   0   CC1a   2      "Base"
			   4   CC1b   4      "Base"
			   8   CC1c   4      "Base"
			   12   CC1d   4      "Base"
			   16   CC1e   8      "Base"
			   24   CC1f   8      "Base"
			   32   char   1   cc1gc   ""
			}
			Length: 40 Alignment: 8
			/CC1a
			pack()
			Structure CC1a {
			   0   short   2   cc1as   ""
			}
			Length: 2 Alignment: 2
			/CC1b
			pack()
			Structure CC1b {
			   0   int   4   cc1bi   ""
			}
			Length: 4 Alignment: 4
			/CC1c
			pack()
			Structure CC1c {
			   0   long   4   cc1cl   ""
			}
			Length: 4 Alignment: 4
			/CC1d
			pack()
			Structure CC1d {
			   0   float   4   cc1df   ""
			}
			Length: 4 Alignment: 4
			/CC1e
			pack()
			Structure CC1e {
			   0   char *   8   cc1ep   ""
			}
			Length: 8 Alignment: 8
			/CC1f
			pack()
			Structure CC1f {
			   0   double   8   cc1fd   ""
			}
			Length: 8 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1g() {
		return convertCommentsToSpeculative(getExpectedStructCC1g());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1g() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1g() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1h	size(48):
		+---
	 0	| {vbptr}
	 8	| cc1hc
  		| <alignment member> (size=7)
  		| <alignment member> (size=2)
		+---
		+--- (virtual base CC1a)
	16	| cc1as
		+---
		+--- (virtual base CC1b)
	20	| cc1bi
		+---
		+--- (virtual base CC1c)
	24	| cc1cl
		+---
		+--- (virtual base CC1d)
	28	| cc1df
		+---
		+--- (virtual base CC1e)
	32	| cc1ep
		+---
		+--- (virtual base CC1f)
	40	| cc1fd
		+---

	CC1h::$vbtable@:
	 0	| 0
	 1	| 16 (CC1hd(CC1h+0)CC1a)
	 2	| 20 (CC1hd(CC1h+0)CC1b)
	 3	| 24 (CC1hd(CC1h+0)CC1c)
	 4	| 28 (CC1hd(CC1h+0)CC1d)
	 5	| 32 (CC1hd(CC1h+0)CC1e)
	 6	| 40 (CC1hd(CC1h+0)CC1f)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            CC1a      16       0       4 0
	            CC1b      20       0       8 0
	            CC1c      24       0      12 0
	            CC1d      28       0      16 0
	            CC1e      32       0      20 0
	            CC1f      40       0      24 0
	 */
	//@formatter:on
	private static String getExpectedStructCC1h() {
		String expected =
		//@formatter:off
			"""
			/CC1h
			pack()
			Structure CC1h {
			   0   CC1h   16      "Self Base"
			   16   CC1a   2      "Virtual Base"
			   20   CC1b   4      "Virtual Base"
			   24   CC1c   4      "Virtual Base"
			   28   CC1d   4      "Virtual Base"
			   32   CC1e   8      "Virtual Base"
			   40   CC1f   8      "Virtual Base"
			}
			Length: 48 Alignment: 8
			/CC1a
			pack()
			Structure CC1a {
			   0   short   2   cc1as   ""
			}
			Length: 2 Alignment: 2
			/CC1b
			pack()
			Structure CC1b {
			   0   int   4   cc1bi   ""
			}
			Length: 4 Alignment: 4
			/CC1c
			pack()
			Structure CC1c {
			   0   long   4   cc1cl   ""
			}
			Length: 4 Alignment: 4
			/CC1d
			pack()
			Structure CC1d {
			   0   float   4   cc1df   ""
			}
			Length: 4 Alignment: 4
			/CC1e
			pack()
			Structure CC1e {
			   0   char *   8   cc1ep   ""
			}
			Length: 8 Alignment: 8
			/CC1f
			pack()
			Structure CC1f {
			   0   double   8   cc1fd   ""
			}
			Length: 8 Alignment: 8
			/CC1h/!internal/CC1h
			pack()
			Structure CC1h {
			   0   pointer   8   {vbptr}   ""
			   8   char   1   cc1hc   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructCC1h() {
		String expected =
		//@formatter:off
			"""
			/CC1h
			pack()
			Structure CC1h {
			   0   CC1h   16      "Self Base"
			   16   char[32]   32      "Filler for 6 Unplaceable Virtual Bases: CC1a; CC1b; CC1c; CC1d; CC1e; CC1f"
			}
			Length: 48 Alignment: 8
			/CC1h/!internal/CC1h
			pack()
			Structure CC1h {
			   0   pointer   8   {vbptr}   ""
			   8   char   1   cc1hc   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1h() {
		String expected =
		//@formatter:off
			"""
			/CC1h
			pack()
			Structure CC1h {
			   0   CC1h   16      "Self Base"
			   16   CC1a   2      "Virtual Base - Speculative Placement"
			   20   CC1b   4      "Virtual Base - Speculative Placement"
			   24   CC1c   4      "Virtual Base - Speculative Placement"
			   28   CC1d   4      "Virtual Base - Speculative Placement"
			   32   CC1e   8      "Virtual Base - Speculative Placement"
			   40   CC1f   8      "Virtual Base - Speculative Placement"
			}
			Length: 48 Alignment: 8
			/CC1a
			pack()
			Structure CC1a {
			   0   short   2   cc1as   ""
			}
			Length: 2 Alignment: 2
			/CC1b
			pack()
			Structure CC1b {
			   0   int   4   cc1bi   ""
			}
			Length: 4 Alignment: 4
			/CC1c
			pack()
			Structure CC1c {
			   0   long   4   cc1cl   ""
			}
			Length: 4 Alignment: 4
			/CC1d
			pack()
			Structure CC1d {
			   0   float   4   cc1df   ""
			}
			Length: 4 Alignment: 4
			/CC1e
			pack()
			Structure CC1e {
			   0   char *   8   cc1ep   ""
			}
			Length: 8 Alignment: 8
			/CC1f
			pack()
			Structure CC1f {
			   0   double   8   cc1fd   ""
			}
			Length: 8 Alignment: 8
			/CC1h/!internal/CC1h
			pack()
			Structure CC1h {
			   0   pointer   8   {vbptr}   ""
			   8   char   1   cc1hc   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1h() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[CC1h]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1h() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructCC1h_00000000());
		return results;
	}

	private static String getVxtStructCC1h_00000000() {
		String expected =
		//@formatter:off
			"""
			/CC1h/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "CC1a"
			   4   int   4      "CC1b"
			   8   int   4      "CC1c"
			   12   int   4      "CC1d"
			   16   int   4      "CC1e"
			   20   int   4      "CC1f"
			}
			Length: 24 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1g_counterpoint	size(40):
		+---
	 0	| cc1as
  		| <alignment member> (size=2)
	 4	| cc1bi
	 8	| cc1cl
	12	| cc1df
	16	| cc1ep
	24	| cc1fd
	32	| cc1gc
  		| <alignment member> (size=7)
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1g_counterpoint() {
		String expected =
		//@formatter:off
			"""
			/CC1g_counterpoint
			pack()
			Structure CC1g_counterpoint {
			   0   short   2   cc1as   ""
			   4   int   4   cc1bi   ""
			   8   long   4   cc1cl   ""
			   12   float   4   cc1df   ""
			   16   char *   8   cc1ep   ""
			   24   double   8   cc1fd   ""
			   32   char   1   cc1gc   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1g_counterpoint() {
		return convertCommentsToSpeculative(getExpectedStructCC1g_counterpoint());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1g_counterpoint() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1g_counterpoint() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1h_counterpoint	size(40):
		+---
	 0	| p
	 8	| cc1hc
  		| <alignment member> (size=1)
	10	| cc1as
	12	| cc1bi
	16	| cc1cl
	20	| cc1df
	24	| cc1ep
	32	| cc1fd
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1h_counterpoint() {
		String expected =
		//@formatter:off
			"""
			/CC1h_counterpoint
			pack()
			Structure CC1h_counterpoint {
			   0   char *   8   p   ""
			   8   char   1   cc1hc   ""
			   10   short   2   cc1as   ""
			   12   int   4   cc1bi   ""
			   16   long   4   cc1cl   ""
			   20   float   4   cc1df   ""
			   24   char *   8   cc1ep   ""
			   32   double   8   cc1fd   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1h_counterpoint() {
		return convertCommentsToSpeculative(getExpectedStructCC1h_counterpoint());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1h_counterpoint() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1h_counterpoint() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1g_counterpoint2	size(40):
		+---
	 0	| cc1as
  		| <alignment member> (size=2)
	 4	| cc1bi
	 8	| cc1cl
	12	| cc1df
	16	| cc1ep
	24	| cc1fd
	32	| cc1gc
  		| <alignment member> (size=7)
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1g_counterpoint2() {
		String expected =
		//@formatter:off
			"""
			/CC1g_counterpoint2
			pack()
			Structure CC1g_counterpoint2 {
			   0   short   2   cc1as   ""
			   4   int   4   cc1bi   ""
			   8   long   4   cc1cl   ""
			   12   float   4   cc1df   ""
			   16   char *   8   cc1ep   ""
			   24   double   8   cc1fd   ""
			   32   char   1   cc1gc   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1g_counterpoint2() {
		return convertCommentsToSpeculative(getExpectedStructCC1g_counterpoint2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1g_counterpoint2() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1g_counterpoint2() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC1h_counterpoint2	size(40):
		+---
	 0	| p
	 8	| cc1hc
  		| <alignment member> (size=1)
	10	| cc1as
	12	| cc1bi
	16	| cc1cl
	20	| cc1df
	24	| cc1ep
	32	| cc1fd
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC1h_counterpoint2() {
		String expected =
		//@formatter:off
			"""
			/CC1h_counterpoint2
			pack()
			Structure CC1h_counterpoint2 {
			   0   char *   8   p   ""
			   8   char   1   cc1hc   ""
			   10   short   2   cc1as   ""
			   12   int   4   cc1bi   ""
			   16   long   4   cc1cl   ""
			   20   float   4   cc1df   ""
			   24   char *   8   cc1ep   ""
			   32   double   8   cc1fd   ""
			}
			Length: 40 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC1h_counterpoint2() {
		return convertCommentsToSpeculative(getExpectedStructCC1h_counterpoint2());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC1h_counterpoint2() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC1h_counterpoint2() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC2a	size(2):
		+---
	 0	| x
	 1	| c
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC2a() {
		String expected =
		//@formatter:off
			"""
			/CC2a
			pack()
			Structure CC2a {
			   0   char   1   x   ""
			   1   char   1   c   ""
			}
			Length: 2 Alignment: 1""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC2a() {
		return convertCommentsToSpeculative(getExpectedStructCC2a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC2a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC2a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC2b	size(4):
		+---
	 0	| x
  		| <alignment member> (size=1)
	 2	| s
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC2b() {
		String expected =
		//@formatter:off
			"""
			/CC2b
			pack()
			Structure CC2b {
			   0   char   1   x   ""
			   2   short   2   s   ""
			}
			Length: 4 Alignment: 2""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC2b() {
		return convertCommentsToSpeculative(getExpectedStructCC2b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC2b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC2b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC2c	size(8):
		+---
	 0	| x
  		| <alignment member> (size=3)
	 4	| i
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC2c() {
		String expected =
		//@formatter:off
			"""
			/CC2c
			pack()
			Structure CC2c {
			   0   char   1   x   ""
			   4   int   4   i   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC2c() {
		return convertCommentsToSpeculative(getExpectedStructCC2c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC2c() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC2c() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC2d	size(8):
		+---
	 0	| x
  		| <alignment member> (size=3)
	 4	| l
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC2d() {
		String expected =
		//@formatter:off
			"""
			/CC2d
			pack()
			Structure CC2d {
			   0   char   1   x   ""
			   4   long   4   l   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC2d() {
		return convertCommentsToSpeculative(getExpectedStructCC2d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC2d() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC2d() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC2e	size(8):
		+---
	 0	| x
  		| <alignment member> (size=3)
	 4	| f
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC2e() {
		String expected =
		//@formatter:off
			"""
			/CC2e
			pack()
			Structure CC2e {
			   0   char   1   x   ""
			   4   float   4   f   ""
			}
			Length: 8 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC2e() {
		return convertCommentsToSpeculative(getExpectedStructCC2e());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC2e() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC2e() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC2f	size(16):
		+---
	 0	| x
		| <alignment member> (size=7)
	 8	| d
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC2f() {
		String expected =
		//@formatter:off
			"""
			/CC2f
			pack()
			Structure CC2f {
			   0   char   1   x   ""
			   8   double   8   d   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC2f() {
		return convertCommentsToSpeculative(getExpectedStructCC2f());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC2f() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC2f() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC2g	size(8):
		+---
	 0	| x
  		| <alignment member> (size=7)
	 8	| p
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC2g() {
		String expected =
		//@formatter:off
			"""
			/CC2g
			pack()
			Structure CC2g {
			   0   char   1   x   ""
			   8   char *   8   p   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC2g() {
		return convertCommentsToSpeculative(getExpectedStructCC2g());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC2g() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC2g() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC2h	size(16):
		+---
	 0	| x
  		| <alignment member> (size=7)
	 8	| ll
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC2h() {
		String expected =
		//@formatter:off
			"""
			/CC2h
			pack()
			Structure CC2h {
			   0   char   1   x   ""
			   8   longlong   8   ll   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC2h() {
		return convertCommentsToSpeculative(getExpectedStructCC2h());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC2h() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC2h() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class CC2j	size(16):
		+---
	 0	| x
  		| <alignment member> (size=7)
	 8	| ld
		+---
	 */
	//@formatter:on
	private static String getExpectedStructCC2j() {
		String expected =
		//@formatter:off
			"""
			/CC2j
			pack()
			Structure CC2j {
			   0   char   1   x   ""
			   8   double   8   ld   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructCC2j() {
		return convertCommentsToSpeculative(getExpectedStructCC2j());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryCC2j() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsCC2j() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DD1a	size(4):
		+---
	 0	| dd1ai
		+---
	 */
	//@formatter:on
	private static String getExpectedStructDD1a() {
		String expected =
		//@formatter:off
			"""
			/DD1a
			pack()
			Structure DD1a {
			   0   int   4   dd1ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructDD1a() {
		return convertCommentsToSpeculative(getExpectedStructDD1a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryDD1a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsDD1a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DD1b	size(20):
		+---
	 0	| {vbptr}
	 8	| dd1bi
  		| <alignment member> (size=4)
		+---
		+--- (virtual base DD1a)
	16	| dd1ai
		+---

	DD1b::$vbtable@:
	 0	| 0
	 1	| 16 (DD1bd(DD1b+0)DD1a)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            DD1a      16       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructDD1b() {
		String expected =
		//@formatter:off
			"""
			/DD1b
			pack()
			Structure DD1b {
			   0   DD1b   16      "Self Base"
			   16   DD1a   4      "Virtual Base"
			}
			Length: 24 Alignment: 8
			/DD1a
			pack()
			Structure DD1a {
			   0   int   4   dd1ai   ""
			}
			Length: 4 Alignment: 4
			/DD1b/!internal/DD1b
			pack()
			Structure DD1b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   dd1bi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructDD1b() {
		String expected =
		//@formatter:off
			"""
			/DD1b
			pack()
			Structure DD1b {
			   0   DD1b   16      "Self Base"
			   16   char[8]   8      "Filler for 1 Unplaceable Virtual Base: DD1a"
			}
			Length: 24 Alignment: 8
			/DD1b/!internal/DD1b
			pack()
			Structure DD1b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   dd1bi   ""
			}
			Length: 16 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructDD1b() {
		return convertCommentsToSpeculative(getExpectedStructDD1b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryDD1b() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[DD1b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsDD1b() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructDD1b_00000000());
		return results;
	}

	private static String getVxtStructDD1b_00000000() {
		String expected =
		//@formatter:off
			"""
			/DD1b/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "DD1a"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DD1c	size(28):
		+---
	 0	| +--- (base class DD1b)
	 0	| | {vbptr}
	 8	| | dd1bi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| dd1ci
  		| <alignment member> (size=4)
		+---
		+--- (virtual base DD1a)
	24	| dd1ai
		+---

	DD1c::$vbtable@:
	 0	| 0
	 1	| 24 (DD1cd(DD1b+0)DD1a)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            DD1a      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructDD1c() {
		String expected =
		//@formatter:off
			"""
			/DD1c
			pack()
			Structure DD1c {
			   0   DD1c   24      "Self Base"
			   24   DD1a   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/DD1a
			pack()
			Structure DD1a {
			   0   int   4   dd1ai   ""
			}
			Length: 4 Alignment: 4
			/DD1b/!internal/DD1b
			pack()
			Structure DD1b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   dd1bi   ""
			}
			Length: 16 Alignment: 8
			/DD1c/!internal/DD1c
			pack()
			Structure DD1c {
			   0   DD1b   16      "Base"
			   16   int   4   dd1ci   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructDD1c() {
		String expected =
		//@formatter:off
			"""
			/DD1c
			pack()
			Structure DD1c {
			   0   DD1c   24      "Self Base"
			   24   char[8]   8      "Filler for 1 Unplaceable Virtual Base: DD1a"
			}
			Length: 32 Alignment: 8
			/DD1b/!internal/DD1b
			pack()
			Structure DD1b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   dd1bi   ""
			}
			Length: 16 Alignment: 8
			/DD1c/!internal/DD1c
			pack()
			Structure DD1c {
			   0   DD1b   16      "Base"
			   16   int   4   dd1ci   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructDD1c() {
		return convertCommentsToSpeculative(getExpectedStructDD1c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryDD1c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[DD1c, DD1b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsDD1c() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructDD1c_00000000());
		return results;
	}

	private static String getVxtStructDD1c_00000000() {
		String expected =
		//@formatter:off
			"""
			/DD1c/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "DD1a"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DD1d	size(28):
		+---
	 0	| +--- (base class DD1b)
	 0	| | {vbptr}
	 8	| | dd1bi
  		| | <alignment member> (size=4)
  		| | <alignment member> (size=4)
		| +---
	16	| dd1di
  		| <alignment member> (size=4)
		+---
		+--- (virtual base DD1a)
	24	| dd1ai
		+---

	DD1d::$vbtable@:
	 0	| 0
	 1	| 24 (DD1dd(DD1b+0)DD1a)
	vbi:	   class  offset o.vbptr  o.vbte fVtorDisp
	            DD1a      24       0       4 0
	 */
	//@formatter:on
	private static String getExpectedStructDD1d() {
		String expected =
		//@formatter:off
			"""
			/DD1d
			pack()
			Structure DD1d {
			   0   DD1d   24      "Self Base"
			   24   DD1a   4      "Virtual Base"
			}
			Length: 32 Alignment: 8
			/DD1a
			pack()
			Structure DD1a {
			   0   int   4   dd1ai   ""
			}
			Length: 4 Alignment: 4
			/DD1b/!internal/DD1b
			pack()
			Structure DD1b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   dd1bi   ""
			}
			Length: 16 Alignment: 8
			/DD1d/!internal/DD1d
			pack()
			Structure DD1d {
			   0   DD1b   16      "Base"
			   16   int   4   dd1di   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getFillerStructDD1d() {
		String expected =
		//@formatter:off
			"""
			/DD1d
			pack()
			Structure DD1d {
			   0   DD1d   24      "Self Base"
			   24   char[8]   8      "Filler for 1 Unplaceable Virtual Base: DD1a"
			}
			Length: 32 Alignment: 8
			/DD1b/!internal/DD1b
			pack()
			Structure DD1b {
			   0   pointer   8   {vbptr}   ""
			   8   int   4   dd1bi   ""
			}
			Length: 16 Alignment: 8
			/DD1d/!internal/DD1d
			pack()
			Structure DD1d {
			   0   DD1b   16      "Base"
			   16   int   4   dd1di   ""
			}
			Length: 24 Alignment: 8""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructDD1d() {
		return convertCommentsToSpeculative(getExpectedStructDD1d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryDD1d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", "     0 vbt []	[DD1d, DD1b]");
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsDD1d() {
		Map<String, String> results = new TreeMap<>();
		results.put("VTABLE_00000000", getVxtStructDD1d_00000000());
		return results;
	}

	private static String getVxtStructDD1d_00000000() {
		String expected =
		//@formatter:off
			"""
			/DD1d/!internal/VTABLE_00000000
			pack()
			Structure VTABLE_00000000 {
			   0   int   4      "DD1a"
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DD2a	size(4):
		+---
	 0	| dd2ai
		+---
	 */
	//@formatter:on
	private static String getExpectedStructDD2a() {
		String expected =
		//@formatter:off
			"""
			/DD2a
			pack()
			Structure DD2a {
			   0   int   4   dd2ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructDD2a() {
		return convertCommentsToSpeculative(getExpectedStructDD2a());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryDD2a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsDD2a() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DD2b	size(4):
		+---
	 0	| dd2bi
		+---
	 */
	//@formatter:on
	private static String getExpectedStructDD2b() {
		String expected =
		//@formatter:off
			"""
			/DD2b
			pack()
			Structure DD2b {
			   0   int   4   dd2bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructDD2b() {
		return convertCommentsToSpeculative(getExpectedStructDD2b());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryDD2b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsDD2b() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DD2c	size(8):
		+---
	 0	| +--- (base class DD2a)
	 0	| | dd2ai
		| +---
	 4	| dd2ci
		+---
	 */
	//@formatter:on
	private static String getExpectedStructDD2c() {
		String expected =
		//@formatter:off
			"""
			/DD2c
			pack()
			Structure DD2c {
			   0   DD2a   4      "Base"
			   4   int   4   dd2ci   ""
			}
			Length: 8 Alignment: 4
			/DD2a
			pack()
			Structure DD2a {
			   0   int   4   dd2ai   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructDD2c() {
		return convertCommentsToSpeculative(getExpectedStructDD2c());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryDD2c() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsDD2c() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DD2d	size(12):
		+---
	 0	| +--- (base class DD2a)
	 0	| | dd2ai
		| +---
	 4	| +--- (base class DD2b)
	 4	| | dd2bi
		| +---
	 8	| dd2di
		+---
	 */
	//@formatter:on
	private static String getExpectedStructDD2d() {
		String expected =
		//@formatter:off
			"""
			/DD2d
			pack()
			Structure DD2d {
			   0   DD2a   4      "Base"
			   4   DD2b   4      "Base"
			   8   int   4   dd2di   ""
			}
			Length: 12 Alignment: 4
			/DD2a
			pack()
			Structure DD2a {
			   0   int   4   dd2ai   ""
			}
			Length: 4 Alignment: 4
			/DD2b
			pack()
			Structure DD2b {
			   0   int   4   dd2bi   ""
			}
			Length: 4 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructDD2d() {
		return convertCommentsToSpeculative(getExpectedStructDD2d());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryDD2d() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsDD2d() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================

	//@formatter:off
	/*
	class DD2e	size(24):
		+---
	 0	| +--- (base class DD2c)
	 0	| | +--- (base class DD2a)
	 0	| | | dd2ai
		| | +---
	 4	| | dd2ci
		| +---
	 8	| +--- (base class DD2d)
	 8	| | +--- (base class DD2a)
	 8	| | | dd2ai
		| | +---
	12	| | +--- (base class DD2b)
	12	| | | dd2bi
		| | +---
	16	| | dd2di
		| +---
	20	| dd2ei
		+---
	 */
	//@formatter:on
	private static String getExpectedStructDD2e() {
		String expected =
		//@formatter:off
			"""
			/DD2e
			pack()
			Structure DD2e {
			   0   DD2c   8      "Base"
			   8   DD2d   12      "Base"
			   20   int   4   dd2ei   ""
			}
			Length: 24 Alignment: 4
			/DD2a
			pack()
			Structure DD2a {
			   0   int   4   dd2ai   ""
			}
			Length: 4 Alignment: 4
			/DD2b
			pack()
			Structure DD2b {
			   0   int   4   dd2bi   ""
			}
			Length: 4 Alignment: 4
			/DD2c
			pack()
			Structure DD2c {
			   0   DD2a   4      "Base"
			   4   int   4   dd2ci   ""
			}
			Length: 8 Alignment: 4
			/DD2d
			pack()
			Structure DD2d {
			   0   DD2a   4      "Base"
			   4   DD2b   4      "Base"
			   8   int   4   dd2di   ""
			}
			Length: 12 Alignment: 4""";
		//@formatter:on
		return expected;
	}

	private static String getSpeculatedStructDD2e() {
		return convertCommentsToSpeculative(getExpectedStructDD2e());
	}

	private static Map<String, String> getExpectedVxtPtrSummaryDD2e() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	private static Map<String, String> getExpectedVxtStructsDD2e() {
		Map<String, String> results = new TreeMap<>();
		return results;
	}

	//==============================================================================================
	//==============================================================================================

	private static final List<ClassID> classIDs = List.of(A, B, C, CC1, CC2, CC3, D, E, F, G, H,
		GG1, GG2, GG3, GG4, I, GX1, HX1, IX1, G1, H1, I1, I2, I3, I4, I5, J1, J2, J3, J4, J5, J6, P,
		Q, R, S, T, U, V, W, WW, X, Z, AA1a, AA1b, AA1, AA2a, AA2b, AA2, AA3a, AA3b, AA3c, AA3d,
		AA3e, AA3f, AA3g, AA4a, AA4b, AA4c, AA4d, AA3e, AA4f, AA4g, AA4h, AA4j, AA4k, AA4m, AA4n,
		AA4p, AA4q, AA4a, AA5b, AA5c, AA5d, AA5e, AA5f, AA5g, AA5h, AA5j, AA6a, AA6b, AA6c, AA6d,
		AA6e, AA6f, AA6g, AA6h, AA6j, AA7a, AA7b, AA7c, AA7c, AA7d, BB1a, BB1b, BB1c, BB1d, BB2z,
		BB2a, BB2b, BB2c, BB2d, BB3a, BB3b, BB3c, BB3d, BB3e, BB3f, BB3g, CC1a, CC1b, CC1c, CC1d,
		CC1e, CC1f, CC1g, CC1h, CC1g_counterpoint, CC1h_counterpoint, CC1g_counterpoint2,
		CC1h_counterpoint2, CC2a, CC2b, CC2c, CC2d, CC2e, CC2f, CC2g, CC2h, CC2j, DD1a, DD1b, DD1c,
		DD1d, DD2a, DD2b, DD2c, DD2d, DD2e);

	private static final Map<ClassID, String> expectedStructs = new LinkedHashMap<>();
	static {
		expectedStructs.put(A, getExpectedStructA());
		expectedStructs.put(B, getExpectedStructB());
		expectedStructs.put(C, getExpectedStructC());
		expectedStructs.put(CC1, getExpectedStructCC1());
		expectedStructs.put(CC2, getExpectedStructCC2());
		expectedStructs.put(CC3, getExpectedStructCC3());
		expectedStructs.put(D, getExpectedStructD());
		expectedStructs.put(E, getExpectedStructE());
		expectedStructs.put(F, getExpectedStructF());
		expectedStructs.put(G, getExpectedStructG());
		expectedStructs.put(H, getExpectedStructH());
		expectedStructs.put(GG1, getExpectedStructGG1());
		expectedStructs.put(GG2, getExpectedStructGG2());
		expectedStructs.put(GG3, getExpectedStructGG3());
		expectedStructs.put(GG4, getExpectedStructGG4());
		expectedStructs.put(I, getExpectedStructI());
		expectedStructs.put(GX1, getExpectedStructGX1());
		expectedStructs.put(HX1, getExpectedStructHX1());
		expectedStructs.put(IX1, getExpectedStructIX1());
		expectedStructs.put(G1, getExpectedStructG1());
		expectedStructs.put(H1, getExpectedStructH1());
		expectedStructs.put(I1, getExpectedStructI1());
		expectedStructs.put(I2, getExpectedStructI2());
		expectedStructs.put(I3, getExpectedStructI3());
		expectedStructs.put(I4, getExpectedStructI4());
		expectedStructs.put(I5, getExpectedStructI5());
		expectedStructs.put(J1, getExpectedStructJ1());
		expectedStructs.put(J2, getExpectedStructJ2());
		expectedStructs.put(J3, getExpectedStructJ3());
		expectedStructs.put(J4, getExpectedStructJ4());
		expectedStructs.put(J6, getExpectedStructJ5());
		expectedStructs.put(J6, getExpectedStructJ6());
		expectedStructs.put(P, getExpectedStructP());
		expectedStructs.put(Q, getExpectedStructQ());
		expectedStructs.put(R, getExpectedStructR());
		expectedStructs.put(S, getExpectedStructS());
		expectedStructs.put(T, getExpectedStructT());
		expectedStructs.put(U, getExpectedStructU());
		expectedStructs.put(V, getExpectedStructV());
		expectedStructs.put(W, getExpectedStructW());
		expectedStructs.put(WW, getExpectedStructWW());
		expectedStructs.put(X, getExpectedStructX());
		expectedStructs.put(Z, getExpectedStructZ());
		expectedStructs.put(AA1a, getExpectedStructAA1a());
		expectedStructs.put(AA1b, getExpectedStructAA1b());
		expectedStructs.put(AA1, getExpectedStructAA1());
		expectedStructs.put(AA2a, getExpectedStructAA2a());
		expectedStructs.put(AA2b, getExpectedStructAA2b());
		expectedStructs.put(AA2, getExpectedStructAA2());
		expectedStructs.put(AA3a, getExpectedStructAA3a());
		expectedStructs.put(AA3b, getExpectedStructAA3b());
		expectedStructs.put(AA3c, getExpectedStructAA3c());
		expectedStructs.put(AA3d, getExpectedStructAA3d());
		expectedStructs.put(AA3e, getExpectedStructAA3e());
		expectedStructs.put(AA3f, getExpectedStructAA3f());
		expectedStructs.put(AA3g, getExpectedStructAA3g());
		expectedStructs.put(AA4a, getExpectedStructAA4a());
		expectedStructs.put(AA4b, getExpectedStructAA4b());
		expectedStructs.put(AA4c, getExpectedStructAA4c());
		expectedStructs.put(AA4d, getExpectedStructAA4d());
		expectedStructs.put(AA4e, getExpectedStructAA4e());
		expectedStructs.put(AA4f, getExpectedStructAA4f());
		expectedStructs.put(AA4g, getExpectedStructAA4g());
		expectedStructs.put(AA4h, getExpectedStructAA4h());
		expectedStructs.put(AA4j, getExpectedStructAA4j());
		expectedStructs.put(AA4k, getExpectedStructAA4k());
		expectedStructs.put(AA4m, getExpectedStructAA4m());
		expectedStructs.put(AA4n, getExpectedStructAA4n());
		expectedStructs.put(AA4p, getExpectedStructAA4p());
		expectedStructs.put(AA4q, getExpectedStructAA4q());
		expectedStructs.put(AA5a, getExpectedStructAA5a());
		expectedStructs.put(AA5b, getExpectedStructAA5b());
		expectedStructs.put(AA5c, getExpectedStructAA5c());
		expectedStructs.put(AA5d, getExpectedStructAA5d());
		expectedStructs.put(AA5e, getExpectedStructAA5e());
		expectedStructs.put(AA5f, getExpectedStructAA5f());
		expectedStructs.put(AA5g, getExpectedStructAA5g());
		expectedStructs.put(AA5h, getExpectedStructAA5h());
		expectedStructs.put(AA5j, getExpectedStructAA5j());
		expectedStructs.put(AA6a, getExpectedStructAA6a());
		expectedStructs.put(AA6b, getExpectedStructAA6b());
		expectedStructs.put(AA6c, getExpectedStructAA6c());
		expectedStructs.put(AA6d, getExpectedStructAA6d());
		expectedStructs.put(AA6e, getExpectedStructAA6e());
		expectedStructs.put(AA6f, getExpectedStructAA6f());
		expectedStructs.put(AA6g, getExpectedStructAA6g());
		expectedStructs.put(AA6h, getExpectedStructAA6h());
		expectedStructs.put(AA6j, getExpectedStructAA6j());
		expectedStructs.put(AA7a, getExpectedStructAA7a());
		expectedStructs.put(AA7b, getExpectedStructAA7b());
		expectedStructs.put(AA7c, getExpectedStructAA7c());
		expectedStructs.put(AA7d, getExpectedStructAA7d());
		expectedStructs.put(BB1a, getExpectedStructBB1a());
		expectedStructs.put(BB1b, getExpectedStructBB1b());
		expectedStructs.put(BB1c, getExpectedStructBB1c());
		expectedStructs.put(BB1d, getExpectedStructBB1d());
		expectedStructs.put(BB2z, getExpectedStructBB2z());
		expectedStructs.put(BB2a, getExpectedStructBB2a());
		expectedStructs.put(BB2b, getExpectedStructBB2b());
		expectedStructs.put(BB2c, getExpectedStructBB2c());
		expectedStructs.put(BB2d, getExpectedStructBB2d());
		expectedStructs.put(BB2e, getExpectedStructBB2e());
		expectedStructs.put(BB3a, getExpectedStructBB3a());
		expectedStructs.put(BB3b, getExpectedStructBB3b());
		expectedStructs.put(BB3c, getExpectedStructBB3c());
		expectedStructs.put(BB3d, getExpectedStructBB3d());
		expectedStructs.put(BB3e, getExpectedStructBB3e());
		expectedStructs.put(BB3f, getExpectedStructBB3f());
		expectedStructs.put(BB3g, getExpectedStructBB3g());
		expectedStructs.put(CC1a, getExpectedStructCC1a());
		expectedStructs.put(CC1b, getExpectedStructCC1b());
		expectedStructs.put(CC1c, getExpectedStructCC1c());
		expectedStructs.put(CC1d, getExpectedStructCC1d());
		expectedStructs.put(CC1e, getExpectedStructCC1e());
		expectedStructs.put(CC1f, getExpectedStructCC1f());
		expectedStructs.put(CC1g, getExpectedStructCC1g());
		expectedStructs.put(CC1h, getExpectedStructCC1h());
		expectedStructs.put(CC1g_counterpoint, getExpectedStructCC1g_counterpoint());
		expectedStructs.put(CC1h_counterpoint, getExpectedStructCC1h_counterpoint());
		expectedStructs.put(CC1g_counterpoint2, getExpectedStructCC1g_counterpoint2());
		expectedStructs.put(CC1h_counterpoint2, getExpectedStructCC1h_counterpoint2());
		expectedStructs.put(CC2a, getExpectedStructCC2a());
		expectedStructs.put(CC2b, getExpectedStructCC2b());
		expectedStructs.put(CC2c, getExpectedStructCC2c());
		expectedStructs.put(CC2d, getExpectedStructCC2d());
		expectedStructs.put(CC2e, getExpectedStructCC2e());
		expectedStructs.put(CC2f, getExpectedStructCC2f());
		expectedStructs.put(CC2g, getExpectedStructCC2g());
		expectedStructs.put(CC2h, getExpectedStructCC2h());
		expectedStructs.put(CC2j, getExpectedStructCC2j());
		expectedStructs.put(DD1a, getExpectedStructDD1a());
		expectedStructs.put(DD1b, getExpectedStructDD1b());
		expectedStructs.put(DD1c, getExpectedStructDD1c());
		expectedStructs.put(DD1d, getExpectedStructDD1d());
		expectedStructs.put(DD2a, getExpectedStructDD2a());
		expectedStructs.put(DD2b, getExpectedStructDD2b());
		expectedStructs.put(DD2c, getExpectedStructDD2c());
		expectedStructs.put(DD2d, getExpectedStructDD2d());
		expectedStructs.put(DD2e, getExpectedStructDD2e());
	}

	private static final Map<ClassID, String> fillerStructs = new LinkedHashMap<>();
	static {
		fillerStructs.putAll(expectedStructs);
		fillerStructs.put(G, getFillerStructG());
		fillerStructs.put(H, getFillerStructH());
		fillerStructs.put(GG1, getFillerStructGG1());
		fillerStructs.put(GG2, getFillerStructGG2());
		fillerStructs.put(GG3, getFillerStructGG3());
		fillerStructs.put(GG4, getFillerStructGG4());
		fillerStructs.put(I, getFillerStructI());
		fillerStructs.put(GX1, getFillerStructGX1());
		fillerStructs.put(HX1, getFillerStructHX1());
		fillerStructs.put(IX1, getFillerStructIX1());
		fillerStructs.put(G1, getFillerStructG1());
		fillerStructs.put(H1, getFillerStructH1());
		fillerStructs.put(I1, getFillerStructI1());
		fillerStructs.put(I2, getFillerStructI2());
		fillerStructs.put(I3, getFillerStructI3());
		fillerStructs.put(I4, getFillerStructI4());
		fillerStructs.put(I5, getFillerStructI5());
		fillerStructs.put(J1, getFillerStructJ1());
		fillerStructs.put(J2, getFillerStructJ2());
		fillerStructs.put(J3, getFillerStructJ3());
		fillerStructs.put(J4, getFillerStructJ4());
		fillerStructs.put(J6, getFillerStructJ6());
		fillerStructs.put(T, getFillerStructT());
		fillerStructs.put(U, getFillerStructU());
		fillerStructs.put(AA3a, getFillerStructAA3a());
		fillerStructs.put(AA3b, getFillerStructAA3b());
		fillerStructs.put(AA3c, getFillerStructAA3c());
		fillerStructs.put(AA3d, getFillerStructAA3d());
		fillerStructs.put(AA3g, getFillerStructAA3g());
		fillerStructs.put(AA4a, getFillerStructAA4a());
		fillerStructs.put(AA4b, getFillerStructAA4b());
		fillerStructs.put(AA4c, getFillerStructAA4c());
		fillerStructs.put(AA4d, getFillerStructAA4d());
		fillerStructs.put(AA4e, getFillerStructAA4e());
		fillerStructs.put(AA4f, getFillerStructAA4f());
		fillerStructs.put(AA4g, getFillerStructAA4g());
		fillerStructs.put(AA4j, getFillerStructAA4j());
		fillerStructs.put(AA4k, getFillerStructAA4k());
		fillerStructs.put(AA4m, getFillerStructAA4m());
		fillerStructs.put(AA4n, getFillerStructAA4n());
		fillerStructs.put(AA4p, getFillerStructAA4p());
		fillerStructs.put(AA4q, getFillerStructAA4q());
		fillerStructs.put(AA5e, getFillerStructAA5e());
		fillerStructs.put(AA5f, getFillerStructAA5f());
		fillerStructs.put(AA5g, getFillerStructAA5g());
		fillerStructs.put(AA5h, getFillerStructAA5h());
		fillerStructs.put(AA5j, getFillerStructAA5j());
		fillerStructs.put(AA6c, getFillerStructAA6c());
		fillerStructs.put(AA6g, getFillerStructAA6g());
		fillerStructs.put(AA6h, getFillerStructAA6h());
		fillerStructs.put(AA6j, getFillerStructAA6j());
		fillerStructs.put(AA7d, getFillerStructAA7d());
		fillerStructs.put(BB1c, getFillerStructBB1c());
		fillerStructs.put(BB1d, getFillerStructBB1d());
		fillerStructs.put(BB2a, getFillerStructBB2a());
		fillerStructs.put(BB2b, getFillerStructBB2b());
		fillerStructs.put(BB2c, getFillerStructBB2c());
		fillerStructs.put(BB2d, getFillerStructBB2d());
		fillerStructs.put(BB2e, getFillerStructBB2e());
		fillerStructs.put(BB3d, getFillerStructBB3d());
		fillerStructs.put(BB3e, getFillerStructBB3e());
		fillerStructs.put(BB3f, getFillerStructBB3f());
		fillerStructs.put(BB3g, getFillerStructBB3g());
		fillerStructs.put(CC1h, getFillerStructCC1h());
		fillerStructs.put(DD1b, getFillerStructDD1b());
		fillerStructs.put(DD1c, getFillerStructDD1c());
		fillerStructs.put(DD1d, getFillerStructDD1d());
	}

	private static final Map<ClassID, String> speculatedStructs = new LinkedHashMap<>();
	static {
		speculatedStructs.put(A, getSpeculatedStructA());
		speculatedStructs.put(B, getSpeculatedStructB());
		speculatedStructs.put(C, getSpeculatedStructC());
		speculatedStructs.put(CC1, getSpeculatedStructCC1());
		speculatedStructs.put(CC2, getSpeculatedStructCC2());
		speculatedStructs.put(CC3, getSpeculatedStructCC3());
		speculatedStructs.put(D, getSpeculatedStructD());
		speculatedStructs.put(E, getSpeculatedStructE());
		speculatedStructs.put(F, getSpeculatedStructF());
		speculatedStructs.put(G, getSpeculatedStructG());
		speculatedStructs.put(H, getSpeculatedStructH());
		speculatedStructs.put(GG1, getSpeculatedStructGG1());
		speculatedStructs.put(GG2, getSpeculatedStructGG2());
		speculatedStructs.put(GG3, getSpeculatedStructGG3());
		speculatedStructs.put(GG4, getSpeculatedStructGG4());
		speculatedStructs.put(I, getSpeculatedStructI());
		speculatedStructs.put(GX1, getSpeculatedStructGX1());
		speculatedStructs.put(HX1, getSpeculatedStructHX1());
		speculatedStructs.put(IX1, getSpeculatedStructIX1());
		speculatedStructs.put(G1, getSpeculatedStructG1());
		speculatedStructs.put(H1, getSpeculatedStructH1());
		speculatedStructs.put(I1, getSpeculatedStructI1());
		speculatedStructs.put(I2, getSpeculatedStructI2());
		speculatedStructs.put(I3, getSpeculatedStructI3());
		speculatedStructs.put(I4, getSpeculatedStructI4());
		speculatedStructs.put(I5, getSpeculatedStructI5());
		speculatedStructs.put(J1, getSpeculatedStructJ1());
		speculatedStructs.put(J2, getSpeculatedStructJ2());
		speculatedStructs.put(J3, getSpeculatedStructJ3());
		speculatedStructs.put(J4, getSpeculatedStructJ4());
		speculatedStructs.put(J5, getSpeculatedStructJ5());
		speculatedStructs.put(J6, getSpeculatedStructJ6());
		speculatedStructs.put(P, getSpeculatedStructP());
		speculatedStructs.put(Q, getSpeculatedStructQ());
		speculatedStructs.put(R, getSpeculatedStructR());
		speculatedStructs.put(S, getSpeculatedStructS());
		speculatedStructs.put(T, getSpeculatedStructT());
		speculatedStructs.put(U, getSpeculatedStructU());
		speculatedStructs.put(V, getSpeculatedStructV());
		speculatedStructs.put(W, getSpeculatedStructW());
		speculatedStructs.put(WW, getSpeculatedStructWW());
		speculatedStructs.put(X, getSpeculatedStructX());
		speculatedStructs.put(Z, getSpeculatedStructZ());
		speculatedStructs.put(P, getSpeculatedStructP());
		speculatedStructs.put(Q, getSpeculatedStructQ());
		speculatedStructs.put(R, getSpeculatedStructR());
		speculatedStructs.put(S, getSpeculatedStructS());
		speculatedStructs.put(T, getSpeculatedStructT());
		speculatedStructs.put(U, getSpeculatedStructU());
		speculatedStructs.put(V, getSpeculatedStructV());
		speculatedStructs.put(W, getSpeculatedStructW());
		speculatedStructs.put(WW, getSpeculatedStructWW());
		speculatedStructs.put(X, getSpeculatedStructX());
		speculatedStructs.put(Z, getSpeculatedStructZ());
		speculatedStructs.put(AA1a, getSpeculatedStructAA1a());
		speculatedStructs.put(AA1b, getSpeculatedStructAA1b());
		speculatedStructs.put(AA1, getSpeculatedStructAA1());
		speculatedStructs.put(AA2a, getSpeculatedStructAA2a());
		speculatedStructs.put(AA2b, getSpeculatedStructAA2b());
		speculatedStructs.put(AA2, getSpeculatedStructAA2());
		speculatedStructs.put(AA3a, getSpeculatedStructAA3a());
		speculatedStructs.put(AA3b, getSpeculatedStructAA3b());
		speculatedStructs.put(AA3c, getSpeculatedStructAA3c());
		speculatedStructs.put(AA3d, getSpeculatedStructAA3d());
		speculatedStructs.put(AA3e, getSpeculatedStructAA3e());
		speculatedStructs.put(AA3f, getSpeculatedStructAA3f());
		speculatedStructs.put(AA3g, getSpeculatedStructAA3g());
		speculatedStructs.put(AA4a, getSpeculatedStructAA4a());
		speculatedStructs.put(AA4b, getSpeculatedStructAA4b());
		speculatedStructs.put(AA4c, getSpeculatedStructAA4c());
		speculatedStructs.put(AA4d, getSpeculatedStructAA4d());
		speculatedStructs.put(AA4e, getSpeculatedStructAA4e());
		speculatedStructs.put(AA4f, getSpeculatedStructAA4f());
		speculatedStructs.put(AA4g, getSpeculatedStructAA4g());
		speculatedStructs.put(AA4h, getSpeculatedStructAA4h());
		speculatedStructs.put(AA4j, getSpeculatedStructAA4j());
		speculatedStructs.put(AA4k, getSpeculatedStructAA4k());
		speculatedStructs.put(AA4m, getSpeculatedStructAA4m());
		speculatedStructs.put(AA4n, getSpeculatedStructAA4n());
		speculatedStructs.put(AA4p, getSpeculatedStructAA4p());
		speculatedStructs.put(AA4q, getSpeculatedStructAA4q());
		speculatedStructs.put(AA5a, getSpeculatedStructAA5a());
		speculatedStructs.put(AA5b, getSpeculatedStructAA5b());
		speculatedStructs.put(AA5c, getSpeculatedStructAA5c());
		speculatedStructs.put(AA5d, getSpeculatedStructAA5d());
		speculatedStructs.put(AA5e, getSpeculatedStructAA5e());
		speculatedStructs.put(AA5f, getSpeculatedStructAA5f());
		speculatedStructs.put(AA5g, getSpeculatedStructAA5g());
		speculatedStructs.put(AA5h, getSpeculatedStructAA5h());
		speculatedStructs.put(AA5j, getSpeculatedStructAA5j());
		speculatedStructs.put(AA6a, getSpeculatedStructAA6a());
		speculatedStructs.put(AA6b, getSpeculatedStructAA6b());
		speculatedStructs.put(AA6c, getSpeculatedStructAA6c());
		speculatedStructs.put(AA6d, getSpeculatedStructAA6d());
		speculatedStructs.put(AA6e, getSpeculatedStructAA6e());
		speculatedStructs.put(AA6f, getSpeculatedStructAA6f());
		speculatedStructs.put(AA6g, getSpeculatedStructAA6g());
		speculatedStructs.put(AA6h, getSpeculatedStructAA6h());
		speculatedStructs.put(AA6j, getSpeculatedStructAA6j());
		speculatedStructs.put(AA7a, getSpeculatedStructAA7a());
		speculatedStructs.put(AA7b, getSpeculatedStructAA7b());
		speculatedStructs.put(AA7c, getSpeculatedStructAA7c());
		speculatedStructs.put(AA7d, getSpeculatedStructAA7d());
		speculatedStructs.put(BB1a, getSpeculatedStructBB1a());
		speculatedStructs.put(BB1b, getSpeculatedStructBB1b());
		speculatedStructs.put(BB1c, getSpeculatedStructBB1c());
		speculatedStructs.put(BB1d, getSpeculatedStructBB1d());
		speculatedStructs.put(BB2z, getSpeculatedStructBB2z());
		speculatedStructs.put(BB2a, getSpeculatedStructBB2a());
		speculatedStructs.put(BB2b, getSpeculatedStructBB2b());
		speculatedStructs.put(BB2c, getSpeculatedStructBB2c());
		speculatedStructs.put(BB2d, getSpeculatedStructBB2d());
		speculatedStructs.put(BB2e, getSpeculatedStructBB2e());
		speculatedStructs.put(BB3a, getSpeculatedStructBB3a());
		speculatedStructs.put(BB3b, getSpeculatedStructBB3b());
		speculatedStructs.put(BB3c, getSpeculatedStructBB3c());
		speculatedStructs.put(BB3d, getSpeculatedStructBB3d());
		speculatedStructs.put(BB3e, getSpeculatedStructBB3e());
		speculatedStructs.put(BB3f, getSpeculatedStructBB3f());
		speculatedStructs.put(BB3g, getSpeculatedStructBB3g());
		speculatedStructs.put(CC1a, getSpeculatedStructCC1a());
		speculatedStructs.put(CC1b, getSpeculatedStructCC1b());
		speculatedStructs.put(CC1c, getSpeculatedStructCC1c());
		speculatedStructs.put(CC1d, getSpeculatedStructCC1d());
		speculatedStructs.put(CC1e, getSpeculatedStructCC1e());
		speculatedStructs.put(CC1f, getSpeculatedStructCC1f());
		speculatedStructs.put(CC1g, getSpeculatedStructCC1g());
		speculatedStructs.put(CC1h, getSpeculatedStructCC1h());
		speculatedStructs.put(CC1g_counterpoint, getSpeculatedStructCC1g_counterpoint());
		speculatedStructs.put(CC1h_counterpoint, getSpeculatedStructCC1h_counterpoint());
		speculatedStructs.put(CC1g_counterpoint2, getSpeculatedStructCC1g_counterpoint2());
		speculatedStructs.put(CC1h_counterpoint2, getSpeculatedStructCC1h_counterpoint2());
		speculatedStructs.put(CC2a, getSpeculatedStructCC2a());
		speculatedStructs.put(CC2b, getSpeculatedStructCC2b());
		speculatedStructs.put(CC2c, getSpeculatedStructCC2c());
		speculatedStructs.put(CC2d, getSpeculatedStructCC2d());
		speculatedStructs.put(CC2e, getSpeculatedStructCC2e());
		speculatedStructs.put(CC2f, getSpeculatedStructCC2f());
		speculatedStructs.put(CC2g, getSpeculatedStructCC2g());
		speculatedStructs.put(CC2h, getSpeculatedStructCC2h());
		speculatedStructs.put(CC2j, getSpeculatedStructCC2j());
		speculatedStructs.put(DD1a, getSpeculatedStructDD1a());
		speculatedStructs.put(DD1b, getSpeculatedStructDD1b());
		speculatedStructs.put(DD1c, getSpeculatedStructDD1c());
		speculatedStructs.put(DD1d, getSpeculatedStructDD1d());
		speculatedStructs.put(DD2a, getSpeculatedStructDD2a());
		speculatedStructs.put(DD2b, getSpeculatedStructDD2b());
		speculatedStructs.put(DD2c, getSpeculatedStructDD2c());
		speculatedStructs.put(DD2d, getSpeculatedStructDD2d());
		speculatedStructs.put(DD2e, getSpeculatedStructDD2e());
	}

	private static final Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
		new LinkedHashMap<>();
	static {
		expectedVxtPtrSummaries.put(A, getExpectedVxtPtrSummaryA());
		expectedVxtPtrSummaries.put(B, getExpectedVxtPtrSummaryB());
		expectedVxtPtrSummaries.put(C, getExpectedVxtPtrSummaryC());
		expectedVxtPtrSummaries.put(CC1, getExpectedVxtPtrSummaryCC1());
		expectedVxtPtrSummaries.put(CC2, getExpectedVxtPtrSummaryCC2());
		expectedVxtPtrSummaries.put(CC3, getExpectedVxtPtrSummaryCC3());
		expectedVxtPtrSummaries.put(D, getExpectedVxtPtrSummaryD());
		expectedVxtPtrSummaries.put(E, getExpectedVxtPtrSummaryE());
		expectedVxtPtrSummaries.put(F, getExpectedVxtPtrSummaryF());
		expectedVxtPtrSummaries.put(G, getExpectedVxtPtrSummaryG());
		expectedVxtPtrSummaries.put(H, getExpectedVxtPtrSummaryH());
		expectedVxtPtrSummaries.put(GG1, getExpectedVxtPtrSummaryGG1());
		expectedVxtPtrSummaries.put(GG2, getExpectedVxtPtrSummaryGG2());
		expectedVxtPtrSummaries.put(GG3, getExpectedVxtPtrSummaryGG3());
		expectedVxtPtrSummaries.put(GG4, getExpectedVxtPtrSummaryGG4());
		expectedVxtPtrSummaries.put(I, getExpectedVxtPtrSummaryI());
		expectedVxtPtrSummaries.put(GX1, getExpectedVxtPtrSummaryGX1());
		expectedVxtPtrSummaries.put(HX1, getExpectedVxtPtrSummaryHX1());
		expectedVxtPtrSummaries.put(IX1, getExpectedVxtPtrSummaryIX1());
		expectedVxtPtrSummaries.put(G1, getExpectedVxtPtrSummaryG1());
		expectedVxtPtrSummaries.put(H1, getExpectedVxtPtrSummaryH1());
		expectedVxtPtrSummaries.put(I1, getExpectedVxtPtrSummaryI1());
		expectedVxtPtrSummaries.put(I2, getExpectedVxtPtrSummaryI2());
		expectedVxtPtrSummaries.put(I3, getExpectedVxtPtrSummaryI3());
		expectedVxtPtrSummaries.put(I4, getExpectedVxtPtrSummaryI4());
		expectedVxtPtrSummaries.put(I5, getExpectedVxtPtrSummaryI5());
		expectedVxtPtrSummaries.put(J1, getExpectedVxtPtrSummaryJ1());
		expectedVxtPtrSummaries.put(J2, getExpectedVxtPtrSummaryJ2());
		expectedVxtPtrSummaries.put(J3, getExpectedVxtPtrSummaryJ3());
		expectedVxtPtrSummaries.put(J4, getExpectedVxtPtrSummaryJ4());
		expectedVxtPtrSummaries.put(J5, getExpectedVxtPtrSummaryJ5());
		expectedVxtPtrSummaries.put(J6, getExpectedVxtPtrSummaryJ6());
		expectedVxtPtrSummaries.put(P, getExpectedVxtPtrSummaryP());
		expectedVxtPtrSummaries.put(Q, getExpectedVxtPtrSummaryQ());
		expectedVxtPtrSummaries.put(R, getExpectedVxtPtrSummaryR());
		expectedVxtPtrSummaries.put(S, getExpectedVxtPtrSummaryS());
		expectedVxtPtrSummaries.put(T, getExpectedVxtPtrSummaryT());
		expectedVxtPtrSummaries.put(U, getExpectedVxtPtrSummaryU());
		expectedVxtPtrSummaries.put(V, getExpectedVxtPtrSummaryV());
		expectedVxtPtrSummaries.put(W, getExpectedVxtPtrSummaryW());
		expectedVxtPtrSummaries.put(WW, getExpectedVxtPtrSummaryWW());
		expectedVxtPtrSummaries.put(X, getExpectedVxtPtrSummaryX());
		expectedVxtPtrSummaries.put(Z, getExpectedVxtPtrSummaryZ());
		expectedVxtPtrSummaries.put(AA1a, getExpectedVxtPtrSummaryAA1a());
		expectedVxtPtrSummaries.put(AA1b, getExpectedVxtPtrSummaryAA1b());
		expectedVxtPtrSummaries.put(AA1, getExpectedVxtPtrSummaryAA1());
		expectedVxtPtrSummaries.put(AA2a, getExpectedVxtPtrSummaryAA2a());
		expectedVxtPtrSummaries.put(AA2b, getExpectedVxtPtrSummaryAA2b());
		expectedVxtPtrSummaries.put(AA2, getExpectedVxtPtrSummaryAA2());
		expectedVxtPtrSummaries.put(AA3a, getExpectedVxtPtrSummaryAA3a());
		expectedVxtPtrSummaries.put(AA3b, getExpectedVxtPtrSummaryAA3b());
		expectedVxtPtrSummaries.put(AA3c, getExpectedVxtPtrSummaryAA3c());
		expectedVxtPtrSummaries.put(AA3d, getExpectedVxtPtrSummaryAA3d());
		expectedVxtPtrSummaries.put(AA3e, getExpectedVxtPtrSummaryAA3e());
		expectedVxtPtrSummaries.put(AA3f, getExpectedVxtPtrSummaryAA3f());
		expectedVxtPtrSummaries.put(AA3g, getExpectedVxtPtrSummaryAA3g());
		expectedVxtPtrSummaries.put(AA4a, getExpectedVxtPtrSummaryAA4a());
		expectedVxtPtrSummaries.put(AA4b, getExpectedVxtPtrSummaryAA4b());
		expectedVxtPtrSummaries.put(AA4c, getExpectedVxtPtrSummaryAA4c());
		expectedVxtPtrSummaries.put(AA4d, getExpectedVxtPtrSummaryAA4d());
		expectedVxtPtrSummaries.put(AA4e, getExpectedVxtPtrSummaryAA4e());
		expectedVxtPtrSummaries.put(AA4f, getExpectedVxtPtrSummaryAA4f());
		expectedVxtPtrSummaries.put(AA4g, getExpectedVxtPtrSummaryAA4g());
		expectedVxtPtrSummaries.put(AA4h, getExpectedVxtPtrSummaryAA4h());
		expectedVxtPtrSummaries.put(AA4j, getExpectedVxtPtrSummaryAA4j());
		expectedVxtPtrSummaries.put(AA4k, getExpectedVxtPtrSummaryAA4k());
		expectedVxtPtrSummaries.put(AA4m, getExpectedVxtPtrSummaryAA4m());
		expectedVxtPtrSummaries.put(AA4n, getExpectedVxtPtrSummaryAA4n());
		expectedVxtPtrSummaries.put(AA4p, getExpectedVxtPtrSummaryAA4p());
		expectedVxtPtrSummaries.put(AA4q, getExpectedVxtPtrSummaryAA4q());
		expectedVxtPtrSummaries.put(AA5a, getExpectedVxtPtrSummaryAA5a());
		expectedVxtPtrSummaries.put(AA5b, getExpectedVxtPtrSummaryAA5b());
		expectedVxtPtrSummaries.put(AA5c, getExpectedVxtPtrSummaryAA5c());
		expectedVxtPtrSummaries.put(AA5d, getExpectedVxtPtrSummaryAA5d());
		expectedVxtPtrSummaries.put(AA5e, getExpectedVxtPtrSummaryAA5e());
		expectedVxtPtrSummaries.put(AA5f, getExpectedVxtPtrSummaryAA5f());
		expectedVxtPtrSummaries.put(AA5g, getExpectedVxtPtrSummaryAA5g());
		expectedVxtPtrSummaries.put(AA5h, getExpectedVxtPtrSummaryAA5h());
		expectedVxtPtrSummaries.put(AA5j, getExpectedVxtPtrSummaryAA5j());
		expectedVxtPtrSummaries.put(AA6a, getExpectedVxtPtrSummaryAA6a());
		expectedVxtPtrSummaries.put(AA6b, getExpectedVxtPtrSummaryAA6b());
		expectedVxtPtrSummaries.put(AA6c, getExpectedVxtPtrSummaryAA6c());
		expectedVxtPtrSummaries.put(AA6d, getExpectedVxtPtrSummaryAA6d());
		expectedVxtPtrSummaries.put(AA6e, getExpectedVxtPtrSummaryAA6e());
		expectedVxtPtrSummaries.put(AA6f, getExpectedVxtPtrSummaryAA6f());
		expectedVxtPtrSummaries.put(AA6g, getExpectedVxtPtrSummaryAA6g());
		expectedVxtPtrSummaries.put(AA6h, getExpectedVxtPtrSummaryAA6h());
		expectedVxtPtrSummaries.put(AA6j, getExpectedVxtPtrSummaryAA6j());
		expectedVxtPtrSummaries.put(AA7a, getExpectedVxtPtrSummaryAA7a());
		expectedVxtPtrSummaries.put(AA7b, getExpectedVxtPtrSummaryAA7b());
		expectedVxtPtrSummaries.put(AA7c, getExpectedVxtPtrSummaryAA7c());
		expectedVxtPtrSummaries.put(AA7d, getExpectedVxtPtrSummaryAA7d());
		expectedVxtPtrSummaries.put(BB1a, getExpectedVxtPtrSummaryBB1a());
		expectedVxtPtrSummaries.put(BB1b, getExpectedVxtPtrSummaryBB1b());
		expectedVxtPtrSummaries.put(BB1c, getExpectedVxtPtrSummaryBB1c());
		expectedVxtPtrSummaries.put(BB1d, getExpectedVxtPtrSummaryBB1d());
		expectedVxtPtrSummaries.put(BB2z, getExpectedVxtPtrSummaryBB2z());
		expectedVxtPtrSummaries.put(BB2a, getExpectedVxtPtrSummaryBB2a());
		expectedVxtPtrSummaries.put(BB2b, getExpectedVxtPtrSummaryBB2b());
		expectedVxtPtrSummaries.put(BB2c, getExpectedVxtPtrSummaryBB2c());
		expectedVxtPtrSummaries.put(BB2d, getExpectedVxtPtrSummaryBB2d());
		expectedVxtPtrSummaries.put(BB2e, getExpectedVxtPtrSummaryBB2e());
		expectedVxtPtrSummaries.put(BB3a, getExpectedVxtPtrSummaryBB3a());
		expectedVxtPtrSummaries.put(BB3b, getExpectedVxtPtrSummaryBB3b());
		expectedVxtPtrSummaries.put(BB3c, getExpectedVxtPtrSummaryBB3c());
		expectedVxtPtrSummaries.put(BB3d, getExpectedVxtPtrSummaryBB3d());
		expectedVxtPtrSummaries.put(BB3e, getExpectedVxtPtrSummaryBB3e());
		expectedVxtPtrSummaries.put(BB3f, getExpectedVxtPtrSummaryBB3f());
		expectedVxtPtrSummaries.put(BB3g, getExpectedVxtPtrSummaryBB3g());
		expectedVxtPtrSummaries.put(CC1a, getExpectedVxtPtrSummaryCC1a());
		expectedVxtPtrSummaries.put(CC1b, getExpectedVxtPtrSummaryCC1b());
		expectedVxtPtrSummaries.put(CC1c, getExpectedVxtPtrSummaryCC1c());
		expectedVxtPtrSummaries.put(CC1d, getExpectedVxtPtrSummaryCC1d());
		expectedVxtPtrSummaries.put(CC1e, getExpectedVxtPtrSummaryCC1e());
		expectedVxtPtrSummaries.put(CC1f, getExpectedVxtPtrSummaryCC1f());
		expectedVxtPtrSummaries.put(CC1g, getExpectedVxtPtrSummaryCC1g());
		expectedVxtPtrSummaries.put(CC1h, getExpectedVxtPtrSummaryCC1h());
		expectedVxtPtrSummaries.put(CC1g_counterpoint, getExpectedVxtPtrSummaryCC1g_counterpoint());
		expectedVxtPtrSummaries.put(CC1h_counterpoint, getExpectedVxtPtrSummaryCC1h_counterpoint());
		expectedVxtPtrSummaries.put(CC1g_counterpoint2,
			getExpectedVxtPtrSummaryCC1g_counterpoint2());
		expectedVxtPtrSummaries.put(CC1h_counterpoint2,
			getExpectedVxtPtrSummaryCC1h_counterpoint2());
		expectedVxtPtrSummaries.put(CC2a, getExpectedVxtPtrSummaryCC2a());
		expectedVxtPtrSummaries.put(CC2b, getExpectedVxtPtrSummaryCC2b());
		expectedVxtPtrSummaries.put(CC2c, getExpectedVxtPtrSummaryCC2c());
		expectedVxtPtrSummaries.put(CC2d, getExpectedVxtPtrSummaryCC2d());
		expectedVxtPtrSummaries.put(CC2e, getExpectedVxtPtrSummaryCC2e());
		expectedVxtPtrSummaries.put(CC2f, getExpectedVxtPtrSummaryCC2f());
		expectedVxtPtrSummaries.put(CC2g, getExpectedVxtPtrSummaryCC2g());
		expectedVxtPtrSummaries.put(CC2h, getExpectedVxtPtrSummaryCC2h());
		expectedVxtPtrSummaries.put(CC2j, getExpectedVxtPtrSummaryCC2j());
		expectedVxtPtrSummaries.put(DD1a, getExpectedVxtPtrSummaryDD1a());
		expectedVxtPtrSummaries.put(DD1b, getExpectedVxtPtrSummaryDD1b());
		expectedVxtPtrSummaries.put(DD1c, getExpectedVxtPtrSummaryDD1c());
		expectedVxtPtrSummaries.put(DD1d, getExpectedVxtPtrSummaryDD1d());
		expectedVxtPtrSummaries.put(DD2a, getExpectedVxtPtrSummaryDD2a());
		expectedVxtPtrSummaries.put(DD2b, getExpectedVxtPtrSummaryDD2b());
		expectedVxtPtrSummaries.put(DD2c, getExpectedVxtPtrSummaryDD2c());
		expectedVxtPtrSummaries.put(DD2d, getExpectedVxtPtrSummaryDD2d());
		expectedVxtPtrSummaries.put(DD2e, getExpectedVxtPtrSummaryDD2e());
	}

	private static final Map<ClassID, Map<String, String>> speculatedVxtPtrSummaries =
		new LinkedHashMap<>();
	static {
		speculatedVxtPtrSummaries.putAll(expectedVxtPtrSummaries);
		// The following will replace entries as needed
		speculatedVxtPtrSummaries.put(J5, getSpeculatedVxtPtrSummaryJ5());
		speculatedVxtPtrSummaries.put(J6, getSpeculatedVxtPtrSummaryJ6());
		// Need to implement values for classes P through DD2e
	}

	private static final Map<ClassID, Map<String, String>> expectedVxtStructs =
		new LinkedHashMap<>();
	static {
		expectedVxtStructs.put(A, getExpectedVxtStructsA());
		expectedVxtStructs.put(B, getExpectedVxtStructsB());
		expectedVxtStructs.put(C, getExpectedVxtStructsC());
		expectedVxtStructs.put(CC1, getExpectedVxtStructsCC1());
		expectedVxtStructs.put(CC2, getExpectedVxtStructsCC2());
		expectedVxtStructs.put(CC3, getExpectedVxtStructsCC3());
		expectedVxtStructs.put(D, getExpectedVxtStructsD());
		expectedVxtStructs.put(E, getExpectedVxtStructsE());
		expectedVxtStructs.put(F, getExpectedVxtStructsF());
		expectedVxtStructs.put(G, getExpectedVxtStructsG());
		expectedVxtStructs.put(H, getExpectedVxtStructsH());
		expectedVxtStructs.put(GG1, getExpectedVxtStructsGG1());
		expectedVxtStructs.put(GG2, getExpectedVxtStructsGG2());
		expectedVxtStructs.put(GG3, getExpectedVxtStructsGG3());
		expectedVxtStructs.put(GG4, getExpectedVxtStructsGG4());
		expectedVxtStructs.put(I, getExpectedVxtStructsI());
		expectedVxtStructs.put(GX1, getExpectedVxtStructsGX1());
		expectedVxtStructs.put(HX1, getExpectedVxtStructsHX1());
		expectedVxtStructs.put(IX1, getExpectedVxtStructsIX1());
		expectedVxtStructs.put(G1, getExpectedVxtStructsG1());
		expectedVxtStructs.put(H1, getExpectedVxtStructsH1());
		expectedVxtStructs.put(I1, getExpectedVxtStructsI1());
		expectedVxtStructs.put(I2, getExpectedVxtStructsI2());
		expectedVxtStructs.put(I3, getExpectedVxtStructsI3());
		expectedVxtStructs.put(I4, getExpectedVxtStructsI4());
		expectedVxtStructs.put(I5, getExpectedVxtStructsI5());
		expectedVxtStructs.put(J1, getExpectedVxtStructsJ1());
		expectedVxtStructs.put(J2, getExpectedVxtStructsJ2());
		expectedVxtStructs.put(J3, getExpectedVxtStructsJ3());
		expectedVxtStructs.put(J4, getExpectedVxtStructsJ4());
		expectedVxtStructs.put(J5, getExpectedVxtStructsJ5());
		expectedVxtStructs.put(J6, getExpectedVxtStructsJ6());
		expectedVxtStructs.put(P, getExpectedVxtStructsP());
		expectedVxtStructs.put(Q, getExpectedVxtStructsQ());
		expectedVxtStructs.put(R, getExpectedVxtStructsR());
		expectedVxtStructs.put(S, getExpectedVxtStructsS());
		expectedVxtStructs.put(T, getExpectedVxtStructsT());
		expectedVxtStructs.put(U, getExpectedVxtStructsU());
		expectedVxtStructs.put(V, getExpectedVxtStructsV());
		expectedVxtStructs.put(W, getExpectedVxtStructsW());
		expectedVxtStructs.put(WW, getExpectedVxtStructsWW());
		expectedVxtStructs.put(X, getExpectedVxtStructsX());
		expectedVxtStructs.put(Z, getExpectedVxtStructsZ());
		expectedVxtStructs.put(AA1a, getExpectedVxtStructsAA1a());
		expectedVxtStructs.put(AA1b, getExpectedVxtStructsAA1b());
		expectedVxtStructs.put(AA1, getExpectedVxtStructsAA1());
		expectedVxtStructs.put(AA2a, getExpectedVxtStructsAA2a());
		expectedVxtStructs.put(AA2b, getExpectedVxtStructsAA2b());
		expectedVxtStructs.put(AA2, getExpectedVxtStructsAA2());
		expectedVxtStructs.put(AA3a, getExpectedVxtStructsAA3a());
		expectedVxtStructs.put(AA3b, getExpectedVxtStructsAA3b());
		expectedVxtStructs.put(AA3c, getExpectedVxtStructsAA3c());
		expectedVxtStructs.put(AA3d, getExpectedVxtStructsAA3d());
		expectedVxtStructs.put(AA3e, getExpectedVxtStructsAA3e());
		expectedVxtStructs.put(AA3f, getExpectedVxtStructsAA3f());
		expectedVxtStructs.put(AA3g, getExpectedVxtStructsAA3g());
		expectedVxtStructs.put(AA4a, getExpectedVxtStructsAA4a());
		expectedVxtStructs.put(AA4b, getExpectedVxtStructsAA4b());
		expectedVxtStructs.put(AA4c, getExpectedVxtStructsAA4c());
		expectedVxtStructs.put(AA4d, getExpectedVxtStructsAA4d());
		expectedVxtStructs.put(AA4e, getExpectedVxtStructsAA4e());
		expectedVxtStructs.put(AA4f, getExpectedVxtStructsAA4f());
		expectedVxtStructs.put(AA4g, getExpectedVxtStructsAA4g());
		expectedVxtStructs.put(AA4h, getExpectedVxtStructsAA4h());
		expectedVxtStructs.put(AA4j, getExpectedVxtStructsAA4j());
		expectedVxtStructs.put(AA4k, getExpectedVxtStructsAA4k());
		expectedVxtStructs.put(AA4m, getExpectedVxtStructsAA4m());
		expectedVxtStructs.put(AA4n, getExpectedVxtStructsAA4n());
		expectedVxtStructs.put(AA4p, getExpectedVxtStructsAA4p());
		expectedVxtStructs.put(AA4q, getExpectedVxtStructsAA4q());
		expectedVxtStructs.put(AA5a, getExpectedVxtStructsAA5a());
		expectedVxtStructs.put(AA5b, getExpectedVxtStructsAA5b());
		expectedVxtStructs.put(AA5c, getExpectedVxtStructsAA5c());
		expectedVxtStructs.put(AA5d, getExpectedVxtStructsAA5d());
		expectedVxtStructs.put(AA5e, getExpectedVxtStructsAA5e());
		expectedVxtStructs.put(AA5f, getExpectedVxtStructsAA5f());
		expectedVxtStructs.put(AA5g, getExpectedVxtStructsAA5g());
		expectedVxtStructs.put(AA5h, getExpectedVxtStructsAA5h());
		expectedVxtStructs.put(AA5j, getExpectedVxtStructsAA5j());
		expectedVxtStructs.put(AA6a, getExpectedVxtStructsAA6a());
		expectedVxtStructs.put(AA6b, getExpectedVxtStructsAA6b());
		expectedVxtStructs.put(AA6c, getExpectedVxtStructsAA6c());
		expectedVxtStructs.put(AA6d, getExpectedVxtStructsAA6d());
		expectedVxtStructs.put(AA6e, getExpectedVxtStructsAA6e());
		expectedVxtStructs.put(AA6f, getExpectedVxtStructsAA6f());
		expectedVxtStructs.put(AA6g, getExpectedVxtStructsAA6g());
		expectedVxtStructs.put(AA6h, getExpectedVxtStructsAA6h());
		expectedVxtStructs.put(AA6j, getExpectedVxtStructsAA6j());
		expectedVxtStructs.put(AA7a, getExpectedVxtStructsAA7a());
		expectedVxtStructs.put(AA7b, getExpectedVxtStructsAA7b());
		expectedVxtStructs.put(AA7c, getExpectedVxtStructsAA7c());
		expectedVxtStructs.put(AA7d, getExpectedVxtStructsAA7d());
		expectedVxtStructs.put(BB1a, getExpectedVxtStructsBB1a());
		expectedVxtStructs.put(BB1b, getExpectedVxtStructsBB1b());
		expectedVxtStructs.put(BB1c, getExpectedVxtStructsBB1c());
		expectedVxtStructs.put(BB1d, getExpectedVxtStructsBB1d());
		expectedVxtStructs.put(BB2z, getExpectedVxtStructsBB2z());
		expectedVxtStructs.put(BB2a, getExpectedVxtStructsBB2a());
		expectedVxtStructs.put(BB2b, getExpectedVxtStructsBB2b());
		expectedVxtStructs.put(BB2c, getExpectedVxtStructsBB2c());
		expectedVxtStructs.put(BB2d, getExpectedVxtStructsBB2d());
		expectedVxtStructs.put(BB2e, getExpectedVxtStructsBB2e());
		expectedVxtStructs.put(BB3a, getExpectedVxtStructsBB3a());
		expectedVxtStructs.put(BB3b, getExpectedVxtStructsBB3b());
		expectedVxtStructs.put(BB3c, getExpectedVxtStructsBB3c());
		expectedVxtStructs.put(BB3d, getExpectedVxtStructsBB3d());
		expectedVxtStructs.put(BB3e, getExpectedVxtStructsBB3e());
		expectedVxtStructs.put(BB3f, getExpectedVxtStructsBB3f());
		expectedVxtStructs.put(BB3g, getExpectedVxtStructsBB3g());
		expectedVxtStructs.put(CC1a, getExpectedVxtStructsCC1a());
		expectedVxtStructs.put(CC1b, getExpectedVxtStructsCC1b());
		expectedVxtStructs.put(CC1c, getExpectedVxtStructsCC1c());
		expectedVxtStructs.put(CC1d, getExpectedVxtStructsCC1d());
		expectedVxtStructs.put(CC1e, getExpectedVxtStructsCC1e());
		expectedVxtStructs.put(CC1f, getExpectedVxtStructsCC1f());
		expectedVxtStructs.put(CC1g, getExpectedVxtStructsCC1g());
		expectedVxtStructs.put(CC1h, getExpectedVxtStructsCC1h());
		expectedVxtStructs.put(CC1g_counterpoint, getExpectedVxtStructsCC1g_counterpoint());
		expectedVxtStructs.put(CC1h_counterpoint, getExpectedVxtStructsCC1h_counterpoint());
		expectedVxtStructs.put(CC1g_counterpoint2, getExpectedVxtStructsCC1g_counterpoint2());
		expectedVxtStructs.put(CC1h_counterpoint2, getExpectedVxtStructsCC1h_counterpoint2());
		expectedVxtStructs.put(CC2a, getExpectedVxtStructsCC2a());
		expectedVxtStructs.put(CC2b, getExpectedVxtStructsCC2b());
		expectedVxtStructs.put(CC2c, getExpectedVxtStructsCC2c());
		expectedVxtStructs.put(CC2d, getExpectedVxtStructsCC2d());
		expectedVxtStructs.put(CC2e, getExpectedVxtStructsCC2e());
		expectedVxtStructs.put(CC2f, getExpectedVxtStructsCC2f());
		expectedVxtStructs.put(CC2g, getExpectedVxtStructsCC2g());
		expectedVxtStructs.put(CC2h, getExpectedVxtStructsCC2h());
		expectedVxtStructs.put(CC2j, getExpectedVxtStructsCC2j());
		expectedVxtStructs.put(DD1a, getExpectedVxtStructsDD1a());
		expectedVxtStructs.put(DD1b, getExpectedVxtStructsDD1b());
		expectedVxtStructs.put(DD1c, getExpectedVxtStructsDD1c());
		expectedVxtStructs.put(DD1d, getExpectedVxtStructsDD1d());
		expectedVxtStructs.put(DD2a, getExpectedVxtStructsDD2a());
		expectedVxtStructs.put(DD2b, getExpectedVxtStructsDD2b());
		expectedVxtStructs.put(DD2c, getExpectedVxtStructsDD2c());
		expectedVxtStructs.put(DD2d, getExpectedVxtStructsDD2d());
		expectedVxtStructs.put(DD2e, getExpectedVxtStructsDD2e());
	}

	private static final Map<ClassID, Map<String, String>> speculatedVxtStructs =
		new LinkedHashMap<>();
	static {
		speculatedVxtStructs.putAll(expectedVxtStructs);
		// The following will replace entries as needed
		speculatedVxtStructs.put(J5, getSpeculatedVxtStructsJ5());
		speculatedVxtStructs.put(J6, getSpeculatedVxtStructsJ6());
		// Need to implement values for classes P through DD2e

		speculatedVxtStructs.put(T, getSpeculatedVxtStructsT());
		speculatedVxtStructs.put(U, getSpeculatedVxtStructsU());

	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================

	public Egray864ProgramCreator() {
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
		CppCompositeType sA = createA_struct(dtm);
		cppTypes.add(sA);
		CppCompositeType sB = createB_struct(dtm);
		cppTypes.add(sB);
		CppCompositeType sC = createC_struct(dtm);
		cppTypes.add(sC);
		CppCompositeType sCC1 = createCC1_struct(dtm);
		cppTypes.add(sCC1);
		CppCompositeType sCC2 = createCC2_struct(dtm);
		cppTypes.add(sCC2);
		CppCompositeType sCC3 = createCC3_struct(dtm);
		cppTypes.add(sCC3);
		CppCompositeType sD = createD_struct(dtm, sC);
		cppTypes.add(sD);
		CppCompositeType sE = createE_struct(dtm);
		cppTypes.add(sE);
		CppCompositeType sF = createF_struct(dtm, sC, sE);
		cppTypes.add(sF);
		CppCompositeType sG = createG_struct(dtm, sC);
		cppTypes.add(sG);
		CppCompositeType sH = createH_struct(dtm, sC);
		cppTypes.add(sH);
		CppCompositeType sGG1 = createGG1_struct(dtm, sCC1);
		cppTypes.add(sGG1);
		CppCompositeType sGG2 = createGG2_struct(dtm, sCC2);
		cppTypes.add(sGG2);
		CppCompositeType sGG3 = createGG3_struct(dtm, sCC2);
		cppTypes.add(sGG3);
		CppCompositeType sGG4 = createGG4_struct(dtm, sCC3);
		cppTypes.add(sGG4);
		CppCompositeType sI = createI_struct(dtm, sG, sH, sC);
		cppTypes.add(sI);
		CppCompositeType sGX1 = createGX1_struct(dtm, sC);
		cppTypes.add(sGX1);
		CppCompositeType sHX1 = createHX1_struct(dtm, sC);
		cppTypes.add(sHX1);
		CppCompositeType sIX1 = createIX1_struct(dtm, sGX1, sHX1, sC);
		cppTypes.add(sIX1);
		CppCompositeType sG1 = createG1_struct(dtm, sC, sE);
		cppTypes.add(sG1);
		CppCompositeType sH1 = createH1_struct(dtm, sC, sE);
		cppTypes.add(sH1);
		CppCompositeType sI1 = createI1_struct(dtm, sG1, sH, sC, sE);
		cppTypes.add(sI1);
		CppCompositeType sI2 = createI2_struct(dtm, sG, sH1, sC, sE);
		cppTypes.add(sI2);
		CppCompositeType sI3 = createI3_struct(dtm, sG1, sH1, sC, sE);
		cppTypes.add(sI3);
		CppCompositeType sI4 = createI4_struct(dtm, sG1, sC, sE);
		cppTypes.add(sI4);
		CppCompositeType sI5 = createI5_struct(dtm, sG1, sE, sC);
		cppTypes.add(sI5);
		CppCompositeType sJ1 = createJ1_struct(dtm, sI1, sI2, sC, sE);
		cppTypes.add(sJ1);
		CppCompositeType sJ2 = createJ2_struct(dtm, sI2, sI1, sC, sE);
		cppTypes.add(sJ2);
		CppCompositeType sJ3 = createJ3_struct(dtm, sI2, sI1, sA, sC, sE);
		cppTypes.add(sJ3);
		CppCompositeType sJ4 =
			createJ4_struct(dtm, sI3, sGG1, sI, sA, sC, sE, sCC1, sCC2, sGG2, sGG3);
		cppTypes.add(sJ4);
		CppCompositeType sJ5 =
			createJ5_struct(dtm, sI3, sGG1, sI, sA, sCC2, sGG2, sGG3, sC, sE, sCC1);
		cppTypes.add(sJ5);
		CppCompositeType sJ6 = createJ6_struct(dtm, sA, sCC3, sGG4, sCC2, sGG3);
		cppTypes.add(sJ6);
		CppCompositeType sP = createP_struct(dtm);
		cppTypes.add(sP);
		CppCompositeType sQ = createQ_struct(dtm, sP);
		cppTypes.add(sQ);
		CppCompositeType sR = createR_struct(dtm);
		cppTypes.add(sR);
		CppCompositeType sS = createS_struct(dtm, sP, sR);
		cppTypes.add(sS);
		CppCompositeType sT = createT_struct(dtm, sP);
		cppTypes.add(sT);
		CppCompositeType sU = createU_struct(dtm, sT, sP);
		cppTypes.add(sU);
		CppCompositeType sV = createV_struct(dtm);
		cppTypes.add(sV);
		CppCompositeType sW = createW_struct(dtm, sV);
		cppTypes.add(sW);
		CppCompositeType sWW = createWW_struct(dtm, sW);
		cppTypes.add(sWW);
		CppCompositeType sX = createX_struct(dtm);
		cppTypes.add(sX);
		CppCompositeType sZ = createZ_struct(dtm);
		cppTypes.add(sZ);
		CppCompositeType sAA1a = createAA1a_struct(dtm);
		cppTypes.add(sAA1a);
		CppCompositeType sAA1b = createAA1b_struct(dtm);
		cppTypes.add(sAA1b);
		CppCompositeType sAA1 = createAA1_struct(dtm, sAA1a, sAA1b);
		cppTypes.add(sAA1);
		CppCompositeType sAA2a = createAA2a_struct(dtm);
		cppTypes.add(sAA2a);
		CppCompositeType sAA2b = createAA2b_struct(dtm);
		cppTypes.add(sAA2b);
		CppCompositeType sAA2 = createAA2_struct(dtm, sAA2a, sAA2b);
		cppTypes.add(sAA2);
		CppCompositeType sAA3a = createAA3a_struct(dtm, sAA2);
		cppTypes.add(sAA3a);
		CppCompositeType sAA3b = createAA3b_struct(dtm, sAA2);
		cppTypes.add(sAA3b);
		CppCompositeType sAA3c = createAA3c_struct(dtm, sAA3a, sAA3b, sAA1, sAA2);
		cppTypes.add(sAA3c);
		CppCompositeType sAA3d = createAA3d_struct(dtm, sAA1, sAA2, sAA3a, sAA3b);
		cppTypes.add(sAA3d);
		CppCompositeType sAA3e = createAA3e_struct(dtm, sAA2);
		cppTypes.add(sAA3e);
		CppCompositeType sAA3f = createAA3f_struct(dtm, sAA2);
		cppTypes.add(sAA3f);
		CppCompositeType sAA3g = createAA3g_struct(dtm, sAA3e, sAA3f);
		cppTypes.add(sAA3g);
		CppCompositeType sAA4a = createAA4a_struct(dtm, sAA1);
		cppTypes.add(sAA4a);
		CppCompositeType sAA4b = createAA4b_struct(dtm, sAA1);
		cppTypes.add(sAA4b);
		CppCompositeType sAA4c = createAA4c_struct(dtm, sAA4a, sAA4b, sAA1);
		cppTypes.add(sAA4c);
		CppCompositeType sAA4d = createAA4d_struct(dtm, sAA4b, sAA1, sAA4a);
		cppTypes.add(sAA4d);
		CppCompositeType sAA4e = createAA4e_struct(dtm, sAA4a, sAA1, sAA4b);
		cppTypes.add(sAA4e);
		CppCompositeType sAA4f = createAA4f_struct(dtm, sAA1, sAA4a, sAA4b);
		cppTypes.add(sAA4f);
		CppCompositeType sAA4g = createAA4g_struct(dtm, sAA4b, sAA1);
		cppTypes.add(sAA4g);
		CppCompositeType sAA4h = createAA4h_struct(dtm);
		cppTypes.add(sAA4h);
		CppCompositeType sAA4j = createAA4j_struct(dtm, sAA4h);
		cppTypes.add(sAA4j);
		CppCompositeType sAA4k = createAA4k_struct(dtm, sAA4h);
		cppTypes.add(sAA4k);
		CppCompositeType sAA4m = createAA4m_struct(dtm, sAA4j, sAA4h);
		cppTypes.add(sAA4m);
		CppCompositeType sAA4n = createAA4n_struct(dtm, sAA4k, sAA4h);
		cppTypes.add(sAA4n);
		CppCompositeType sAA4p = createAA4p_struct(dtm, sAA4m, sAA4h);
		cppTypes.add(sAA4p);
		CppCompositeType sAA4q = createAA4q_struct(dtm, sAA4n, sAA4m, sAA4h);
		cppTypes.add(sAA4q);
		CppCompositeType sAA5a = createAA5a_struct(dtm);
		cppTypes.add(sAA5a);
		CppCompositeType sAA5b = createAA5b_struct(dtm);
		cppTypes.add(sAA5b);
		CppCompositeType sAA5c = createAA5c_struct(dtm);
		cppTypes.add(sAA5c);
		CppCompositeType sAA5d = createAA5d_struct(dtm);
		cppTypes.add(sAA5d);
		CppCompositeType sAA5e = createAA5e_struct(dtm, sAA5a, sAA5b);
		cppTypes.add(sAA5e);
		CppCompositeType sAA5f = createAA5f_struct(dtm, sAA5c, sAA5d);
		cppTypes.add(sAA5f);
		CppCompositeType sAA5g = createAA5g_struct(dtm, sAA5c, sAA5b, sAA5e);
		cppTypes.add(sAA5g);
		CppCompositeType sAA5h = createAA5h_struct(dtm, sAA5a, sAA5d, sAA5f);
		cppTypes.add(sAA5h);
		CppCompositeType sAA5j = createAA5j_struct(dtm, sAA5g, sAA5h, sAA5b, sAA5e, sAA5d, sAA5f);
		cppTypes.add(sAA5j);
		CppCompositeType sAA6a = createAA6a_struct(dtm);
		cppTypes.add(sAA6a);
		CppCompositeType sAA6b = createAA6b_struct(dtm, sAA6a);
		cppTypes.add(sAA6b);
		CppCompositeType sAA6c = createAA6c_struct(dtm, sAA6a);
		cppTypes.add(sAA6c);
		CppCompositeType sAA6d = createAA6d_struct(dtm, sAA6a);
		cppTypes.add(sAA6d);
		CppCompositeType sAA6e = createAA6e_struct(dtm, sAA6a);
		cppTypes.add(sAA6e);
		CppCompositeType sAA6f = createAA6f_struct(dtm, sAA6b, sAA6a);
		cppTypes.add(sAA6f);
		CppCompositeType sAA6g = createAA6g_struct(dtm, sAA6c, sAA6a);
		cppTypes.add(sAA6g);
		CppCompositeType sAA6h = createAA6h_struct(dtm, sAA6a, sAA6c);
		cppTypes.add(sAA6h);
		CppCompositeType sAA6j = createAA6j_struct(dtm, sAA6a, sAA6c);
		cppTypes.add(sAA6j);
		CppCompositeType sAA7a = createAA7a_struct(dtm);
		cppTypes.add(sAA7a);
		CppCompositeType sAA7b = createAA7b_struct(dtm);
		cppTypes.add(sAA7b);
		CppCompositeType sAA7c = createAA7c_struct(dtm, sAA7a, sAA7b);
		cppTypes.add(sAA7c);
		CppCompositeType sAA7d = createAA7d_struct(dtm, sAA7a, sAA7b);
		cppTypes.add(sAA7d);
		CppCompositeType sBB1a = createBB1a_struct(dtm);
		cppTypes.add(sBB1a);
		CppCompositeType sBB1b = createBB1b_struct(dtm, sBB1a);
		cppTypes.add(sBB1b);
		CppCompositeType sBB1c = createBB1c_struct(dtm, sBB1a);
		cppTypes.add(sBB1c);
		CppCompositeType sBB1d = createBB1d_struct(dtm, sBB1b, sBB1c, sBB1a);
		cppTypes.add(sBB1d);
		CppCompositeType sBB2z = createBB2z_struct(dtm);
		cppTypes.add(sBB2z);
		CppCompositeType sBB2a = createBB2a_struct(dtm, sBB2z);
		cppTypes.add(sBB2a);
		CppCompositeType sBB2b = createBB2b_struct(dtm, sBB2a, sBB2z);
		cppTypes.add(sBB2b);
		CppCompositeType sBB2c = createBB2c_struct(dtm, sBB2z, sBB2a);
		cppTypes.add(sBB2c);
		CppCompositeType sBB2d = createBB2d_struct(dtm, sBB2b, sBB2c, sBB2z, sBB2a);
		cppTypes.add(sBB2d);
		CppCompositeType sBB2e = createBB2e_struct(dtm, sBB2b, sBB2z);
		cppTypes.add(sBB2e);
		CppCompositeType sBB3a = createBB3a_struct(dtm);
		cppTypes.add(sBB3a);
		CppCompositeType sBB3b = createBB3b_struct(dtm);
		cppTypes.add(sBB3b);
		CppCompositeType sBB3c = createBB3c_struct(dtm);
		cppTypes.add(sBB3c);
		CppCompositeType sBB3d = createBB3d_struct(dtm, sBB3a, sBB3c, sBB3b);
		cppTypes.add(sBB3d);
		CppCompositeType sBB3e = createBB3e_struct(dtm, sBB3b, sBB3a, sBB3c);
		cppTypes.add(sBB3e);
		CppCompositeType sBB3f = createBB3f_struct(dtm, sBB3d, sBB3e, sBB3b, sBB3a, sBB3c);
		cppTypes.add(sBB3f);
		CppCompositeType sBB3g = createBB3g_struct(dtm, sBB3e, sBB3d, sBB3a, sBB3c, sBB3b);
		cppTypes.add(sBB3g);
		CppCompositeType sCC1a = createCC1a_struct(dtm);
		cppTypes.add(sCC1a);
		CppCompositeType sCC1b = createCC1b_struct(dtm);
		cppTypes.add(sCC1b);
		CppCompositeType sCC1c = createCC1c_struct(dtm);
		cppTypes.add(sCC1c);
		CppCompositeType sCC1d = createCC1d_struct(dtm);
		cppTypes.add(sCC1d);
		CppCompositeType sCC1e = createCC1e_struct(dtm);
		cppTypes.add(sCC1e);
		CppCompositeType sCC1f = createCC1f_struct(dtm);
		cppTypes.add(sCC1f);
		CppCompositeType sCC1g = createCC1g_struct(dtm, sCC1a, sCC1b, sCC1c, sCC1d, sCC1e, sCC1f);
		cppTypes.add(sCC1g);
		CppCompositeType sCC1h = createCC1h_struct(dtm, sCC1a, sCC1b, sCC1c, sCC1d, sCC1e, sCC1f);
		cppTypes.add(sCC1h);
		CppCompositeType sCC1g_counterpoint = createCC1g_counterpoint_struct(dtm);
		cppTypes.add(sCC1g_counterpoint);
		CppCompositeType sCC1h_counterpoint = createCC1h_counterpoint_struct(dtm);
		cppTypes.add(sCC1h_counterpoint);
		CppCompositeType sCC1g_counterpoint2 = createCC1g_counterpoint2_struct(dtm);
		cppTypes.add(sCC1g_counterpoint2);
		CppCompositeType sCC1h_counterpoint2 = createCC1h_counterpoint2_struct(dtm);
		cppTypes.add(sCC1h_counterpoint2);
		CppCompositeType sCC2a = createCC2a_struct(dtm);
		cppTypes.add(sCC2a);
		CppCompositeType sCC2b = createCC2b_struct(dtm);
		cppTypes.add(sCC2b);
		CppCompositeType sCC2c = createCC2c_struct(dtm);
		cppTypes.add(sCC2c);
		CppCompositeType sCC2d = createCC2d_struct(dtm);
		cppTypes.add(sCC2d);
		CppCompositeType sCC2e = createCC2e_struct(dtm);
		cppTypes.add(sCC2e);
		CppCompositeType sCC2f = createCC2f_struct(dtm);
		cppTypes.add(sCC2f);
		CppCompositeType sCC2g = createCC2g_struct(dtm);
		cppTypes.add(sCC2g);
		CppCompositeType sCC2h = createCC2h_struct(dtm);
		cppTypes.add(sCC2h);
		CppCompositeType sCC2j = createCC2j_struct(dtm);
		cppTypes.add(sCC2j);
		CppCompositeType sDD1a = createDD1a_struct(dtm);
		cppTypes.add(sDD1a);
		CppCompositeType sDD1b = createDD1b_struct(dtm, sDD1a);
		cppTypes.add(sDD1b);
		CppCompositeType sDD1c = createDD1c_struct(dtm, sDD1b, sDD1a);
		cppTypes.add(sDD1c);
		CppCompositeType sDD1d = createDD1d_struct(dtm, sDD1b, sDD1a);
		cppTypes.add(sDD1d);
		CppCompositeType sDD2a = createDD2a_struct(dtm);
		cppTypes.add(sDD2a);
		CppCompositeType sDD2b = createDD2b_struct(dtm);
		cppTypes.add(sDD2b);
		CppCompositeType sDD2c = createDD2c_struct(dtm, sDD2a);
		cppTypes.add(sDD2c);
		CppCompositeType sDD2d = createDD2d_struct(dtm, sDD2a, sDD2b);
		cppTypes.add(sDD2d);
		CppCompositeType sDD2e = createDD2e_struct(dtm, sDD2c, sDD2d);
		cppTypes.add(sDD2e);
		return cppTypes;
	}
}
