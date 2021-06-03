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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;

/**
 * Metrics captured during the parsing and interpreting of a PDB.  This is a Ghidra class
 *  separate from the PDB API that we have crafted to help us quantify and qualify metatdata
 *  about the PDB.
 */
public class PdbReaderMetrics {

	/**
	 * This data is used as we develop this capability, and we could actively use it during
	 *  normal operations to give feedback towards this continued development.
	 * <P>
	 * The list indicates which Data Types ({@link AbstractMsType}) have been seen in real data,
	 *  giving us some confidence as to whether we have parsed them OK or not.  We can set a break
	 *  point in the method containing the switch statement to trigger whenever we find a
	 *  symbol type not in this list.
	 */
	private static Set<Integer> dataTypesSeen = new HashSet<>();
	static {
		dataTypesSeen.add(0x0001);
		dataTypesSeen.add(0x0002);
		dataTypesSeen.add(0x0003);
		dataTypesSeen.add(0x0004);
		dataTypesSeen.add(0x0005);
		dataTypesSeen.add(0x0006);
		dataTypesSeen.add(0x0007);
		dataTypesSeen.add(0x0008);
		dataTypesSeen.add(0x0009);
		dataTypesSeen.add(0x000a);
//		dataTypesSeen.add(0x000b);
//		dataTypesSeen.add(0x000c);
//		dataTypesSeen.add(0x000d);
		dataTypesSeen.add(0x000e);
//		dataTypesSeen.add(0x000f);
//		dataTypesSeen.add(0x0010);
//		dataTypesSeen.add(0x0011);
//		dataTypesSeen.add(0x0012);
//		dataTypesSeen.add(0x0013);
//		dataTypesSeen.add(0x0014);
//		dataTypesSeen.add(0x0015);
//		dataTypesSeen.add(0x0016);

//		dataTypesSeen.add(0x0200);
		dataTypesSeen.add(0x0201);
//		dataTypesSeen.add(0x0202);
//		dataTypesSeen.add(0x0203);
		dataTypesSeen.add(0x0204);
//		dataTypesSeen.add(0x0205);
		dataTypesSeen.add(0x0206);
		dataTypesSeen.add(0x0207);
//		dataTypesSeen.add(0x0208);
//		dataTypesSeen.add(0x0209);
//		dataTypesSeen.add(0x020a);
//		dataTypesSeen.add(0x020b);
//		dataTypesSeen.add(0x020c);

		dataTypesSeen.add(0x0400);
//		dataTypesSeen.add(0x0401);
//		dataTypesSeen.add(0x0402);
		dataTypesSeen.add(0x0403);
//		dataTypesSeen.add(0x0404);
//		dataTypesSeen.add(0x0405);
		dataTypesSeen.add(0x0406);
		dataTypesSeen.add(0x0407);
		dataTypesSeen.add(0x0408);
		dataTypesSeen.add(0x0409);
		dataTypesSeen.add(0x040a);
//		dataTypesSeen.add(0x040b);
		dataTypesSeen.add(0x040c);
//		dataTypesSeen.add(0x040d);

		dataTypesSeen.add(0x1001);
		dataTypesSeen.add(0x1002);
		dataTypesSeen.add(0x1003);
		dataTypesSeen.add(0x1004);
		dataTypesSeen.add(0x1005);
		dataTypesSeen.add(0x1006);
		dataTypesSeen.add(0x1007);
		dataTypesSeen.add(0x1008);
		dataTypesSeen.add(0x1009);
//		dataTypesSeen.add(0x100a);
//		dataTypesSeen.add(0x100b);
//		dataTypesSeen.add(0x100c);
//		dataTypesSeen.add(0x100d);
//		dataTypesSeen.add(0x100e);
//		dataTypesSeen.add(0x100f);
//		dataTypesSeen.add(0x1010);
//		dataTypesSeen.add(0x1011);

		dataTypesSeen.add(0x1201);
//		dataTypesSeen.add(0x1202);
		dataTypesSeen.add(0x1203);
//		dataTypesSeen.add(0x1204);
		dataTypesSeen.add(0x1205); //Bit-fields
		dataTypesSeen.add(0x1206);
//		dataTypesSeen.add(0x1207);
//		dataTypesSeen.add(0x1209);
//		dataTypesSeen.add(0x1209);
//		dataTypesSeen.add(0x120a);

		dataTypesSeen.add(0x1400);
		dataTypesSeen.add(0x1401);
		dataTypesSeen.add(0x1402);
//		dataTypesSeen.add(0x1403);
		dataTypesSeen.add(0x1404);
		dataTypesSeen.add(0x1405);
		dataTypesSeen.add(0x1406);
		dataTypesSeen.add(0x1407);
		dataTypesSeen.add(0x1408);
		dataTypesSeen.add(0x1409);
//		dataTypesSeen.add(0x140a);
		dataTypesSeen.add(0x140b);
//		dataTypesSeen.add(0x140c);
//		dataTypesSeen.add(0x140d);
//		dataTypesSeen.add(0x140e);
//		dataTypesSeen.add(0x140f);

//		dataTypesSeen.add(0x1501);
		dataTypesSeen.add(0x1502);
		dataTypesSeen.add(0x1503);
		dataTypesSeen.add(0x1504);
		dataTypesSeen.add(0x1505); //Structures
		dataTypesSeen.add(0x1506);
		dataTypesSeen.add(0x1507);
//		dataTypesSeen.add(0x1508);
//		dataTypesSeen.add(0x1509);
//		dataTypesSeen.add(0x150a);
//		dataTypesSeen.add(0x150b);
//		dataTypesSeen.add(0x150c);
		dataTypesSeen.add(0x150d);
		dataTypesSeen.add(0x150e);
		dataTypesSeen.add(0x150f);
		dataTypesSeen.add(0x1510);
		dataTypesSeen.add(0x1511);
//		dataTypesSeen.add(0x1512);
//		dataTypesSeen.add(0x1513);
//		dataTypesSeen.add(0x1514);
//		dataTypesSeen.add(0x1515);
//		dataTypesSeen.add(0x1516);
//		dataTypesSeen.add(0x1517);
//		dataTypesSeen.add(0x1518);
//		dataTypesSeen.add(0x1519);
//		dataTypesSeen.add(0x151a);
//		dataTypesSeen.add(0x151b);
//		dataTypesSeen.add(0x151c);
		dataTypesSeen.add(0x151d);

		dataTypesSeen.add(0x1601);
		dataTypesSeen.add(0x1602);
		dataTypesSeen.add(0x1603);
		dataTypesSeen.add(0x1604);
		dataTypesSeen.add(0x1605);
		dataTypesSeen.add(0x1606);
		dataTypesSeen.add(0x1607);
	}

	private static Set<Integer> knownPrimitives = new HashSet<>();
	static {
		// specials:
		knownPrimitives.add(0x0000);
		knownPrimitives.add(0x0001);
		knownPrimitives.add(0x0002);
		knownPrimitives.add(0x0003);
		knownPrimitives.add(0x0103);
		knownPrimitives.add(0x0203);
		knownPrimitives.add(0x0303);
		knownPrimitives.add(0x0403);
		knownPrimitives.add(0x0503);
		knownPrimitives.add(0x0603);
		knownPrimitives.add(0x0703); //From LLVM description
		knownPrimitives.add(0x0004);
		knownPrimitives.add(0x0005);
		knownPrimitives.add(0x0006);
		knownPrimitives.add(0x0007);
		knownPrimitives.add(0x0008);
		knownPrimitives.add(0x0408);
		knownPrimitives.add(0x0608);
		knownPrimitives.add(0x0708); //From LLVM description
		knownPrimitives.add(0x0060);
		knownPrimitives.add(0x0061);
		knownPrimitives.add(0x0062);

		// Signed Character types
		knownPrimitives.add(0x0010);
		knownPrimitives.add(0x0110);
		knownPrimitives.add(0x0210);
		knownPrimitives.add(0x0310);
		knownPrimitives.add(0x0410);
		knownPrimitives.add(0x0510);
		knownPrimitives.add(0x0610);
		knownPrimitives.add(0x0710); //From LLVM description

		// Unsigned Character types
		knownPrimitives.add(0x0020);
		knownPrimitives.add(0x0120);
		knownPrimitives.add(0x0220);
		knownPrimitives.add(0x0320);
		knownPrimitives.add(0x0420);
		knownPrimitives.add(0x0520);
		knownPrimitives.add(0x0620);
		knownPrimitives.add(0x0720); //From LLVM description

		// Real character types
		knownPrimitives.add(0x0070);
		knownPrimitives.add(0x0170);
		knownPrimitives.add(0x0270);
		knownPrimitives.add(0x0370);
		knownPrimitives.add(0x0470);
		knownPrimitives.add(0x0570);
		knownPrimitives.add(0x0670);
		knownPrimitives.add(0x0770); //From LLVM description

		// Really a wide character types
		knownPrimitives.add(0x0071);
		knownPrimitives.add(0x0171);
		knownPrimitives.add(0x0271);
		knownPrimitives.add(0x0371);
		knownPrimitives.add(0x0471);
		knownPrimitives.add(0x0571);
		knownPrimitives.add(0x0671);
		knownPrimitives.add(0x0771); //From LLVM description

		// 16-bit char types
		knownPrimitives.add(0x007a);
		knownPrimitives.add(0x017a);
		knownPrimitives.add(0x027a);
		knownPrimitives.add(0x037a);
		knownPrimitives.add(0x047a);
		knownPrimitives.add(0x057a);
		knownPrimitives.add(0x067a);
		knownPrimitives.add(0x077a); //From LLVM description

		// 32-bit unicode char types
		knownPrimitives.add(0x007b);
		knownPrimitives.add(0x017b);
		knownPrimitives.add(0x027b);
		knownPrimitives.add(0x037b);
		knownPrimitives.add(0x047b);
		knownPrimitives.add(0x057b);
		knownPrimitives.add(0x067b);
		knownPrimitives.add(0x077b); //From LLVM description

		// 8-bit int types
		knownPrimitives.add(0x0068);
		knownPrimitives.add(0x0168);
		knownPrimitives.add(0x0268);
		knownPrimitives.add(0x0368);
		knownPrimitives.add(0x0468);
		knownPrimitives.add(0x0568);
		knownPrimitives.add(0x0668);
		knownPrimitives.add(0x0768); //From LLVM description

		// 8-bit unsigned int types
		knownPrimitives.add(0x0069);
		knownPrimitives.add(0x0169);
		knownPrimitives.add(0x0269);
		knownPrimitives.add(0x0369);
		knownPrimitives.add(0x0469);
		knownPrimitives.add(0x0569);
		knownPrimitives.add(0x0669);
		knownPrimitives.add(0x0769); //From LLVM description

		// 16-bit short types
		knownPrimitives.add(0x0011);
		knownPrimitives.add(0x0111);
		knownPrimitives.add(0x0211);
		knownPrimitives.add(0x0311);
		knownPrimitives.add(0x0411);
		knownPrimitives.add(0x0511);
		knownPrimitives.add(0x0611);
		knownPrimitives.add(0x0711); //From LLVM description

		// 16-bit unsigned short types
		knownPrimitives.add(0x0021);
		knownPrimitives.add(0x0121);
		knownPrimitives.add(0x0221);
		knownPrimitives.add(0x0321);
		knownPrimitives.add(0x0421);
		knownPrimitives.add(0x0521);
		knownPrimitives.add(0x0621);
		knownPrimitives.add(0x0721); //From LLVM description

		// 16-bit signed int types
		knownPrimitives.add(0x0072);
		knownPrimitives.add(0x0172);
		knownPrimitives.add(0x0272);
		knownPrimitives.add(0x0372);
		knownPrimitives.add(0x0472);
		knownPrimitives.add(0x0572);
		knownPrimitives.add(0x0672);
		knownPrimitives.add(0x0772); //From LLVM description

		// 16-bit unsigned int types
		knownPrimitives.add(0x0073);
		knownPrimitives.add(0x0173);
		knownPrimitives.add(0x0273);
		knownPrimitives.add(0x0373);
		knownPrimitives.add(0x0473);
		knownPrimitives.add(0x0573);
		knownPrimitives.add(0x0673);
		knownPrimitives.add(0x0773); //From LLVM description

		// 32-bit long types
		knownPrimitives.add(0x0012);
		knownPrimitives.add(0x0112);
		knownPrimitives.add(0x0212);
		knownPrimitives.add(0x0312);
		knownPrimitives.add(0x0412);
		knownPrimitives.add(0x0512);
		knownPrimitives.add(0x0612);
		knownPrimitives.add(0x0712); //From LLVM description

		// 32-bit unsigned long types
		knownPrimitives.add(0x0022);
		knownPrimitives.add(0x0122);
		knownPrimitives.add(0x0222);
		knownPrimitives.add(0x0322);
		knownPrimitives.add(0x0422);
		knownPrimitives.add(0x0522);
		knownPrimitives.add(0x0622);
		knownPrimitives.add(0x0722); //From LLVM description

		// 32-bit signed int types
		knownPrimitives.add(0x0074);
		knownPrimitives.add(0x0174);
		knownPrimitives.add(0x0274);
		knownPrimitives.add(0x0374);
		knownPrimitives.add(0x0474);
		knownPrimitives.add(0x0574);
		knownPrimitives.add(0x0674);
		knownPrimitives.add(0x0774); //From LLVM description

		// 32-bit unsigned int types
		knownPrimitives.add(0x0075);
		knownPrimitives.add(0x0175);
		knownPrimitives.add(0x0275);
		knownPrimitives.add(0x0375);
		knownPrimitives.add(0x0475);
		knownPrimitives.add(0x0575);
		knownPrimitives.add(0x0675);
		knownPrimitives.add(0x0775); //From LLVM description

		// 64-bit quad types
		knownPrimitives.add(0x0013);
		knownPrimitives.add(0x0113);
		knownPrimitives.add(0x0213);
		knownPrimitives.add(0x0313);
		knownPrimitives.add(0x0413);
		knownPrimitives.add(0x0513);
		knownPrimitives.add(0x0613);
		knownPrimitives.add(0x0713); //From LLVM description

		// 64-bit unsigned quad types
		knownPrimitives.add(0x0023);
		knownPrimitives.add(0x0123);
		knownPrimitives.add(0x0223);
		knownPrimitives.add(0x0323);
		knownPrimitives.add(0x0423);
		knownPrimitives.add(0x0523);
		knownPrimitives.add(0x0623);
		knownPrimitives.add(0x0723); //From LLVM description

		// 64-bit signed int types
		knownPrimitives.add(0x0076);
		knownPrimitives.add(0x0176);
		knownPrimitives.add(0x0276);
		knownPrimitives.add(0x0376);
		knownPrimitives.add(0x0476);
		knownPrimitives.add(0x0576);
		knownPrimitives.add(0x0676);
		knownPrimitives.add(0x0776); //From LLVM description

		// 64-bit unsigned int types
		knownPrimitives.add(0x0077);
		knownPrimitives.add(0x0177);
		knownPrimitives.add(0x0277);
		knownPrimitives.add(0x0377);
		knownPrimitives.add(0x0477);
		knownPrimitives.add(0x0577);
		knownPrimitives.add(0x0677);
		knownPrimitives.add(0x0777); //From LLVM description

		// 128-bit octet types
		knownPrimitives.add(0x0014);
		knownPrimitives.add(0x0114);
		knownPrimitives.add(0x0214);
		knownPrimitives.add(0x0314);
		knownPrimitives.add(0x0414);
		knownPrimitives.add(0x0514);
		knownPrimitives.add(0x0614);
		knownPrimitives.add(0x0714); //From LLVM description

		// 128-bit unsigned octet types
		knownPrimitives.add(0x0024);
		knownPrimitives.add(0x0124);
		knownPrimitives.add(0x0224);
		knownPrimitives.add(0x0324);
		knownPrimitives.add(0x0424);
		knownPrimitives.add(0x0524);
		knownPrimitives.add(0x0624);
		knownPrimitives.add(0x0724); //From LLVM description

		// 128-bit signed int types
		knownPrimitives.add(0x0078);
		knownPrimitives.add(0x0178);
		knownPrimitives.add(0x0278);
		knownPrimitives.add(0x0378);
		knownPrimitives.add(0x0478);
		knownPrimitives.add(0x0578);
		knownPrimitives.add(0x0678);
		knownPrimitives.add(0x0778); //From LLVM description

		// 128-bit unsigned int types
		knownPrimitives.add(0x0079);
		knownPrimitives.add(0x0179);
		knownPrimitives.add(0x0279);
		knownPrimitives.add(0x0379);
		knownPrimitives.add(0x0479);
		knownPrimitives.add(0x0579);
		knownPrimitives.add(0x0679);
		knownPrimitives.add(0x0779); //From LLVM description

		// 16-bit real types
		knownPrimitives.add(0x0046);
		knownPrimitives.add(0x0146);
		knownPrimitives.add(0x0246);
		knownPrimitives.add(0x0346);
		knownPrimitives.add(0x0446);
		knownPrimitives.add(0x0546);
		knownPrimitives.add(0x0646);
		knownPrimitives.add(0x0746); //From LLVM description

		// 32-bit real types
		knownPrimitives.add(0x0040);
		knownPrimitives.add(0x0140);
		knownPrimitives.add(0x0240);
		knownPrimitives.add(0x0340);
		knownPrimitives.add(0x0440);
		knownPrimitives.add(0x0540);
		knownPrimitives.add(0x0640);
		knownPrimitives.add(0x0740); //From LLVM description

		// 32-bit partial-precision real types
		knownPrimitives.add(0x0045);
		knownPrimitives.add(0x0145);
		knownPrimitives.add(0x0245);
		knownPrimitives.add(0x0345);
		knownPrimitives.add(0x0445);
		knownPrimitives.add(0x0545);
		knownPrimitives.add(0x0645);
		knownPrimitives.add(0x0745); //From LLVM description

		// 48-bit real types
		knownPrimitives.add(0x0044);
		knownPrimitives.add(0x0144);
		knownPrimitives.add(0x0244);
		knownPrimitives.add(0x0344);
		knownPrimitives.add(0x0444);
		knownPrimitives.add(0x0544);
		knownPrimitives.add(0x0644);
		knownPrimitives.add(0x0744); //From LLVM description

		// 64-bit real types
		knownPrimitives.add(0x0041);
		knownPrimitives.add(0x0141);
		knownPrimitives.add(0x0241);
		knownPrimitives.add(0x0341);
		knownPrimitives.add(0x0441);
		knownPrimitives.add(0x0541);
		knownPrimitives.add(0x0641);
		knownPrimitives.add(0x0741); //From LLVM description

		// 80-bit real types
		knownPrimitives.add(0x0042);
		knownPrimitives.add(0x0142);
		knownPrimitives.add(0x0242);
		knownPrimitives.add(0x0342);
		knownPrimitives.add(0x0442);
		knownPrimitives.add(0x0542);
		knownPrimitives.add(0x0642);
		knownPrimitives.add(0x0742); //From LLVM description

		// 128-bit real types
		knownPrimitives.add(0x0043);
		knownPrimitives.add(0x0143);
		knownPrimitives.add(0x0243);
		knownPrimitives.add(0x0343);
		knownPrimitives.add(0x0443);
		knownPrimitives.add(0x0543);
		knownPrimitives.add(0x0643);
		knownPrimitives.add(0x0743); //From LLVM description

		// 32-bit complex types
		knownPrimitives.add(0x0050);
		knownPrimitives.add(0x0150);
		knownPrimitives.add(0x0250);
		knownPrimitives.add(0x0350);
		knownPrimitives.add(0x0450);
		knownPrimitives.add(0x0550);
		knownPrimitives.add(0x0650);
		knownPrimitives.add(0x0750); //From LLVM description

		// 64-bit complex types
		knownPrimitives.add(0x0051);
		knownPrimitives.add(0x0151);
		knownPrimitives.add(0x0251);
		knownPrimitives.add(0x0351);
		knownPrimitives.add(0x0451);
		knownPrimitives.add(0x0551);
		knownPrimitives.add(0x0651);
		knownPrimitives.add(0x0751); //From LLVM description

		// 80-bit complex types
		knownPrimitives.add(0x0052);
		knownPrimitives.add(0x0152);
		knownPrimitives.add(0x0252);
		knownPrimitives.add(0x0352);
		knownPrimitives.add(0x0452);
		knownPrimitives.add(0x0552);
		knownPrimitives.add(0x0652);
		knownPrimitives.add(0x0752); //From LLVM description

		// 128-bit complex types
		// Not in MSFT API; found in LLVM description
		knownPrimitives.add(0x0053);
		knownPrimitives.add(0x0153);
		knownPrimitives.add(0x0253);
		knownPrimitives.add(0x0353);
		knownPrimitives.add(0x0453);
		knownPrimitives.add(0x0553);
		knownPrimitives.add(0x0653);
		knownPrimitives.add(0x0753);

		// 48-bit complex types
		// Not in MSFT API; found in LLVM description
		knownPrimitives.add(0x0054);
		knownPrimitives.add(0x0154);
		knownPrimitives.add(0x0254);
		knownPrimitives.add(0x0354);
		knownPrimitives.add(0x0454);
		knownPrimitives.add(0x0554);
		knownPrimitives.add(0x0654);
		knownPrimitives.add(0x0754);

		// 32-bit partial precision complex types
		// Not in MSFT API; found in LLVM description
		knownPrimitives.add(0x0055);
		knownPrimitives.add(0x0155);
		knownPrimitives.add(0x0255);
		knownPrimitives.add(0x0355);
		knownPrimitives.add(0x0455);
		knownPrimitives.add(0x0555);
		knownPrimitives.add(0x0655);
		knownPrimitives.add(0x0755);

		// 16-bit complex types
		knownPrimitives.add(0x0056);
		knownPrimitives.add(0x0156);
		knownPrimitives.add(0x0256);
		knownPrimitives.add(0x0356);
		knownPrimitives.add(0x0456);
		knownPrimitives.add(0x0556);
		knownPrimitives.add(0x0656);
		knownPrimitives.add(0x0756); //From LLVM description

		// 8-bit boolean types
		knownPrimitives.add(0x0030);
		knownPrimitives.add(0x0130);
		knownPrimitives.add(0x0230);
		knownPrimitives.add(0x0330);
		knownPrimitives.add(0x0430);
		knownPrimitives.add(0x0530);
		knownPrimitives.add(0x0630);
		knownPrimitives.add(0x0730); //From LLVM description

		// 16-bit boolean types
		knownPrimitives.add(0x0031);
		knownPrimitives.add(0x0131);
		knownPrimitives.add(0x0231);
		knownPrimitives.add(0x0331);
		knownPrimitives.add(0x0431);
		knownPrimitives.add(0x0531);
		knownPrimitives.add(0x0631);
		knownPrimitives.add(0x0731); //From LLVM description

		// 32-bit boolean types
		knownPrimitives.add(0x0032);
		knownPrimitives.add(0x0132);
		knownPrimitives.add(0x0232);
		knownPrimitives.add(0x0332);
		knownPrimitives.add(0x0432);
		knownPrimitives.add(0x0532);
		knownPrimitives.add(0x0632);
		knownPrimitives.add(0x0732); //From LLVM description

		// 64-bit boolean types
		knownPrimitives.add(0x0033);
		knownPrimitives.add(0x0133);
		knownPrimitives.add(0x0233);
		knownPrimitives.add(0x0333);
		knownPrimitives.add(0x0433);
		knownPrimitives.add(0x0533);
		knownPrimitives.add(0x0633);
		knownPrimitives.add(0x0733); //From LLVM description

		// 128-bit boolean types
		// Not in MSFT API; found in LLVM description
		knownPrimitives.add(0x0034);
		knownPrimitives.add(0x0134);
		knownPrimitives.add(0x0234);
		knownPrimitives.add(0x0334);
		knownPrimitives.add(0x0434);
		knownPrimitives.add(0x0534);
		knownPrimitives.add(0x0634);
		knownPrimitives.add(0x0734);

		// Internal type with pointers
		knownPrimitives.add(0x01f0);
		knownPrimitives.add(0x02f0);
		knownPrimitives.add(0x03f0);
		knownPrimitives.add(0x04f0);
		knownPrimitives.add(0x05f0);
		knownPrimitives.add(0x06f0);
		knownPrimitives.add(0x07f0); //From LLVM description
	}
	/**
	 * This list indicates which Symbol Types ({@link AbstractMsSymbol}) have been seen in real
	 *  data, giving us some confidence as to whether we have parsed them OK or not.  We can set
	 *  a break point in the method containing the switch statement to trigger whenever we find a
	 *  symbol type not in this list.
	 */
	private static Set<Integer> symbolTypesSeen = new HashSet<>(); //temporary for filling in types
	static {
		symbolTypesSeen.add(0x0001);
//		symbolTypesSeen.add(0x0002);
		symbolTypesSeen.add(0x0003);
//		symbolTypesSeen.add(0x0004);
//		symbolTypesSeen.add(0x0005);
		symbolTypesSeen.add(0x0006);
//		symbolTypesSeen.add(0x0007);
//		symbolTypesSeen.add(0x0008);
//		symbolTypesSeen.add(0x0009);
//		symbolTypesSeen.add(0x000a);
//		symbolTypesSeen.add(0x000b);
//		symbolTypesSeen.add(0x000c);
//		symbolTypesSeen.add(0x000d);
//		symbolTypesSeen.add(0x000e);

//		symbolTypesSeen.add(0x0100);
//		symbolTypesSeen.add(0x0101);
//		symbolTypesSeen.add(0x0102);
//		symbolTypesSeen.add(0x0103);
//		symbolTypesSeen.add(0x0104);
//		symbolTypesSeen.add(0x0105);
//		symbolTypesSeen.add(0x0106);
//		symbolTypesSeen.add(0x0107);
//		symbolTypesSeen.add(0x0108);
//		symbolTypesSeen.add(0x0109);
//		symbolTypesSeen.add(0x010a);
//		symbolTypesSeen.add(0x010b);
//		symbolTypesSeen.add(0x010c);

//		symbolTypesSeen.add(0x0200);
//		symbolTypesSeen.add(0x0201);
//		symbolTypesSeen.add(0x0202);
//		symbolTypesSeen.add(0x0203);
//		symbolTypesSeen.add(0x0204);
//		symbolTypesSeen.add(0x0205);
//		symbolTypesSeen.add(0x0206);
//		symbolTypesSeen.add(0x0207);
//		symbolTypesSeen.add(0x0208);
//		symbolTypesSeen.add(0x0209);
//		symbolTypesSeen.add(0x020a);
//		symbolTypesSeen.add(0x020b);
//		symbolTypesSeen.add(0x020c);
//		symbolTypesSeen.add(0x020d);
//		symbolTypesSeen.add(0x020e);
//		symbolTypesSeen.add(0x020f);

//		symbolTypesSeen.add(0x0300);
//		symbolTypesSeen.add(0x0301);

//		symbolTypesSeen.add(0x0400);
//		symbolTypesSeen.add(0x0401);
//		symbolTypesSeen.add(0x0402);
//		symbolTypesSeen.add(0x0403);
		symbolTypesSeen.add(0x0404);

//		symbolTypesSeen.add(0x1001);
		symbolTypesSeen.add(0x1002);
//		symbolTypesSeen.add(0x1003);
//		symbolTypesSeen.add(0x1004);
//		symbolTypesSeen.add(0x1005);
//		symbolTypesSeen.add(0x1006);
//		symbolTypesSeen.add(0x1007);
//		symbolTypesSeen.add(0x1008);
//		symbolTypesSeen.add(0x1009);
//		symbolTypesSeen.add(0x100a);
//		symbolTypesSeen.add(0x100b);
//		symbolTypesSeen.add(0x100c);
//		symbolTypesSeen.add(0x100d);
//		symbolTypesSeen.add(0x100e);
//		symbolTypesSeen.add(0x100f);
//		symbolTypesSeen.add(0x1010);
//		symbolTypesSeen.add(0x1011);
		symbolTypesSeen.add(0x1012);
//		symbolTypesSeen.add(0x1013);
//		symbolTypesSeen.add(0x1014);
//		symbolTypesSeen.add(0x1015);
//		symbolTypesSeen.add(0x1016);
//		symbolTypesSeen.add(0x1017);
//		symbolTypesSeen.add(0x1018);
//		symbolTypesSeen.add(0x1019);
//		symbolTypesSeen.add(0x101a);
//		symbolTypesSeen.add(0x101b);
//		symbolTypesSeen.add(0x101c);
//		symbolTypesSeen.add(0x101d);
//		symbolTypesSeen.add(0x101e);
//		symbolTypesSeen.add(0x101f);
//		symbolTypesSeen.add(0x1020);
//		symbolTypesSeen.add(0x1021);
//		symbolTypesSeen.add(0x1022);
//		symbolTypesSeen.add(0x1023);
//		symbolTypesSeen.add(0x1024);
//		symbolTypesSeen.add(0x1025);
//		symbolTypesSeen.add(0x1026);
//		symbolTypesSeen.add(0x1027);
//		symbolTypesSeen.add(0x1028);
//		symbolTypesSeen.add(0x1029);

		symbolTypesSeen.add(0x1101);
		symbolTypesSeen.add(0x1102);
		symbolTypesSeen.add(0x1103);
//		symbolTypesSeen.add(0x1104);
		symbolTypesSeen.add(0x1105);
		symbolTypesSeen.add(0x1106);
		symbolTypesSeen.add(0x1107);
		symbolTypesSeen.add(0x1108);
//		symbolTypesSeen.add(0x1109);
//		symbolTypesSeen.add(0x110a);
		symbolTypesSeen.add(0x110b);
		symbolTypesSeen.add(0x110c);
		symbolTypesSeen.add(0x110d);
		symbolTypesSeen.add(0x110e);
		symbolTypesSeen.add(0x110f);
		symbolTypesSeen.add(0x1110);
		symbolTypesSeen.add(0x1111);
//		symbolTypesSeen.add(0x1112);
		symbolTypesSeen.add(0x1113);
		symbolTypesSeen.add(0x1114);
		symbolTypesSeen.add(0x1115);
		symbolTypesSeen.add(0x1116);
//		symbolTypesSeen.add(0x1117);
//		symbolTypesSeen.add(0x1118);
//		symbolTypesSeen.add(0x1119);
//		symbolTypesSeen.add(0x111a);
//		symbolTypesSeen.add(0x111b);
//		symbolTypesSeen.add(0x111c);
//		symbolTypesSeen.add(0x111d);
//		symbolTypesSeen.add(0x111e);
//		symbolTypesSeen.add(0x111f);
		symbolTypesSeen.add(0x1120);
//		symbolTypesSeen.add(0x1121);
//		symbolTypesSeen.add(0x1122);
//		symbolTypesSeen.add(0x1123);
		symbolTypesSeen.add(0x1124);
		symbolTypesSeen.add(0x1125);
//		symbolTypesSeen.add(0x1126);
		symbolTypesSeen.add(0x1127);
//		symbolTypesSeen.add(0x1128);
		symbolTypesSeen.add(0x1129);
		symbolTypesSeen.add(0x112a);
//		symbolTypesSeen.add(0x112b);
		symbolTypesSeen.add(0x112c);
		symbolTypesSeen.add(0x112d);
//		symbolTypesSeen.add(0x112e);
//		symbolTypesSeen.add(0x112f);
//		symbolTypesSeen.add(0x1130);
//		symbolTypesSeen.add(0x1131);
		symbolTypesSeen.add(0x1132);
//		symbolTypesSeen.add(0x1133);
//		symbolTypesSeen.add(0x1134);
//		symbolTypesSeen.add(0x1135);
		symbolTypesSeen.add(0x1136);
		symbolTypesSeen.add(0x1137);
		symbolTypesSeen.add(0x1138);
		symbolTypesSeen.add(0x1139);
		symbolTypesSeen.add(0x113a);
//		symbolTypesSeen.add(0x113b);
		symbolTypesSeen.add(0x113c);
		symbolTypesSeen.add(0x113d);
		symbolTypesSeen.add(0x113e);
//		symbolTypesSeen.add(0x113f);
//		symbolTypesSeen.add(0x1140);
		symbolTypesSeen.add(0x1141);
		symbolTypesSeen.add(0x1142);
		symbolTypesSeen.add(0x1143);
		symbolTypesSeen.add(0x1144);
		symbolTypesSeen.add(0x1145);
//		symbolTypesSeen.add(0x1146);
//		symbolTypesSeen.add(0x1147);
//		symbolTypesSeen.add(0x1148);
//		symbolTypesSeen.add(0x1149);
//		symbolTypesSeen.add(0x114a);
//		symbolTypesSeen.add(0x114b);
		symbolTypesSeen.add(0x114c);
		symbolTypesSeen.add(0x114d);
		symbolTypesSeen.add(0x114e);
//		symbolTypesSeen.add(0x114f);
//		symbolTypesSeen.add(0x1150);
//		symbolTypesSeen.add(0x1151);
//		symbolTypesSeen.add(0x1152);
		symbolTypesSeen.add(0x1153);
//		symbolTypesSeen.add(0x1154);
//		symbolTypesSeen.add(0x1155);
//		symbolTypesSeen.add(0x1156);
//		symbolTypesSeen.add(0x1157);
//		symbolTypesSeen.add(0x1158);
		symbolTypesSeen.add(0x1159);
		symbolTypesSeen.add(0x115a);
//		symbolTypesSeen.add(0x115b);
//		symbolTypesSeen.add(0x115c);
//		symbolTypesSeen.add(0x115d);
		symbolTypesSeen.add(0x115e);
//		symbolTypesSeen.add(0x115f);
//		symbolTypesSeen.add(0x1169);
//		symbolTypesSeen.add(0x1161);
//		symbolTypesSeen.add(0x1162);
//		symbolTypesSeen.add(0x1163);
//		symbolTypesSeen.add(0x1164);
//		symbolTypesSeen.add(0x1165);
//      There is not documentation for anything beyond 0x1165.
//		symbolTypesSeen.add(0x1166);
		symbolTypesSeen.add(0x1167);
		symbolTypesSeen.add(0x1168);
	}

	private AbstractPdb pdb;
	private Set<PdbAnomaly> pdbAnomalies = new TreeSet<>();

	private int numSegments = -1;

	private Set<Integer> unknownPrimitives = new HashSet<>();
	private Set<Integer> newDataTypes = new HashSet<>();
	private Set<Integer> newSymbolTypes = new HashSet<>();

	public PdbReaderMetrics(AbstractPdb pdb) {
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
	}

	public void witnessIpiDetection(boolean ipiStreamHasNoName, boolean hasIdStream) {
		if (ipiStreamHasNoName && !hasIdStream) {
			pdbAnomalies.add(PdbAnomaly.UNINDICATED_EXISTING_IPI);
		}
	}

	public void witnessedSectionSegmentNumber(int segment) {
		if (numSegments == -1) {
			numSegments = pdb.getDebugInfo().getSegmentMapList().size();
		}
		if (segment < 0 || segment > numSegments) {
			PdbLog.message("segment " + segment + " out of range [0," + numSegments + ")");
		}
		else if (segment == numSegments) {
			pdbAnomalies.add(PdbAnomaly.MAX_SEGMENT_AS_BASE);
		}
	}

	public void witnessRecordNumber(RecordNumber recordNumber) {
		switch (recordNumber.getCategory()) {
			case TYPE:
				if (recordNumber.getNumber() < 0) {
					witnessDataRecordNumberHighBitSet();
					recordNumber = pdb.fixupTypeIndex(recordNumber, AbstractMsType.class);
				}
				break;
			case ITEM:
				if (recordNumber.getNumber() < 0) {
					witnessItemRecordNumberHighBitSet();
					recordNumber = pdb.fixupTypeIndex(recordNumber, AbstractMsType.class);
				}
				break;
			// TODO: for consideration... has implications...
			//case SYMBOL:
			default:
				break;
		}
		// Separate switch because local recordNumber might have changed by fixupTypeIndex.
		switch (recordNumber.getCategory()) {
			case TYPE:
				if (recordNumber.getNumber() < pdb.getTypeProgramInterface().getTypeIndexMin()) {
					witnessPrimitive(recordNumber.getNumber());
				}
				break;
			case ITEM:
				if (recordNumber.getNumber() < pdb.getItemProgramInterface().getTypeIndexMin()) {
					// Not sure what to do here.  What are records in this range?
					// Worse is when it was originally a TYPE with high bit set. Why would it
					// just not be given a non-set high bit if primitive.
					//witnessPrimitive(recordNumber.getNumber());
				}
				break;
			default:
				break;
		}
	}

	private void witnessDataRecordNumberHighBitSet() {
		pdbAnomalies.add(PdbAnomaly.DATA_RECORD_NUMBER_HIGH_BIT);
	}

	private void witnessItemRecordNumberHighBitSet() {
		pdbAnomalies.add(PdbAnomaly.ITEM_RECORD_NUMBER_HIGH_BIT);
	}

	/**
	 * Method to capture data/item type IDs that have not been seen before in development.
	 * @param dataTypeId The data/item type ID witnessed.
	 */
	public void witnessDataTypeId(int dataTypeId) {
		if (!dataTypesSeen.contains(dataTypeId)) {
			newDataTypes.add(dataTypeId);
		}
	}

	/**
	 * Method to capture symbol type IDs that have not been seen before in development.
	 * @param symbolTypeId The symbol type ID witnessed.
	 */
	public void witnessSymbolTypeId(int symbolTypeId) {
		if (!symbolTypesSeen.contains(symbolTypeId)) {
			newSymbolTypes.add(symbolTypeId);
		}
	}

	/**
	 * Method to capture unknown primitive type record numbers.  All primitive record numbers
	 * should be passed into this, and this method will only determine and log which are unknown.
	 * @param recNum The record number.
	 */
	public void witnessPrimitive(int recNum) {
		if (!knownPrimitives.contains(recNum)) {
			unknownPrimitives.add(recNum);
		}
	}

	/**
	 * Return some post-processing metrics on the PDB
	 * @return {@link String} of pretty output.
	 */
	public String getPostProcessingReport() {
		StringBuilder builder = new StringBuilder();
		builder.append("===Begin PdbReaderMetrics Report===\n");
		String anomaliesReport = reportAnomalies();
		if (!anomaliesReport.isEmpty()) {
			builder.append(anomaliesReport);
			builder.append("\n");
		}
		String unknownPrimitivesReport = getUnknownPrimitivesLog();
		if (!unknownPrimitivesReport.isEmpty()) {
			builder.append(unknownPrimitivesReport);
			builder.append("\n");
		}
		String dataTypesReport = getNewDataTypesLog();
		if (!dataTypesReport.isEmpty()) {
			builder.append(dataTypesReport);
			builder.append("\n");
		}
		String symbolTypesReport = getNewSymbolTypesLog();
		if (!symbolTypesReport.isEmpty()) {
			builder.append(symbolTypesReport);
			builder.append("\n");
		}
		builder.append("====End PdbReaderMetrics Report====\n");
		return builder.toString();
	}

	/**
	 * Returns a log of unknown primitive type record numbers.
	 * @return {@link String} of pretty output message.
	 */
	private String getUnknownPrimitivesLog() {
		StringBuilder builder = new StringBuilder();
		DelimiterState ds = new DelimiterState("Unknown Primitive Record Numbers Seen: ", ",");
		/*
		 * Sort these before printing to avoid sorting performance hit when logging is not used.
		 */
		Set<Integer> sortedSet = new TreeSet<>(unknownPrimitives);
		for (Integer val : sortedSet) {
			builder.append(ds.out(true, String.format("0X%04X", val)));
		}
		return builder.toString();
	}

	/**
	 * Returns a list of Type/Item IDs that we have not seen in real data while testing.
	 * @return {@link String} of pretty output message.
	 */
	private String getNewDataTypesLog() {
		StringBuilder builder = new StringBuilder();
		DelimiterState ds = new DelimiterState("New Type/Item IDs Seen: ", ",");
		/*
		 * Sort these before printing to avoid sorting performance hit when logging is not used.
		 */
		Set<Integer> sortedSet = new TreeSet<>(newDataTypes);
		for (Integer val : sortedSet) {
			builder.append(ds.out(true, String.format("0X%04X", val)));
		}
		return builder.toString();
	}

	/**
	 * Returns a list of Symbol IDs that we have not seen in real data while testing.
	 * @return {@link String} of pretty output message.
	 */
	private String getNewSymbolTypesLog() {
		StringBuilder builder = new StringBuilder();
		DelimiterState ds = new DelimiterState("New Symbol IDs Seen: ", ",");
		/*
		 * Sort these before printing to avoid sorting performance hit when logging is not used.
		 */
		Set<Integer> sortedSet = new TreeSet<>(newSymbolTypes);
		for (Integer val : sortedSet) {
			builder.append(ds.out(true, String.format("0X%04X", val)));
		}
		return builder.toString();
	}

	/**
	 * Reports the metrics captured by this class.
	 * @return a {@link String} report of the metrics captured.
	 */
	private String reportAnomalies() {
		StringBuilder builder = new StringBuilder();
		if (pdbAnomalies.size() > 0) {
			builder.append("PDB Anomalies: ");
			builder.append(pdbAnomalies);
			builder.append("\n");
		}
		return builder.toString();
	}

	/**
	 * Anomaly from the PDB specification.  These might indicate a toolchain other than MSFT VS.
	 */
	private enum PdbAnomaly {

		UNKNOWN("???", -1),

		UNINDICATED_EXISTING_IPI("Unindicated IPI Exists", 0x00),
		DATA_RECORD_NUMBER_HIGH_BIT("Data record number high bit set", 0x01),
		ITEM_RECORD_NUMBER_HIGH_BIT("Item record number high bit set", 0x02),
		MAX_SEGMENT_AS_BASE("Max segment refers to segment zero", 0x03);

		private static final Map<Integer, PdbAnomaly> BY_VALUE = new HashMap<>();
		static {
			for (PdbAnomaly val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String description;
		private final int value;

		@Override
		public String toString() {
			return description;
		}

//		public int getValue() {
//			return value;
//		}
//
//		public static PdbAnomaly fromValue(int val) {
//			return BY_VALUE.getOrDefault(val, UNKNOWN);
//		}
//
		private PdbAnomaly(String description, int value) {
			this.description = description;
			this.value = value;
		}
	}

}
