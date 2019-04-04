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
package ghidra.pdb.pdbreader.symbol;

import java.util.HashMap;
import java.util.Map;

import ghidra.pdb.AbstractParsableItem;
import ghidra.pdb.pdbreader.AbstractPdb;

/**
 * Register Name component for certain PDB symbols.
 */
public class RegisterName extends AbstractParsableItem {

	private static final String regX86[] = { "None", "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
		"ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "eax", "ecx", "edx", "ebx", "esp", "ebp",
		"esi", "edi", "es", "cs", "ss", "ds", "fs", "gs", "ip", "flags", "eip", "eflags", "???",
		"???", "???", "???", "???", "temp", "temph", "quote", "pcdr3", "pcdr4", "pcdr5", "pcdr6",
		"pcdr7", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???",
		"???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???",
		"???", "???", "???", "???", "???", "???", "???", "cr0", "cr1", "cr2", "cr3", "cr4", "???",
		"???", "???", "???", "???", "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7", "???",
		"???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "gdtr", "gdtl",
		"idtr", "idtl", "ldtr", "tr", "???", "???", "???", "???", "???", "???", "???", "???", "???",
		"???", "???", "???", "st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)",
		"ctrl", "stat", "tag", "fpip", "fpcs", "fpdo", "fpds", "fpeip", "fped0" };

	private static final String regAmd64[] = { "None", "al", "cl", "dl", "bl", "ah", "ch", "dh",
		"bh", "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "eax", "ecx", "edx", "ebx", "esp",
		"ebp", "esi", "edi", "es", "cs", "ss", "ds", "fs", "gs", "flags", "rip", "eflags", "???",
		"???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???",
		"???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???",
		"???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???", "???",
		"???", "???", "???", "???", "???", "???", "cr0", "cr1", "cr2", "cr3", "cr4", "???", "???",
		"???", "cr8", "???", "dr0", "dr0", "dr0", "dr0", "dr0", "dr0", "dr0", "dr0", "dr0", "dr0",
		"dr0", "dr0", "dr0", "dr0", "dr0", "dr0", "???", "???", "???", "???", "gdtr", "gdtl",
		"idtr", "idtl", "ldtr", "tr", "???", "???", "???", "???", "???", "???", "???", "???", "???",
		"???", "???", "???", "st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)",
		"ctrl", "stat", "tag", "fpip", "fpcs", "fpdo", "fpds", "isem", "fpeip", "fped0", "mm0",
		"mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4",
		"xmm5", "xmm6", "xmm7", "xmm0_0", "xmm0_1", "xmm0_2", "xmm0_3", "xmm0_0", "xmm0_1",
		"xmm0_2", "xmm0_3", "xmm1_0", "xmm1_1", "xmm1_2", "xmm1_3", "xmm2_0", "xmm2_1", "xmm2_2",
		"xmm2_3", "xmm3_0", "xmm3_1", "xmm3_2", "xmm3_3", "xmm4_0", "xmm4_1", "xmm4_2", "xmm4_3",
		"xmm5_0", "xmm5_1", "xmm5_2", "xmm5_3", "xmm6_0", "xmm6_1", "xmm6_2", "xmm6_3", "xmm7_0",
		"xmm7_1", "xmm7_2", "xmm7_3", "xmm0l", "xmm1l", "xmm2l", "xmm3l", "xmm4l", "xmm5l", "xmm6l",
		"xmm7l", "xmm0l", "xmm1h", "xmm2h", "xmm3h", "xmm4h", "xmm5h", "xmm6h", "xmm7h", "???",
		"mxcsr", "???", "???", "???", "???", "???", "???", "???", "???", "emm0l", "emm1l", "emm2l",
		"emm3l", "emm4l", "emm5l", "emm6l", "emm7l", "emm0h", "emm1h", "emm2h", "emm3h", "emm4h",
		"emm5h", "emm6h", "emm7h", "mm00", "mm01", "mm10", "mm11", "mm20", "mm21", "mm30", "mm31",
		"mm40", "mm41", "mm50", "mm51", "mm60", "mm61", "mm70", "mm71", "xmm8", "xmm9", "xmm10",
		"xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm8_0", "xmm8_1", "xmm8_2", "xmm8_3",
		"xmm9_0", "xmm9_1", "xmm9_2", "xmm9_3", "xmm10_0", "xmm10_1", "xmm10_2", "xmm10_3",
		"xmm11_0", "xmm11_1", "xmm11_2", "xmm11_3", "xmm12_0", "xmm12_1", "xmm12_2", "xmm12_3",
		"xmm13_0", "xmm13_1", "xmm13_2", "xmm13_3", "xmm14_0", "xmm14_1", "xmm14_2", "xmm14_3",
		"xmm15_0", "xmm15_1", "xmm15_2", "xmm15_3", "xmm8l", "xmm9l", "xmm10l", "xmm11l", "xmm12l",
		"xmm13l", "xmm14l", "xmm15l", "xmm8h", "xmm9h", "xmm10h", "xmm11h", "xmm12h", "xmm13h",
		"xmm14h", "xmm15h", "emm8l", "emm9l", "emm10l", "emm11l", "emm12l", "emm13l", "emm14l",
		"emm15l", "emm8h", "emm9h", "emm10h", "emm11h", "emm12h", "emm13h", "emm14h", "emm15h",
		"sil", "dil", "bpl", "spl", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "fbp", "rsp", "r8",
		"r9", "r10", "r11", "r12", "r13", "r14", "r15", "r8b", "r9b", "r10b", "r11b", "r12b",
		"r13b", "r14b", "r15b", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "r8d",
		"r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };

	private static final String regMips[] = { "None", "???", "???", "???", "???", "???", "???",
		"???", "???", "???", "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2",
		"t3", "t4", "t5", "t6", "t7", "s0", "s1", "t2", "s3", "s4", "s5", "s6", "s7", "t8", "t9",
		"k0", "k1", "gp", "sp", "s8", "ra", "lo", "hi", "???", "???", "???", "???", "???", "???",
		"Fir", "Psr", "???", "???", "???", "???", "???", "???", "???", "???", "$f0", "$f1", "$f2",
		"$f3", "$f4", "$f5", "$f6", "$f7", "$f8", "$f9", "$f10", "$f11", "$f12", "$f13", "$f14",
		"$f15", "$f16", "$f17", "$f18", "$f19", "$f20", "$f21", "$f22", "$f23", "$f24", "$f25",
		"$f26", "$f27", "$f28", "$f29", "$f30", "$f31", "Fsr" };

	// Indices 41-48 are actually:
	//   R68_MMUSR030, R68_MMUSR, R68_URP, R68_DTT0, R68_DTT1, R68_ITT0, R68_ITT1
	private static final String reg68k[] = { "CCR", "SR", "SUP", "MSP", "SFC", "DFC", "CACR", "VBR",
		"CARR", "ISP", "PC", "???", "FPCR", "FPSR", "FPIAR", "???", "FPO", "FP1", "FP2", "FP3",
		"FP4", "FP5", "FP6", "FP7", "???", "???", "???", "???", "???", "???", "???", "???", "???",
		"???", "???", "PSR", "PCSR", "VAL", "CRP", "SRP", "DRP", "TC", "AC", "SCC", "CAL", "TT0",
		"TT1", "???", "BAD0", "BAD1", "BAD2", "BAD3", "BAD4", "BAD5", "BAD6", "BAD7", "BAC0",
		"BAC1", "BAC2", "BAC3", "BAC4", "BAC5", "BAC6", "BAC7", };

	private static final String regAlpha[] = { "None", "???", "???", "???", "???", "???", "???",
		"???", "???", "???", "$f0", "$f1", "$f2", "$f3", "$f4", "$f5", "$f6", "$f7", "$f8", "$f9",
		"$f10", "$f11", "$f12", "$f13", "$f14", "$f15", "$f16", "$f17", "$f18", "$f19", "$f20",
		"$f21", "$f22", "$f23", "$f24", "$f25", "$f26", "$f27", "$f28", "$f29", "$f30", "$f31",
		"v0", "t0", "t1", "t2", "t3", "t4", "t5", "t7", "t7", "s0", "s1", "s2", "s3", "s4", "s5",
		"fp", "a0", "a1", "a2", "a3", "a4", "a5", "t8", "t9", "t10", "t11", "ra", "t12", "at", "gp",
		"sp", "zero", "Fpcr", "Fir", "Psr", "FltFsr" };

	private static final String regPpc[] =
		{ "None", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
			"r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24",
			"r25", "r26", "r27", "r28", "r29", "r30", "r31", "cr", "cr0", "cr1", "cr2", "cr3",
			"cr4", "cr5", "cr6", "cr7", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9",
			"f10", "f11", "f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19", "f20", "f21",
			"f22", "f23", "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31", "Fpscr", "Msr" };

	private static final String regSh[] = { "None", "???", "???", "???", "???", "???", "???", "???",
		"???", "???", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
		"r12", "r13", "fp", "sp", "???", "???", "???", "???", "???", "???", "???", "???", "???",
		"???", "???", "???", "gbr", "pr", "mach", "macl", "???", "???", "???", "???", "???", "???",
		"???", "???", "pc", "sr", "???", "???", "???", "???", "???", "???", "???", "???", "bara",
		"basra", "bamra", "bbra", "barb", "basrb", "bamrb", "bbr", "bdrb", "bdmrb", "brcr" };

	private static final Map<Integer, String> regIa64Map = new HashMap<>();
	static {
		regIa64Map.put(0, "None");
		// Branch Registers
		regIa64Map.put(512, "br0");
		regIa64Map.put(513, "br1");
		regIa64Map.put(514, "br2");
		regIa64Map.put(515, "br3");
		regIa64Map.put(516, "br4");
		regIa64Map.put(517, "br5");
		regIa64Map.put(518, "br6");
		regIa64Map.put(519, "br7");
		// Predicate Registers
		regIa64Map.put(704, "");
		regIa64Map.put(705, "");
		regIa64Map.put(706, "");
		regIa64Map.put(707, "");
		regIa64Map.put(708, "");
		regIa64Map.put(709, "");
		regIa64Map.put(710, "");
		regIa64Map.put(711, "");
		regIa64Map.put(712, "");
		regIa64Map.put(713, "");
		regIa64Map.put(714, "");
		regIa64Map.put(715, "");
		regIa64Map.put(716, "");
		regIa64Map.put(717, "");
		regIa64Map.put(718, "");
		regIa64Map.put(719, "");
		regIa64Map.put(720, "");
		regIa64Map.put(721, "");
		regIa64Map.put(722, "");
		regIa64Map.put(723, "");
		regIa64Map.put(724, "");
		regIa64Map.put(725, "");
		regIa64Map.put(726, "");
		regIa64Map.put(727, "");
		regIa64Map.put(728, "");
		regIa64Map.put(729, "");
		regIa64Map.put(730, "");
		regIa64Map.put(731, "");
		regIa64Map.put(732, "");
		regIa64Map.put(733, "");
		regIa64Map.put(734, "");
		regIa64Map.put(735, "");
		regIa64Map.put(736, "");
		regIa64Map.put(737, "");
		regIa64Map.put(738, "");
		regIa64Map.put(739, "");
		regIa64Map.put(740, "");
		regIa64Map.put(741, "");
		regIa64Map.put(742, "");
		regIa64Map.put(743, "");
		regIa64Map.put(744, "");
		regIa64Map.put(745, "");
		regIa64Map.put(746, "");
		regIa64Map.put(747, "");
		regIa64Map.put(748, "");
		regIa64Map.put(749, "");
		regIa64Map.put(750, "");
		regIa64Map.put(751, "");
		regIa64Map.put(752, "");
		regIa64Map.put(753, "");
		regIa64Map.put(754, "");
		regIa64Map.put(755, "");
		regIa64Map.put(756, "");
		regIa64Map.put(757, "");
		regIa64Map.put(758, "");
		regIa64Map.put(759, "");
		regIa64Map.put(760, "");
		regIa64Map.put(761, "");
		regIa64Map.put(762, "");
		regIa64Map.put(763, "");
		regIa64Map.put(764, "");
		regIa64Map.put(765, "");
		regIa64Map.put(766, "");
		regIa64Map.put(767, "");
		regIa64Map.put(768, "preds");
		// Banked General Registers
		regIa64Map.put(832, "h0");
		regIa64Map.put(833, "h1");
		regIa64Map.put(834, "h2");
		regIa64Map.put(835, "h3");
		regIa64Map.put(836, "h4");
		regIa64Map.put(837, "h5");
		regIa64Map.put(838, "h6");
		regIa64Map.put(839, "h7");
		regIa64Map.put(840, "h8");
		regIa64Map.put(841, "h9");
		regIa64Map.put(842, "h10");
		regIa64Map.put(843, "h11");
		regIa64Map.put(844, "h12");
		regIa64Map.put(845, "h13");
		regIa64Map.put(846, "h14");
		regIa64Map.put(847, "h15");
		// Special Registers
		regIa64Map.put(1016, "ip");
		regIa64Map.put(1017, "umask");
		regIa64Map.put(1018, "cfm");
		regIa64Map.put(1019, "psr");
		// Banked General Registers
		regIa64Map.put(1020, "nats");
		regIa64Map.put(1021, "nats2");
		regIa64Map.put(1022, "nats3");
		// General-Purpose Registers
		// Integer registers
		regIa64Map.put(1023, "r0");

		regIa64Map.put(1024, "r0");
		regIa64Map.put(1025, "r1");
		regIa64Map.put(1026, "r2");
		regIa64Map.put(1027, "r3");
		regIa64Map.put(1028, "r4");
		regIa64Map.put(1029, "r5");
		regIa64Map.put(1030, "r6");
		regIa64Map.put(1031, "r7");
		regIa64Map.put(1032, "r8");
		regIa64Map.put(1033, "r9");
		regIa64Map.put(1034, "r10");
		regIa64Map.put(1035, "r11");
		regIa64Map.put(1036, "r12");
		regIa64Map.put(1037, "r13");
		regIa64Map.put(1038, "r14");
		regIa64Map.put(1039, "r15");
		regIa64Map.put(1040, "r16");
		regIa64Map.put(1041, "r17");
		regIa64Map.put(1042, "r18");
		regIa64Map.put(1043, "r19");
		regIa64Map.put(1044, "r20");
		regIa64Map.put(1045, "r21");
		regIa64Map.put(1046, "r22");
		regIa64Map.put(1047, "r23");
		regIa64Map.put(1048, "r24");
		regIa64Map.put(1049, "r25");
		regIa64Map.put(1050, "r26");
		regIa64Map.put(1051, "r27");
		regIa64Map.put(1052, "r28");
		regIa64Map.put(1053, "r29");
		regIa64Map.put(1054, "r30");
		regIa64Map.put(1055, "r31");
		// Register Stack
		regIa64Map.put(1056, "r32");
		regIa64Map.put(1057, "r33");
		regIa64Map.put(1058, "r34");
		regIa64Map.put(1059, "r35");
		regIa64Map.put(1060, "r36");
		regIa64Map.put(1061, "r37");
		regIa64Map.put(1062, "r38");
		regIa64Map.put(1063, "r39");
		regIa64Map.put(1064, "r40");
		regIa64Map.put(1065, "r41");
		regIa64Map.put(1066, "r42");
		regIa64Map.put(1067, "r43");
		regIa64Map.put(1068, "r44");
		regIa64Map.put(1069, "r45");
		regIa64Map.put(1070, "r46");
		regIa64Map.put(1071, "r47");
		regIa64Map.put(1072, "r48");
		regIa64Map.put(1073, "r49");
		regIa64Map.put(1074, "r50");
		regIa64Map.put(1075, "r51");
		regIa64Map.put(1076, "r52");
		regIa64Map.put(1077, "r53");
		regIa64Map.put(1078, "r54");
		regIa64Map.put(1079, "r55");
		regIa64Map.put(1080, "r56");
		regIa64Map.put(1081, "r57");
		regIa64Map.put(1082, "r58");
		regIa64Map.put(1083, "r59");
		regIa64Map.put(1084, "r60");
		regIa64Map.put(1085, "r61");
		regIa64Map.put(1086, "r62");
		regIa64Map.put(1087, "r63");
		regIa64Map.put(1088, "r64");
		regIa64Map.put(1089, "r65");
		regIa64Map.put(1090, "r66");
		regIa64Map.put(1091, "r67");
		regIa64Map.put(1092, "r68");
		regIa64Map.put(1093, "r69");
		regIa64Map.put(1094, "r70");
		regIa64Map.put(1095, "r71");
		regIa64Map.put(1096, "r72");
		regIa64Map.put(1097, "r73");
		regIa64Map.put(1098, "r74");
		regIa64Map.put(1099, "r75");
		regIa64Map.put(1100, "r76");
		regIa64Map.put(1101, "r77");
		regIa64Map.put(1102, "r78");
		regIa64Map.put(1103, "r79");
		regIa64Map.put(1104, "r80");
		regIa64Map.put(1105, "r81");
		regIa64Map.put(1106, "r82");
		regIa64Map.put(1107, "r83");
		regIa64Map.put(1108, "r84");
		regIa64Map.put(1109, "r85");
		regIa64Map.put(1110, "r86");
		regIa64Map.put(1111, "r87");
		regIa64Map.put(1112, "r88");
		regIa64Map.put(1113, "r89");
		regIa64Map.put(1114, "r90");
		regIa64Map.put(1115, "r91");
		regIa64Map.put(1116, "r92");
		regIa64Map.put(1117, "r93");
		regIa64Map.put(1118, "r94");
		regIa64Map.put(1119, "r95");
		regIa64Map.put(1120, "r96");
		regIa64Map.put(1121, "r97");
		regIa64Map.put(1122, "r98");
		regIa64Map.put(1123, "r99");
		regIa64Map.put(1124, "r100");
		regIa64Map.put(1125, "r101");
		regIa64Map.put(1126, "r102");
		regIa64Map.put(1127, "r103");
		regIa64Map.put(1128, "r104");
		regIa64Map.put(1129, "r105");
		regIa64Map.put(1130, "r106");
		regIa64Map.put(1131, "r107");
		regIa64Map.put(1132, "r108");
		regIa64Map.put(1133, "r109");
		regIa64Map.put(1134, "r110");
		regIa64Map.put(1135, "r111");
		regIa64Map.put(1136, "r112");
		regIa64Map.put(1137, "r113");
		regIa64Map.put(1138, "r114");
		regIa64Map.put(1139, "r115");
		regIa64Map.put(1140, "r116");
		regIa64Map.put(1141, "r117");
		regIa64Map.put(1142, "r118");
		regIa64Map.put(1143, "r119");
		regIa64Map.put(1144, "r120");
		regIa64Map.put(1145, "r121");
		regIa64Map.put(1146, "r122");
		regIa64Map.put(1147, "r123");
		regIa64Map.put(1148, "r124");
		regIa64Map.put(1149, "r125");
		regIa64Map.put(1150, "r126");
		regIa64Map.put(1151, "r127");
		// Floating-Point Registers
		// Low Floating Point Registers
		regIa64Map.put(2048, "f0");
		regIa64Map.put(2049, "f1");
		regIa64Map.put(2050, "f2");
		regIa64Map.put(2051, "f3");
		regIa64Map.put(2052, "f4");
		regIa64Map.put(2053, "f5");
		regIa64Map.put(2054, "f6");
		regIa64Map.put(2055, "f7");
		regIa64Map.put(2056, "f8");
		regIa64Map.put(2057, "f9");
		regIa64Map.put(2058, "f10");
		regIa64Map.put(2059, "f11");
		regIa64Map.put(2060, "f12");
		regIa64Map.put(2061, "f13");
		regIa64Map.put(2062, "f14");
		regIa64Map.put(2063, "f15");
		regIa64Map.put(2064, "f16");
		regIa64Map.put(2065, "f17");
		regIa64Map.put(2066, "f18");
		regIa64Map.put(2067, "f19");
		regIa64Map.put(2068, "f20");
		regIa64Map.put(2069, "f21");
		regIa64Map.put(2070, "f22");
		regIa64Map.put(2071, "f23");
		regIa64Map.put(2072, "f24");
		regIa64Map.put(2073, "f25");
		regIa64Map.put(2074, "f26");
		regIa64Map.put(2075, "f27");
		regIa64Map.put(2076, "f28");
		regIa64Map.put(2077, "f29");
		regIa64Map.put(2078, "f30");
		regIa64Map.put(2079, "f31");
		regIa64Map.put(2080, "f32");
		regIa64Map.put(2081, "f33");
		regIa64Map.put(2082, "f34");
		regIa64Map.put(2083, "f35");
		regIa64Map.put(2084, "f36");
		regIa64Map.put(2085, "f37");
		regIa64Map.put(2086, "f38");
		regIa64Map.put(2087, "f39");
		regIa64Map.put(2088, "f40");
		regIa64Map.put(2089, "f41");
		regIa64Map.put(2090, "f42");
		regIa64Map.put(2091, "f43");
		regIa64Map.put(2092, "f44");
		regIa64Map.put(2093, "f45");
		regIa64Map.put(2094, "f46");
		regIa64Map.put(2095, "f47");
		regIa64Map.put(2096, "f48");
		regIa64Map.put(2097, "f49");
		regIa64Map.put(2098, "f50");
		regIa64Map.put(2099, "f51");
		regIa64Map.put(2100, "f52");
		regIa64Map.put(2101, "f53");
		regIa64Map.put(2102, "f54");
		regIa64Map.put(2103, "f55");
		regIa64Map.put(2104, "f56");
		regIa64Map.put(2105, "f57");
		regIa64Map.put(2106, "f58");
		regIa64Map.put(2107, "f59");
		regIa64Map.put(2108, "f60");
		regIa64Map.put(2109, "f61");
		regIa64Map.put(2110, "f62");
		regIa64Map.put(2111, "f63");
		regIa64Map.put(2112, "f64");
		regIa64Map.put(2113, "f65");
		regIa64Map.put(2114, "f66");
		regIa64Map.put(2115, "f67");
		regIa64Map.put(2116, "f68");
		regIa64Map.put(2117, "f69");
		regIa64Map.put(2118, "f70");
		regIa64Map.put(2119, "f71");
		regIa64Map.put(2120, "f72");
		regIa64Map.put(2121, "f73");
		regIa64Map.put(2122, "f74");
		regIa64Map.put(2123, "f75");
		regIa64Map.put(2124, "f76");
		regIa64Map.put(2125, "f77");
		regIa64Map.put(2126, "f78");
		regIa64Map.put(2127, "f79");
		regIa64Map.put(2128, "f80");
		regIa64Map.put(2129, "f81");
		regIa64Map.put(2130, "f82");
		regIa64Map.put(2131, "f83");
		regIa64Map.put(2132, "f84");
		regIa64Map.put(2133, "f85");
		regIa64Map.put(2134, "f86");
		regIa64Map.put(2135, "f87");
		regIa64Map.put(2136, "f88");
		regIa64Map.put(2137, "f89");
		regIa64Map.put(2138, "f90");
		regIa64Map.put(2139, "f91");
		regIa64Map.put(2140, "f92");
		regIa64Map.put(2141, "f93");
		regIa64Map.put(2142, "f94");
		regIa64Map.put(2143, "f95");
		regIa64Map.put(2144, "f96");
		regIa64Map.put(2145, "f97");
		regIa64Map.put(2146, "f98");
		regIa64Map.put(2147, "f99");
		regIa64Map.put(2148, "f100");
		regIa64Map.put(2149, "f101");
		regIa64Map.put(2150, "f102");
		regIa64Map.put(2151, "f103");
		regIa64Map.put(2152, "f104");
		regIa64Map.put(2153, "f105");
		regIa64Map.put(2154, "f106");
		regIa64Map.put(2155, "f107");
		regIa64Map.put(2156, "f108");
		regIa64Map.put(2157, "f109");
		regIa64Map.put(2158, "f110");
		regIa64Map.put(2159, "f111");
		regIa64Map.put(2160, "f112");
		regIa64Map.put(2161, "f113");
		regIa64Map.put(2162, "f114");
		regIa64Map.put(2163, "f115");
		regIa64Map.put(2164, "f116");
		regIa64Map.put(2165, "f117");
		regIa64Map.put(2166, "f118");
		regIa64Map.put(2167, "f119");
		regIa64Map.put(2168, "f120");
		regIa64Map.put(2169, "f121");
		regIa64Map.put(2170, "f122");
		regIa64Map.put(2171, "f123");
		regIa64Map.put(2172, "f124");
		regIa64Map.put(2173, "f125");
		regIa64Map.put(2174, "f126");
		regIa64Map.put(2175, "f127");
		// Application Registers
		regIa64Map.put(3072, "apkr0");
		regIa64Map.put(3073, "apkr1");
		regIa64Map.put(3074, "apkr2");
		regIa64Map.put(3075, "apkr3");
		regIa64Map.put(3076, "apkr4");
		regIa64Map.put(3077, "apkr5");
		regIa64Map.put(3078, "apkr6");
		regIa64Map.put(3079, "apkr7");
		regIa64Map.put(3080, "ar8");
		regIa64Map.put(3081, "ar9");
		regIa64Map.put(3082, "ar10");
		regIa64Map.put(3083, "ar11");
		regIa64Map.put(3084, "ar12");
		regIa64Map.put(3085, "ar13");
		regIa64Map.put(3086, "ar14");
		regIa64Map.put(3087, "ar15");
		regIa64Map.put(3088, "rsbsc");
		regIa64Map.put(3089, "rsbsp");
		regIa64Map.put(3090, "rsbspstore");
		regIa64Map.put(3091, "rsrnat");
		regIa64Map.put(3092, "r20");
		regIa64Map.put(3093, "stfcr");
		regIa64Map.put(3094, "r22");
		regIa64Map.put(3095, "r23");
		regIa64Map.put(3096, "eflag");
		regIa64Map.put(3097, "csd");
		regIa64Map.put(3098, "ssd");
		regIa64Map.put(3099, "cflg");
		regIa64Map.put(3100, "stfsr");
		regIa64Map.put(3101, "stfir");
		regIa64Map.put(3102, "stfdr");
		regIa64Map.put(3103, "ar31");
		regIa64Map.put(3104, "apccv");
		regIa64Map.put(3105, "ar33");
		regIa64Map.put(3106, "ar34");
		regIa64Map.put(3107, "ar35");
		regIa64Map.put(3108, "apunat");
		regIa64Map.put(3109, "ar37");
		regIa64Map.put(3110, "ar38");
		regIa64Map.put(3111, "ar39");
		regIa64Map.put(3112, "stfpsr");
		regIa64Map.put(3113, "ar41");
		regIa64Map.put(3114, "ar42");
		regIa64Map.put(3115, "ar43");
		regIa64Map.put(3116, "apitc");
		regIa64Map.put(3117, "ar45");
		regIa64Map.put(3118, "ar46");
		regIa64Map.put(3119, "ar47");
		regIa64Map.put(3120, "ar48");
		regIa64Map.put(3121, "ar49");
		regIa64Map.put(3122, "ar50");
		regIa64Map.put(3123, "ar51");
		regIa64Map.put(3124, "ar52");
		regIa64Map.put(3125, "ar53");
		regIa64Map.put(3126, "ar54");
		regIa64Map.put(3127, "ar55");
		regIa64Map.put(3128, "ar56");
		regIa64Map.put(3129, "ar57");
		regIa64Map.put(3130, "ar58");
		regIa64Map.put(3131, "ar59");
		regIa64Map.put(3132, "ar60");
		regIa64Map.put(3133, "ar61");
		regIa64Map.put(3134, "ar62");
		regIa64Map.put(3135, "ar63");
		regIa64Map.put(3136, "rspfs");
		regIa64Map.put(3137, "aplc");
		regIa64Map.put(3138, "apec");
		regIa64Map.put(3139, "ar67");
		regIa64Map.put(3140, "ar68");
		regIa64Map.put(3141, "ar69");
		regIa64Map.put(3142, "ar70");
		regIa64Map.put(3143, "ar71");
		regIa64Map.put(3144, "ar72");
		regIa64Map.put(3145, "ar73");
		regIa64Map.put(3146, "ar74");
		regIa64Map.put(3147, "ar75");
		regIa64Map.put(3148, "ar76");
		regIa64Map.put(3149, "ar77");
		regIa64Map.put(3150, "ar78");
		regIa64Map.put(3151, "ar79");
		regIa64Map.put(3152, "ar80");
		regIa64Map.put(3153, "ar81");
		regIa64Map.put(3154, "ar82");
		regIa64Map.put(3155, "ar83");
		regIa64Map.put(3156, "ar84");
		regIa64Map.put(3157, "ar85");
		regIa64Map.put(3158, "ar86");
		regIa64Map.put(3159, "ar87");
		regIa64Map.put(3160, "ar88");
		regIa64Map.put(3161, "ar89");
		regIa64Map.put(3162, "ar90");
		regIa64Map.put(3163, "ar91");
		regIa64Map.put(3164, "ar92");
		regIa64Map.put(3165, "ar93");
		regIa64Map.put(3166, "ar94");
		regIa64Map.put(3167, "ar95");
		regIa64Map.put(3168, "ar96");
		regIa64Map.put(3169, "ar97");
		regIa64Map.put(3170, "ar98");
		regIa64Map.put(3171, "ar99");
		regIa64Map.put(3172, "ar100");
		regIa64Map.put(3173, "ar101");
		regIa64Map.put(3174, "ar102");
		regIa64Map.put(3175, "ar103");
		regIa64Map.put(3176, "ar104");
		regIa64Map.put(3177, "ar105");
		regIa64Map.put(3178, "ar106");
		regIa64Map.put(3179, "ar107");
		regIa64Map.put(3180, "ar108");
		regIa64Map.put(3181, "ar109");
		regIa64Map.put(3182, "ar110");
		regIa64Map.put(3183, "ar111");
		regIa64Map.put(3184, "ar112");
		regIa64Map.put(3185, "ar113");
		regIa64Map.put(3186, "ar114");
		regIa64Map.put(3187, "ar115");
		regIa64Map.put(3188, "ar116");
		regIa64Map.put(3189, "ar117");
		regIa64Map.put(3190, "ar118");
		regIa64Map.put(3191, "ar119");
		regIa64Map.put(3192, "ar120");
		regIa64Map.put(3193, "ar121");
		regIa64Map.put(3194, "ar122");
		regIa64Map.put(3195, "ar123");
		regIa64Map.put(3196, "ar124");
		regIa64Map.put(3197, "ar125");
		regIa64Map.put(3198, "ar126");
		regIa64Map.put(3199, "ar127");

		regIa64Map.put(3328, "cpuid0");
		regIa64Map.put(3329, "cpuid1");
		regIa64Map.put(3330, "cpuid2");
		regIa64Map.put(3331, "cpuid3");
		regIa64Map.put(3332, "cpuid4");

		regIa64Map.put(4096, "apdcr");
		regIa64Map.put(4097, "apitm");
		regIa64Map.put(4098, "apiva");
		regIa64Map.put(4099, "cr3");
		regIa64Map.put(4100, "cr4");
		regIa64Map.put(4101, "cr5");
		regIa64Map.put(4102, "cr6");
		regIa64Map.put(4103, "cr7");
		regIa64Map.put(4104, "appta");
		regIa64Map.put(4105, "apgpta");
		regIa64Map.put(4106, "cr10");
		regIa64Map.put(4107, "cr11");
		regIa64Map.put(4108, "cr12");
		regIa64Map.put(4109, "cr13");
		regIa64Map.put(4110, "cr14");
		regIa64Map.put(4111, "cr15");
		regIa64Map.put(4112, "stipsr");
		regIa64Map.put(4113, "stisr");
		regIa64Map.put(4114, "cr18");
		regIa64Map.put(4115, "stiip");
		regIa64Map.put(4116, "stifa");
		regIa64Map.put(4117, "stitir");
		regIa64Map.put(4118, "stiipa");
		regIa64Map.put(4119, "stifs");
		regIa64Map.put(4120, "stiim");
		regIa64Map.put(4121, "stiha");
		regIa64Map.put(4122, "cr26");
		regIa64Map.put(4123, "cr27");
		regIa64Map.put(4124, "cr28");
		regIa64Map.put(4125, "cr29");
		regIa64Map.put(4126, "cr30");
		regIa64Map.put(4127, "cr31");
		regIa64Map.put(4128, "cr32");
		regIa64Map.put(4129, "cr33");
		regIa64Map.put(4130, "cr34");
		regIa64Map.put(4131, "cr35");
		regIa64Map.put(4132, "cr36");
		regIa64Map.put(4133, "cr37");
		regIa64Map.put(4134, "cr38");
		regIa64Map.put(4135, "cr39");
		regIa64Map.put(4136, "cr40");
		regIa64Map.put(4137, "cr41");
		regIa64Map.put(4138, "cr42");
		regIa64Map.put(4139, "cr43");
		regIa64Map.put(4140, "cr44");
		regIa64Map.put(4141, "cr45");
		regIa64Map.put(4142, "cr46");
		regIa64Map.put(4143, "cr47");
		regIa64Map.put(4144, "cr48");
		regIa64Map.put(4145, "cr49");
		regIa64Map.put(4146, "cr50");
		regIa64Map.put(4147, "cr51");
		regIa64Map.put(4148, "cr52");
		regIa64Map.put(4149, "cr53");
		regIa64Map.put(4150, "cr54");
		regIa64Map.put(4151, "cr55");
		regIa64Map.put(4152, "cr56");
		regIa64Map.put(4153, "cr57");
		regIa64Map.put(4154, "cr58");
		regIa64Map.put(4155, "cr59");
		regIa64Map.put(4156, "cr60");
		regIa64Map.put(4157, "cr61");
		regIa64Map.put(4158, "cr62");
		regIa64Map.put(4159, "cr63");
		regIa64Map.put(4160, "salid");
		regIa64Map.put(4161, "saivr");
		regIa64Map.put(4162, "satpr");
		regIa64Map.put(4163, "saeoi");
		regIa64Map.put(4164, "sairr0");
		regIa64Map.put(4165, "sairr1");
		regIa64Map.put(4166, "sairr2");
		regIa64Map.put(4167, "sairr3");
		regIa64Map.put(4168, "saitv");
		regIa64Map.put(4169, "sapmv");
		regIa64Map.put(4170, "sacmcv");
		regIa64Map.put(4171, "cr75");
		regIa64Map.put(4172, "cr76");
		regIa64Map.put(4173, "cr77");
		regIa64Map.put(4174, "cr78");
		regIa64Map.put(4175, "cr79");
		regIa64Map.put(4176, "salrr0");
		regIa64Map.put(4177, "salrr1");
		regIa64Map.put(4178, "cr82");
		regIa64Map.put(4179, "cr83");
		regIa64Map.put(4180, "cr84");
		regIa64Map.put(4181, "cr85");
		regIa64Map.put(4182, "cr86");
		regIa64Map.put(4183, "cr87");
		regIa64Map.put(4184, "cr88");
		regIa64Map.put(4185, "cr89");
		regIa64Map.put(4186, "cr90");
		regIa64Map.put(4187, "cr91");
		regIa64Map.put(4188, "cr92");
		regIa64Map.put(4189, "cr93");
		regIa64Map.put(4190, "cr94");
		regIa64Map.put(4191, "cr95");
		regIa64Map.put(4192, "cr96");
		regIa64Map.put(4193, "cr97");
		regIa64Map.put(4194, "cr98");
		regIa64Map.put(4195, "cr99");
		regIa64Map.put(4196, "cr100");
		regIa64Map.put(4197, "cr101");
		regIa64Map.put(4198, "cr102");
		regIa64Map.put(4199, "cr103");
		regIa64Map.put(4200, "cr104");
		regIa64Map.put(4201, "cr105");
		regIa64Map.put(4202, "cr106");
		regIa64Map.put(4203, "cr107");
		regIa64Map.put(4204, "cr108");
		regIa64Map.put(4205, "cr109");
		regIa64Map.put(4206, "cr110");
		regIa64Map.put(4207, "cr111");
		regIa64Map.put(4208, "cr112");
		regIa64Map.put(4209, "cr113");
		regIa64Map.put(4210, "cr114");
		regIa64Map.put(4211, "cr115");
		regIa64Map.put(4212, "cr116");
		regIa64Map.put(4213, "cr117");
		regIa64Map.put(4214, "cr118");
		regIa64Map.put(4215, "cr119");
		regIa64Map.put(4216, "cr120");
		regIa64Map.put(4217, "cr121");
		regIa64Map.put(4218, "cr122");
		regIa64Map.put(4219, "cr123");
		regIa64Map.put(4220, "cr124");
		regIa64Map.put(4221, "cr125");
		regIa64Map.put(4222, "cr126");
		regIa64Map.put(4223, "cr127");

		regIa64Map.put(5120, "pkr0");
		regIa64Map.put(5121, "pkr1");
		regIa64Map.put(5122, "pkr2");
		regIa64Map.put(5123, "pkr3");
		regIa64Map.put(5124, "pkr4");
		regIa64Map.put(5125, "pkr5");
		regIa64Map.put(5126, "pkr6");
		regIa64Map.put(5127, "pkr7");
		regIa64Map.put(5128, "pkr8");
		regIa64Map.put(5129, "pkr9");
		regIa64Map.put(5130, "pkr10");
		regIa64Map.put(5131, "pkr11");
		regIa64Map.put(5132, "pkr12");
		regIa64Map.put(5133, "pkr13");
		regIa64Map.put(5134, "pkr14");
		regIa64Map.put(5135, "pkr15");

		regIa64Map.put(6144, "rr0");
		regIa64Map.put(6145, "rr1");
		regIa64Map.put(6146, "rr2");
		regIa64Map.put(6147, "rr3");
		regIa64Map.put(6148, "rr4");
		regIa64Map.put(6149, "rr5");
		regIa64Map.put(6150, "rr6");
		regIa64Map.put(6151, "rr7");

		regIa64Map.put(7168, "pfd0");
		regIa64Map.put(7169, "pfd1");
		regIa64Map.put(7170, "pfd2");
		regIa64Map.put(7171, "pfd3");
		regIa64Map.put(7172, "pfd4");
		regIa64Map.put(7173, "pfd5");
		regIa64Map.put(7174, "pfd6");
		regIa64Map.put(7175, "pfd7");
		regIa64Map.put(7176, "pfd8");
		regIa64Map.put(7177, "pfd9");
		regIa64Map.put(7178, "pfd10");
		regIa64Map.put(7179, "pfd11");
		regIa64Map.put(7180, "pfd12");
		regIa64Map.put(7181, "pfd13");
		regIa64Map.put(7182, "pfd14");
		regIa64Map.put(7183, "pfd15");
		regIa64Map.put(7184, "pfd16");
		regIa64Map.put(7185, "pfd17");

		regIa64Map.put(7424, "pfc0");
		regIa64Map.put(7425, "pfc1");
		regIa64Map.put(7426, "pfc2");
		regIa64Map.put(7427, "pfc3");
		regIa64Map.put(7428, "pfc4");
		regIa64Map.put(7429, "pfc5");
		regIa64Map.put(7430, "pfc6");
		regIa64Map.put(7431, "pfc7");
		regIa64Map.put(7432, "pfc8");
		regIa64Map.put(7433, "pfc9");
		regIa64Map.put(7434, "pfc10");
		regIa64Map.put(7435, "pfc11");
		regIa64Map.put(7436, "pfc12");
		regIa64Map.put(7437, "pfc13");
		regIa64Map.put(7438, "pfc14");
		regIa64Map.put(7439, "pfc15");

		regIa64Map.put(8192, "tri0");
		regIa64Map.put(8193, "tri1");
		regIa64Map.put(8194, "tri2");
		regIa64Map.put(8195, "tri3");
		regIa64Map.put(8196, "tri4");
		regIa64Map.put(8197, "tri5");
		regIa64Map.put(8198, "tri6");
		regIa64Map.put(8199, "tri7");

		regIa64Map.put(8320, "trd0");
		regIa64Map.put(8321, "trd1");
		regIa64Map.put(8322, "trd2");
		regIa64Map.put(8323, "trd3");
		regIa64Map.put(8324, "trd4");
		regIa64Map.put(8325, "trd5");
		regIa64Map.put(8326, "trd6");
		regIa64Map.put(8327, "trd7");

		regIa64Map.put(8448, "dbi0");
		regIa64Map.put(8449, "dbi1");
		regIa64Map.put(8450, "dbi2");
		regIa64Map.put(8451, "dbi3");
		regIa64Map.put(8452, "dbi4");
		regIa64Map.put(8453, "dbi5");
		regIa64Map.put(8454, "dbi6");
		regIa64Map.put(8455, "dbi7");

		regIa64Map.put(8576, "dbd0");
		regIa64Map.put(8577, "dbd1");
		regIa64Map.put(8578, "dbd2");
		regIa64Map.put(8579, "dbd3");
		regIa64Map.put(8580, "dbd4");
		regIa64Map.put(8581, "dbd5");
		regIa64Map.put(8582, "dbd6");
		regIa64Map.put(8583, "dbd7");
	}

	private static final String badRegister = "bad register";

	//==============================================================================================
	private AbstractPdb pdb;
	private int register;

	//==============================================================================================
	/**
	 * Constructor for this symbol component.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param register Register ID.
	 */
	public RegisterName(AbstractPdb pdb, int register) {
		this.pdb = pdb;
		this.register = register;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isRegNone() {
		return (register == 0);
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getRegisterName(pdb.getTargetProcessorIndexNumber(), register));
	}

	private String getRegisterName(int processorIn, int registerIn) {
		if (registerIn < 0) {
			return badRegister;
		}
		if (processorIn >= 0x00 && processorIn <= 0x07 && registerIn < regX86.length) {
			return regX86[registerIn];
		}
		else if (processorIn >= 0x10 && processorIn <= 0x18 && registerIn < regMips.length) {
			return regMips[registerIn];
		}
		else if (processorIn >= 0x20 && processorIn <= 0x24 && registerIn < reg68k.length) {
			return reg68k[registerIn];
		}
		else if (processorIn >= 0x30 && processorIn <= 0x34 && registerIn < regAlpha.length) {
			return regAlpha[registerIn];
		}
		else if (processorIn >= 0x40 && processorIn <= 0x45 && registerIn < regPpc.length) {
			return regPpc[registerIn];
		}
		else if (processorIn >= 0x50 && processorIn <= 0x54 && registerIn < regSh.length) {
			return regSh[registerIn];
		}

		else if (processorIn == 0xd0 && registerIn < regAmd64.length) {
			return regAmd64[registerIn];
		}
		else if (processorIn >= 0x80 && processorIn <= 0x81 && registerIn < regIa64Map.size()) {
			String val = regIa64Map.get(registerIn);
			if (val != null) {
				return val;
			}
		}
		// TODO:  Don't have anything for arm, and other processors. See API for possibilities.
		return badRegister;
	}

}
