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
		"xmm5", "xmm6", "xmm7", "xmm0_0", "xmm0_1", "xmm0_2", "xmm0_3", "xmm1_0", "xmm1_1",
		"xmm1_2", "xmm1_3", "xmm2_0", "xmm2_1", "xmm2_2", "xmm2_3", "xmm3_0", "xmm3_1", "xmm3_2",
		"xmm3_3", "xmm4_0", "xmm4_1", "xmm4_2", "xmm4_3", "xmm5_0", "xmm5_1", "xmm5_2", "xmm5_3",
		"xmm6_0", "xmm6_1", "xmm6_2", "xmm6_3", "xmm7_0", "xmm7_1", "xmm7_2", "xmm7_3", "xmm0l",
		"xmm1l", "xmm2l", "xmm3l", "xmm4l", "xmm5l", "xmm6l", "xmm7l", "xmm0h", "xmm1h", "xmm2h",
		"xmm3h", "xmm4h", "xmm5h", "xmm6h", "xmm7h", "???", "mxcsr", "???", "???", "???", "???",
		"???", "???", "???", "???", "emm0l", "emm1l", "emm2l", "emm3l", "emm4l", "emm5l", "emm6l",
		"emm7l", "emm0h", "emm1h", "emm2h", "emm3h", "emm4h", "emm5h", "emm6h", "emm7h", "mm00",
		"mm01", "mm10", "mm11", "mm20", "mm21", "mm30", "mm31", "mm40", "mm41", "mm50", "mm51",
		"mm60", "mm61", "mm70", "mm71", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14",
		"xmm15", "xmm8_0", "xmm8_1", "xmm8_2", "xmm8_3", "xmm9_0", "xmm9_1", "xmm9_2", "xmm9_3",
		"xmm10_0", "xmm10_1", "xmm10_2", "xmm10_3", "xmm11_0", "xmm11_1", "xmm11_2", "xmm11_3",
		"xmm12_0", "xmm12_1", "xmm12_2", "xmm12_3", "xmm13_0", "xmm13_1", "xmm13_2", "xmm13_3",
		"xmm14_0", "xmm14_1", "xmm14_2", "xmm14_3", "xmm15_0", "xmm15_1", "xmm15_2", "xmm15_3",
		"xmm8l", "xmm9l", "xmm10l", "xmm11l", "xmm12l", "xmm13l", "xmm14l", "xmm15l", "xmm8h",
		"xmm9h", "xmm10h", "xmm11h", "xmm12h", "xmm13h", "xmm14h", "xmm15h", "emm8l", "emm9l",
		"emm10l", "emm11l", "emm12l", "emm13l", "emm14l", "emm15l", "emm8h", "emm9h", "emm10h",
		"emm11h", "emm12h", "emm13h", "emm14h", "emm15h", "sil", "dil", "bpl", "spl", "rax", "rbx",
		"rcx", "rdx", "rsi", "rdi", "fbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
		"r15", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", "r8w", "r9w", "r10w",
		"r11w", "r12w", "r13w", "r14w", "r15w", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d",
		"r14d", "r15d" };

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

	private static final Map<Integer, String> ia64RegistersById = new HashMap<>();
	static {
		ia64RegistersById.put(0, "None");
		// Branch Registers
		ia64RegistersById.put(512, "br0");
		ia64RegistersById.put(513, "br1");
		ia64RegistersById.put(514, "br2");
		ia64RegistersById.put(515, "br3");
		ia64RegistersById.put(516, "br4");
		ia64RegistersById.put(517, "br5");
		ia64RegistersById.put(518, "br6");
		ia64RegistersById.put(519, "br7");
		// Predicate Registers
		ia64RegistersById.put(704, "");
		ia64RegistersById.put(705, "");
		ia64RegistersById.put(706, "");
		ia64RegistersById.put(707, "");
		ia64RegistersById.put(708, "");
		ia64RegistersById.put(709, "");
		ia64RegistersById.put(710, "");
		ia64RegistersById.put(711, "");
		ia64RegistersById.put(712, "");
		ia64RegistersById.put(713, "");
		ia64RegistersById.put(714, "");
		ia64RegistersById.put(715, "");
		ia64RegistersById.put(716, "");
		ia64RegistersById.put(717, "");
		ia64RegistersById.put(718, "");
		ia64RegistersById.put(719, "");
		ia64RegistersById.put(720, "");
		ia64RegistersById.put(721, "");
		ia64RegistersById.put(722, "");
		ia64RegistersById.put(723, "");
		ia64RegistersById.put(724, "");
		ia64RegistersById.put(725, "");
		ia64RegistersById.put(726, "");
		ia64RegistersById.put(727, "");
		ia64RegistersById.put(728, "");
		ia64RegistersById.put(729, "");
		ia64RegistersById.put(730, "");
		ia64RegistersById.put(731, "");
		ia64RegistersById.put(732, "");
		ia64RegistersById.put(733, "");
		ia64RegistersById.put(734, "");
		ia64RegistersById.put(735, "");
		ia64RegistersById.put(736, "");
		ia64RegistersById.put(737, "");
		ia64RegistersById.put(738, "");
		ia64RegistersById.put(739, "");
		ia64RegistersById.put(740, "");
		ia64RegistersById.put(741, "");
		ia64RegistersById.put(742, "");
		ia64RegistersById.put(743, "");
		ia64RegistersById.put(744, "");
		ia64RegistersById.put(745, "");
		ia64RegistersById.put(746, "");
		ia64RegistersById.put(747, "");
		ia64RegistersById.put(748, "");
		ia64RegistersById.put(749, "");
		ia64RegistersById.put(750, "");
		ia64RegistersById.put(751, "");
		ia64RegistersById.put(752, "");
		ia64RegistersById.put(753, "");
		ia64RegistersById.put(754, "");
		ia64RegistersById.put(755, "");
		ia64RegistersById.put(756, "");
		ia64RegistersById.put(757, "");
		ia64RegistersById.put(758, "");
		ia64RegistersById.put(759, "");
		ia64RegistersById.put(760, "");
		ia64RegistersById.put(761, "");
		ia64RegistersById.put(762, "");
		ia64RegistersById.put(763, "");
		ia64RegistersById.put(764, "");
		ia64RegistersById.put(765, "");
		ia64RegistersById.put(766, "");
		ia64RegistersById.put(767, "");
		ia64RegistersById.put(768, "preds");
		// Banked General Registers
		ia64RegistersById.put(832, "h0");
		ia64RegistersById.put(833, "h1");
		ia64RegistersById.put(834, "h2");
		ia64RegistersById.put(835, "h3");
		ia64RegistersById.put(836, "h4");
		ia64RegistersById.put(837, "h5");
		ia64RegistersById.put(838, "h6");
		ia64RegistersById.put(839, "h7");
		ia64RegistersById.put(840, "h8");
		ia64RegistersById.put(841, "h9");
		ia64RegistersById.put(842, "h10");
		ia64RegistersById.put(843, "h11");
		ia64RegistersById.put(844, "h12");
		ia64RegistersById.put(845, "h13");
		ia64RegistersById.put(846, "h14");
		ia64RegistersById.put(847, "h15");
		// Special Registers
		ia64RegistersById.put(1016, "ip");
		ia64RegistersById.put(1017, "umask");
		ia64RegistersById.put(1018, "cfm");
		ia64RegistersById.put(1019, "psr");
		// Banked General Registers
		ia64RegistersById.put(1020, "nats");
		ia64RegistersById.put(1021, "nats2");
		ia64RegistersById.put(1022, "nats3");
		// General-Purpose Registers
		// Integer registers
		ia64RegistersById.put(1023, "r0");

		ia64RegistersById.put(1024, "r0");
		ia64RegistersById.put(1025, "r1");
		ia64RegistersById.put(1026, "r2");
		ia64RegistersById.put(1027, "r3");
		ia64RegistersById.put(1028, "r4");
		ia64RegistersById.put(1029, "r5");
		ia64RegistersById.put(1030, "r6");
		ia64RegistersById.put(1031, "r7");
		ia64RegistersById.put(1032, "r8");
		ia64RegistersById.put(1033, "r9");
		ia64RegistersById.put(1034, "r10");
		ia64RegistersById.put(1035, "r11");
		ia64RegistersById.put(1036, "r12");
		ia64RegistersById.put(1037, "r13");
		ia64RegistersById.put(1038, "r14");
		ia64RegistersById.put(1039, "r15");
		ia64RegistersById.put(1040, "r16");
		ia64RegistersById.put(1041, "r17");
		ia64RegistersById.put(1042, "r18");
		ia64RegistersById.put(1043, "r19");
		ia64RegistersById.put(1044, "r20");
		ia64RegistersById.put(1045, "r21");
		ia64RegistersById.put(1046, "r22");
		ia64RegistersById.put(1047, "r23");
		ia64RegistersById.put(1048, "r24");
		ia64RegistersById.put(1049, "r25");
		ia64RegistersById.put(1050, "r26");
		ia64RegistersById.put(1051, "r27");
		ia64RegistersById.put(1052, "r28");
		ia64RegistersById.put(1053, "r29");
		ia64RegistersById.put(1054, "r30");
		ia64RegistersById.put(1055, "r31");
		// Register Stack
		ia64RegistersById.put(1056, "r32");
		ia64RegistersById.put(1057, "r33");
		ia64RegistersById.put(1058, "r34");
		ia64RegistersById.put(1059, "r35");
		ia64RegistersById.put(1060, "r36");
		ia64RegistersById.put(1061, "r37");
		ia64RegistersById.put(1062, "r38");
		ia64RegistersById.put(1063, "r39");
		ia64RegistersById.put(1064, "r40");
		ia64RegistersById.put(1065, "r41");
		ia64RegistersById.put(1066, "r42");
		ia64RegistersById.put(1067, "r43");
		ia64RegistersById.put(1068, "r44");
		ia64RegistersById.put(1069, "r45");
		ia64RegistersById.put(1070, "r46");
		ia64RegistersById.put(1071, "r47");
		ia64RegistersById.put(1072, "r48");
		ia64RegistersById.put(1073, "r49");
		ia64RegistersById.put(1074, "r50");
		ia64RegistersById.put(1075, "r51");
		ia64RegistersById.put(1076, "r52");
		ia64RegistersById.put(1077, "r53");
		ia64RegistersById.put(1078, "r54");
		ia64RegistersById.put(1079, "r55");
		ia64RegistersById.put(1080, "r56");
		ia64RegistersById.put(1081, "r57");
		ia64RegistersById.put(1082, "r58");
		ia64RegistersById.put(1083, "r59");
		ia64RegistersById.put(1084, "r60");
		ia64RegistersById.put(1085, "r61");
		ia64RegistersById.put(1086, "r62");
		ia64RegistersById.put(1087, "r63");
		ia64RegistersById.put(1088, "r64");
		ia64RegistersById.put(1089, "r65");
		ia64RegistersById.put(1090, "r66");
		ia64RegistersById.put(1091, "r67");
		ia64RegistersById.put(1092, "r68");
		ia64RegistersById.put(1093, "r69");
		ia64RegistersById.put(1094, "r70");
		ia64RegistersById.put(1095, "r71");
		ia64RegistersById.put(1096, "r72");
		ia64RegistersById.put(1097, "r73");
		ia64RegistersById.put(1098, "r74");
		ia64RegistersById.put(1099, "r75");
		ia64RegistersById.put(1100, "r76");
		ia64RegistersById.put(1101, "r77");
		ia64RegistersById.put(1102, "r78");
		ia64RegistersById.put(1103, "r79");
		ia64RegistersById.put(1104, "r80");
		ia64RegistersById.put(1105, "r81");
		ia64RegistersById.put(1106, "r82");
		ia64RegistersById.put(1107, "r83");
		ia64RegistersById.put(1108, "r84");
		ia64RegistersById.put(1109, "r85");
		ia64RegistersById.put(1110, "r86");
		ia64RegistersById.put(1111, "r87");
		ia64RegistersById.put(1112, "r88");
		ia64RegistersById.put(1113, "r89");
		ia64RegistersById.put(1114, "r90");
		ia64RegistersById.put(1115, "r91");
		ia64RegistersById.put(1116, "r92");
		ia64RegistersById.put(1117, "r93");
		ia64RegistersById.put(1118, "r94");
		ia64RegistersById.put(1119, "r95");
		ia64RegistersById.put(1120, "r96");
		ia64RegistersById.put(1121, "r97");
		ia64RegistersById.put(1122, "r98");
		ia64RegistersById.put(1123, "r99");
		ia64RegistersById.put(1124, "r100");
		ia64RegistersById.put(1125, "r101");
		ia64RegistersById.put(1126, "r102");
		ia64RegistersById.put(1127, "r103");
		ia64RegistersById.put(1128, "r104");
		ia64RegistersById.put(1129, "r105");
		ia64RegistersById.put(1130, "r106");
		ia64RegistersById.put(1131, "r107");
		ia64RegistersById.put(1132, "r108");
		ia64RegistersById.put(1133, "r109");
		ia64RegistersById.put(1134, "r110");
		ia64RegistersById.put(1135, "r111");
		ia64RegistersById.put(1136, "r112");
		ia64RegistersById.put(1137, "r113");
		ia64RegistersById.put(1138, "r114");
		ia64RegistersById.put(1139, "r115");
		ia64RegistersById.put(1140, "r116");
		ia64RegistersById.put(1141, "r117");
		ia64RegistersById.put(1142, "r118");
		ia64RegistersById.put(1143, "r119");
		ia64RegistersById.put(1144, "r120");
		ia64RegistersById.put(1145, "r121");
		ia64RegistersById.put(1146, "r122");
		ia64RegistersById.put(1147, "r123");
		ia64RegistersById.put(1148, "r124");
		ia64RegistersById.put(1149, "r125");
		ia64RegistersById.put(1150, "r126");
		ia64RegistersById.put(1151, "r127");
		// Floating-Point Registers
		// Low Floating Point Registers
		ia64RegistersById.put(2048, "f0");
		ia64RegistersById.put(2049, "f1");
		ia64RegistersById.put(2050, "f2");
		ia64RegistersById.put(2051, "f3");
		ia64RegistersById.put(2052, "f4");
		ia64RegistersById.put(2053, "f5");
		ia64RegistersById.put(2054, "f6");
		ia64RegistersById.put(2055, "f7");
		ia64RegistersById.put(2056, "f8");
		ia64RegistersById.put(2057, "f9");
		ia64RegistersById.put(2058, "f10");
		ia64RegistersById.put(2059, "f11");
		ia64RegistersById.put(2060, "f12");
		ia64RegistersById.put(2061, "f13");
		ia64RegistersById.put(2062, "f14");
		ia64RegistersById.put(2063, "f15");
		ia64RegistersById.put(2064, "f16");
		ia64RegistersById.put(2065, "f17");
		ia64RegistersById.put(2066, "f18");
		ia64RegistersById.put(2067, "f19");
		ia64RegistersById.put(2068, "f20");
		ia64RegistersById.put(2069, "f21");
		ia64RegistersById.put(2070, "f22");
		ia64RegistersById.put(2071, "f23");
		ia64RegistersById.put(2072, "f24");
		ia64RegistersById.put(2073, "f25");
		ia64RegistersById.put(2074, "f26");
		ia64RegistersById.put(2075, "f27");
		ia64RegistersById.put(2076, "f28");
		ia64RegistersById.put(2077, "f29");
		ia64RegistersById.put(2078, "f30");
		ia64RegistersById.put(2079, "f31");
		ia64RegistersById.put(2080, "f32");
		ia64RegistersById.put(2081, "f33");
		ia64RegistersById.put(2082, "f34");
		ia64RegistersById.put(2083, "f35");
		ia64RegistersById.put(2084, "f36");
		ia64RegistersById.put(2085, "f37");
		ia64RegistersById.put(2086, "f38");
		ia64RegistersById.put(2087, "f39");
		ia64RegistersById.put(2088, "f40");
		ia64RegistersById.put(2089, "f41");
		ia64RegistersById.put(2090, "f42");
		ia64RegistersById.put(2091, "f43");
		ia64RegistersById.put(2092, "f44");
		ia64RegistersById.put(2093, "f45");
		ia64RegistersById.put(2094, "f46");
		ia64RegistersById.put(2095, "f47");
		ia64RegistersById.put(2096, "f48");
		ia64RegistersById.put(2097, "f49");
		ia64RegistersById.put(2098, "f50");
		ia64RegistersById.put(2099, "f51");
		ia64RegistersById.put(2100, "f52");
		ia64RegistersById.put(2101, "f53");
		ia64RegistersById.put(2102, "f54");
		ia64RegistersById.put(2103, "f55");
		ia64RegistersById.put(2104, "f56");
		ia64RegistersById.put(2105, "f57");
		ia64RegistersById.put(2106, "f58");
		ia64RegistersById.put(2107, "f59");
		ia64RegistersById.put(2108, "f60");
		ia64RegistersById.put(2109, "f61");
		ia64RegistersById.put(2110, "f62");
		ia64RegistersById.put(2111, "f63");
		ia64RegistersById.put(2112, "f64");
		ia64RegistersById.put(2113, "f65");
		ia64RegistersById.put(2114, "f66");
		ia64RegistersById.put(2115, "f67");
		ia64RegistersById.put(2116, "f68");
		ia64RegistersById.put(2117, "f69");
		ia64RegistersById.put(2118, "f70");
		ia64RegistersById.put(2119, "f71");
		ia64RegistersById.put(2120, "f72");
		ia64RegistersById.put(2121, "f73");
		ia64RegistersById.put(2122, "f74");
		ia64RegistersById.put(2123, "f75");
		ia64RegistersById.put(2124, "f76");
		ia64RegistersById.put(2125, "f77");
		ia64RegistersById.put(2126, "f78");
		ia64RegistersById.put(2127, "f79");
		ia64RegistersById.put(2128, "f80");
		ia64RegistersById.put(2129, "f81");
		ia64RegistersById.put(2130, "f82");
		ia64RegistersById.put(2131, "f83");
		ia64RegistersById.put(2132, "f84");
		ia64RegistersById.put(2133, "f85");
		ia64RegistersById.put(2134, "f86");
		ia64RegistersById.put(2135, "f87");
		ia64RegistersById.put(2136, "f88");
		ia64RegistersById.put(2137, "f89");
		ia64RegistersById.put(2138, "f90");
		ia64RegistersById.put(2139, "f91");
		ia64RegistersById.put(2140, "f92");
		ia64RegistersById.put(2141, "f93");
		ia64RegistersById.put(2142, "f94");
		ia64RegistersById.put(2143, "f95");
		ia64RegistersById.put(2144, "f96");
		ia64RegistersById.put(2145, "f97");
		ia64RegistersById.put(2146, "f98");
		ia64RegistersById.put(2147, "f99");
		ia64RegistersById.put(2148, "f100");
		ia64RegistersById.put(2149, "f101");
		ia64RegistersById.put(2150, "f102");
		ia64RegistersById.put(2151, "f103");
		ia64RegistersById.put(2152, "f104");
		ia64RegistersById.put(2153, "f105");
		ia64RegistersById.put(2154, "f106");
		ia64RegistersById.put(2155, "f107");
		ia64RegistersById.put(2156, "f108");
		ia64RegistersById.put(2157, "f109");
		ia64RegistersById.put(2158, "f110");
		ia64RegistersById.put(2159, "f111");
		ia64RegistersById.put(2160, "f112");
		ia64RegistersById.put(2161, "f113");
		ia64RegistersById.put(2162, "f114");
		ia64RegistersById.put(2163, "f115");
		ia64RegistersById.put(2164, "f116");
		ia64RegistersById.put(2165, "f117");
		ia64RegistersById.put(2166, "f118");
		ia64RegistersById.put(2167, "f119");
		ia64RegistersById.put(2168, "f120");
		ia64RegistersById.put(2169, "f121");
		ia64RegistersById.put(2170, "f122");
		ia64RegistersById.put(2171, "f123");
		ia64RegistersById.put(2172, "f124");
		ia64RegistersById.put(2173, "f125");
		ia64RegistersById.put(2174, "f126");
		ia64RegistersById.put(2175, "f127");
		// Application Registers
		ia64RegistersById.put(3072, "apkr0");
		ia64RegistersById.put(3073, "apkr1");
		ia64RegistersById.put(3074, "apkr2");
		ia64RegistersById.put(3075, "apkr3");
		ia64RegistersById.put(3076, "apkr4");
		ia64RegistersById.put(3077, "apkr5");
		ia64RegistersById.put(3078, "apkr6");
		ia64RegistersById.put(3079, "apkr7");
		ia64RegistersById.put(3080, "ar8");
		ia64RegistersById.put(3081, "ar9");
		ia64RegistersById.put(3082, "ar10");
		ia64RegistersById.put(3083, "ar11");
		ia64RegistersById.put(3084, "ar12");
		ia64RegistersById.put(3085, "ar13");
		ia64RegistersById.put(3086, "ar14");
		ia64RegistersById.put(3087, "ar15");
		ia64RegistersById.put(3088, "rsbsc");
		ia64RegistersById.put(3089, "rsbsp");
		ia64RegistersById.put(3090, "rsbspstore");
		ia64RegistersById.put(3091, "rsrnat");
		ia64RegistersById.put(3092, "r20");
		ia64RegistersById.put(3093, "stfcr");
		ia64RegistersById.put(3094, "r22");
		ia64RegistersById.put(3095, "r23");
		ia64RegistersById.put(3096, "eflag");
		ia64RegistersById.put(3097, "csd");
		ia64RegistersById.put(3098, "ssd");
		ia64RegistersById.put(3099, "cflg");
		ia64RegistersById.put(3100, "stfsr");
		ia64RegistersById.put(3101, "stfir");
		ia64RegistersById.put(3102, "stfdr");
		ia64RegistersById.put(3103, "ar31");
		ia64RegistersById.put(3104, "apccv");
		ia64RegistersById.put(3105, "ar33");
		ia64RegistersById.put(3106, "ar34");
		ia64RegistersById.put(3107, "ar35");
		ia64RegistersById.put(3108, "apunat");
		ia64RegistersById.put(3109, "ar37");
		ia64RegistersById.put(3110, "ar38");
		ia64RegistersById.put(3111, "ar39");
		ia64RegistersById.put(3112, "stfpsr");
		ia64RegistersById.put(3113, "ar41");
		ia64RegistersById.put(3114, "ar42");
		ia64RegistersById.put(3115, "ar43");
		ia64RegistersById.put(3116, "apitc");
		ia64RegistersById.put(3117, "ar45");
		ia64RegistersById.put(3118, "ar46");
		ia64RegistersById.put(3119, "ar47");
		ia64RegistersById.put(3120, "ar48");
		ia64RegistersById.put(3121, "ar49");
		ia64RegistersById.put(3122, "ar50");
		ia64RegistersById.put(3123, "ar51");
		ia64RegistersById.put(3124, "ar52");
		ia64RegistersById.put(3125, "ar53");
		ia64RegistersById.put(3126, "ar54");
		ia64RegistersById.put(3127, "ar55");
		ia64RegistersById.put(3128, "ar56");
		ia64RegistersById.put(3129, "ar57");
		ia64RegistersById.put(3130, "ar58");
		ia64RegistersById.put(3131, "ar59");
		ia64RegistersById.put(3132, "ar60");
		ia64RegistersById.put(3133, "ar61");
		ia64RegistersById.put(3134, "ar62");
		ia64RegistersById.put(3135, "ar63");
		ia64RegistersById.put(3136, "rspfs");
		ia64RegistersById.put(3137, "aplc");
		ia64RegistersById.put(3138, "apec");
		ia64RegistersById.put(3139, "ar67");
		ia64RegistersById.put(3140, "ar68");
		ia64RegistersById.put(3141, "ar69");
		ia64RegistersById.put(3142, "ar70");
		ia64RegistersById.put(3143, "ar71");
		ia64RegistersById.put(3144, "ar72");
		ia64RegistersById.put(3145, "ar73");
		ia64RegistersById.put(3146, "ar74");
		ia64RegistersById.put(3147, "ar75");
		ia64RegistersById.put(3148, "ar76");
		ia64RegistersById.put(3149, "ar77");
		ia64RegistersById.put(3150, "ar78");
		ia64RegistersById.put(3151, "ar79");
		ia64RegistersById.put(3152, "ar80");
		ia64RegistersById.put(3153, "ar81");
		ia64RegistersById.put(3154, "ar82");
		ia64RegistersById.put(3155, "ar83");
		ia64RegistersById.put(3156, "ar84");
		ia64RegistersById.put(3157, "ar85");
		ia64RegistersById.put(3158, "ar86");
		ia64RegistersById.put(3159, "ar87");
		ia64RegistersById.put(3160, "ar88");
		ia64RegistersById.put(3161, "ar89");
		ia64RegistersById.put(3162, "ar90");
		ia64RegistersById.put(3163, "ar91");
		ia64RegistersById.put(3164, "ar92");
		ia64RegistersById.put(3165, "ar93");
		ia64RegistersById.put(3166, "ar94");
		ia64RegistersById.put(3167, "ar95");
		ia64RegistersById.put(3168, "ar96");
		ia64RegistersById.put(3169, "ar97");
		ia64RegistersById.put(3170, "ar98");
		ia64RegistersById.put(3171, "ar99");
		ia64RegistersById.put(3172, "ar100");
		ia64RegistersById.put(3173, "ar101");
		ia64RegistersById.put(3174, "ar102");
		ia64RegistersById.put(3175, "ar103");
		ia64RegistersById.put(3176, "ar104");
		ia64RegistersById.put(3177, "ar105");
		ia64RegistersById.put(3178, "ar106");
		ia64RegistersById.put(3179, "ar107");
		ia64RegistersById.put(3180, "ar108");
		ia64RegistersById.put(3181, "ar109");
		ia64RegistersById.put(3182, "ar110");
		ia64RegistersById.put(3183, "ar111");
		ia64RegistersById.put(3184, "ar112");
		ia64RegistersById.put(3185, "ar113");
		ia64RegistersById.put(3186, "ar114");
		ia64RegistersById.put(3187, "ar115");
		ia64RegistersById.put(3188, "ar116");
		ia64RegistersById.put(3189, "ar117");
		ia64RegistersById.put(3190, "ar118");
		ia64RegistersById.put(3191, "ar119");
		ia64RegistersById.put(3192, "ar120");
		ia64RegistersById.put(3193, "ar121");
		ia64RegistersById.put(3194, "ar122");
		ia64RegistersById.put(3195, "ar123");
		ia64RegistersById.put(3196, "ar124");
		ia64RegistersById.put(3197, "ar125");
		ia64RegistersById.put(3198, "ar126");
		ia64RegistersById.put(3199, "ar127");

		ia64RegistersById.put(3328, "cpuid0");
		ia64RegistersById.put(3329, "cpuid1");
		ia64RegistersById.put(3330, "cpuid2");
		ia64RegistersById.put(3331, "cpuid3");
		ia64RegistersById.put(3332, "cpuid4");

		ia64RegistersById.put(4096, "apdcr");
		ia64RegistersById.put(4097, "apitm");
		ia64RegistersById.put(4098, "apiva");
		ia64RegistersById.put(4099, "cr3");
		ia64RegistersById.put(4100, "cr4");
		ia64RegistersById.put(4101, "cr5");
		ia64RegistersById.put(4102, "cr6");
		ia64RegistersById.put(4103, "cr7");
		ia64RegistersById.put(4104, "appta");
		ia64RegistersById.put(4105, "apgpta");
		ia64RegistersById.put(4106, "cr10");
		ia64RegistersById.put(4107, "cr11");
		ia64RegistersById.put(4108, "cr12");
		ia64RegistersById.put(4109, "cr13");
		ia64RegistersById.put(4110, "cr14");
		ia64RegistersById.put(4111, "cr15");
		ia64RegistersById.put(4112, "stipsr");
		ia64RegistersById.put(4113, "stisr");
		ia64RegistersById.put(4114, "cr18");
		ia64RegistersById.put(4115, "stiip");
		ia64RegistersById.put(4116, "stifa");
		ia64RegistersById.put(4117, "stitir");
		ia64RegistersById.put(4118, "stiipa");
		ia64RegistersById.put(4119, "stifs");
		ia64RegistersById.put(4120, "stiim");
		ia64RegistersById.put(4121, "stiha");
		ia64RegistersById.put(4122, "cr26");
		ia64RegistersById.put(4123, "cr27");
		ia64RegistersById.put(4124, "cr28");
		ia64RegistersById.put(4125, "cr29");
		ia64RegistersById.put(4126, "cr30");
		ia64RegistersById.put(4127, "cr31");
		ia64RegistersById.put(4128, "cr32");
		ia64RegistersById.put(4129, "cr33");
		ia64RegistersById.put(4130, "cr34");
		ia64RegistersById.put(4131, "cr35");
		ia64RegistersById.put(4132, "cr36");
		ia64RegistersById.put(4133, "cr37");
		ia64RegistersById.put(4134, "cr38");
		ia64RegistersById.put(4135, "cr39");
		ia64RegistersById.put(4136, "cr40");
		ia64RegistersById.put(4137, "cr41");
		ia64RegistersById.put(4138, "cr42");
		ia64RegistersById.put(4139, "cr43");
		ia64RegistersById.put(4140, "cr44");
		ia64RegistersById.put(4141, "cr45");
		ia64RegistersById.put(4142, "cr46");
		ia64RegistersById.put(4143, "cr47");
		ia64RegistersById.put(4144, "cr48");
		ia64RegistersById.put(4145, "cr49");
		ia64RegistersById.put(4146, "cr50");
		ia64RegistersById.put(4147, "cr51");
		ia64RegistersById.put(4148, "cr52");
		ia64RegistersById.put(4149, "cr53");
		ia64RegistersById.put(4150, "cr54");
		ia64RegistersById.put(4151, "cr55");
		ia64RegistersById.put(4152, "cr56");
		ia64RegistersById.put(4153, "cr57");
		ia64RegistersById.put(4154, "cr58");
		ia64RegistersById.put(4155, "cr59");
		ia64RegistersById.put(4156, "cr60");
		ia64RegistersById.put(4157, "cr61");
		ia64RegistersById.put(4158, "cr62");
		ia64RegistersById.put(4159, "cr63");
		ia64RegistersById.put(4160, "salid");
		ia64RegistersById.put(4161, "saivr");
		ia64RegistersById.put(4162, "satpr");
		ia64RegistersById.put(4163, "saeoi");
		ia64RegistersById.put(4164, "sairr0");
		ia64RegistersById.put(4165, "sairr1");
		ia64RegistersById.put(4166, "sairr2");
		ia64RegistersById.put(4167, "sairr3");
		ia64RegistersById.put(4168, "saitv");
		ia64RegistersById.put(4169, "sapmv");
		ia64RegistersById.put(4170, "sacmcv");
		ia64RegistersById.put(4171, "cr75");
		ia64RegistersById.put(4172, "cr76");
		ia64RegistersById.put(4173, "cr77");
		ia64RegistersById.put(4174, "cr78");
		ia64RegistersById.put(4175, "cr79");
		ia64RegistersById.put(4176, "salrr0");
		ia64RegistersById.put(4177, "salrr1");
		ia64RegistersById.put(4178, "cr82");
		ia64RegistersById.put(4179, "cr83");
		ia64RegistersById.put(4180, "cr84");
		ia64RegistersById.put(4181, "cr85");
		ia64RegistersById.put(4182, "cr86");
		ia64RegistersById.put(4183, "cr87");
		ia64RegistersById.put(4184, "cr88");
		ia64RegistersById.put(4185, "cr89");
		ia64RegistersById.put(4186, "cr90");
		ia64RegistersById.put(4187, "cr91");
		ia64RegistersById.put(4188, "cr92");
		ia64RegistersById.put(4189, "cr93");
		ia64RegistersById.put(4190, "cr94");
		ia64RegistersById.put(4191, "cr95");
		ia64RegistersById.put(4192, "cr96");
		ia64RegistersById.put(4193, "cr97");
		ia64RegistersById.put(4194, "cr98");
		ia64RegistersById.put(4195, "cr99");
		ia64RegistersById.put(4196, "cr100");
		ia64RegistersById.put(4197, "cr101");
		ia64RegistersById.put(4198, "cr102");
		ia64RegistersById.put(4199, "cr103");
		ia64RegistersById.put(4200, "cr104");
		ia64RegistersById.put(4201, "cr105");
		ia64RegistersById.put(4202, "cr106");
		ia64RegistersById.put(4203, "cr107");
		ia64RegistersById.put(4204, "cr108");
		ia64RegistersById.put(4205, "cr109");
		ia64RegistersById.put(4206, "cr110");
		ia64RegistersById.put(4207, "cr111");
		ia64RegistersById.put(4208, "cr112");
		ia64RegistersById.put(4209, "cr113");
		ia64RegistersById.put(4210, "cr114");
		ia64RegistersById.put(4211, "cr115");
		ia64RegistersById.put(4212, "cr116");
		ia64RegistersById.put(4213, "cr117");
		ia64RegistersById.put(4214, "cr118");
		ia64RegistersById.put(4215, "cr119");
		ia64RegistersById.put(4216, "cr120");
		ia64RegistersById.put(4217, "cr121");
		ia64RegistersById.put(4218, "cr122");
		ia64RegistersById.put(4219, "cr123");
		ia64RegistersById.put(4220, "cr124");
		ia64RegistersById.put(4221, "cr125");
		ia64RegistersById.put(4222, "cr126");
		ia64RegistersById.put(4223, "cr127");

		ia64RegistersById.put(5120, "pkr0");
		ia64RegistersById.put(5121, "pkr1");
		ia64RegistersById.put(5122, "pkr2");
		ia64RegistersById.put(5123, "pkr3");
		ia64RegistersById.put(5124, "pkr4");
		ia64RegistersById.put(5125, "pkr5");
		ia64RegistersById.put(5126, "pkr6");
		ia64RegistersById.put(5127, "pkr7");
		ia64RegistersById.put(5128, "pkr8");
		ia64RegistersById.put(5129, "pkr9");
		ia64RegistersById.put(5130, "pkr10");
		ia64RegistersById.put(5131, "pkr11");
		ia64RegistersById.put(5132, "pkr12");
		ia64RegistersById.put(5133, "pkr13");
		ia64RegistersById.put(5134, "pkr14");
		ia64RegistersById.put(5135, "pkr15");

		ia64RegistersById.put(6144, "rr0");
		ia64RegistersById.put(6145, "rr1");
		ia64RegistersById.put(6146, "rr2");
		ia64RegistersById.put(6147, "rr3");
		ia64RegistersById.put(6148, "rr4");
		ia64RegistersById.put(6149, "rr5");
		ia64RegistersById.put(6150, "rr6");
		ia64RegistersById.put(6151, "rr7");

		ia64RegistersById.put(7168, "pfd0");
		ia64RegistersById.put(7169, "pfd1");
		ia64RegistersById.put(7170, "pfd2");
		ia64RegistersById.put(7171, "pfd3");
		ia64RegistersById.put(7172, "pfd4");
		ia64RegistersById.put(7173, "pfd5");
		ia64RegistersById.put(7174, "pfd6");
		ia64RegistersById.put(7175, "pfd7");
		ia64RegistersById.put(7176, "pfd8");
		ia64RegistersById.put(7177, "pfd9");
		ia64RegistersById.put(7178, "pfd10");
		ia64RegistersById.put(7179, "pfd11");
		ia64RegistersById.put(7180, "pfd12");
		ia64RegistersById.put(7181, "pfd13");
		ia64RegistersById.put(7182, "pfd14");
		ia64RegistersById.put(7183, "pfd15");
		ia64RegistersById.put(7184, "pfd16");
		ia64RegistersById.put(7185, "pfd17");

		ia64RegistersById.put(7424, "pfc0");
		ia64RegistersById.put(7425, "pfc1");
		ia64RegistersById.put(7426, "pfc2");
		ia64RegistersById.put(7427, "pfc3");
		ia64RegistersById.put(7428, "pfc4");
		ia64RegistersById.put(7429, "pfc5");
		ia64RegistersById.put(7430, "pfc6");
		ia64RegistersById.put(7431, "pfc7");
		ia64RegistersById.put(7432, "pfc8");
		ia64RegistersById.put(7433, "pfc9");
		ia64RegistersById.put(7434, "pfc10");
		ia64RegistersById.put(7435, "pfc11");
		ia64RegistersById.put(7436, "pfc12");
		ia64RegistersById.put(7437, "pfc13");
		ia64RegistersById.put(7438, "pfc14");
		ia64RegistersById.put(7439, "pfc15");

		ia64RegistersById.put(8192, "tri0");
		ia64RegistersById.put(8193, "tri1");
		ia64RegistersById.put(8194, "tri2");
		ia64RegistersById.put(8195, "tri3");
		ia64RegistersById.put(8196, "tri4");
		ia64RegistersById.put(8197, "tri5");
		ia64RegistersById.put(8198, "tri6");
		ia64RegistersById.put(8199, "tri7");

		ia64RegistersById.put(8320, "trd0");
		ia64RegistersById.put(8321, "trd1");
		ia64RegistersById.put(8322, "trd2");
		ia64RegistersById.put(8323, "trd3");
		ia64RegistersById.put(8324, "trd4");
		ia64RegistersById.put(8325, "trd5");
		ia64RegistersById.put(8326, "trd6");
		ia64RegistersById.put(8327, "trd7");

		ia64RegistersById.put(8448, "dbi0");
		ia64RegistersById.put(8449, "dbi1");
		ia64RegistersById.put(8450, "dbi2");
		ia64RegistersById.put(8451, "dbi3");
		ia64RegistersById.put(8452, "dbi4");
		ia64RegistersById.put(8453, "dbi5");
		ia64RegistersById.put(8454, "dbi6");
		ia64RegistersById.put(8455, "dbi7");

		ia64RegistersById.put(8576, "dbd0");
		ia64RegistersById.put(8577, "dbd1");
		ia64RegistersById.put(8578, "dbd2");
		ia64RegistersById.put(8579, "dbd3");
		ia64RegistersById.put(8580, "dbd4");
		ia64RegistersById.put(8581, "dbd5");
		ia64RegistersById.put(8582, "dbd6");
		ia64RegistersById.put(8583, "dbd7");
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
		Objects.requireNonNull(pdb, "pdb cannot be null");
		this.pdb = pdb;
		this.register = register;
	}

	/**
	 * Tells if there is no register.
	 * @return True if there is no register.
	 */
	public boolean isRegNone() {
		return (register == 0);
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(getRegisterName(pdb.getTargetProcessor(), register));
	}

	private String getRegisterName(Processor processorIn, int registerIn) {

		// We do not have registers for many of the processors... set the default.
		String registerName = badRegister;
		switch (processorIn) {

			case UNKNOWN:
			case UNK1AB:
			case UNK304:
				break;

			case I8080:
			case I8086:
			case I80286:
			case I80386:
			case I80486:
			case PENTIUM:
			case PENTIUMPRO_PENTIUMII:
			case PENTIUMIII:
				if (registerIn < regX86.length) {
					registerName = regX86[registerIn];
				}
				break;

			case MIPS_MIPSR4000:
			case MIPS16:
			case MIPS32:
			case MIPS64:
			case MIPSI:
			case MIPSII:
			case MIPSIII:
			case MIPSIV:
			case MIPSV:
				if (registerIn < regMips.length) {
					registerName = regMips[registerIn];
				}
				break;

			case M68000:
			case M68010:
			case M68020:
			case M68030:
			case M68040:
				if (registerIn < reg68k.length) {
					registerName = reg68k[registerIn];
				}
				break;

			case ALPHA_21064:
			case ALPHA_21164:
			case ALPHA_21164A:
			case ALPHA_21264:
			case ALPHA_21364:
				if (registerIn < regAlpha.length) {
					registerName = regAlpha[registerIn];
				}
				break;

			case PPC601:
			case PPC603:
			case PPC604:
			case PPC620:
			case PPCFP:
			case PPCBE:
				if (registerIn < regPpc.length) {
					registerName = regPpc[registerIn];
				}
				break;

			case SH3:
			case SH3E:
			case SH3DSP:
			case SH4:
			case SHMEDIA:
				if (registerIn < regSh.length) {
					registerName = regSh[registerIn];
				}
				break;

			case ARM3:
			case ARM4:
			case ARM4T:
			case ARM5:
			case ARM5T:
			case ARM6:
			case ARM_XMAC:
			case ARM_WMMX:
			case ARM7:
				break;

			case OMNI:
				break;

			case IA64_IA64_1:
			case IA64_2:
				if (registerIn < ia64RegistersById.size()) {
					registerName = ia64RegistersById.get(registerIn);
				}
				break;

			case CEE:
				break;

			case AM33:
				break;

			case M32R:
				break;

			case TRICORE:
				break;

			case X64_AMD64:
				if (registerIn < regAmd64.length) {
					registerName = regAmd64[registerIn];
				}
				break;

			case EBC:
				break;

			case THUMB:
			case ARMNT:
			case ARM64:
				break;

			case D3D11_SHADER:
				break;

		}
		return registerName;

	}

}
