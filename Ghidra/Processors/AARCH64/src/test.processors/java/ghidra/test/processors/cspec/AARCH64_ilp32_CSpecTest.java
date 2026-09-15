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
package ghidra.test.processors.cspec;

import ghidra.test.compilers.support.CSpecPrototypeTest;

public class AARCH64_ilp32_CSpecTest extends CSpecPrototypeTest {
	private static final String LANGUAGE_ID = "AARCH64:BE:32:ilp32";
	private static final String COMPILER_SPEC_ID = "default";

	private static final String CALLING_CONVENTION = "__cdecl";

	private static final String[] EXPECTED_PROTOTYPE_ERRORS = {
		"paramsPrimitiveIdentical_0",
		"paramsPrimitiveIdentical_1",
		"paramsPrimitiveIdentical_2",
		"paramsPrimitiveIdentical_3",
		"paramsPrimitiveIdentical_4",
		"paramsPrimitiveAlternate_5",
		"paramsPrimitiveAlternate_6",
		"paramsPrimitiveAlternate_8",
		"paramsPrimitiveAlternate_9",
		"paramsPrimitiveIdentical_10",
		"paramsPrimitiveIdentical_13",
		"paramsPrimitiveAlternate_16",
		"paramsPrimitiveAlternate_17",
		"paramsSingletonStruct_18",
		"paramsSingletonStruct_19",
		"paramsSingletonStruct_20",
		"paramsSingletonStruct_21",
		"paramsSingletonStruct_22",
		"paramsSingletonStruct_23",
		"paramsPairStruct_25",
		"paramsPairStruct_26",
		"paramsPairStruct_29",
		"paramsPairStruct_30",
		"paramsPairStruct_31",
		"paramsTripStruct_32",
		"paramsTripStruct_33",
		"paramsTripStruct_34",
		"paramsTripStruct_35",
		"paramsTripStruct_36",
		"paramsTripStruct_37",
		"paramsTripStruct_38",
		"paramsQuadStruct_39",
		"paramsQuadStruct_41",
		"paramsQuadStruct_42",
		"paramsQuadStruct_43",
		"paramsQuadStruct_44",
		"paramsQuadStruct_45",
		"paramsMixedStruct_46",
		"paramsMixedStruct_47",
		"paramsMixedStruct_48",
		"paramsMixedStruct_49",
		"paramsVariadic_I_I_C_C_S_S_I_I_L_L_50",
		"paramsVariadic_I_I_I_I_I_I_I_I_I_I_51",
		"paramsMisc_53",
		"paramsMisc_54",
		"paramsMisc_55",
		"paramsUnion_56",
		"paramsUnion_57",
		"paramsUnion_58",
		"paramsUnion_59",
		"paramsUnion_60",
		"paramsUnion_61",
		"paramsUnion_62",
		"paramsUnion_63",
		"paramsUnion_64",
		"paramsUnion_65",
		"paramsUnion_66",
		"paramsUnion_67",
		"paramsUnion_68",
		"paramsUnion_69",
		"paramsUnion_70",
		"paramsUnion_73",
		"paramsUnion_75",
		"returnSingleton_78",
		"returnPair_79",
		"returnTriple_80",
		"returnQuad_81",
		"returnUnion_82",
		"returnUnion_83",
		"returnSingleton_85",
		"returnPair_86",
		"returnTriple_87",
		"returnUnion_89",
		"returnUnion_90",
		"returnSingleton_92",
		"returnTriple_94",
		"returnQuad_95",
		"returnUnion_96",
		"returnSingleton_98",
		"returnTriple_100",
		"returnQuad_101",
		"returnUnion_102",
		"returnMixed_103",
		"returnUnion_104",
		"returnUnion_105",
		"returnSingleton_107",
		"returnPair_108",
		"returnTriple_109",
		"returnQuad_110",
		"returnMixed_111",
		"returnUnion_113",
		"returnUnion_114",
		"returnSingleton_116",
		"returnPair_117",
		"returnTriple_118",
		"returnQuad_119",
		"returnMixed_120",
		"returnUnion_122",
		"returnMixed_123",
		"returnUnion_124",
		"returnPair_127",
		"returnTriple_128",
		"returnQuad_129"
	};

	public AARCH64_ilp32_CSpecTest() throws Exception {
		super(EXPECTED_PROTOTYPE_ERRORS);
	}

	@Override
	public String getLanguageID() {
		return LANGUAGE_ID;
	}

	@Override
	public String getCompilerSpecID() {
		return COMPILER_SPEC_ID;
	}

	@Override
	public String getCallingConvention() {
		return CALLING_CONVENTION;
	}

}
