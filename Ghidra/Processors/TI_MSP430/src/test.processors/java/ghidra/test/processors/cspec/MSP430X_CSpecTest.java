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

public class MSP430X_CSpecTest extends CSpecPrototypeTest {
	private static final String LANGUAGE_ID = "TI_MSP430X:LE:32:default";
	private static final String COMPILER_SPEC_ID = "default";

	private static final String CALLING_CONVENTION = "__stdcall";

	private static final String[] EXPECTED_PROTOTYPE_ERRORS = {
		"paramsPrimitiveIdentical_0",
		"paramsPrimitiveIdentical_3",
		"paramsPrimitiveIdentical_4",
		"paramsPrimitiveAlternate_5",
		"paramsPrimitiveAlternate_6",
		"paramsPrimitiveIdentical_7",
		"paramsPrimitiveAlternate_9",
		"paramsPrimitiveIdentical_10",
		"paramsPrimitiveAlternate_11",
		"paramsPrimitiveAlternate_12",
		"paramsPrimitiveIdentical_13",
		"paramsPrimitiveAlternate_14",
		"paramsPrimitiveAlternate_15",
		"paramsPrimitiveAlternate_16",
		"paramsPrimitiveAlternate_17",
		"paramsSingletonStruct_18",
		"paramsSingletonStruct_19",
		"paramsSingletonStruct_20",
		"paramsSingletonStruct_21",
		"paramsSingletonStruct_22",
		"paramsSingletonStruct_23",
		"paramsSingletonStruct_24",
		"paramsPairStruct_25",
		"paramsPairStruct_26",
		"paramsPairStruct_27",
		"paramsPairStruct_28",
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
		"paramsQuadStruct_40",
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
		"paramsVariadic_L_d_L_d_L_d_L_d_L_d_52",
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
		"paramsUnion_71",
		"paramsUnion_72",
		"paramsUnion_73",
		"paramsUnion_74",
		"paramsUnion_75",
		"paramsUnion_76",
		"returnSingleton_78",
		"returnPair_79",
		"returnTriple_80",
		"returnQuad_81",
		"returnUnion_82",
		"returnUnion_83",
		"returnSingleton_85",
		"returnPair_86",
		"returnUnion_89",
		"returnSingleton_92",
		"returnPair_93",
		"returnUnion_96",
		"returnPrimitive_97",
		"returnSingleton_98",
		"returnUnion_102",
		"returnPrimitive_106",
		"returnSingleton_107",
		"returnUnion_112",
		"returnPrimitive_115",
		"returnPrimitive_125",
	};

	public MSP430X_CSpecTest() throws Exception {
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
