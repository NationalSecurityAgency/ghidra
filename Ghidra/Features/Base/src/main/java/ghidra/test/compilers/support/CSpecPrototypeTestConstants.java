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
package ghidra.test.compilers.support;

/**
 * Constants that are used by the CSpecPrototypeUtil to decode cspec test binary source code function
 * names.
 */
public class CSpecPrototypeTestConstants {
	public static final String FIELD_NAME_PREFIX = "fld";

	public static final String STRUCT_CHAR_SINGLETON_NAME = "sc";
	public static final String STRUCT_SHORT_SINGLETON_NAME = "ss";
	public static final String STRUCT_INT_SINGLETON_NAME = "si";
	public static final String STRUCT_LONG_SINGLETON_NAME = "sl";
	public static final String STRUCT_LONG_LONG_SINGLETON_NAME = "sll";
	public static final String STRUCT_FLOAT_SINGLETON_NAME = "sf";
	public static final String STRUCT_DOUBLE_SINGLETON_NAME = "sd";

	public static final String STRUCT_CHAR_PAIR_NAME = "prc";
	public static final String STRUCT_SHORT_PAIR_NAME = "prs";
	public static final String STRUCT_INT_PAIR_NAME = "pri";
	public static final String STRUCT_LONG_PAIR_NAME = "prl";
	public static final String STRUCT_LONG_LONG_PAIR_NAME = "prll";
	public static final String STRUCT_FLOAT_PAIR_NAME = "prf";
	public static final String STRUCT_DOUBLE_PAIR_NAME = "prd";

	public static final String STRUCT_CHAR_TRIP_NAME = "trc";
	public static final String STRUCT_SHORT_TRIP_NAME = "trs";
	public static final String STRUCT_INT_TRIP_NAME = "tri";
	public static final String STRUCT_LONG_TRIP_NAME = "trl";
	public static final String STRUCT_LONG_LONG_TRIP_NAME = "trll";
	public static final String STRUCT_FLOAT_TRIP_NAME = "trf";
	public static final String STRUCT_DOUBLE_TRIP_NAME = "trd";

	public static final String STRUCT_CHAR_QUAD_NAME = "qc";
	public static final String STRUCT_SHORT_QUAD_NAME = "qs";
	public static final String STRUCT_INT_QUAD_NAME = "qi";
	public static final String STRUCT_LONG_QUAD_NAME = "ql";
	public static final String STRUCT_LONG_LONG_QUAD_NAME = "qll";
	public static final String STRUCT_FLOAT_QUAD_NAME = "qf";
	public static final String STRUCT_DOUBLE_QUAD_NAME = "qd";

	public static final String STRUCT_INT_LONG_INT = "stili";
	public static final String STRUCT_FLOAT_INT_FLOAT = "stfif";
	public static final String STRUCT_LONG_DOUBLE_LONG = "stldl";
	public static final String STRUCT_FLOAT_DOUBLE_FLOAT = "stfdf";

	public static final String UNION_CHAR = "unsc";
	public static final String UNION_SHORT = "unss";
	public static final String UNION_INT = "unsi";
	public static final String UNION_LONG = "unsl";
	public static final String UNION_FLOAT = "unsf";
	public static final String UNION_DOUBLE = "unsd";
	public static final String UNION_LONG_LONG = "unsll";

	public static final String UNION_INT_LONG = "unpil";
	public static final String UNION_FLOAT_DOUBLE = "unpfd";
	public static final String UNION_INT_FLOAT = "unpif";
	public static final String UNION_LONG_DOUBLE = "unpld";
	public static final String UNION_INT_DOUBLE = "unpid";
	public static final String UNION_LONG_FLOAT = "unplf";

	public static final String UNION_STRUCT_INT = "unsti";
	public static final String UNION_STRUCT_FLOAT = "unstf";
	public static final String UNION_MIXED_STRUCT_INTEGRAL = "unmsti";
	public static final String UNION_MIXED_STRUCT_FLOATING = "unmstf";
	public static final String UNION_MIXED_STRUCT_ALL_SMALL = "unmstas";
	public static final String UNION_MIXED_STRUCT_ALL_LARGE = "unmstal";

	public static final String UNION_STRUCT_TRIP_CHAR = "unsttc";
	public static final String UNION_STRUCT_TRIP_SHORT = "unstts";

	public static final String PARAMS_PRIMITIVE_IDENTICAL = "paramsPrimitiveIdentical";
	public static final String PARAMS_PRIMITIVE_ALTERNATE = "paramsPrimitiveAlternate";
	public static final String PARAMS_MISC = "paramsMisc";
	public static final String PARAMS_VARIADIC = "paramsVariadic";
	public static final String PARAMS_SINGLETON_STRUCT = "paramsSingletonStruct";
	public static final String PARAMS_PAIR_STRUCT = "paramsPairStruct";
	public static final String PARAMS_TRIP_STRUCT = "paramsTripStruct";
	public static final String PARAMS_QUAD_STRUCT = "paramsQuadStruct";
	public static final String PARAMS_MIXED_STRUCT = "paramsMixedStruct";
	public static final String PARAMS_UNION = "paramsUnion";
	public static final String PRODUCER = "producer";
	public static final String EXTERNAL = "external";

	public static final String RETURN_PRIMITIVE = "returnPrimitive";
	public static final String RETURN_SINGLETON = "returnSingleton";
	public static final String RETURN_PAIR = "returnPair";
	public static final String RETURN_TRIPLE = "returnTriple";
	public static final String RETURN_QUAD = "returnQuad";
	public static final String RETURN_MIXED = "returnMixed";
	public static final String RETURN_UNION = "returnUnion";
}
