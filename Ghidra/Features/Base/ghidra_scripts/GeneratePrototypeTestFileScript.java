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
// This script prompts the user to select a processor, compiler, and prototype and
// then generates a source file used to test that prototype (test using the script
// TestPrototypeScript.java). The script provides a dialog to the user to determine
// a number of properties of the source file, such as whether to include certain 
// data types.  A "Pre-specifier" is a string placed before a function definition
// to force the compiler to use a certain calling convention. A "Post-specifier" is
// defined similarly.
//
// Compile the resulting file with gcc as follows:
// gcc file.c -o file -O1 -c -fno-inline -fno-leading-underscore
// (note that the object file has the same name as the source file but no suffix).
// If compiling with a different compiler use equivalent options.

import java.io.*;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.compilers.support.CSpecPrototypeTestConstants;

public class GeneratePrototypeTestFileScript extends GhidraScript {

	float floatIntPart = 2.0f;
	float floatFracPart = 0.5f;
	double doubleIntPart = 2.0;
	double doubleFracPart = 0.5;

	private static final String INCLUDE_LONG_LONG = "Include long long";
	private static final String NUM_PARAMS = "Number of Parameters";
	private static final String INCLUDE_FLOAT = "Include float";
	private static final String INCLUDE_DOUBLE = "Include double";
	private static final String CALLING_CONVENTION = "Calling Convention";
	private static final String SPECIFIER = "Specifier";
	private static final String OUTPUT_DIRECTORY = "Output Directory";
	private static final String UNSIGNED_TYPES = "Unsigned Integral Types";
	private static final String DECORATE_VARARGS = "Decorate Variadic Functions";

	// not final since user can choose to use signed or unsigned types
	private static String CHAR_TYPE = "uchar";
	private static String SHORT_TYPE = "ushort";
	private static String INT_TYPE = "uint";
	private static String LONG_TYPE = "ulong";
	private static String LONG_LONG_TYPE = "ulonglong";

	private long variableVal = 0x01;
	private long multiplier = 0x0101010101010101l;
	private int funcCounter = 0;
	private String ccGhidraName;
	private String preSpecifier = "";
	private boolean includeFloat;
	private boolean includeDouble;
	private boolean includeLongLong;
	private boolean unsignedTypes = true;
	private boolean decorateVarargs = true;

	private int charSize;
	private int shortSize;
	private int intSize;
	private int longSize;
	private int longLongSize;

	private int numParams;
	private static final int DEFAULT_NUM_PARAMS = 12;

	private File outputDirectory;

	@Override
	protected void run() throws Exception {

		Set<Processor> processors = new HashSet<>();
		LanguageService langService = DefaultLanguageService.getLanguageService();
		langService.getLanguageDescriptions(false).forEach(l -> processors.add(l.getProcessor()));
		List<String> processorNames = new ArrayList<>();
		processors.forEach(p -> processorNames.add(p.toString()));
		Collections.sort(processorNames, String.CASE_INSENSITIVE_ORDER);
		String defaultProcessor =
			currentProgram == null ? null : currentProgram.getLanguage().getProcessor().toString();
		String chosenProc =
			askChoice("Select Processor", "Processor:", processorNames, defaultProcessor);

		LanguageCompilerSpecQuery query = new LanguageCompilerSpecQuery(
			Processor.toProcessor(chosenProc), null, null, null, null);
		List<LanguageCompilerSpecPair> specPairs = langService.getLanguageCompilerSpecPairs(query);
		Collections.sort(specPairs);

		LanguageCompilerSpecPair defaultPair =
			currentProgram == null ? null : currentProgram.getLanguageCompilerSpecPair();

		LanguageCompilerSpecPair langPair =
			askChoice("Select Language and Compiler", "Lang/Comp:", specPairs, defaultPair);
		DataOrganization dataOrg = langPair.getCompilerSpec().getDataOrganization();

		charSize = dataOrg.getCharSize();
		shortSize = dataOrg.getShortSize();
		intSize = dataOrg.getIntegerSize();
		longSize = dataOrg.getLongSize();
		longLongSize = dataOrg.getLongLongSize();

		PrototypeModel[] prototypes = langPair.getCompilerSpec().getCallingConventions();
		String[] ccNames = new String[prototypes.length];
		for (int i = 0; i < prototypes.length; ++i) {
			ccNames[i] = prototypes[i].getName();
		}
		PrototypeModel defaultModel = langPair.getCompilerSpec().getDefaultCallingConvention();

		GhidraValuesMap values = new GhidraValuesMap();
		values.defineChoice(CALLING_CONVENTION, defaultModel.getName(), ccNames);
		values.defineInt(NUM_PARAMS, DEFAULT_NUM_PARAMS);
		values.defineBoolean(UNSIGNED_TYPES, true);
		values.defineString(SPECIFIER, "");
		values.defineBoolean(DECORATE_VARARGS, true);
		values.defineBoolean(INCLUDE_LONG_LONG, true);
		values.defineBoolean(INCLUDE_FLOAT, true);
		values.defineBoolean(INCLUDE_DOUBLE, true);
		values.defineDirectory(OUTPUT_DIRECTORY, new File(System.getProperty("user.home")));

		askValues("Configure Prototype Test", "Language/Compiler: " + langPair.toString(), values);
		ccGhidraName = values.getChoice(CALLING_CONVENTION);
		numParams = values.getInt(NUM_PARAMS);
		int numVariables = numParams + 1; // create extra variable for testing return values

		preSpecifier = values.getString(SPECIFIER);
		includeLongLong = values.getBoolean(INCLUDE_LONG_LONG);
		includeFloat = values.getBoolean(INCLUDE_FLOAT);
		includeDouble = values.getBoolean(INCLUDE_DOUBLE);
		outputDirectory = values.getFile(OUTPUT_DIRECTORY);
		unsignedTypes = values.getBoolean(UNSIGNED_TYPES);
		decorateVarargs = values.getBoolean(DECORATE_VARARGS);

		StringBuilder src = new StringBuilder();

		if (unsignedTypes) {
			src.append("typedef unsigned char uchar;\n");
			src.append("typedef unsigned short ushort;\n");
			src.append("typedef unsigned int uint;\n");
			src.append("typedef unsigned long ulong;\n\n");
		}
		else {
			CHAR_TYPE = "char";
			SHORT_TYPE = "short";
			INT_TYPE = "int";
			LONG_TYPE = "long";
			LONG_LONG_TYPE = "longlong";
		}

		// create primitive type global variables
		// create at least 11 since the variadic function tests need that many
		int numPrimitives = Math.max(11, numVariables);
		createIntegralTypeGlobals(src, CHAR_TYPE, charSize, numPrimitives);
		createIntegralTypeGlobals(src, SHORT_TYPE, shortSize, numPrimitives);
		createIntegralTypeGlobals(src, INT_TYPE, intSize, numPrimitives);
		createIntegralTypeGlobals(src, LONG_TYPE, longSize, numPrimitives);
		if (includeLongLong) {
			if (unsignedTypes) {
				src.append("typedef unsigned long long ulonglong;\n");
			}
			else {
				src.append("typedef long long longlong;\n");
			}
			createIntegralTypeGlobals(src, LONG_LONG_TYPE, longLongSize, numPrimitives);
		}
		if (includeFloat) {
			createFloatingPointGlobals(src, numPrimitives);
		}
		if (includeDouble) {
			createDoubleGlobals(src, numPrimitives);
		}

		// create singleton struct global variables
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_CHAR_SINGLETON_NAME,
			List.of(CHAR_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_SHORT_SINGLETON_NAME,
			List.of(SHORT_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_INT_SINGLETON_NAME,
			List.of(INT_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_LONG_SINGLETON_NAME,
			List.of(LONG_TYPE),
			numVariables);
		if (includeFloat) {
			defineAndCreateStructGlobals(src,
				CSpecPrototypeTestConstants.STRUCT_FLOAT_SINGLETON_NAME, List.of("float"),
				numVariables);
		}
		if (includeDouble) {
			defineAndCreateStructGlobals(src,
				CSpecPrototypeTestConstants.STRUCT_DOUBLE_SINGLETON_NAME, List.of("double"),
				numVariables);
		}
		if (includeLongLong) {
			defineAndCreateStructGlobals(src,
				CSpecPrototypeTestConstants.STRUCT_LONG_LONG_SINGLETON_NAME,
				List.of(LONG_LONG_TYPE), numVariables);
		}

		// create pair struct global variables
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_CHAR_PAIR_NAME,
			List.of(CHAR_TYPE, CHAR_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_SHORT_PAIR_NAME,
			List.of(SHORT_TYPE, SHORT_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_INT_PAIR_NAME,
			List.of(INT_TYPE, INT_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_LONG_PAIR_NAME,
			List.of(LONG_TYPE, LONG_TYPE),
			numVariables);
		if (includeFloat) {
			defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_FLOAT_PAIR_NAME,
				List.of("float", "float"),
				numVariables);
		}
		if (includeDouble) {
			defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_DOUBLE_PAIR_NAME,
				List.of("double", "double"),
				numVariables);
		}
		if (includeLongLong) {
			defineAndCreateStructGlobals(src,
				CSpecPrototypeTestConstants.STRUCT_LONG_LONG_PAIR_NAME,
				List.of(LONG_LONG_TYPE, LONG_LONG_TYPE), numVariables);
		}

		// create triple struct global variables
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_CHAR_TRIP_NAME,
			List.of(CHAR_TYPE, CHAR_TYPE, CHAR_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_SHORT_TRIP_NAME,
			List.of(SHORT_TYPE, SHORT_TYPE, SHORT_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_INT_TRIP_NAME,
			List.of(INT_TYPE, INT_TYPE, INT_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_LONG_TRIP_NAME,
			List.of(LONG_TYPE, LONG_TYPE, LONG_TYPE),
			numVariables);
		if (includeFloat) {
			defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_FLOAT_TRIP_NAME,
				List.of("float", "float", "float"),
				numVariables);
		}
		if (includeDouble) {
			defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_DOUBLE_TRIP_NAME,
				List.of("double", "double", "double"),
				numVariables);
		}
		if (includeLongLong) {
			defineAndCreateStructGlobals(src,
				CSpecPrototypeTestConstants.STRUCT_LONG_LONG_TRIP_NAME,
				List.of(LONG_LONG_TYPE, LONG_LONG_TYPE, LONG_LONG_TYPE), numVariables);
		}

		// create quad struct global variables
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_CHAR_QUAD_NAME,
			List.of(CHAR_TYPE, CHAR_TYPE, CHAR_TYPE, CHAR_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_SHORT_QUAD_NAME,
			List.of(SHORT_TYPE, SHORT_TYPE, SHORT_TYPE, SHORT_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_INT_QUAD_NAME,
			List.of(INT_TYPE, INT_TYPE, INT_TYPE, INT_TYPE),
			numVariables);
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_LONG_QUAD_NAME,
			List.of(LONG_TYPE, LONG_TYPE, LONG_TYPE, LONG_TYPE),
			numVariables);
		if (includeFloat) {
			defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_FLOAT_QUAD_NAME,
				List.of("float", "float", "float", "float"),
				numVariables);
		}
		if (includeDouble) {
			defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_DOUBLE_QUAD_NAME,
				List.of("double", "double", "double", "double"),
				numVariables);
		}
		if (includeLongLong) {
			defineAndCreateStructGlobals(src,
				CSpecPrototypeTestConstants.STRUCT_LONG_LONG_QUAD_NAME,
				List.of(LONG_LONG_TYPE, LONG_LONG_TYPE, LONG_LONG_TYPE, LONG_LONG_TYPE),
				numVariables);
		}

		// create mixed struct global variables
		defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_INT_LONG_INT,
			List.of(INT_TYPE, LONG_TYPE, INT_TYPE),
			numVariables);
		if (includeFloat) {
			defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_FLOAT_INT_FLOAT,
				List.of("float", INT_TYPE, "float"), numVariables);
		}
		if (includeDouble) {
			defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_LONG_DOUBLE_LONG,
				List.of(LONG_TYPE, "double", LONG_TYPE), numVariables);
		}
		if (includeFloat && includeDouble) {
			defineAndCreateStructGlobals(src, CSpecPrototypeTestConstants.STRUCT_FLOAT_DOUBLE_FLOAT,
				List.of("float", "double", "float"), numVariables);
		}

		// Create union variables
		defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_CHAR, List.of(CHAR_TYPE),
			numVariables);
		defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_SHORT,
			List.of(SHORT_TYPE), numVariables);
		defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_INT, List.of(INT_TYPE),
			numVariables);
		defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_LONG, List.of(LONG_TYPE),
			numVariables);

		defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_INT_LONG,
			List.of(INT_TYPE, LONG_TYPE),
			numVariables);

		defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_STRUCT_INT,
			List.of(CSpecPrototypeTestConstants.STRUCT_INT_QUAD_NAME), numVariables);
		defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_INTEGRAL,
			List.of(CSpecPrototypeTestConstants.STRUCT_INT_QUAD_NAME,
				CSpecPrototypeTestConstants.STRUCT_LONG_QUAD_NAME,
				CSpecPrototypeTestConstants.STRUCT_INT_LONG_INT),
			numVariables);

		// Want some weird-sized unions
		defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_STRUCT_TRIP_CHAR,
			List.of(CSpecPrototypeTestConstants.STRUCT_CHAR_TRIP_NAME), numVariables);
		defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_STRUCT_TRIP_SHORT,
			List.of(CSpecPrototypeTestConstants.STRUCT_SHORT_TRIP_NAME), numVariables);

		if (includeFloat) {
			defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_FLOAT,
				List.of("float"), numVariables);
			defineAndCreateUnionGlobals(
				src, CSpecPrototypeTestConstants.UNION_INT_FLOAT, List.of(INT_TYPE, "float"),
				numVariables);
			defineAndCreateUnionGlobals(
				src, CSpecPrototypeTestConstants.UNION_LONG_FLOAT, List.of(LONG_TYPE, "float"),
				numVariables);
			defineAndCreateUnionGlobals(
				src, CSpecPrototypeTestConstants.UNION_STRUCT_FLOAT,
				List.of(CSpecPrototypeTestConstants.STRUCT_FLOAT_QUAD_NAME), numVariables);
			defineAndCreateUnionGlobals(
				src, CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_ALL_SMALL,
				List.of(CSpecPrototypeTestConstants.STRUCT_FLOAT_INT_FLOAT), numVariables);
		}
		if (includeDouble) {
			defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_DOUBLE,
				List.of("double"), numVariables);
			defineAndCreateUnionGlobals(
				src, CSpecPrototypeTestConstants.UNION_INT_DOUBLE, List.of(INT_TYPE, "double"),
				numVariables);
			defineAndCreateUnionGlobals(
				src, CSpecPrototypeTestConstants.UNION_LONG_DOUBLE, List.of(LONG_TYPE, "double"),
				numVariables);
			defineAndCreateUnionGlobals(
				src, CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_ALL_LARGE,
				List.of(CSpecPrototypeTestConstants.STRUCT_LONG_DOUBLE_LONG), numVariables);
		}
		if (includeFloat && includeDouble) {
			defineAndCreateUnionGlobals(
				src, CSpecPrototypeTestConstants.UNION_FLOAT_DOUBLE, List.of("float", "double"),
				numVariables);
			defineAndCreateUnionGlobals(src,
				CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_FLOATING,
				List.of(CSpecPrototypeTestConstants.STRUCT_FLOAT_QUAD_NAME,
					CSpecPrototypeTestConstants.STRUCT_DOUBLE_QUAD_NAME,
					CSpecPrototypeTestConstants.STRUCT_FLOAT_DOUBLE_FLOAT),
				numVariables);
		}
		if (includeLongLong) {
			defineAndCreateUnionGlobals(src, CSpecPrototypeTestConstants.UNION_LONG_LONG,
				List.of(LONG_LONG_TYPE),
				numVariables);
		}

		// create test functions for passing primitive types
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_IDENTICAL,
			repeat(CHAR_TYPE, numParams),
			false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_IDENTICAL,
			repeat(SHORT_TYPE, numParams),
			false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_IDENTICAL,
			repeat(INT_TYPE, numParams), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_IDENTICAL,
			repeat(LONG_TYPE, numParams),
			false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_IDENTICAL,
			repeat(INT_TYPE + " *", numParams),
			false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_ALTERNATE,
			repeatList(numParams, CHAR_TYPE, LONG_TYPE), false, Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_ALTERNATE,
			repeatList(numParams, LONG_TYPE, CHAR_TYPE), false, Collections.emptyList());

		if (includeLongLong) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_IDENTICAL,
				repeat(LONG_LONG_TYPE, numParams),
				false, Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_ALTERNATE,
				repeatList(numParams, CHAR_TYPE, LONG_LONG_TYPE), false, Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_ALTERNATE,
				repeatList(numParams, LONG_LONG_TYPE, CHAR_TYPE), false, Collections.emptyList());
		}
		if (includeFloat) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_IDENTICAL,
				repeat("float", numParams),
				false, Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_ALTERNATE,
				repeatList(numParams, INT_TYPE, "float"), false, Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_ALTERNATE,
				repeatList(numParams, "float", INT_TYPE), false, Collections.emptyList());
		}
		if (includeDouble) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_IDENTICAL,
				repeat("double", numParams),
				false, Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_ALTERNATE,
				repeatList(numParams, LONG_TYPE, "double"), false, Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_ALTERNATE,
				repeatList(numParams, "double", LONG_TYPE), false, Collections.emptyList());
		}
		if (includeFloat && includeDouble) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_ALTERNATE,
				repeatList(numParams, "float", "double"), false, Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PRIMITIVE_ALTERNATE,
				repeatList(numParams, "double", "float"), false, Collections.emptyList());
		}

		// create test functions for passing singleton structs
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_SINGLETON_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_CHAR_SINGLETON_NAME, numParams), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_SINGLETON_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_SHORT_SINGLETON_NAME, numParams), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_SINGLETON_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_INT_SINGLETON_NAME, numParams), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_SINGLETON_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_LONG_SINGLETON_NAME, numParams), false,
			Collections.emptyList());
		if (includeFloat) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_SINGLETON_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_FLOAT_SINGLETON_NAME, numParams), false,
				Collections.emptyList());
		}
		if (includeDouble) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_SINGLETON_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_DOUBLE_SINGLETON_NAME, numParams), false,
				Collections.emptyList());
		}
		if (includeLongLong) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_SINGLETON_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_LONG_LONG_SINGLETON_NAME, numParams),
				false, Collections.emptyList());
		}

		// create test functions for passing pair structs
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PAIR_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_CHAR_PAIR_NAME, numParams),
			false, Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PAIR_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_SHORT_PAIR_NAME, numParams),
			false, Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PAIR_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_INT_PAIR_NAME, numParams),
			false, Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PAIR_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_LONG_PAIR_NAME, numParams),
			false, Collections.emptyList());
		if (includeFloat) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PAIR_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_FLOAT_PAIR_NAME, numParams), false,
				Collections.emptyList());
		}
		if (includeDouble) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PAIR_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_DOUBLE_PAIR_NAME, numParams), false,
				Collections.emptyList());
		}
		if (includeLongLong) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_PAIR_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_LONG_LONG_PAIR_NAME, numParams), false,
				Collections.emptyList());
		}

		// create test functions for passing triple structs
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_TRIP_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_CHAR_TRIP_NAME, numParams),
			false, Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_TRIP_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_SHORT_TRIP_NAME, numParams),
			false, Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_TRIP_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_INT_TRIP_NAME, numParams),
			false, Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_TRIP_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_LONG_TRIP_NAME, numParams),
			false, Collections.emptyList());
		if (includeFloat) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_TRIP_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_FLOAT_TRIP_NAME, numParams), false,
				Collections.emptyList());
		}
		if (includeDouble) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_TRIP_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_DOUBLE_TRIP_NAME, numParams), false,
				Collections.emptyList());
		}
		if (includeLongLong) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_TRIP_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_LONG_LONG_TRIP_NAME, numParams), false,
				Collections.emptyList());
		}

		// create test functions for passing quad structs
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_QUAD_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_CHAR_QUAD_NAME, numParams),
			false, Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_QUAD_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_SHORT_QUAD_NAME, numParams),
			false, Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_QUAD_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_INT_QUAD_NAME, numParams),
			false, Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_QUAD_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_LONG_QUAD_NAME, numParams),
			false, Collections.emptyList());
		if (includeFloat) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_QUAD_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_FLOAT_QUAD_NAME, numParams), false,
				Collections.emptyList());
		}
		if (includeDouble) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_QUAD_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_DOUBLE_QUAD_NAME, numParams), false,
				Collections.emptyList());
		}
		if (includeLongLong) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_QUAD_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_LONG_LONG_QUAD_NAME, numParams), false,
				Collections.emptyList());
		}

		// create test functions for passing mixed structs
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_MIXED_STRUCT,
			repeat(CSpecPrototypeTestConstants.STRUCT_INT_LONG_INT, numParams),
			false, Collections.emptyList());
		if (includeFloat) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_MIXED_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_FLOAT_INT_FLOAT, numParams), false,
				Collections.emptyList());
		}
		if (includeDouble) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_MIXED_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_LONG_DOUBLE_LONG, numParams), false,
				Collections.emptyList());
		}
		if (includeFloat && includeDouble) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_MIXED_STRUCT,
				repeat(CSpecPrototypeTestConstants.STRUCT_FLOAT_DOUBLE_FLOAT, numParams), false,
				Collections.emptyList());
		}

		// create variadic test functions
		// encode arg list in function name to facilitate applying signature overrides
		// use capital letters for unsigned
		String variadicTypeString = "_i_i_c_c_s_s_i_i_l_l";
		if (unsignedTypes) {
			variadicTypeString = variadicTypeString.toUpperCase();
		}

		createParamTestFunction(src,
			CSpecPrototypeTestConstants.PARAMS_VARIADIC + variadicTypeString,
			List.of(INT_TYPE, INT_TYPE), true,
			List.of(CHAR_TYPE, CHAR_TYPE, SHORT_TYPE, SHORT_TYPE, INT_TYPE, INT_TYPE, LONG_TYPE,
				LONG_TYPE));

		variadicTypeString = "_i_i_i_i_i_i_i_i_i_i";
		if (unsignedTypes) {
			variadicTypeString = variadicTypeString.toUpperCase();
		}
		createParamTestFunction(src,
			CSpecPrototypeTestConstants.PARAMS_VARIADIC + variadicTypeString,
			List.of(INT_TYPE), true, repeat(INT_TYPE, 9));

		variadicTypeString = "_l_d_l_d_l_d_l_d_l_d";
		if (unsignedTypes) {
			variadicTypeString = variadicTypeString.replace('l', 'L');
		}
		if (includeDouble) {
			createParamTestFunction(src,
				CSpecPrototypeTestConstants.PARAMS_VARIADIC + variadicTypeString,
				List.of(LONG_TYPE, "double"), true,
				List.of(LONG_TYPE, "double", LONG_TYPE, "double", LONG_TYPE, "double", LONG_TYPE,
					"double"));
		}

		// create miscellaneous parameter tests
		if (includeFloat) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_MISC,
				repeatList(numParams, "float",
					CSpecPrototypeTestConstants.STRUCT_FLOAT_SINGLETON_NAME),
				false,
				Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_MISC,
				repeatList(numParams, "float", CSpecPrototypeTestConstants.STRUCT_FLOAT_PAIR_NAME),
				false,
				Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_MISC,
				repeatList(numParams, CSpecPrototypeTestConstants.STRUCT_FLOAT_PAIR_NAME, INT_TYPE,
					"float"),
				false,
				Collections.emptyList());
		}

		// Union tests
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
			repeatList(numParams, CSpecPrototypeTestConstants.UNION_CHAR), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
			repeatList(numParams, CSpecPrototypeTestConstants.UNION_SHORT), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
			repeatList(numParams, CSpecPrototypeTestConstants.UNION_INT), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
			repeatList(numParams, CSpecPrototypeTestConstants.UNION_LONG), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
			repeatList(numParams, CSpecPrototypeTestConstants.UNION_INT_LONG), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
			repeatList(numParams, CSpecPrototypeTestConstants.UNION_STRUCT_INT), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
			repeatList(numParams, CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_INTEGRAL), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
			repeatList(numParams, CSpecPrototypeTestConstants.UNION_STRUCT_TRIP_CHAR), false,
			Collections.emptyList());
		createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
			repeatList(numParams, CSpecPrototypeTestConstants.UNION_STRUCT_TRIP_SHORT), false,
			Collections.emptyList());

		if (includeFloat) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_FLOAT), false,
				Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_INT_FLOAT), false,
				Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_LONG_FLOAT), false,
				Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_STRUCT_FLOAT), false,
				Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_ALL_SMALL),
				false, Collections.emptyList());
		}
		if (includeDouble) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_DOUBLE), false,
				Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_INT_DOUBLE), false,
				Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_LONG_DOUBLE), false,
				Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_ALL_LARGE),
				false, Collections.emptyList());
		}
		if (includeDouble && includeFloat) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_FLOAT_DOUBLE), false,
				Collections.emptyList());
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_FLOATING),
				false, Collections.emptyList());
		}
		if (includeLongLong) {
			createParamTestFunction(src, CSpecPrototypeTestConstants.PARAMS_UNION,
				repeatList(numParams, CSpecPrototypeTestConstants.UNION_LONG_LONG), false,
				Collections.emptyList());
		}

		// Return tests

		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PRIMITIVE, CHAR_TYPE);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_SINGLETON,
			CSpecPrototypeTestConstants.STRUCT_CHAR_SINGLETON_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PAIR,
			CSpecPrototypeTestConstants.STRUCT_CHAR_PAIR_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_TRIPLE,
			CSpecPrototypeTestConstants.STRUCT_CHAR_TRIP_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_QUAD,
			CSpecPrototypeTestConstants.STRUCT_CHAR_QUAD_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
			CSpecPrototypeTestConstants.UNION_CHAR);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
			CSpecPrototypeTestConstants.UNION_STRUCT_TRIP_CHAR);

		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PRIMITIVE, SHORT_TYPE);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_SINGLETON,
			CSpecPrototypeTestConstants.STRUCT_SHORT_SINGLETON_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PAIR,
			CSpecPrototypeTestConstants.STRUCT_SHORT_PAIR_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_TRIPLE,
			CSpecPrototypeTestConstants.STRUCT_SHORT_TRIP_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_QUAD,
			CSpecPrototypeTestConstants.STRUCT_SHORT_QUAD_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
			CSpecPrototypeTestConstants.UNION_SHORT);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
			CSpecPrototypeTestConstants.UNION_STRUCT_TRIP_SHORT);

		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PRIMITIVE, INT_TYPE);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_SINGLETON,
			CSpecPrototypeTestConstants.STRUCT_INT_SINGLETON_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PAIR,
			CSpecPrototypeTestConstants.STRUCT_INT_PAIR_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_TRIPLE,
			CSpecPrototypeTestConstants.STRUCT_INT_TRIP_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_QUAD,
			CSpecPrototypeTestConstants.STRUCT_INT_QUAD_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
			CSpecPrototypeTestConstants.UNION_INT);

		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PRIMITIVE, LONG_TYPE);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_SINGLETON,
			CSpecPrototypeTestConstants.STRUCT_LONG_SINGLETON_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PAIR,
			CSpecPrototypeTestConstants.STRUCT_LONG_PAIR_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_TRIPLE,
			CSpecPrototypeTestConstants.STRUCT_LONG_TRIP_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_QUAD,
			CSpecPrototypeTestConstants.STRUCT_LONG_QUAD_NAME);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
			CSpecPrototypeTestConstants.UNION_LONG);

		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_MIXED,
			CSpecPrototypeTestConstants.STRUCT_INT_LONG_INT);

		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
			CSpecPrototypeTestConstants.UNION_STRUCT_INT);
		createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
			CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_INTEGRAL);

		if (includeFloat) {
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PRIMITIVE, "float");
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_SINGLETON,
				CSpecPrototypeTestConstants.STRUCT_FLOAT_SINGLETON_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PAIR,
				CSpecPrototypeTestConstants.STRUCT_FLOAT_PAIR_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_TRIPLE,
				CSpecPrototypeTestConstants.STRUCT_FLOAT_TRIP_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_QUAD,
				CSpecPrototypeTestConstants.STRUCT_FLOAT_QUAD_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_MIXED,
				CSpecPrototypeTestConstants.STRUCT_FLOAT_INT_FLOAT);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
				CSpecPrototypeTestConstants.UNION_FLOAT);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
				CSpecPrototypeTestConstants.UNION_STRUCT_FLOAT);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
				CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_ALL_SMALL);
		}
		if (includeDouble) {
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PRIMITIVE, "double");
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_SINGLETON,
				CSpecPrototypeTestConstants.STRUCT_DOUBLE_SINGLETON_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PAIR,
				CSpecPrototypeTestConstants.STRUCT_DOUBLE_PAIR_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_TRIPLE,
				CSpecPrototypeTestConstants.STRUCT_DOUBLE_TRIP_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_QUAD,
				CSpecPrototypeTestConstants.STRUCT_DOUBLE_QUAD_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_MIXED,
				CSpecPrototypeTestConstants.STRUCT_LONG_DOUBLE_LONG);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
				CSpecPrototypeTestConstants.UNION_DOUBLE);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
				CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_ALL_LARGE);
		}
		if (includeFloat && includeDouble) {
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_MIXED,
				CSpecPrototypeTestConstants.STRUCT_FLOAT_DOUBLE_FLOAT);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
				CSpecPrototypeTestConstants.UNION_MIXED_STRUCT_FLOATING);
		}
		if (includeLongLong) {
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PRIMITIVE,
				LONG_LONG_TYPE);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_SINGLETON,
				CSpecPrototypeTestConstants.STRUCT_LONG_LONG_SINGLETON_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_PAIR,
				CSpecPrototypeTestConstants.STRUCT_LONG_LONG_PAIR_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_TRIPLE,
				CSpecPrototypeTestConstants.STRUCT_LONG_LONG_TRIP_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_QUAD,
				CSpecPrototypeTestConstants.STRUCT_LONG_LONG_QUAD_NAME);
			createReturnTestFunction(src, CSpecPrototypeTestConstants.RETURN_UNION,
				CSpecPrototypeTestConstants.UNION_LONG_LONG);
		}

		writeFile(langPair, src);

	}

	private void createReturnTestFunction(Appendable app, String baseFuncName,
			String returnType) throws IOException {
		int id = funcCounter++;
		String count = Integer.toString(id);
		app.append(returnType);
		if (!StringUtils.isAllBlank(preSpecifier)) {
			app.append(" ");
			app.append(preSpecifier);
		}
		app.append(" ");
		app.append(CSpecPrototypeTestConstants.PRODUCER);
		app.append("_");
		app.append(count);
		app.append("(void)");
		app.append(" { return ");
		app.append(returnType);
		app.append("_0;}\n");
		if (!StringUtils.isAllBlank(preSpecifier)) {
			app.append(preSpecifier);
			app.append(" ");
		}
		app.append("extern void consumer_");
		app.append(count);
		app.append("(");
		app.append(returnType);
		app.append(");\n");
		app.append("void ");
		app.append(baseFuncName);
		app.append("_");
		app.append(count);
		app.append("(void){ consumer_");
		app.append(count);
		app.append("(");
		app.append(CSpecPrototypeTestConstants.PRODUCER);
		app.append("_");
		app.append(count);
		app.append("());}\n\n");

	}

	private void defineAndCreateStructGlobals(Appendable src, String structName, List<String> types,
			int nParams) throws IOException {
		createStructDefinition(src, structName, types);
		createStructGlobals(src, structName, types, nParams);
	}

	private void defineAndCreateUnionGlobals(Appendable src, String unionName, List<String> types,
			int nParams) throws IOException {
		createUnionDefinition(src, unionName, types);
		createUnionGlobals(src, unionName, types, nParams);
	}

	private void createStructDefinition(Appendable src, String structName, List<String> types)
			throws IOException {
		int fieldCount = 0;
		src.append("typedef struct ");
		src.append(structName);
		src.append(" {\n");
		for (int i = 0; i < types.size(); ++i) {
			src.append("    ");
			src.append(types.get(i));
			src.append(" ");
			src.append(CSpecPrototypeTestConstants.FIELD_NAME_PREFIX);
			src.append("_");
			src.append(types.get(i));
			src.append("_");
			src.append(Integer.toString(fieldCount++));
			src.append(";\n");
		}
		src.append("} ");
		src.append(structName);
		src.append(";\n\n");
	}

	private void createUnionDefinition(Appendable src, String unionName, List<String> types)
			throws IOException {
		int fieldCount = 0;
		src.append("typedef union ");
		src.append(unionName);
		src.append(" {\n");
		for (int i = 0; i < types.size(); ++i) {
			src.append("    ");
			src.append(types.get(i));
			src.append(" ");
			src.append(CSpecPrototypeTestConstants.FIELD_NAME_PREFIX);
			src.append("_");
			src.append(types.get(i));
			src.append("_");
			src.append(Integer.toString(fieldCount++));
			src.append(";\n");
		}
		src.append("} ");
		src.append(unionName);
		src.append(";\n\n");
	}

	private List<String> repeat(String base, int length) {
		List<String> repeated = new ArrayList<>(length);
		for (int i = 0; i < length; ++i) {
			repeated.add(base);
		}
		return repeated;
	}

	private List<String> repeatList(int length, String... entries) {
		List<String> repeats = new ArrayList<>(length);
		for (int i = 0; i < length; ++i) {
			repeats.add(entries[i % entries.length]);
		}
		return repeats;
	}

	private void createIntegralTypeGlobals(Appendable app, String typeName, int size,
			int numVariables) throws IOException {
		for (int i = 0; i < numVariables; ++i) {
			app.append("const ");
			app.append(typeName);
			app.append(" ");
			app.append(typeName);
			app.append("_");
			app.append(Integer.toString(i));
			app.append(" = ");
			app.append(getNextHexValue(size));
			app.append(";\n");
		}
		app.append("\n");
	}

	private void structInitializer(Appendable app, List<String> fieldTypes) throws IOException {
		for (int j = 0; j < fieldTypes.size(); ++j) {
			app.append(".");
			app.append(CSpecPrototypeTestConstants.FIELD_NAME_PREFIX);
			app.append("_");
			app.append(fieldTypes.get(j));
			app.append("_");
			app.append(Integer.toString(j));
			app.append(" = ");
			switch (fieldTypes.get(j)) {
				case "char":
				case "uchar":
					app.append(getNextHexValue(charSize));
					break;
				case "short":
				case "ushort":
					app.append(getNextHexValue(shortSize));
					break;
				case "int":
				case "uint":
					app.append(getNextHexValue(intSize));
					break;
				case "long":
				case "ulong":
					app.append(getNextHexValue(longSize));
					break;
				case "longlong":
				case "ulonglong":
					app.append(getNextHexValue(longLongSize));
					break;
				case "float":
					app.append(getNextFloatValue());
					break;
				case "double":
					app.append(getNextDoubleValue());
					break;
				default:
					throw new IllegalArgumentException(
						"Unsupported field type: " + fieldTypes.get(j));
			}
			if (j != fieldTypes.size() - 1) {
				app.append(", ");
			}
		}
	}

	private void createStructGlobals(Appendable app, String structName, List<String> fieldTypes,
			int num) throws IOException {
		for (int i = 0; i < num; ++i) {
			app.append("const ");
			app.append(structName);
			app.append(" ");
			app.append(structName);
			app.append("_");
			app.append(Integer.toString(i));
			app.append(" = { ");
			structInitializer(app, fieldTypes);
			app.append(" };\n");
		}
		app.append("\n");
	}

	private void createUnionGlobals(Appendable app, String unionName, List<String> fieldTypes,
			int num) throws IOException {
		for (int i = 0; i < num; ++i) {
			app.append("const ");
			app.append(unionName);
			app.append(" ");
			app.append(unionName);
			app.append("_");
			app.append(Integer.toString(i));
			app.append(" = { ");
			// Enable only one field
			int whichField = i % fieldTypes.size();
			app.append(".");
			app.append(CSpecPrototypeTestConstants.FIELD_NAME_PREFIX);
			app.append("_");
			app.append(fieldTypes.get(whichField));
			app.append("_");
			app.append(Integer.toString(whichField));
			app.append(" = ");
			switch (fieldTypes.get(whichField)) {
				case "char":
				case "uchar":
					app.append(getNextHexValue(charSize));
					break;
				case "short":
				case "ushort":
					app.append(getNextHexValue(shortSize));
					break;
				case "int":
				case "uint":
					app.append(getNextHexValue(intSize));
					break;
				case "long":
				case "ulong":
					app.append(getNextHexValue(longSize));
					break;
				case "longlong":
				case "ulonglong":
					app.append(getNextHexValue(longLongSize));
					break;
				case "float":
					app.append(getNextFloatValue());
					break;
				case "double":
					app.append(getNextDoubleValue());
					break;
				case CSpecPrototypeTestConstants.STRUCT_INT_QUAD_NAME:
					app.append("{ ");
					structInitializer(app, List.of(INT_TYPE, INT_TYPE, INT_TYPE, INT_TYPE));
					app.append(" }\n");
					break;
				case CSpecPrototypeTestConstants.STRUCT_LONG_QUAD_NAME:
					app.append("{ ");
					structInitializer(app, List.of(LONG_TYPE, LONG_TYPE, LONG_TYPE, LONG_TYPE));
					app.append(" }\n");
					break;
				case CSpecPrototypeTestConstants.STRUCT_INT_LONG_INT:
					app.append("{ ");
					structInitializer(app, List.of(INT_TYPE, LONG_TYPE, INT_TYPE));
					app.append(" }\n");
					break;
				case CSpecPrototypeTestConstants.STRUCT_FLOAT_QUAD_NAME:
					app.append("{ ");
					structInitializer(app, List.of("float", "float", "float", "float"));
					app.append(" }\n");
					break;
				case CSpecPrototypeTestConstants.STRUCT_DOUBLE_QUAD_NAME:
					app.append("{ ");
					structInitializer(app, List.of("double", "double", "double", "double"));
					app.append(" }\n");
					break;
				case CSpecPrototypeTestConstants.STRUCT_FLOAT_DOUBLE_FLOAT:
					app.append("{ ");
					structInitializer(app, List.of("float", "double", "float"));
					app.append(" }\n");
					break;
				case CSpecPrototypeTestConstants.STRUCT_FLOAT_INT_FLOAT:
					app.append("{ ");
					structInitializer(app, List.of("float", INT_TYPE, "float"));
					app.append(" }\n");
					break;
				case CSpecPrototypeTestConstants.STRUCT_LONG_DOUBLE_LONG:
					app.append("{ ");
					structInitializer(app, List.of(LONG_TYPE, "double", LONG_TYPE));
					app.append(" }\n");
					break;
				case CSpecPrototypeTestConstants.STRUCT_CHAR_TRIP_NAME:
					app.append("{ ");
					structInitializer(app, List.of(CHAR_TYPE, CHAR_TYPE, CHAR_TYPE));
					app.append(" }\n");
					break;
				case CSpecPrototypeTestConstants.STRUCT_SHORT_TRIP_NAME:
					app.append("{ ");
					structInitializer(app, List.of(SHORT_TYPE, SHORT_TYPE, SHORT_TYPE));
					app.append(" }\n");
					break;
				default:
					throw new IllegalArgumentException(
						"Unsupported field type: " + fieldTypes.get(whichField));
			}
			app.append(" };\n");
		}
		app.append("\n");

	}

	private String getNextHexValue(int size) {
		long localMultiplier = size == 8 ? multiplier : multiplier & ((1l << (8 * size)) - 1);
		long retVal = localMultiplier * variableVal;
		// if the value is larger than one byte, make the most significant byte 0xff
		// this helps diagnose endianness issues
		if (size > 1) {
			long adjustment = 0xffL << (8 * (size - 1));
			retVal |= adjustment;
		}
		variableVal = variableVal == 0xfe ? 1 : variableVal + 1;
		return "0x" + Long.toHexString(retVal);
	}

	private void createFloatingPointGlobals(Appendable app, int numVariables) throws IOException {
		for (int i = 0; i < numVariables; ++i) {
			app.append("const float float");
			app.append("_");
			app.append(Integer.toString(i));
			app.append(" = ");
			app.append(getNextFloatValue());
			app.append(";\n");
		}
		app.append("\n");
	}

	private CharSequence getNextFloatValue() {
		float retVal = floatIntPart + floatFracPart;
		floatIntPart *= 2;
		floatFracPart /= 2;
		if (floatIntPart >= 8000) {
			floatIntPart = 2.0f;
			floatFracPart = .5f;
		}
		return Float.toString(retVal);
	}

	private void createDoubleGlobals(Appendable app, int numVariables) throws IOException {
		for (int i = 0; i < numVariables; ++i) {
			app.append("const double double");
			app.append("_");
			app.append(Integer.toString(i));
			app.append(" = ");
			app.append(getNextDoubleValue());
			app.append(";\n");
		}
		app.append("\n");
	}

	private String getNextDoubleValue() {
		double retVal = doubleIntPart + doubleFracPart;
		doubleIntPart *= 2;
		doubleFracPart /= 2;
		if (doubleIntPart > 50000) {
			doubleIntPart = 2.0;
			doubleFracPart /= 2;
		}
		return Double.toString(retVal);
	}

	private void createParamTestFunction(Appendable app, String baseFuncName,
			List<String> fixedInputTypes, boolean isVarArgs, List<String> varArgsTypes)
			throws IOException {
		app.append("extern void");
		if (!StringUtils.isAllBlank(preSpecifier) && (!isVarArgs || decorateVarargs)) {
			app.append(" ");
			app.append(preSpecifier);
		}
		app.append(" ");
		int testFuncNumber = funcCounter++;
		String targetName =
			CSpecPrototypeTestConstants.EXTERNAL + "_target_" + Integer.toString(testFuncNumber);
		app.append(targetName);
		app.append("(");
		for (int i = 0; i < fixedInputTypes.size(); ++i) {
			if (fixedInputTypes.get(i).contains("*")) {
				app.append("const ");
			}
			app.append(fixedInputTypes.get(i));
			if (i != fixedInputTypes.size() - 1) {
				app.append(",");
			}
		}
		if (isVarArgs) {
			app.append(",...");
		}
		app.append(")");
		app.append(";\n");
		app.append("void ");
		app.append(baseFuncName);
		app.append("_");
		app.append(Integer.toString(testFuncNumber));
		app.append("(void) {\n");
		app.append("    ");
		app.append(targetName);
		app.append("(");
		List<String> inputs = new ArrayList<>();
		inputs.addAll(fixedInputTypes);
		inputs.addAll(varArgsTypes);
		for (int i = 0; i < inputs.size(); ++i) {
			if (inputs.get(i).contains("*")) {
				app.append("&"); // address-of operator
				app.append(inputs.get(i).split(" ")[0]);
			}
			else {
				app.append(inputs.get(i));
			}
			app.append("_");
			app.append(Integer.toString(i + 1));
			if (i != inputs.size() - 1) {
				app.append(",");
			}
		}
		app.append(");\n}\n\n");
	}

	private void writeFile(LanguageCompilerSpecPair langPair, StringBuilder programText)
			throws IOException {
		File out = new File(outputDirectory,
			langPair.toString().replace(":", "_") + "_" + ccGhidraName + ".c");
		try (FileWriter fWriter = new FileWriter(out)) {
			fWriter.write(programText.toString());
			println("Wrote " + out.getAbsolutePath());
		}
		return;
	}

}
