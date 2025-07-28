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
package mdemangler.datatype;

import mdemangler.MDException;
import mdemangler.MDMang;
import mdemangler.MDMang.ProcessingMode;
import mdemangler.datatype.complex.*;
import mdemangler.datatype.extended.*;
import mdemangler.datatype.modifier.*;
import mdemangler.object.MDObjectCPP;

/**
 * The class parses data types.  There are different parsers that are at different levels
 *  of the type hierarchy of (Microsoft) data types.  There are parseDataType,
 *  parsePrimaryDataType, etc.  These exist because, in the typing system of C/C++,
 *  certain things are permitted and other things are not.  For instance, you can have
 *  a reference to a pointer, but not a pointer to a reference.  These are enforced
 *  by calling the appropriate parser at the appropriate place in the code.
 */
public class MDDataTypeParser {
	/**
	 * This method is only to be used by MDMang itself for the highest level type parsing where
	 * there is not already a multi-retry. This method checks for the '.' starting character,
	 * determines the type by calling the {@link #parseDataType(MDMang, boolean)}, parses the type,
	 * and does the multi-mode retry if there is an exception on the first pass as
	 * MDMangObjectParser does for generic mangled objects
	 * @param dmang - the MDMang driver
	 * @param isHighest - boolean indicating whether something else modifies or names the data
	 *  type to be parsed, which impacts when certain overloaded CV modifiers can be applied.
	 * @return - a type derived from MDDataType
	 * @throws MDException on parsing error
	 */
	public static MDDataType determineAndParseDataType(MDMang dmang, boolean isHighest)
			throws MDException {

		MDDataType dt = null;

		dmang.setProcessingMode(ProcessingMode.DEFAULT_STANDARD);
		try {
			dmang.pushContext();
			if (dmang.peek() == '.') {
				dmang.increment(); // skip the now-optional '.'
			}
			dt = parseDataType(dmang, isHighest);
			dt.parse();
			dmang.popContext();
		}
		catch (MDException e1) {
			dmang.resetState();
			dmang.setProcessingMode(ProcessingMode.LLVM);
			try {
				dmang.pushContext();
				dmang.increment(); // skip the '.'
				dt = parseDataType(dmang, isHighest);
				dt.parse();
				dmang.popContext();
			}
			catch (MDException e2) {
				throw new MDException(
					"Reason1: " + e1.getMessage().trim() + "; Reason2: " + e2.getMessage().trim());
			}
		}
		return dt;
	}

	/**
	 * This method parses all data types.  Specifically, it parses void, data indirect types,
	 * function indirect types, and all types parsed by parsePrimaryDataType().
	 * @param dmang - the MDMang driver
	 * @param isHighest - boolean indicating whether something else modifies or names the data
	 *  type to be parsed, which impacts when certain overloaded CV modifiers can be applied.
	 * @return - a type derived from MDDataType
	 * @throws MDException on parsing error
	 */
	public static MDDataType parseDataType(MDMang dmang, boolean isHighest) throws MDException {
		MDDataType dt;
		char code = dmang.peek();
		switch (code) {
			case '?':
				dmang.increment();
				dt = new MDQuestionModifierType(dmang);
				break;
			case 'X':
				// The wiki document says 'X' can be void or coclass, but we have never been able
				//  to make coclass manifest itself, so we are factoring out the code that could
				//  have allowed it: This was MDMang.xVoidPermitted(), which read a flag from
				//  MDContext.  The ability is also being factored out of MDContext.
				dmang.increment();
				dt = new MDVoidDataType(dmang);
				break;
			case MDMang.DONE:
				throw new MDException("Type code not expected: " + code);
			default:
				dt = parsePrimaryDataType(dmang, isHighest);
				break;
		}
		return dt;
	}

	/**
	 * This method parses references and all types parsed by parseBasicDataType() and
	 *  parseSpecialExtendedType().
	 * @param dmang - the MDMang driver
	 * @param isHighest - boolean indicating whether something else modifies or names the data
	 *  type to be parsed, which impacts when certain overloaded CV modifiers can be applied.
	 * @return - a type derived from MDDataType
	 * @throws MDException on parsing error
	 */
	public static MDDataType parsePrimaryDataType(MDMang dmang, boolean isHighest)
			throws MDException {
		MDDataType dt;
		char code = dmang.peek();
		switch (code) {
			case 'A':
				dmang.increment();
				dt = new MDReferenceType(dmang, isHighest, false, false);
				break;
			case 'B':
				dmang.increment();
				dt = new MDReferenceType(dmang, isHighest, false, true);
				break;
			case MDMang.DONE:
				throw new MDException("PrimaryDataType: no data for type code");
			default:
				dt = parseBasicDataType(dmang, isHighest);
				break;
		}
		return dt;
	}

	/**
	 * This method parses special extended data types that Microsoft had not originally planned
	 * for, which include function indirect, pointer reference data type, data reference type,
	 * data reference reference type, std::nullptr_t, and (soon) other missing types
	 * @param dmang - the MDMang driver
	 * @param isHighest - boolean indicating whether something else modifies or names the data
	 *  type to be parsed, which impacts when certain overloaded CV modifiers can be applied.
	 * @return - a type derived from MDDataType
	 * @throws MDException on parsing error
	 */
	public static MDDataType parseSpecialExtendedType(MDMang dmang, boolean isHighest)
			throws MDException {
		MDDataType dt;
		char code = dmang.getAndIncrement();
		if (code != '$') {
			throw new MDException("ExtendedType invalid character: " + code);
		}
		code = dmang.getAndIncrement();
		switch (code) {
			case 'A':
				dt = new MDFunctionIndirectType(dmang);
				break;
			case 'B':
				dt = new MDPointerRefDataType(dmang);
				break;
			case 'C':
				dt = new MDDataReferenceType(dmang);
				break;
			case 'Q':
				dt = new MDDataRightReferenceType(dmang, isHighest, false, false);
				break;
			case 'R':
				dt = new MDDataRightReferenceType(dmang, isHighest, false, true);
				break;
			case 'T':
				dt = new MDStdNullPtrType(dmang);
				break;
			case 'Y': // UINFO: QualifiedName only (no type)
				// TODO: implementation. Try symbol like "?var@@3$$Yabc@@"
				dt = new MDNamedUnspecifiedType(dmang);
				break;
			case 'V': // Empty type parameter pack?
				dt = new MDEmptyParameterType(dmang);
				break;
			case 'Z': // End template parameter pack?
				dt = new MDEndParameterType(dmang);
				break;
			case 'S': // invalid (UINFO)
			case 'F': // Investigate $$F in CVMod processing... does it belong here?
			default:
				throw new MDException("SpecialDataType: unrecognized code: " + code);
		}
		return dt;
	}

	/**
	 * This method parses basic and extended data types.
	 * @param dmang - the MDMang driver
	 * @param isHighest - boolean indicating whether something else modifies or names the data
	 *  type to be parsed, which impacts when certain overloaded CV modifiers can be applied.
	 * @return - a type derived from MDDataType
	 * @throws MDException on parsing error
	 */
	public static MDDataType parseBasicDataType(MDMang dmang, boolean isHighest)
			throws MDException {
		MDDataType dt;
		char code = dmang.getAndIncrement();
		switch (code) {
			case '?':
				// Not sure if this should be here or other place.  I suppose could have a
				//  reference to one of these, so wouldn't want it in "Primary" data types
				dt = new MDCustomType(dmang);
				break;
			case '$':
				dt = parseSpecialExtendedType(dmang, isHighest);
				break;
			case 'C':
				dt = new MDCharDataType(dmang);
				dt.setSigned();
				break;
			case 'D':
				dt = new MDCharDataType(dmang);
				break;
			case 'E':
				dt = new MDCharDataType(dmang);
				dt.setUnsigned();
				break;
			case 'F':
				dt = new MDShortDataType(dmang);
				break;
			case 'G':
				dt = new MDShortDataType(dmang);
				dt.setUnsigned();
				break;
			case 'H':
				dt = new MDIntDataType(dmang);
				break;
			case 'I':
				dt = new MDIntDataType(dmang);
				dt.setUnsigned();
				break;
			case 'J':
				dt = new MDLongDataType(dmang);
				break;
			case 'K':
				dt = new MDLongDataType(dmang);
				dt.setUnsigned();
				break;
			case 'L': // Unknown complex type: UINFO: "segment" type
				dt = new MDComplexType(dmang);
				break;
			case 'M':
				dt = new MDFloatDataType(dmang);
				break;
			case 'N':
				dt = new MDDoubleDataType(dmang);
				break;
			case 'O':
				dt = new MDLongDoubleDataType(dmang);
				break;
			case 'P':
				dt = new MDPointerType(dmang, isHighest, false, false);
				break;
			case 'Q':
				dt = new MDPointerType(dmang, isHighest, true, false);
				break;
			case 'R':
				dt = new MDPointerType(dmang, isHighest, false, true);
				break;
			case 'S':
				dt = new MDPointerType(dmang, isHighest, true, true);
				break;
			case 'T':
				dt = new MDUnionType(dmang);
				break;
			case 'U':
				dt = new MDStructType(dmang);
				break;
			case 'V':
				dt = new MDClassType(dmang);
				break;
			case 'W':
				dt = new MDEnumType(dmang);
				break;
			case 'X': // Purposefully redundant (also found in parsdDataType)
				// The wiki document says 'X' can be void or coclass, but we have never been able
				//  to make coclass manifest itself, so we are factoring out the code that could
				//  have allowed it: This was MDMang.xVoidPermitted(), which read a flag from
				//  MDContext.  The ability is also being factored out of MDContext.
				dt = new MDVoidDataType(dmang);
				break;
			case 'Y':
				dt = new MDCointerfaceType(dmang, 1);
				break;
			case 'Z':
				//There really is no data path to get us to this case 'Z', so will never get cover.
				dt = new MDVarArgsType(dmang);
				break;
			case '_': // Extended types
				code = dmang.getAndIncrement();
				switch (code) {
					case '$':
						dt = new MDW64Type(dmang);
						break;
					case 'D':
						dt = new MDInt8DataType(dmang);
						break;
					case 'E':
						dt = new MDInt8DataType(dmang);
						dt.setUnsigned();
						break;
					case 'F':
						dt = new MDInt16DataType(dmang);
						break;
					case 'G':
						dt = new MDInt16DataType(dmang);
						dt.setUnsigned();
						break;
					case 'H':
						dt = new MDInt32DataType(dmang);
						break;
					case 'I':
						dt = new MDInt32DataType(dmang);
						dt.setUnsigned();
						break;
					case 'J':
						dt = new MDInt64DataType(dmang);
						break;
					case 'K':
						dt = new MDInt64DataType(dmang);
						dt.setUnsigned();
						break;
					case 'L':
						dt = new MDInt128DataType(dmang);
						break;
					case 'M':
						dt = new MDInt128DataType(dmang);
						dt.setUnsigned();
						break;
					case 'N':
						dt = new MDBoolDataType(dmang);
						break;
					case 'O':
						// TODO: possibly change this to ExtendedDataType (currently 'O' ArrayType
						//  is a "ModifiedType")--investigate further
						// 20230731: note that this class uses a CVMod type, which support its
						//  being a MDModifierType.
						dt = new MDArrayBasicType(dmang);
						break;
					case 'P':
						dt = new MDUnknownPExtendedDataType(dmang);
						break;
					case 'Q':
						dt = new MDChar8DataType(dmang);
						break;
					case 'R':
						dt = new MDUnknownRExtendedDataType(dmang);
						break;
					case 'S':
						dt = new MDChar16DataType(dmang);
						break;
					case 'T':
						dt = new MDUnknownTExtendedDataType(dmang);
						break;
					case 'U':
						dt = new MDChar32DataType(dmang);
						break;
					case 'V':
						dt = new MDUnknownVExtendedDataType(dmang);
						break;
					case 'W':
						dt = new MDWcharDataType(dmang);
						break;
					case 'X': // TODO: more unknown about this.
						dt = new MDCoclassType(dmang, 2);
						break;
					case 'Y': // TODO: more unknown about this.
						dt = new MDCointerfaceType(dmang, 2);
						break;
					case '_':
						// 20160728: Windows 10 stuff... stubbing for now to try to help figure
						//  this out.
						// TODO 20170328: MDObjectCPP is wrong here (especially after moving the
						//  parsing of '?' inside of MDObjectCPP.
						//20180404: This is still broken, so exception gets thrown->no coverage.
						MDObjectCPP object = new MDObjectCPP(dmang);
						object.parse();
						dt = new MDDataType(dmang);
						dt.setName(object.toString());
//						dt.insert(dtBuilder);
//						dt.setTypeName(dtBuilder.emit());
//						dt.setTypeName(object.emit());
						// MDQualifiedName qualifiedName = new MDQualifiedName(dmang);
						// dt = new MDComplexType();
//						MDTemplateNameAndArguments tn = new MDTemplateNameAndArguments(dmang);
//						dt.setTypeName("{MDMANG_UNK_EXTENDEDTYPE:" + tn.emit() + "}"); // 20160728 temp
						break;
					case MDMang.DONE:
						throw new MDException("Extended BasicDataType: no data for type code");
					default:
						throw new MDException("Extended BasicDataType: unrecognized code: " + code);
				}
				break;
			case '@':
				// 20160926: Hypothesis: this only occurs for the function return type of
				//  constructors and destructors.
				// Do: grep '@@QEAA@' fixnameout6.txt | grep -v '?0' | grep -v '?1'
				//  --also try variations, leaving out the 2nd or 3rd grep.
				MDVoidDataType dtv = new MDVoidDataType(dmang);
				dtv.setNonPrinting();
				dt = dtv;
				break;
			case MDMang.DONE:
				throw new MDException("BasicDataType: no data for type code");
			default:
				throw new MDException("BasicDataType: unrecognized code: " + code);
		}
		return dt;
	}
}
