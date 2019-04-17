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
package mdemangler.datatype.modifier;

import java.util.*;

import mdemangler.*;
import mdemangler.naming.MDQualification;

/**
 * This class represents a Const/Volatile modifier (and extra stuff) of a modifier
 * type within a Microsoft mangled symbol.
 */
public class MDCVMod extends MDParsableItem {
	public static final char SPACE = ' ';

	public static final char POINTER_CHAR = '*';
	public static final char REFERENCE_CHAR = '&';
	public static final char CARROT_CHAR = '^';
	public static final char PERCENT_CHAR = '%';
	// private static final String FUNCTIONPOINTER = "*"; // TODO: eliminate
	// with
	// // old code
	// private static final String FUNCTIONREFERENCE = "&"; // TODO: eliminate
	// with
	// // old code
	private static final String POINTER = "*";
	private static final String REFERENCE = "&";
	private static final String CARROT = "^";
	private static final String PERCENT = "%";
	private static final String REFREF = "&&";

	private final static String PTR64 = " __ptr64";
	private static final String UNALIGNED = "__unaligned ";
	private static final String RESTRICT = " __restrict";
	private static final String CONST = "const ";
	private static final String VOLATILE = "volatile ";
	private static final String LREF = "& ";
	private static final String RREF = "&& ";

	// private final static String PTR64 = "__ptr64";
	// private static final String UNALIGNED = "__unaligned";
	// private static final String RESTRICT = "__restrict";
	// private static final String CONST = "const";
	// private static final String VOLATILE = "volatile";

	private static final String prefixEmitClausePinPointer = "cli::pin_ptr<";
	private static final String suffixEmitClausePinPointer = ">";
	private static final String prefixEmitClauseCLIArray = "cli::array<";
	private static final String suffixEmitClauseCLIArray = ">^";
	// private static final String prefixEmitClauseBased = "__based(";
	// private static final String suffixEmitClauseBased = ")";

	// C-V Modifiers
	private boolean isPointer64; // Can be pointer or reference
	private boolean isUnaligned;
	private boolean isRestricted;
	private boolean isThisPointerMod;
	private boolean isLRef;
	private boolean isRRef;
	private boolean isConst;
	private boolean isVolatile;
	private boolean isFunction;
	private boolean isBased;
	private boolean isMember;
	// Added C-V modifier 20140423
	private boolean isData;

	// private boolean isFunctionPointer;

	private boolean foundManagedProperty;
	private boolean isGC;
	// private boolean isPin;
	private boolean isPinPointer;
	private boolean isCLIProperty;
	private boolean isCLIArray;
	// private boolean isCLI;
	private int arrayRank;
	private boolean noProperties;
	private boolean noCV;

	// TODO: Name this better once understood. For now, special pointer.
	String special;

	private MDQualification qual;
	private MDCVMod thisPointerCVMod; // TODO: check if EFI or CV portion
	// private String basedName;
	private MDBasedAttribute basedType;

	public MDCVMod(MDMang dmang) {
		super(dmang);
	}

	private enum CvPrefix {
		ptr64, unaligned, restrict
	}

	private List<CvPrefix> prefixList = new ArrayList<>();

	public void clearProperties() {
		noProperties = true;
	}

	public boolean hasProperties() {
		return !noProperties; // double negative
	}

	public void clearCV() {
		noCV = true;
	}

	public boolean hasCV() {
		return !noCV; // double negative
	}

	private enum CvModifierType {
		// other is being used (diff from plain) for TEMPLATE types (need qual
		// to be output)
		plain,
		pointer,
		reference,
		refref,
		carrot, // TODO: eliminate with old code
		percent, // TODO: eliminate with old code
		functionpointer, // TODO: eliminate with old code
		functionreference, // TODO: eliminate with old code
		array,
		question,
		other
	}

	private CvModifierType modType = CvModifierType.plain;

	public void setArrayType() {
		modType = CvModifierType.array;
	}

	public void setPointerType() {
		modType = CvModifierType.pointer;
	}

	public void setReferenceType() {
		modType = CvModifierType.reference;
	}

	public void setRefRefTemplateParameter() {
		modType = CvModifierType.refref;
	}

	// public void setCarrotType() {
	// modType = cvModifierType.carrot;
	// }
	//
	// public void setPercentType() {
	// modType = cvModifierType.percent;
	// }
	//
	public void setOtherType() {
		modType = CvModifierType.other;
	}

	public void setQuestionType() {
		modType = CvModifierType.question;
	}

	public boolean isPointerType() {
		return (modType == CvModifierType.pointer);
	}

	public boolean isReferenceType() {
		return (modType == CvModifierType.reference);
	}

	public boolean isFunctionPointerType() {
		return (isFunction && (modType == CvModifierType.pointer));
	}

	public boolean isFunctionReferenceType() {
		return (isFunction && (modType == CvModifierType.reference));
	}

	public boolean isArrayType() {
		return (modType == CvModifierType.array);
	}

	public boolean isOtherType() {
		return (modType == CvModifierType.other);
	}

	public boolean isQuestionType() {
		return (modType == CvModifierType.question);
	}

	public MDCVMod getThisPointerMDCVMod() {
		return thisPointerCVMod;
	}

	public boolean isPointer64() {
		return isPointer64;
	}

	public void setGC() {
		isGC = true;
	}

	public boolean isGC() {
		return isGC;
	}

	public void setPinPointer() {
		isPinPointer = true;
	}

	public boolean isPinPointer() {
		return isPinPointer;
	}

	public void setCLIProperty() {
		isCLIProperty = true;
	}

	public boolean isCLIProperty() {
		return isCLIProperty;
	}

	public void setCLIArray() {
		isCLIArray = true;
	}

	public boolean isCLIArray() {
		return isCLIArray;
	}

	public boolean isUnaligned() {
		return isUnaligned;
	}

	public boolean isRestricted() {
		return isRestricted;
	}

	public void setConst() {
		isConst = true;
	}

	public void clearConst() {
		isConst = false;
	}

	public boolean isConst() {
		return isConst;
	}

	public void setVolatile() {
		isVolatile = true;
	}

	public void clearVolatile() {
		isVolatile = false;
	}

	public boolean isVolatile() {
		return isVolatile;
	}

	public void setThisPointerMod() {
		isThisPointerMod = true;
	}

	public String getBasedName() {
		if (basedType == null) {
			return null;
		}
		return basedType.toString();
	}

	public boolean isBased() {
		return (basedType != null);
	}

	// public String getBasedName() {
	// return basedName;
	// }
	//
	// public boolean isBased() {
	// return !(basedName == null || "".equals(basedName));
	// }
	//
	public boolean isMember() {
		return isMember;
	}

	public boolean isFunction() {
		return isFunction;
	}

	public void setIsFunction() {
		isFunction = true;
	}

	public boolean isData() {
		return isData;
	}

	public String getMemberScope() {
		if (qual == null) {
			return null;
		}
		return qual.toString();
	}

	// Added 20170412 to try have available to get MSFT affect on this "invalid"
	// condition.
	public boolean isBasedPtrBased() {
		return (isBased && basedType.isBasedPtrBased());
	}

	public void checkInvalidSymbol() throws MDException {
		if (isFunction && (foundManagedProperty || (prefixList.size() != 0))) {
			throw new MDException(
				"EFI and Managed Properies not permitted for function pointer/reference");
		}
		// if (isFunction &&
		// !((modType == cvModifierType.functionpointer) || (modType ==
		// cvModifierType.pointer) ||
		// (modType == cvModifierType.functionreference) ||
		// (modType == cvModifierType.reference) || (modType ==
		// cvModifierType.array))) {
		// TODO: for refactoring... currently, "plain" should only now be for
		// MDModifierType
		// base (which should only be for '?' parsing).
		// 20170530: if (isFunction && (modType == cvModifierType.plain)) {
		// TODO: for refactoring... currently, "plain" should only now be for
		// MDModifierType base
		// (which should only be for '?' parsing).
		// if (isFunction &&
		// ((modType != cvModifierType.pointer) && (modType !=
		// cvModifierType.reference))) {
		// TODO: for refactoring... currently, "plain" should only now be for
		// MDModifierType
		// base (which should only be for '?' parsing).
		if (isFunction && (modType == CvModifierType.question)) {
			throw new MDException("Function refType only permitted on pointer or reference");
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		if (hasProperties()) {
			// Can have an initial set of EFI, but not required.
			// Can have multiple managed properties, but must have something
			// from an EFI set
			// in between them.
			parseEFGHI();
			while (parseManagedProperty() && parseEFGHI()) {
				// empty loop--work done in the test condition: assumes correct
				// left-to-right
				// processing of test components
			}
		}
		if (hasCV()) {
			parseCV();
		}
		checkInvalidSymbol();
	}

	private boolean parseEFGHI() throws MDException {
		boolean prefixDone = false;
		boolean foundOne = false;
		while (!prefixDone) {
			switch (dmang.peek()) {
				case 'E':
					dmang.parseInfoPush(0, "__ptr64");
					dmang.increment();
					isPointer64 = true;
					foundOne = true;
					prefixList.add(CvPrefix.ptr64);
					dmang.parseInfoPop();
					break;
				case 'F':
					dmang.parseInfoPush(0, "__unaligned");
					dmang.increment();
					isUnaligned = true;
					foundOne = true;
					prefixList.add(CvPrefix.unaligned);
					dmang.parseInfoPop();
					break;
				case 'G':
					// MDMANG SPECIALIZATION USED.
					if (dmang.allowCVModLRefRRef()) {
						if (!isThisPointerMod) {
							throw new MDException("LRef only permitted on 'this' pointer");
						}
						dmang.parseInfoPush(0, "LRef");
						dmang.increment();
						isLRef = true;
						foundOne = true;
						dmang.parseInfoPop();
					}
					else {
						prefixDone = true;
					}
					break;
				case 'H':
					// MDMANG SPECIALIZATION USED.
					if (dmang.allowCVModLRefRRef()) {
						if (!isThisPointerMod) {
							throw new MDException("RRef only permitted on 'this' pointer");
						}
						dmang.parseInfoPush(0, "RRef");
						dmang.increment();
						isRRef = true;
						foundOne = true;
						dmang.parseInfoPop();
					}
					else {
						prefixDone = true;
					}
					break;
				case 'I':
					dmang.parseInfoPush(0, "__restricted");
					dmang.increment();
					isRestricted = true;
					foundOne = true;
					prefixList.add(CvPrefix.restrict);
					dmang.parseInfoPop();
					break;
				default:
					prefixDone = true;
					break;
			}
		}
		return foundOne;
	}

	public boolean parseManagedProperty() throws MDException {
		// TODO: work on this.
		// $A for __gc and $B for __pin
		// What are these?
		// Others?
		//
		if (dmang.peek() != '$') {
			return false;
		}
		dmang.increment();
		// TODO: work on this.
		// $A for __gc and $B for __pin
		// What are these?
		// Others?
		char code = dmang.peek();
		switch (code) {
			case 'A':
				dmang.increment();
				setGC();
				// if (isPointerType()) {
				// setCarrotType();
				// }
				// else if (isReferenceType()) {
				// setPercentType();
				// }
				break;
			case 'B':
				dmang.increment();
				// if ((modType == cvModifierType.pointer) ||
				// (modType == cvModifierType.functionpointer) ||
				// (modType == cvModifierType.carrot) ||
				// (modType == cvModifierType.percent) ||
				// (modType == cvModifierType.reference) ||
				// (modType == cvModifierType.functionreference)) {
				if ((modType != CvModifierType.plain) && (modType != CvModifierType.other)) {
					setPinPointer();
				}
				// if ((modType != cvModifierType.plain) && (modType !=
				// cvModifierType.array) &&
				// (modType != cvModifierType.other)) {
				// setPinPointer();
				// }
				// if ((modType != cvModifierType.plain) && (modType !=
				// cvModifierType.array)) {
				// setPinPointer();
				// }
				break;
			case 'C':
				dmang.increment();
				setCLIProperty();
				if (modType == CvModifierType.plain) {
					setPointerType();
				}
				// setPercentType();
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9': {
				setCLIArray();
				dmang.increment();
				if (code >= '0' && code <= '9') {
					arrayRank = code - '0';
				}
				else if (code >= 'A' && code <= 'F') {
					arrayRank = code - 'A' + 10;
				}
				else {
					throw new MDException("invalid cli:array rank");
				}
				code = dmang.getAndIncrement();
				// Upon fuzzing this, use ch - '0', but it will take any ASCII
				// character for this
				// second character. For instance, '!' so that if we have "1!", then
				// this is
				// ('1'-'0')*16 + ('!' - '0') = 1 * 16 + (-15) = 1. The second
				// character can
				// be beyond 'Z' as well as between '9' and 'A'.
				arrayRank = arrayRank * 16 + code - '0';
				// if (ch >= '0' && ch <= '9') {
				// arrayRank = arrayRank * 16 + ch - '0';
				// }
				// else if (ch >= 'A' && ch <= 'F') {
				// arrayRank = arrayRank * 16 + ch - 'A' + 10;
				// }
				// else {
				// throw new MDException("invalid cli:array rank");
				// }
				// 20160823 dmang.getAndIncrement(); //skip next character (seems it
				// can be any
				// character, except possibly '$')
				// 20160823 clearCV();
				break;
			}
			default:
				// Could be others.
				throw new MDException("unknown managed property: " + code);
		}
		foundManagedProperty = true;
		return true;
	}

	private void parseCV() throws MDException {
		// Note: Codes E, F, G, and H used to contain "far" and now are
		// different.
		// E = "far" ; F = "const far" ; G = "volatile far" ; H = "const
		// volatile far"
		// However, E and F are now prefixes; and G and H are grouped with
		// others.
		// There is probably historical reason (look into this more?) for, for
		// example, C, G, and K to be the same. Perhaps C was the small memory
		// model,
		// G had far pointers, and K was huge????
		char code = dmang.getAndIncrement();
		switch (code) {
			case 'A':
				isData = true;
				break;
			case 'B':
			case 'J':
				isData = true;
				isConst = true;
				break;
			case 'C':
			case 'G':
			case 'K':
				isData = true;
				isVolatile = true;
				break;
			case 'D':
			case 'H':
			case 'L':
				isData = true;
				isConst = true;
				isVolatile = true;
				break;
			case 'M':
				isData = true;
				isBased = true;
				break;
			case 'N':
				isData = true;
				isConst = true;
				isBased = true;
				break;
			case 'O':
				isData = true;
				isVolatile = true;
				isBased = true;
				break;
			case 'P':
				isData = true;
				isConst = true;
				isVolatile = true;
				isBased = true;
				break;
			case 'Q':
			case 'U':
			case 'Y':
				isData = true;
				isMember = true;
				break;
			case 'R':
			case 'V':
			case 'Z':
				isData = true;
				isConst = true;
				isMember = true;
				break;
			case 'S':
			case 'W':
			case '0':
				isData = true;
				isVolatile = true;
				isMember = true;
				break;
			case 'T':
			case 'X':
			case '1':
				isData = true;
				isConst = true;
				isVolatile = true;
				isMember = true;
				break;
			case '2':
				isData = true;
				isBased = true;
				isMember = true;
				break;
			case '3':
				isData = true;
				isConst = true;
				isBased = true;
				isMember = true;
				break;
			case '4':
				isData = true;
				isVolatile = true;
				isBased = true;
				isMember = true;
				break;
			case '5':
				isData = true;
				isConst = true;
				isVolatile = true;
				isBased = true;
				isMember = true;
				break;
			case '6':
			case '7':
				isFunction = true;
				break;
			case '8':
			case '9':
				isFunction = true;
				isMember = true;
				break;
			case '_':
				isFunction = true;
				char code1 = dmang.getAndIncrement();
				switch (code1) {
					case 'A':
					case 'B':
						isBased = true;
						break;
					case 'C':
					case 'D':
						isBased = true;
						isMember = true;
						break;
					default:
						throw new MDException("CV code not expected: _" + code1);
				}
				break;
			case MDMang.DONE:
				break;
			// case '$':
			// dmang.previous();
			// break;
			default:
				throw new MDException("CV code not expected: " + code);
		}
		if (isMember) {
			qual = new MDQualification(dmang);
			qual.parse();
			if (isFunction) {
				// TODO: check if EFI or CV portion-->I think might be any all
				// const volatile __ptr64.
				thisPointerCVMod = new MDCVMod(dmang);
				thisPointerCVMod.setThisPointerMod();
				thisPointerCVMod.parse();
			}
		}
		if (isBased) {
			basedType = new MDBasedAttribute(dmang);
			basedType.parse();
		}
	}

	// TODO 20160210... need to keep typeName in this object... and/or merge
	// this with
	// MDModifierType...
	public void insertManagedPropertiesPrefix(StringBuilder builder) {
		// Reason: need to keep VarName (coming in from builder) separate from
		// *, &, etc.,
		// which gets inserted inside the EIF
		if (isCLIArray) { // Supersedes Pin Pointer
			dmang.insertString(builder, prefixEmitClauseCLIArray);
		}
		else if (isPinPointer) {
			dmang.insertString(builder, prefixEmitClausePinPointer);
		}
	}

	public void insertManagedPropertiesSuffix(StringBuilder builder) {
		if (isCLIArray) {
			dmang.appendString(builder, " ");
			if (arrayRank > 1) {
				dmang.appendString(builder, ",");
				dmang.appendString(builder, Integer.toUnsignedString(arrayRank));
			}
			dmang.appendString(builder, suffixEmitClauseCLIArray);
			// if (arrayRank > 1) {
			// builder.insertString(Integer.toUnsignedString(arrayRank));
			// builder.insertString(",");
			// }
		}
		else if (isPinPointer) {
			// dmang.appendString(builder, " ");
			dmang.appendString(builder, suffixEmitClausePinPointer);
		}
	}

	public void insertManagedProperties(StringBuilder builder) {
		if (isCLIArray) {
			dmang.insertString(builder, prefixEmitClauseCLIArray);
			dmang.appendString(builder, " ");
			if (arrayRank > 1) {
				dmang.appendString(builder, ",");
				dmang.appendString(builder, Integer.toUnsignedString(arrayRank));
			}
			dmang.appendString(builder, suffixEmitClauseCLIArray);
		}
		else if (isPinPointer) {
			dmang.insertString(builder, prefixEmitClausePinPointer);
			dmang.appendString(builder, " ");
			dmang.appendString(builder, suffixEmitClausePinPointer);
		}
	}

	// ==============
	@Override
	public void insert(StringBuilder builder) {
		if (isCLIArray) {
			// 20160823
			// insertPrefixEI(xbuilder); //20160930 removed, because parsed, but
			// not inserted.
			// 20160929
			// xbuilder.insertSpacedString(suffixEmitClauseCLIArray);
			// if (arrayRank > 1) {
			// xbuilder.insertString(Integer.toUnsignedString(arrayRank));
			// xbuilder.insertString(",");
			// }
			// insertF(builder); //20160930 removed, because parsed, but not
			// inserted.
			// 20160823
			// StringBuilder builder = new StringBuilder();
			// emitPrefixEI(builder);
			// MDMang.insertSpacedString(builder, suffixEmitClauseCLIArray);
			//// emitModType(builder);
			// emitF(builder);
			// xbuilder.insertSpacedString(builder.toString());
		}
		else {
			if (isPinPointer) {
				// 20160929
				// xbuilder.insertSpacedString(suffixEmitClausePinPointer);
			}
			StringBuilder modBuilder = new StringBuilder();
			insertGH(modBuilder);
			insertPrefixEI(modBuilder);
			insertModType(modBuilder);
			insertF(modBuilder);
			insertCV(modBuilder);
			dmang.insertSpacedString(builder, modBuilder.toString());
			// if ("BASED5".equals(emitCV(cvStringBuilder))) {
			// xbuilder.insertSpacedString(null);
			// }
			// else {
			// xbuilder.insertSpacedString(cvStringBuilder.toString());
			// }
		}
	}

	public String getModTypeAnnotation() {
		String annotation = "";
		switch (modType) {
			case pointer:
				if (isCLIProperty()) { // highest precedence, even if isGC is set.
					annotation = PERCENT;
				}
				else if (isGC()) {
					annotation = CARROT;
				}
				else {
					annotation = POINTER;
				}
				break;
			case reference:
				if (isCLIProperty()) { // highest precedence, even if isGC is set.
					annotation = PERCENT;
				}
				else if (isGC()) {
					annotation = PERCENT;
				}
				else {
					annotation = REFERENCE;
				}
				break;
			case refref:
				if (isCLIProperty()) { // highest precedence, even if isGC is set.
					annotation = PERCENT;
				}
				else if (isGC()) {
					annotation = PERCENT;
				}
				else {
					annotation = REFREF;
				}
				break;
			case array:
				// annotation = "";
				break;
			case other:
			case plain:
			default:
				if (isCLIProperty()) {
					annotation = PERCENT;
					// dmang.insertSpacedString(builder, annotation);
				}
				break;
		}
		return annotation;
	}

	public void insertModType(StringBuilder builder) {
		String annotation = getModTypeAnnotation();
		dmang.insertSpacedString(builder, annotation);
		// if( modType != cvModifierType.array) {
		// if (isFunction) {
		// dmang.insertSpacedString(builder, annotation);
		// }
		// else { //want both isData and no marking
		// //if (isData) {
		// dmang.insertSpacedString(builder, annotation);
		// }
		// }
		// switch (modType) {
		// case pointer:
		// if (isCLIProperty()) { //highest precedence, even if isGC is set.
		// annotation = PERCENT;
		// }
		// else if (isGC()) {
		// annotation = CARROT;
		// }
		// else {
		// annotation = POINTER;
		// }
		// if (isFunction) {
		// dmang.insertSpacedString(builder, annotation);
		// }
		// else { //want both isData and no marking
		// //if (isData) {
		// dmang.insertSpacedString(builder, annotation);
		// }
		// break;
		// case reference:
		// if (isCLIProperty()) { //highest precedence, even if isGC is set.
		// annotation = PERCENT;
		// }
		// else if (isGC()) {
		// annotation = PERCENT;
		// }
		// else {
		// annotation = REFERENCE;
		// }
		// if (isData) {
		// dmang.insertSpacedString(builder, annotation);
		// }
		// else if (isFunction) {
		// dmang.insertString(builder, annotation);
		// }
		// break;
		// case refref:
		// if (isCLIProperty()) { //highest precedence, even if isGC is set.
		// annotation = PERCENT;
		// }
		// else if (isGC()) {
		// annotation = PERCENT;
		// }
		// else {
		// annotation = REFREF;
		// }
		// if (isData) {
		// dmang.insertSpacedString(builder, annotation);
		// }
		// else if (isFunction) {
		// dmang.insertString(builder, annotation);
		// }
		// break;
		// case array:
		// //do nothing (for now)... TODO: see if something should be done ([])
		// // while refactoring.
		// break;
		// case other:
		// case plain:
		// default:
		// if (isCLIProperty()) {
		// annotation = PERCENT;
		//// if (isData) {
		//// dmang.insertSpacedString(builder, annotation);
		//// }
		//// else if (isFunction) {
		//// dmang.insertString(builder, annotation);
		//// }
		//// dmang.insertString(builder, annotation);
		// dmang.insertSpacedString(builder, annotation);
		// }
		// //else do nothing
		// break;
		// }
	}

	// public void insertModType(StringBuilder builder) {
	// String annotation;
	// switch (modType) {
	// case pointer:
	// if (isCLIProperty()) { //highest precedence, even if isGC is set.
	// annotation = PERCENT;
	// }
	// else if (isGC()) {
	// annotation = CARROT;
	// }
	// else {
	// annotation = POINTER;
	// }
	// if (isFunction) {
	// dmang.insertSpacedString(builder, annotation);
	// }
	// else { //want both isData and no marking
	// //if (isData) {
	// dmang.insertSpacedString(builder, annotation);
	// }
	// break;
	// case reference:
	// if (isCLIProperty()) { //highest precedence, even if isGC is set.
	// annotation = PERCENT;
	// }
	// else if (isGC()) {
	// annotation = PERCENT;
	// }
	// else {
	// annotation = REFERENCE;
	// }
	// if (isData) {
	// dmang.insertSpacedString(builder, annotation);
	// }
	// else if (isFunction) {
	// dmang.insertString(builder, annotation);
	// }
	// break;
	// case refref:
	// if (isCLIProperty()) { //highest precedence, even if isGC is set.
	// annotation = PERCENT;
	// }
	// else if (isGC()) {
	// annotation = PERCENT;
	// }
	// else {
	// annotation = REFREF;
	// }
	// if (isData) {
	// dmang.insertSpacedString(builder, annotation);
	// }
	// else if (isFunction) {
	// dmang.insertString(builder, annotation);
	// }
	// break;
	// case array:
	// //do nothing (for now)... TODO: see if something should be done ([])
	// // while refactoring.
	// break;
	// case other:
	// case plain:
	// default:
	// if (isCLIProperty()) {
	// annotation = PERCENT;
	//// if (isData) {
	//// dmang.insertSpacedString(builder, annotation);
	//// }
	//// else if (isFunction) {
	//// dmang.insertString(builder, annotation);
	//// }
	//// dmang.insertString(builder, annotation);
	// dmang.insertSpacedString(builder, annotation);
	// }
	// //else do nothing
	// break;
	// }
	// }

	public void insertF(StringBuilder builder) {
		for (CvPrefix p : prefixList) {
			switch (p) {
				case unaligned:
					dmang.insertSpacedString(builder, UNALIGNED);
					break;
				default:
					break;
			}
		}
	}

	public void insertGH(StringBuilder builder) {
		if (isRRef) {
			dmang.insertString(builder, RREF);
		}
		if (isLRef) {
			dmang.insertString(builder, LREF);
		}
	}

	public void insertPrefixEI(StringBuilder builder) {
		ListIterator<CvPrefix> li = prefixList.listIterator(prefixList.size());
		StringBuilder EIBuilder = new StringBuilder();
		while (li.hasPrevious()) {
			CvPrefix p = li.previous();
			switch (p) {
				case ptr64:
					dmang.insertSpacedString(EIBuilder, PTR64);
					break;
				case restrict:
					dmang.insertSpacedString(EIBuilder, RESTRICT);
					break;
				default:
					break;
			}
		}
		dmang.insertString(builder, EIBuilder.toString());
	}

	public void insertCV(StringBuilder builder) {
		if (isMember) {
			if (qual != null) {
				// TODO: this line helps for some, but hurts other (see
				// moremoremore2_variation042,
				// 043, 044)
				// if ((modType != cvModifierType.plain) && (modType !=
				// cvModifierType.question)) {
				if (modType != CvModifierType.plain) {
					if (qual.hasContent()) {
						dmang.insertString(builder, "::");
						qual.insert(builder);
					}
				}
			}
			// dmang.insertString(builder, " ");
		}
		if (isBased) {
			basedType.insert(builder);
			if (basedType.isBasedPtrBased()) {
				return;
			}
		}
		if (isVolatile) {
			dmang.insertSpacedString(builder, VOLATILE);
		}
		if (isConst) {
			dmang.insertSpacedString(builder, CONST);
		}
	}
}
