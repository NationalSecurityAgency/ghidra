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
package mdemangler.naming;

import mdemangler.*;
import mdemangler.datatype.MDDataTypeParser;
import mdemangler.object.MDObjectCPP;

// TODO: 20140422 Found document at
//  http://vgce.googlecode.com/svn-history/r238/trunk/docs/nameDecoration.txt
// that has further interpretations (right or wrong) for:
// _W: `omni callsig'()
// __E: `dynamic initializer for 'function''()
// __F: `dynamic atexit destructor for 'function''()
// __G: `vector copy constructor iterator'()
// __H: `vector vbase copy constructor iterator'()
// __I: `managed vector copy constructor iterator'()
// __J: `local static thread guard'()

// Another page:
//  http://www.geoffchappell.com/studies/msvc/language/decoration/name.htm, has some
//  additional ones
// _P: `udt returning'
// _Q: `EH'

/**
 * This class represents a special name (following wiki page naming convention for
 * Microsoft Demangler) type of MDBasicName.  Special names tend to be C++ operator
 * names.
 */
public class MDSpecialName extends MDParsableItem {
	private String name;
	// TODO: evaluate where this should go: pass "type" in and assign directly?  call methods to
	// retrieve these from outside?  This pertains to all of these: isConstructor, isDestructor,
	// isTypeCast, isQualified, RTTINumber.
	private boolean isConstructor;
	private boolean isDestructor;
	private boolean isTypeCast;
	private boolean isQualified;
	private int rttiNumber = -1;
	private MDString mstring;
	private String castTypeString;

	public MDSpecialName(MDMang dmang, int startIndexOffset) {
		super(dmang, startIndexOffset);
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public void setCastTypeString(String castTypeString) {
		this.castTypeString = castTypeString;
	}

	public boolean isConstructor() {
		return isConstructor;
	}

	public boolean isDestructor() {
		return isDestructor;
	}

	public boolean isTypeCast() {
		return isTypeCast;
	}

	public boolean isQualified() {
		return isQualified;
	}

	/**
	 * Returns the RTTI number:{0-4, or -1 if not an RTTI}
	 * @return int RTTI number:{0-4, or -1 if not an RTTI}
	 */
	public int getRTTINumber() {
		return rttiNumber;
	}

	public boolean isString() {
		return (mstring != null);
	}

	public MDString getMDString() {
		return mstring;
	}

	public byte[] getBytes() {
		return mstring.getBytes();
	}

	@Override
	public void insert(StringBuilder builder) {
		dmang.insertString(builder, name);
		if (isTypeCast && castTypeString != null) {
			dmang.appendString(builder, " ");
			dmang.appendString(builder, castTypeString);
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		isQualified = true;
		switch (dmang.getAndIncrement()) {
			case '0':
				dmang.parseInfoPush(1, "constructor");
				isConstructor = true;
				name = "";
				dmang.parseInfoPop();
				break;
			case '1':
				dmang.parseInfoPush(1, "destructor");
				isDestructor = true;
				name = "";
				dmang.parseInfoPop();
				break;
			case '2':
				dmang.parseInfoPush(1, "operator new");
				name = "operator new";// NEW
				dmang.parseInfoPop();
				break;
			case '3':
				dmang.parseInfoPush(1, "operator delete");
				name = "operator delete";// DELETE
				dmang.parseInfoPop();
				break;
			case '4':
				dmang.parseInfoPush(1, "operator=");
				name = "operator=";// Assignment
				dmang.parseInfoPop();
				break;
			case '5':
				dmang.parseInfoPush(1, "operator>>");
				name = "operator>>";// Right shift
				dmang.parseInfoPop();
				break;
			case '6':
				dmang.parseInfoPush(1, "operator<<");
				name = "operator<<";// Left shift
				dmang.parseInfoPop();
				break;
			case '7':
				dmang.parseInfoPush(1, "operator!");
				name = "operator!";// Logical NOT
				dmang.parseInfoPop();
				break;
			case '8':
				dmang.parseInfoPush(1, "operator==");
				name = "operator==";// Equality
				dmang.parseInfoPop();
				break;
			case '9':
				dmang.parseInfoPush(1, "operator!=");
				name = "operator!=";// Inequality
				dmang.parseInfoPop();
				break;
			case 'A':
				dmang.parseInfoPush(1, "operator[]");
				name = "operator[]";// Array subscript
				dmang.parseInfoPop();
				break;
			case 'B':
				dmang.parseInfoPush(1, "operator [type cast]");
				name = "operator";// type cast
				isTypeCast = true;
				dmang.parseInfoPop();
				break;
			case 'C':
				dmang.parseInfoPush(1, "operator->");
				name = "operator->";// Pointer dereference
				dmang.parseInfoPop();
				break;
			case 'D':
				dmang.parseInfoPush(1, "operator*");
				name = "operator*";// Multiplication
				dmang.parseInfoPop();
				break;
			case 'E':
				dmang.parseInfoPush(1, "operator++");
				name = "operator++";// Increment
				dmang.parseInfoPop();
				break;
			case 'F':
				dmang.parseInfoPush(1, "operator--");
				name = "operator--";// Decrement
				dmang.parseInfoPop();
				break;
			case 'G':
				dmang.parseInfoPush(1, "operator-");
				name = "operator-";// Subtraction
				dmang.parseInfoPop();
				break;
			case 'H':
				dmang.parseInfoPush(1, "operator+");
				name = "operator+";// Addition
				dmang.parseInfoPop();
				break;
			case 'I':
				dmang.parseInfoPush(1, "operator& (address-of)");
				name = "operator&";// Address-of
				dmang.parseInfoPop();
				break;
			case 'J':
				dmang.parseInfoPush(1, "operator->*");
				name = "operator->*";// Pointer-to-member selection
				dmang.parseInfoPop();
				break;
			case 'K':
				dmang.parseInfoPush(1, "operator/");
				name = "operator/";// Division
				dmang.parseInfoPop();
				break;
			case 'L':
				dmang.parseInfoPush(1, "operator%");
				name = "operator%";// Modulus
				dmang.parseInfoPop();
				break;
			case 'M':
				dmang.parseInfoPush(1, "operator<");
				name = "operator<";// Less than
				dmang.parseInfoPop();
				break;
			case 'N':
				dmang.parseInfoPush(1, "operator<=");
				name = "operator<=";// Less than or equal to
				dmang.parseInfoPop();
				break;
			case 'O':
				dmang.parseInfoPush(1, "operator>");
				name = "operator>";// Greater than
				dmang.parseInfoPop();
				break;
			case 'P':
				dmang.parseInfoPush(1, "operator>=");
				name = "operator>=";// Greater than or equal to
				dmang.parseInfoPop();
				break;
			case 'Q':
				dmang.parseInfoPush(1, "operator,");
				name = "operator,";// Comma
				dmang.parseInfoPop();
				break;
			case 'R':
				dmang.parseInfoPush(1, "operator()");
				name = "operator()";// Function call
				dmang.parseInfoPop();
				break;
			case 'S':
				dmang.parseInfoPush(1, "operator~");
				name = "operator~";// One's complement
				dmang.parseInfoPop();
				break;
			case 'T':
				dmang.parseInfoPush(1, "operator^");
				name = "operator^";// Exclusive OR
				dmang.parseInfoPop();
				break;
			case 'U':
				dmang.parseInfoPush(1, "operator|");
				name = "operator|";// Bitwise inclusive OR
				dmang.parseInfoPop();
				break;
			case 'V':
				dmang.parseInfoPush(1, "operator&&");
				name = "operator&&";// Logical AND
				dmang.parseInfoPop();
				break;
			case 'W':
				dmang.parseInfoPush(1, "operator||");
				name = "operator||";// Logical OR
				dmang.parseInfoPop();
				break;
			case 'X':
				dmang.parseInfoPush(1, "operator*=");
				name = "operator*=";// Multiplication/assignment
				dmang.parseInfoPop();
				break;
			case 'Y':
				dmang.parseInfoPush(1, "operator+=");
				name = "operator+=";// Addition/assignment
				dmang.parseInfoPop();
				break;
			case 'Z':
				dmang.parseInfoPush(1, "operator-=");
				name = "operator-=";// Subtraction/assignment
				dmang.parseInfoPop();
				break;
			case '_':
				switch (dmang.getAndIncrement()) {
					case '0':
						dmang.parseInfoPush(2, "operator/=");
						name = "operator/=";// Division/assignment
						dmang.parseInfoPop();
						break;
					case '1':
						dmang.parseInfoPush(2, "operator%=");
						name = "operator%=";// Modulus/assignment
						dmang.parseInfoPop();
						break;
					case '2':
						dmang.parseInfoPush(2, "operator>>=");
						name = "operator>>=";// Right shift/assignment
						dmang.parseInfoPop();
						break;
					case '3':
						dmang.parseInfoPush(2, "operator<<=");
						name = "operator<<=";// Left shift/assignment
						dmang.parseInfoPop();
						break;
					case '4':
						dmang.parseInfoPush(2, "operator&=");
						name = "operator&=";// Bitwise AND/assignment
						dmang.parseInfoPop();
						break;
					case '5':
						dmang.parseInfoPush(2, "operator|=");
						name = "operator|=";// Bitwise inclusive OR/assignment
						dmang.parseInfoPop();
						break;
					case '6':
						dmang.parseInfoPush(2, "operator^=");
						name = "operator^=";// Exclusive OR/assignment
						dmang.parseInfoPop();
						break;
					case '7':
						dmang.parseInfoPush(2, "vftable");
						name = "`vftable'";// TODO - data
						dmang.parseInfoPop();
						break;
					case '8':
						dmang.parseInfoPush(2, "vbtable");
						name = "`vbtable'";// TODO - data
						dmang.parseInfoPop();
						break;
					case '9':
						dmang.parseInfoPush(2, "vcall");
						name = "`vcall'";
						dmang.parseInfoPop();
						break;
					case 'A':
						dmang.parseInfoPush(2, "typeof");
						name = "`typeof'";
						dmang.parseInfoPop();
						break;
					case 'B':
						// are these always static?...if not update this and handle elsewhere
						dmang.parseInfoPush(2, "local static guard");
						name = "`local static guard'";
						dmang.parseInfoPop();
						break;
					case 'C':
						dmang.parseInfoPush(2, "string");
						mstring = new MDString(dmang);
						mstring.parse();
						name = mstring.toString();
						dmang.parseInfoPop();
						break;
					case 'D':
						dmang.parseInfoPush(2, "vbase destructor");
						name = "`vbase destructor'";
						dmang.parseInfoPop();
						break;
					case 'E':
						dmang.parseInfoPush(2, "vector deleting destructor");
						name = "`vector deleting destructor'";
						dmang.parseInfoPop();
						break;
					case 'F':
						dmang.parseInfoPush(2, "default constructor closure");
						name = "`default constructor closure'";
						dmang.parseInfoPop();
						break;
					case 'G':
						dmang.parseInfoPush(2, "scalar deleting destructor");
						name = "`scalar deleting destructor'";
						dmang.parseInfoPop();
						break;
					case 'H':
						dmang.parseInfoPush(2, "vector constructor iterator");
						name = "`vector constructor iterator'";
						dmang.parseInfoPop();
						break;
					case 'I':
						dmang.parseInfoPush(2, "vector destructor iterator");
						name = "`vector destructor iterator'";
						dmang.parseInfoPop();
						break;
					case 'J':
						dmang.parseInfoPush(2, "vector vbase constructor iterator");
						name = "`vector vbase constructor iterator'";
						dmang.parseInfoPop();
						break;
					case 'K':
						dmang.parseInfoPush(2, "virtual displacement map");
						name = "`virtual displacement map'";
						dmang.parseInfoPop();
						break;
					case 'L':
						dmang.parseInfoPush(2, "eh vector constructor iterator");
						name = "`eh vector constructor iterator'";
						dmang.parseInfoPop();
						break;
					case 'M':
						dmang.parseInfoPush(2, "eh vector destructor iterator");
						name = "`eh vector destructor iterator'";
						dmang.parseInfoPop();
						break;
					case 'N':
						dmang.parseInfoPush(2, "eh vector vbase constructor iterator");
						name = "`eh vector vbase constructor iterator'";
						dmang.parseInfoPop();
						break;
					case 'O':
						dmang.parseInfoPush(2, "copy constructor closure");
						name = "`copy constructor closure'";
						dmang.parseInfoPop();
						break;
					case 'P':  // TODO: UNKNOWN guess (see note at top)
						dmang.parseInfoPush(2, "udt returning");
						MDSpecialName nestedSpecialName = new MDSpecialName(dmang, 0);
						nestedSpecialName.parse();
						StringBuilder nestedBuilder = new StringBuilder();
						nestedSpecialName.insert(nestedBuilder);
						dmang.insertString(nestedBuilder, "`udt returning'");
						name = nestedBuilder.toString();
						dmang.parseInfoPop();
						break;
					case 'Q': // TODO: UNKNOWN guess (see note at top)
						dmang.parseInfoPush(2, "EH");
						// 20160909: Looks blank to me for my manufactured tests... would like
						//  to find real symbols.
						name = "";
						// 20160909CHANGED THIS:  name = "`EH'"; //must have more embedding as
						//  we haven't gotten undname to return yet.
						dmang.parseInfoPop();
						break;
					case 'R':
						isQualified = false;
						switch (dmang.getAndIncrement()) {
							case '0':
								rttiNumber = 0;
								dmang.parseInfoPush(3, "RTTI Type Descriptor");
								// We had one of these _R0 where "void" needed to be permitted.
								// TODO: evaluate all embedded object types for possible need
								//  to push an xVoidPermitted context!!!!!
								MDType tmpMDType = MDDataTypeParser.parseDataType(dmang, false);
								tmpMDType.parse();
								StringBuilder RTTIBuilder = new StringBuilder();
								tmpMDType.insert(RTTIBuilder);
								dmang.appendString(RTTIBuilder, " `RTTI Type Descriptor'");
								name = RTTIBuilder.toString();
								dmang.parseInfoPop();
								break;
							case '1':
								rttiNumber = 1;
								// Checked all combinations for these (0-9,A@-encoded,?-signed) 20140430
								dmang.parseInfoPush(3, "RTTI Base Class Descriptor at [...]");
								MDSignedEncodedNumber a = new MDSignedEncodedNumber(dmang);
								a.parse();
								MDSignedEncodedNumber b = new MDSignedEncodedNumber(dmang);
								b.parse();
								MDSignedEncodedNumber c = new MDSignedEncodedNumber(dmang);
								c.parse();
								MDEncodedNumber d = new MDEncodedNumber(dmang);
								d.parse();
								name = "`RTTI Base Class Descriptor at (" + a + "," + b + "," + c +
									"," + d + ")'";
								dmang.parseInfoPop();
								break;
							case '2':
								rttiNumber = 2;
								dmang.parseInfoPush(3, "RTTI Base Class Array");
								name = "`RTTI Base Class Array'";
								dmang.parseInfoPop();
								break;
							case '3':
								rttiNumber = 3;
								dmang.parseInfoPush(3, "RTTI Class Hierarchy Descriptor");
								name = "`RTTI Class Hierarchy Descriptor'";
								dmang.parseInfoPop();
								break;
							case '4':
								rttiNumber = 4;
								dmang.parseInfoPush(3, "RTTI Complete Object Locator");
								name = "`RTTI Complete Object Locator'";
								dmang.parseInfoPop();
								break;
						}
						break;
					case 'S':
						dmang.parseInfoPush(2, "local vftable");
						name = "`local vftable'";
						dmang.parseInfoPop();
						break;
					case 'T':
						dmang.parseInfoPush(2, "local vftable constructor closure");
						name = "`local vftable constructor closure'";
						dmang.parseInfoPop();
						break;
					case 'U':
						dmang.parseInfoPush(2, "operator new[]");
						name = "operator new[]";
						dmang.parseInfoPop();
						break;
					case 'V':
						dmang.parseInfoPush(2, "operator delete[]");
						name = "operator delete[]";
						dmang.parseInfoPop();
						break;
					case 'W':
						// TODO: UNKNOWN guess (see note at top), undname does not return this
						//  value... might need special options (embedded objects)
						// TODO: UINFO: Special reserved value: OC_omni_callsig_init
						dmang.parseInfoPush(2, "omni callsig");
						name = "`omni callsig'";
						dmang.parseInfoPop();
						break;
					case 'X':
						dmang.parseInfoPush(2, "placement delete closure");
						name = "`placement delete closure'";
						dmang.parseInfoPop();
						break;
					case 'Y':
						dmang.parseInfoPush(2, "placement delete[] closure");
						name = "`placement delete[] closure'";
						dmang.parseInfoPop();
						break;
					case '_':
						switch (dmang.getAndIncrement()) {
							case 'A':
								dmang.parseInfoPush(3, "managed vector constructor iterator");
								name = "`managed vector constructor iterator'";
								dmang.parseInfoPop();
								break;
							case 'B':
								dmang.parseInfoPush(3, "managed vector destructor iterator");
								name = "`managed vector destructor iterator'";
								dmang.parseInfoPop();
								break;
							case 'C':
								dmang.parseInfoPush(3, "eh vector copy constructor iterator");
								name = "`eh vector copy constructor iterator'";
								dmang.parseInfoPop();
								break;
							case 'D':
								dmang.parseInfoPush(3, "eh vector vbase copy constructor iterator");
								name = "`eh vector vbase copy constructor iterator'";
								dmang.parseInfoPop();
								break;
							case 'E': {
								dmang.parseInfoPush(3, "dynamic initializer for [Object]");
								StringBuilder builder = new StringBuilder();
								// TODO... 20160812: This looks like new ObjectCPP and ObjectC
								if (dmang.peek() == '?') {
									// 20170418 TODO: fuzz this to see if we need to do a
									//  dmang.pushModifierContext();
									MDObjectCPP objectCPP = new MDObjectCPP(dmang);
									objectCPP.parse();
									// MDMANG SPECIALIZATION USED.
									objectCPP = dmang.getEmbeddedObject(objectCPP);
									// 20170418 TODO: see NOTE above... we might need a
									//  dmang.popContext();
									objectCPP.insert(builder);
									// MDMANG SPECIALIZATION USED.
									// dmang.parseEmbeddedObjectQualification(builder);
									dmang.parseEmbeddedObjectSuffix();
								}
								else {
									// Note: Not all components of Basic Name can be parsed
									//  through this path, as there is an immediate test for
									//  '?' within its parsing, but a simple MDFragmentName
									//  here is also not correct, as it must be able to be put
									//  into backreference names.  Consulted UINFO, which
									//  indicates that MDBasicName is correct.
									MDBasicName basicName = new MDBasicName(dmang);
									basicName.parse();
									basicName.insert(builder);
								}
								dmang.appendString(builder, "''");
								dmang.insertString(builder, "`dynamic initializer for '");
								name = builder.toString();
								dmang.parseInfoPop();
							}
								break;
							case 'F': {
								dmang.parseInfoPush(3, "dynamic atexit destructor operator");
								StringBuilder builder = new StringBuilder();
								// TODO... 20160812: This looks like new ObjectCPP and ObjectC
								if (dmang.peek() == '?') {
									// 20170418 TODO: fuzz this to see if we need to do a
									//  dmang.pushModifierContext();
									MDObjectCPP objectCPP = new MDObjectCPP(dmang);
									objectCPP.parse();
									// MDMANG SPECIALIZATION USED.
									objectCPP = dmang.getEmbeddedObject(objectCPP);
									// 20170418 TODO: see NOTE above... we might need a
									//  dmang.popContext();
									objectCPP.insert(builder);
									// MDMANG SPECIALIZATION USED.
									// dmang.parseEmbeddedObjectQualification(builder);
									dmang.parseEmbeddedObjectSuffix();
								}
								else {
									// Note: Not all components of Basic Name can be parsed
									//  through this path, as there is an immediate test for
									//  '?' within its parsing, but a simple MDFragmentName
									//  here is also not correct, as it must be able to be
									//  put into backreference names.  Consulted UINFO, which
									//  indicates that MDBasicName is correct.
									MDBasicName basicName = new MDBasicName(dmang);
									basicName.parse();
									basicName.insert(builder);
								}
								dmang.appendString(builder, "''");
								dmang.insertString(builder, "`dynamic atexit destructor for '");
								name = builder.toString();
								dmang.parseInfoPop();
							}
								break;
							case 'G':
								dmang.parseInfoPush(3, "vector copy constructor");
								name = "`vector copy constructor iterator'";
								dmang.parseInfoPop();
								break;
							case 'H':
								dmang.parseInfoPush(3, "vector vbase copy constructor");
								name = "`vector vbase copy constructor iterator'";
								dmang.parseInfoPop();
								break;
							case 'I':
								dmang.parseInfoPush(3, "managed vector copy constructor");
								name = "`managed vector copy constructor iterator'";
								dmang.parseInfoPop();
								break;
							case 'J':
								dmang.parseInfoPush(3, "thread guard");
								name = "`local static thread guard'";
								dmang.parseInfoPop();
								break;
							case 'K':
								dmang.parseInfoPush(3, "udl");
								// Our test has manufactured symbol "??__Kabc@def@@3HA"
								// 20170329: Confirmed that this is not a MDReusableName with
								// manufactured symbol "??__Kabc@def@0@3HA"
								MDFragmentName fragment = new MDFragmentName(dmang);
								fragment.parse();
								StringBuilder fragBuilder = new StringBuilder();
								fragment.insert(fragBuilder);
								dmang.insertString(fragBuilder, "operator \"\" ");
								name = fragBuilder.toString();
								dmang.parseInfoPop();
								break;
							default:
								dmang.parseInfoPush(3, "UNKNOWN OPERATOR TYPE");
								name = "ERROR UNKNOWN OPERATOR TYPE";
								dmang.parseInfoPop();
								break;
						}
						break;
					default:
						dmang.parseInfoPush(2, "UNKNOWN OPERATOR TYPE");
						name = "ERROR UNKNOWN OPERATOR TYPE";
						dmang.parseInfoPop();
						break;
				}
				break;
			default:
				dmang.parseInfoPush(1, "UNKNOWN OPERATOR TYPE");
				name = "ERROR UNKNOWN OPERATOR TYPE";
				dmang.parseInfoPop();
				break;
		}
	}
}

/******************************************************************************/
/******************************************************************************/
