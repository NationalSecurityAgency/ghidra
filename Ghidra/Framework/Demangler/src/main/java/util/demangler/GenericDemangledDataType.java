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
package util.demangler;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A class to represent a demangled data type.
 */
public class GenericDemangledDataType extends GenericDemangledType {

	protected static final Pattern ARRAY_SUBSCRIPT_PATTERN = Pattern.compile("\\[\\d*\\]");

	public static final char SPACE = ' ';

	private static final String STATIC = "static";

	public static final String UNALIGNED = "__unaligned";
	public static final String UNSIGNED = "unsigned";
	public static final String SIGNED = "signed";

	public static final String ARR_NOTATION = "[]";
	public static final String REF_NOTATION = "&";
	public static final String PTR_NOTATION = "*";

	public static final String VOLATILE = "volatile";
	public static final String COMPLEX = "complex";
	public static final String CLASS = "class";
	public static final String ENUM = "enum";
	public static final String STRUCT = "struct";
	public static final String UNION = "union";
	public static final String COCLASS = "coclass";
	public static final String COINTERFACE = "cointerface";
	public static final String CONST = "const";
	protected static final String FAR = "far";
	protected static final String RESTRICT = "restrict";

	public final static String VARARGS = "...";
	public final static String VOID = "void";
	public final static String BOOL = "bool";
	public final static String CHAR = "char";
	public final static String WCHAR_T = "wchar_t";
	public final static String SHORT = "short";
	public final static String INT = "int";
	public final static String INT0_T = "int0_t";//TODO
	public final static String LONG = "long";
	public final static String LONG_LONG = "long long";
	public final static String FLOAT = "float";
	public final static String DOUBLE = "double";
	public final static String INT64 = "__int64";
	public final static String INT128 = "__int128";//TODO
	public final static String FLOAT128 = "__float128";//TODO
	public final static String LONG_DOUBLE = "long double";
	public final static String PTR64 = "__ptr64";
	public final static String STRING = "string";

	public final static String[] PRIMITIVES = { VOID, BOOL, CHAR, WCHAR_T, SHORT, INT, INT0_T, LONG,
		LONG_LONG, FLOAT, DOUBLE, INT128, FLOAT128, LONG_DOUBLE, };

	/** private/protected/public */
	protected String access;

	protected boolean isStatic;
	protected boolean isArray;
	protected boolean isClass;
	protected boolean isComplex;
	protected boolean isEnum;
	protected boolean isPointer64;
	protected boolean isReference;
	protected boolean isSigned;//explicitly signed!
	protected boolean isStruct;
	protected boolean isTemplate;
	protected boolean isUnaligned;
	protected boolean isUnion;
	protected boolean isUnsigned;
	protected boolean isVarArgs;
	protected boolean isVolatile;
	protected int pointerLevels = 0;
	protected boolean isFar;
	protected boolean isRestrict;
	//This basedAttributte is an attribute on a modified type (such as a pointer) in the
	// Microsoft model, which declares what the modified type is based on.  Search the
	// Internet for "Microsoft based pointer" to get a better explanation of its usage
	// (I imagine that it is implemented as a hidden pointer index).
	protected String basedAttribute;
	protected String memberScope;
	protected boolean isCoclass;
	protected boolean isCointerface;

	/**
	 * Constructs a new demangled datatype.
	 * @param name the name of the datatype
	 */
	public GenericDemangledDataType(String name) {
		super(name);
	}

	public GenericDemangledDataType copy() {
		GenericDemangledDataType copy = new GenericDemangledDataType(getName());
		copyInto(copy);
		return copy;
	}

	public void copyInto(GenericDemangledDataType destination) {
		GenericDemangledDataType source = this;

		// note: for now this copy is additive for the attributes in that it won't turn off 
		//       an attribute that was already on.  If this is not what we want, then we may 
		//       need a second copy method.

		destination.isStatic |= source.isStatic;
		destination.isArray |= source.isArray;
		destination.isClass |= source.isClass;
		destination.isComplex |= source.isComplex;
		destination.isEnum |= source.isEnum;
		destination.isPointer64 |= source.isPointer64;
		destination.isReference |= source.isReference;
		destination.isSigned |= source.isSigned;
		destination.isStruct |= source.isStruct;
		destination.isTemplate |= source.isTemplate;
		destination.isUnaligned |= source.isUnaligned;
		destination.isUnion |= source.isUnion;
		destination.isUnsigned |= source.isUnsigned;
		destination.isVarArgs |= source.isVarArgs;
		destination.isVolatile |= source.isVolatile;

		destination.pointerLevels = destination.pointerLevels + source.pointerLevels; // ?
		destination.isFar |= source.isFar;
		destination.isRestrict |= source.isRestrict;

		updateAccess(destination, source);
		destination.setNamespace(source.getNamespace());
		destination.setTemplate(source.getTemplate());
		destination.basedAttribute = source.basedAttribute;
		destination.memberScope = source.memberScope;

		destination.isCoclass |= source.isCoclass;
		destination.isCointerface |= source.isCointerface;

		if (source.isConst()) {
			destination.setConst();
		}
		if (source.isVolatile()) {
			destination.setVolatile();
		}
	}

	private void updateAccess(GenericDemangledDataType destination,
			GenericDemangledDataType source) {

		String currentAccess = destination.getAccess();
		if (currentAccess != null && !currentAccess.trim().isEmpty()) {
			// don't overwrite the current access (if we need to, we can write a combining algorithm)
			return;
		}

		destination.setAccess(source.getAccess());
	}

	public void copyInto(GenericDemangledVariable destination) {

		GenericDemangledDataType source = this;

		List<String> list = new ArrayList<>();
		if (source.isConst()) {
			list.add("const");
		}
		if (source.isVolatile) {
			list.add("volatile");
		}
		if (source.isFar) {
			list.add("far");
		}
		if (source.isRestrict) {
			list.add("restrict");
		}

		StringBuilder buffy = new StringBuilder();
		for (String string : list) {
			buffy.append(string).append(' ');
		}

		// 
		// Note: this method is crossing a bridge from one hierarchy to another.  The values 
		//       in the other type are not a one-to-one match, as is the case when copying
		//       into variables in this class's type hierarchy.  So, we just add values to this 
		//       method as we find them.
		//
		String storage = buffy.toString().trim();
		destination.setStorageClass(storage.isEmpty() ? null : storage);

		destination.setStatic(source.isStatic());
		destination.setVisibilty(source.getAccess());

		// TODO merge the hierarchies!! so that we don't have to different signature generation
		//      and this method becomes like the one above.

		if (source.isStruct) {
			destination.setStruct();
		}

		if (source.isUnsigned) {
			destination.setUnsigned();
		}
	}

	public int getPointerLevels() {
		return pointerLevels;
	}

	public void setPointerLevels(int levels) {
		this.pointerLevels = levels;
	}

	public void incrementPointerLevels() {
		pointerLevels++;
	}

	public void setAccess(String access) {
		this.access = access;
	}

	public String getAccess() {
		return access;
	}

	public void setStatic() {
		isStatic = true;
	}

	public boolean isStatic() {
		return isStatic;
	}

	public void setArray() {
		isArray = true;
	}

	public void setClass() {
		isClass = true;
	}

	public void setComplex() {
		isComplex = true;
	}

	public void setEnum() {
		isEnum = true;
	}

	public void setPointer64() {
		isPointer64 = true;
	}

	public void setReference() {
		isReference = true;
	}

	public void setSigned() {
		isSigned = true;
	}

	public void setStruct() {
		isStruct = true;
	}

	public void setTemplate() {
		isTemplate = true;
	}

	public void setUnion() {
		isUnion = true;
	}

	public void setCoclass() {
		isCoclass = true;
	}

	public void setCointerface() {
		isCointerface = true;
	}

	public void setUnsigned() {
		isUnsigned = true;
	}

	public void setUnaligned() {
		isUnaligned = true;
	}

	public boolean isUnaligned() {
		return isUnaligned;
	}

	public void setVarArgs() {
		isVarArgs = true;
	}

	@Override
	public void setVolatile() {
		isVolatile = true;
	}

	public void setFar() {
		isFar = true;
	}

	public boolean isFar() {
		return isFar;
	}

	public void setRestrict() {
		isRestrict = true;
	}

	public boolean isRestrict() {
		return isRestrict;
	}

	public boolean isArray() {
		return isArray;
	}

	public boolean isClass() {
		return isClass;
	}

	public boolean isComplex() {
		return isComplex;
	}

	public boolean isEnum() {
		return isEnum;
	}

	public boolean isPointer() {
		return pointerLevels > 0;
	}

	public boolean isPointer64() {
		return isPointer64;
	}

	public boolean isReference() {
		return isReference;
	}

	public boolean isSigned() {
		return isSigned;
	}

	public boolean isStruct() {
		return isStruct;
	}

	public boolean isTemplate() {
		return isTemplate;
	}

	public boolean isUnion() {
		return isUnion;
	}

	public boolean isCoclass() {
		return isCoclass;
	}

	public boolean isCointerface() {
		return isCointerface;
	}

	public boolean isUnsigned() {
		return isUnsigned;
	}

	public boolean isVarArgs() {
		return isVarArgs;
	}

	public boolean isVoid() {
		return VOID.equals(getName());
	}

	@Override
	public boolean isVolatile() {
		return isVolatile;
	}

	public String getBasedName() {
		return basedAttribute;
	}

	public void setBasedName(String basedName) {
		this.basedAttribute = basedName;
	}

	public String getMemberScope() {
		return memberScope;
	}

	public void setMemberScope(String memberScope) {
		this.memberScope = memberScope;
	}

	public boolean isPrimitive() {
		boolean isPrimitiveDT =
			!(isArray || isClass || isComplex || isEnum || isPointer() || isPointer64 || isSigned ||
				isTemplate || isUnion || isCoclass || isCointerface || isVarArgs || isVolatile);
		if (isPrimitiveDT) {
			for (String primitiveNames : PRIMITIVES) {
				if (getName().equals(primitiveNames)) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public String toSignature() {
		StringBuffer buffer = new StringBuffer();

		if (access != null) {
			buffer.append(access).append(SPACE);
		}

		if (isStatic) {
			buffer.append(STATIC).append(SPACE);
		}

		if (isUnion) {
			buffer.append(UNION).append(SPACE);
		}
		if (isStruct) {
			buffer.append(STRUCT).append(SPACE);
		}
		if (isEnum) {
			buffer.append(ENUM).append(SPACE);
		}
		if (isClass) {
			buffer.append(CLASS).append(SPACE);
		}
		if (isCoclass) {
			buffer.append(COCLASS).append(SPACE);
		}
		if (isCointerface) {
			buffer.append(COINTERFACE).append(SPACE);
		}
		if (isComplex) {
			buffer.append(COMPLEX).append(SPACE);
		}
		if (isSigned) {
			buffer.append(SIGNED).append(SPACE);
		}
		if (isUnsigned) {
			buffer.append(UNSIGNED).append(SPACE);
		}

		if (getNamespace() != null) {
			buffer.append(getNamespace().toNamespace());
		}

		String space = "";
		if (getName() != null) {
			buffer.append(getName());
			space = String.valueOf(SPACE);
		}

		if (getTemplate() != null) {
			buffer.append(getTemplate().toTemplate());
			space = String.valueOf(SPACE);
		}

		if (isConst()) {
			buffer.append(space).append(CONST);
			space = String.valueOf(SPACE);
		}

		if (isVolatile()) {
			buffer.append(space).append(VOLATILE);
			space = String.valueOf(SPACE);
		}

		if (isUnaligned) {
			buffer.append(space).append(UNALIGNED);
			space = String.valueOf(SPACE);
		}

		if (isFar) {
			buffer.append(space).append(FAR);
			space = String.valueOf(SPACE);
		}

		if (isRestrict) {
			buffer.append(space).append(RESTRICT);
			space = String.valueOf(SPACE);
		}

		boolean hasPointers = pointerLevels >= 1;
		if (hasPointers) {
			buffer.append(space + PTR_NOTATION);
			space = String.valueOf(SPACE);
		}

		if (isReference) {

			// ugly, but MS does this			
			if (isConst() && hasPointers) {
				buffer.append(space).append(CONST);
				space = String.valueOf(SPACE);
			}
			if (isVolatile() && hasPointers) {
				buffer.append(space).append(VOLATILE);
				space = String.valueOf(SPACE);
			}

			buffer.append(space).append(REF_NOTATION);
			space = String.valueOf(SPACE);
		}

		if (isPointer64) {
			buffer.append(space).append(PTR64);
			space = String.valueOf(SPACE);
		}

		for (int i = 1; i < pointerLevels; i++) {

			// ugly, but MS does this			
			if (isConst()) {
				buffer.append(space).append(CONST);
				space = String.valueOf(SPACE);
			}
			if (isVolatile()) {
				buffer.append(space).append(VOLATILE);
				space = String.valueOf(SPACE);
			}

			buffer.append(space).append(PTR_NOTATION);
			space = String.valueOf(SPACE);

			// ugly, but MS does this
			if (isPointer64) {
				buffer.append(space).append(PTR64);
				space = String.valueOf(SPACE);
			}
		}

		if (isArray) {
			Matcher matcher = ARRAY_SUBSCRIPT_PATTERN.matcher(getName());
			if (!matcher.find()) {
				// only put subscript on if the name doesn't have it
				buffer.append(ARR_NOTATION);
			}
		}
		return buffer.toString();
	}

	@Override
	public String toString() {
		return toSignature();
	}

}
