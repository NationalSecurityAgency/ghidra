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
package mdemangler.typeinfo;

import mdemangler.*;
import mdemangler.naming.MDNameModifier;

/**
 *
 */
public class MDTypeInfo extends MDParsableItem implements MDNameModifier {
	private static final String PRIVATE = "private: ";
	private static final String PROTECTED = "protected: ";
	private static final String PUBLIC = "public: ";
	private static final String STATIC = "static ";
	private static final String VIRTUAL = "virtual ";
	private static final String THUNK = "[thunk]:";
	private static final String EXTERNC = "extern \"C\" ";

	private enum AccessSpecifier {
		_NOT_SPECIFIED, _PRIVATE, _PROTECTED, _PUBLIC
	}

	// There are 5 "storage classes" possible: auto, register, static, extern, mutable (some
	// call them "storage qualifiers").
	// TODO: We are currently co-mingling virtual into this, and it should be put into its own
	// thing (whatever it is)
	// TODO: Found elsewhere, const and volatile are considered "type qualifiers" (not storage
	// class items).
	private enum StorageClass {
		_NOT_SPECIFIED, _STATIC, _VIRTUAL
	}

	/**
	 * Enum representing pointer format.
	 */
	enum PointerFormat {
		_NOT_SPECIFIED, _NEAR, _FAR //HUGE not present in mangling.
	}

	private StorageClass storage = StorageClass._NOT_SPECIFIED;
	private AccessSpecifier access = AccessSpecifier._NOT_SPECIFIED;
	private PointerFormat pointerFormat = PointerFormat._NOT_SPECIFIED;
	private boolean isThunk = false;
	private boolean isMember = true;
	private boolean isExternC = false;
	private char specialHandlingCode = '\0';

	protected MDType mdtype;
	protected boolean isTypeCast;

	public MDTypeInfo(MDMang dmang) {
		super(dmang, 1);
	}

	@Override
	public String getModifier() {
		return "";
	}

	public void setPrivate() {
		access = AccessSpecifier._PRIVATE;
	}

	public boolean isPrivate() {
		return (access == AccessSpecifier._PRIVATE);
	}

	public void setProtected() {
		access = AccessSpecifier._PROTECTED;
	}

	public boolean isProtected() {
		return (access == AccessSpecifier._PROTECTED);
	}

	public void setPublic() {
		access = AccessSpecifier._PUBLIC;
	}

	public boolean isPublic() {
		return (access == AccessSpecifier._PUBLIC);
	}

	public void setStatic() {
		storage = StorageClass._STATIC;
	}

	public boolean isStatic() {
		return (storage == StorageClass._STATIC);
	}

	public void setVirtual() {
		storage = StorageClass._VIRTUAL;
	}

	public boolean isVirtual() {
		return (storage == StorageClass._VIRTUAL);
	}

	public void setPointerFormat(PointerFormat pointerFormat) {
		this.pointerFormat = pointerFormat;
	}

	public boolean isNear() {
		return (pointerFormat == PointerFormat._NEAR);
	}

	public boolean isFar() {
		return (pointerFormat == PointerFormat._FAR);
	}

	public void setThunk() {
		isThunk = true;
	}

	public boolean isThunk() {
		return isThunk;
	}

	public void setExternC() {
		isExternC = true;
	}

	public boolean isExternC() {
		return isExternC;
	}

	public void setSpecialHandlingCode(char code) {
		specialHandlingCode = code;
	}

	public char getSpecialHandlingCode() {
		return specialHandlingCode;
	}

	public void setNonMember() {
		isMember = false;
	}

	public boolean isMember() {
		return isMember;
	}

	public void setTypeCast() {
		isTypeCast = true;
	}

	public MDType getMDType() {
		return mdtype;
	}

	@Override
	public void insert(StringBuilder builder) {
		if (mdtype != null) {
			mdtype.insert(builder);
		}
		insertAccessModifiers(builder);
	}

	private void insertAccessModifiers(StringBuilder builder) {
		StringBuilder modifiersBuilder = new StringBuilder();
		switch (storage) {
			case _NOT_SPECIFIED:
				break;
			case _STATIC:
				dmang.insertString(modifiersBuilder, STATIC);
				break;
			case _VIRTUAL:
				dmang.insertString(modifiersBuilder, VIRTUAL);
				break;
		}
		switch (access) {
			case _NOT_SPECIFIED:
				break;
			case _PRIVATE:
				dmang.insertString(modifiersBuilder, PRIVATE);
				break;
			case _PROTECTED:
				dmang.insertString(modifiersBuilder, PROTECTED);
				break;
			case _PUBLIC:
				dmang.insertString(modifiersBuilder, PUBLIC);
				break;
		}
		if (isThunk) {
			// TODO: note that case of "$B" (in access parsing), we need a space
			//  after it and before specific other stuff.
			dmang.insertString(modifiersBuilder, THUNK);
		}
		if (isExternC) {
			dmang.insertString(modifiersBuilder, EXTERNC);
		}
		dmang.insertSpacedString(builder, modifiersBuilder.toString());
	}

	@Override
	protected void parseInternal() throws MDException {
		if (mdtype != null) {
			mdtype.parse();
		}
	}
}

/******************************************************************************/
/******************************************************************************/
