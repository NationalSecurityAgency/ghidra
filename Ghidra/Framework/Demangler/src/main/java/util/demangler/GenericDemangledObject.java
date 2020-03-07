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

/**
 * A class to represent a demangled object.
 */
public abstract class GenericDemangledObject {

	protected static final String NAMESPACE_SEPARATOR = "::";
	protected static final String AT = "@";

	protected static final String EMPTY_STRING = "";
	protected static final String SPACE = " ";

	protected String originalMangled;
	protected String specialPrefix;
	protected String specialMidfix;
	protected String specialSuffix;
	protected GenericDemangledType namespace;
	protected String visibility;//public, protected, etc.
	protected String storageClass;//const, volatile, etc
	protected String name;
	protected boolean isConst;
	protected boolean isVolatile;
	protected boolean isStatic;
	protected boolean isVirtual;
	protected boolean isThunk;
	protected boolean isPointer64;
	// temp
	protected boolean isStruct;
	protected boolean isUnsigned;
	protected boolean isUnaligned;
	protected boolean isRestrict;
	protected String basedName;
	protected String memberScope;

	private String signature;

	/** 
	 * Returns the name of the demangled object.
	 * @return the name of the demangled object
	 */
	public String getName() {
		return name;
	}

	public boolean isConst() {
		return isConst;
	}

	public void setConst(boolean isConst) {
		this.isConst = isConst;
	}

	public boolean isVolatile() {
		return isVolatile;
	}

	public void setVolatile(boolean isVolatile) {
		this.isVolatile = isVolatile;
	}

	public boolean isStatic() {
		return isStatic;
	}

	public void setStatic(boolean isStatic) {
		this.isStatic = isStatic;
	}

	public boolean isVirtual() {
		return isVirtual;
	}

	public void setVirtual(boolean isVirtual) {
		this.isVirtual = isVirtual;
	}

	public boolean isThunk() {
		return isThunk;
	}

	public void setThunk(boolean isThunk) {
		this.isThunk = isThunk;
	}

	public boolean isPointer64() {
		return isPointer64;
	}

	public void setPointer64(boolean isPointer64) {
		this.isPointer64 = isPointer64;
	}

	public void setUnsigned() {
		isUnsigned = true;
	}

	public void setStruct() {
		isStruct = true;
	}

	public void setUnaligned() {
		isUnaligned = true;
	}

	public boolean isUnaligned() {
		return isUnaligned;
	}

	public void setRestrict() {
		isRestrict = true;
	}

	public boolean isRestrict() {
		return isRestrict;
	}

	public String getBasedName() {
		return basedName;
	}

	public void setBasedName(String basedName) {
		this.basedName = basedName;
	}

	public String getMemberScope() {
		return memberScope;
	}

	public void setMemberScope(String memberScope) {
		this.memberScope = memberScope;
	}

	/**
	 * Sets the name of the demangled object
	 * @param name the new name
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Sets the original mangled name
	 * @param mangled the original mangled name
	 */
	public void setOriginalMangled(String mangled) {
		this.originalMangled = mangled;
	}

	public String getOriginalMangled() {
		return originalMangled;
	}

	/**
	 * Returns the namespace containing this demangled object.
	 * @return the namespace containing this demangled object
	 */
	public GenericDemangledType getNamespace() {
		return namespace;
	}

	/**
	 * 
	 * @param namespace
	 */
	public void setNamespace(GenericDemangledType namespace) {
		this.namespace = namespace;
	}

	public String getVisibility() {
		return visibility;
	}

	public void setVisibilty(String visibility) {
		this.visibility = visibility;
	}

	public String getStorageClass() {
		return storageClass;
	}

	public void setStorageClass(String storageClass) {
		this.storageClass = storageClass;
	}

	public String getSpecialPrefix() {
		return specialPrefix;
	}

	public void setSpecialPrefix(String special) {
		this.specialPrefix = special;
	}

	public String getSpecialMidfix() {
		return specialMidfix;
	}

	public void setSpecialMidfix(String chargeType) {
		this.specialMidfix = chargeType;
	}

	public String getSpecialSuffix() {
		return specialSuffix;
	}

	public void setSpecialSuffix(String specialSuffix) {
		this.specialSuffix = specialSuffix;
	}

	/**
	 * Returns a complete signature for the demangled symbol.
	 * <br>For example:
	 *           {@code "unsigned long foo" 
	 *            "unsigned char * ClassA::getFoo(float, short *)"
	 *            "void * getBar(int **, MyStruct &)"}
	 * <br><b>Note: based on the underlying mangling scheme, the 
	 * return type may or may not be specified in the signature.</b>
	 * @param format true if signature should be pretty printed
	 * @return a complete signature for the demangled symbol
	 */
	public abstract String getSignature(boolean format);

	/**
	 * Sets the signature. Calling this method will
	 * override the auto-generated signature.
	 * @param signature the signature
	 */
	public void setSignature(String signature) {
		this.signature = signature;
	}

	@Override
	public String toString() {
		return getSignature(false);
	}

	protected String generatePlateComment() {
		return (signature == null) ? getSignature(true) : signature;
	}

	protected String pad(int len) {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < len; i++) {
			buffer.append(' ');
		}
		return buffer.toString();
	}
}
