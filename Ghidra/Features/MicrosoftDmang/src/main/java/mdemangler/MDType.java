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
package mdemangler;

/**
 * 
 */
public class MDType extends MDParsableItem {

	private String name = ""; // temporary until Object is inherited from?
//	private String nameModifier = "";

//	private boolean isMember = true;
//	private boolean hasCVMod = false;
//	private boolean isBased = false;
//	private boolean isConst;
//	private boolean isVolatile;

//	protected MDBasedType based;

//	//Added 20170412 for based5 (and probably for other)--might need to have a "referencedType"
	// --for now... a boolean flag.
//	private boolean isReferencedType = false;
//
//	//Added 20170412 for based5 (and probably for other)--might need to have a "referencedType"
	// --for now... a boolean flag.
//	public void setIsReferencedType() {
//		isReferencedType = true;
//	}
//
//	//Added 20170412 for based5 (and probably for other)--might need to have a "referencedType"
	// --for now... a boolean flag.
//	public boolean isReferencedType() {
//		return isReferencedType;
//	}

	// 20170523 attempt
//	private boolean isArray = false;
//
//	public void setIsArray() {
//		isArray = true;
//	}
//
//	public boolean isArray() {
//		return isArray;
//	}

	//	private final String typeName;

	public MDType(MDMang dmang) {
		super(dmang);
//		based = new MDBasedType(dmang);
	}

	public MDType(MDMang dmang, int startIndexOffset) {
		super(dmang, startIndexOffset);
	}

//	public void setNameModifier(String nameModifier) {
//		this.nameModifier = nameModifier;
//	}
//
	@Override
	protected void parseInternal() throws MDException {
//		if (isBased && ((isMember() && isStatic()) || !isStatic())) {
//			dmang.parse(based);
//		}
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

//	public void setTypeName(String name) {
//		typeName = name;
//	}

//	public String getTypeName() {
//		return typeName;
//	}

//	public void setNonMember() {
//		isMember = false;
//	}
//
//	public boolean isMember() {
//		return isMember;
//	}
//
//	public void setHasCVMod() {
//		hasCVMod = true;
//	}
//
//	public boolean hasCVMod() {
//		return hasCVMod;
//	}

//	public void setBased() {
//		isBased = true;
//	}
//
//	public void clearBased() {
//		isBased = false;
//	}
//
//	public boolean isBased() {
//		return isBased;
//	}
//

//	public void setConst() {
//		isConst = true;
//	}
//
//	public void clearConst() {
//		isConst = false;
//	}
//
//	public boolean isConst() {
//		return isConst;
//	}
//
//	public void setVolatile() {
//		isVolatile = true;
//	}
//
//	public void clearVolatile() {
//		isVolatile = false;
//	}
//
//	public boolean isVolatile() {
//		return isVolatile;
//	}
//
	@Override
	public void insert(StringBuilder builder) {
//		dmang.appendString(builder, nameModifier);
//		based.insert(builder);
	}

//	public void insertAccessModifiers(StringBuilder builder) {
//		StringBuilder modifiersBuilder = new StringBuilder();
//		//Items to be added to the right-hand side
//		if (isVolatile) {
//			dmang.appendString(modifiersBuilder, VOLATILE);
//		}
//		if (isConst) {
//			dmang.appendString(modifiersBuilder, CONST);
//		}
//		dmang.insertSpacedString(builder, modifiersBuilder.toString());
//	}
}
