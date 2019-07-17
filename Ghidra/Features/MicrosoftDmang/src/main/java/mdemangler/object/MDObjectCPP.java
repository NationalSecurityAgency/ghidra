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
package mdemangler.object;

import mdemangler.MDException;
import mdemangler.MDMang;
import mdemangler.naming.MDBasicName;
import mdemangler.naming.MDQualifiedBasicName;
import mdemangler.typeinfo.MDTypeInfo;
import mdemangler.typeinfo.MDTypeInfoParser;

/**
 * This class represents a derivative of an <b><code>MDObject</code></b> which is a C++ object.
 */
public class MDObjectCPP extends MDObject {
	protected MDQualifiedBasicName qualifiedName;
	protected MDTypeInfo typeInfo;
	protected boolean embeddedObjectFlag;

	public MDObjectCPP(MDMang dmang) {
		super(dmang);
	}

	public MDQualifiedBasicName getQualifiedName() {
		return qualifiedName;
	}

	public MDTypeInfo getTypeInfo() {
		return typeInfo;
	}

	/**
	 * Returns the embedded object if there is one.  Else returns itself.
	 *  @see MDBasicName#getEmbeddedObject()
	 * @return An MDObjectCPP representing the original or the embedded object.
	 */
	public MDObjectCPP getEmbeddedObject() {
		if (embeddedObjectFlag) {
			return getQualifiedName().getBasicName().getEmbeddedObject();
		}
		return this;
	}

	@Override
	public void insert(StringBuilder builder) {
		qualifiedName.insert(builder);
		if (typeInfo != null) {
			typeInfo.insert(builder);
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		if (dmang.peek() != '?') {
			throw new MDException("Invalid ObjectCPP");
		}
		dmang.increment();
		if ((dmang.peek(0) == '?') && (dmang.peek(1) == '?')) { //??? prefix
			embeddedObjectFlag = true;
		}
		qualifiedName = new MDQualifiedBasicName(dmang);
		qualifiedName.parse();
		if (qualifiedName.isString()) {
			return;
		}
		if (dmang.peek() != MDMang.DONE) {
			int RTTINum = qualifiedName.getRTTINumber();
			typeInfo = MDTypeInfoParser.parse(dmang, RTTINum);
			if (qualifiedName.isTypeCast()) {
				typeInfo.setTypeCast();
			}
			typeInfo.parse();
			if (!typeInfo.getNameModifier().isEmpty()) {
				qualifiedName.setNameModifier(typeInfo.getNameModifier());
			}
		}
	}
}

/******************************************************************************/
/******************************************************************************/
