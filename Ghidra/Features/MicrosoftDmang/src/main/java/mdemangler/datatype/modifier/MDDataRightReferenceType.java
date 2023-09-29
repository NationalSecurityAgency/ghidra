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

import mdemangler.MDException;
import mdemangler.MDMang;

/**
 * This class represents a "data right reference" data type within a Microsoft mangled symbol.
 * It is one of a number of "extended" data types not originally planned by Microsoft.
 */
public class MDDataRightReferenceType extends MDModifierType {

	public MDDataRightReferenceType(MDMang dmang, boolean isHighest, boolean isConst,
			boolean isVolatile) {
		super(dmang, 3);
		if (isHighest) {
			setConst(isConst);
			setVolatile(isVolatile);
		}
		else {
			setConst(false);
			setVolatile(false);
		}
		cvMod.setRightReferenceTemplateParameter();
	}

	@Override
	protected void parseInternal() throws MDException {
		super.parseInternal();
	}

	@Override
	public void insertCVMod(StringBuilder builder) {
		if (cvMod.isFunction()) {
			StringBuilder cvBuilder = new StringBuilder();
			cvMod.insert(cvBuilder);
			dmang.insertString(builder, cvBuilder.toString());
		}
		else {
			cvMod.insert(builder);
		}
		// Following to to clean the Based5 "bug" if seen.  See comments in MDBasedAttribute.
		dmang.cleanOutput(builder);
	}
}
