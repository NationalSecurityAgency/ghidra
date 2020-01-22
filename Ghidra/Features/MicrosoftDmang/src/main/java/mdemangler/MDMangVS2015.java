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

import mdemangler.datatype.modifier.MDArrayBasicType;
import mdemangler.datatype.modifier.MDCVMod;
import mdemangler.naming.MDFragmentName;
import mdemangler.naming.MDQualification;
import mdemangler.object.*;
import mdemangler.template.MDTemplateArgumentsList;

/**
 * An <b><code>MDMang</code></b> extension that tailors output to Visual Studio 2015 output
 *  results.
 */
public class MDMangVS2015 extends MDMang {

	@Override
	public MDParsableItem demangle(String mangledIn, boolean errorOnRemainingChars)
			throws MDException {
		MDParsableItem returnedItem = super.demangle(mangledIn, errorOnRemainingChars);
		//VS2015 does not understand all of the object types that we made up.  These all fall
		// under MDObjectReserved; but it does understand MDObjectBracket objects.
		if (returnedItem instanceof MDObjectBracket) {
			return returnedItem;
		}
		if (returnedItem instanceof MDObjectReserved) {
			throw new MDException("Invalid mangled symbol.");
		}
		return returnedItem;
	}

	/******************************************************************************/
	// SPECIALIZATION METHODS
	@Override
	public void insert(StringBuilder builder, MDString mdstring) {
		insertString(builder, mdstring.getName());
	}

	@Override
	public void insert(StringBuilder builder, MDQualification qualification) {
		qualification.insert_VSAll(builder);
	}

	@Override
	public boolean emptyFirstArgComma(MDTemplateArgumentsList args) {
		return true;
	}

	@Override
	public boolean templateBackrefComma(MDTemplateArgumentsList args) {
		return false;
	}

	@Override
	public void insertManagedPropertiesSuffix(StringBuilder builder, MDCVMod cvMod) {
		// Do nothing
	}

	// TODO: Look into this further. We may no longer need to have this
	// specialization, but it
	// be that I just haven't implemented it yet too...
	// @Override
	// public void parseEmbeddedObjectSuffix() throws MDMangException {
	// //Do nothing
	// }

	@Override
	public void insertCLIArrayRefSuffix(StringBuilder builder, StringBuilder refBuilder) {
		// 20161004: Eliminates function template arg const volatile (BQRS) from
		// cli::array.
		// But makes worse: testCLI_1b()
		builder.setLength(0);
		insertString(builder, refBuilder.toString());
	}

	@Override
	public String parseFragmentName(MDFragmentName fn) throws MDException {
		return fn.parseFragmentName_VS2All();
	}

	@Override
	public void appendArrayNotation(StringBuilder builder, MDArrayBasicType arrayBasicType) {
		arrayBasicType.appendArrayNotation(builder);
	}

	@Override
	public boolean allowMDTypeInfoParserDefault() {
		return true;
	}

	@Override
	public boolean processQualCAsSpecialFragment() {
		return false;
	}

	@Override
	public MDObjectCPP getEmbeddedObject(MDObjectCPP obj) {
		return obj.getEmbeddedObject();
	}

	@Override
	public void processHashedObject(MDObjectCPP obj) throws MDException {
		obj.processHashedObjectMSVC();
	}

}

/******************************************************************************/
/******************************************************************************/
