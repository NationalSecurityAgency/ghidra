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
package ghidra.app.plugin.core.decompiler.export;

import static ghidra.program.model.pcode.ElementId.*;

import java.util.HashSet;
import java.util.Set;

import ghidra.app.decompiler.DecompileProcess;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;

public class ExportableDecompileResults extends DecompileResults {

	final PackedDecode localDecoder;
	final private Set<String> valueSet = new HashSet<>();

	private BasePcodeExporter ex;
	private int addressUnique = 0;

	public ExportableDecompileResults(Function func, Language language, CompilerSpec compilerSpec,
			PcodeDataTypeManager dtm, String errorMsg, PackedDecode decoder,
			DecompileProcess.DisposeState processState) {
		super(func, language, compilerSpec, dtm, errorMsg, null, processState);
		localDecoder = decoder;
	}

	public void processDoc(BasePcodeExporter pfEx) {
		try {
			this.ex = pfEx;
			int documentElem = localDecoder.openElement(ELEM_DOC);
			Function f = getFunction();
			String key = f.getName() + "@" + f.getEntryPoint();
			iterateElements(key, documentElem);
			localDecoder.closeElement(documentElem);
		}
		catch (DecoderException e) {		// Error while walking the DOM
			Msg.error(this, e.getMessage(), e);
			return;
		}
		catch (Exception e) {				// Exception with the underlying stream
			Msg.error(this, e.getMessage(), e);
			return;
		}
	}

	private void iterateElements(String name, int parentId) throws DecoderException {
		PcodeElements parentType = PcodeElements.find(parentId);
		int n = 0;
		int argn = 0;
		int opn = 0;
		String highVar = null;
		for (;;) {
			int childId = localDecoder.peekElement();
			if (childId == 0) {
				break;
			}
			String childName = name + ":" + childId + ":" + n++;
			PcodeElements childType = PcodeElements.find(childId);
			String fnelem =
				"E_" + parentType.name().toUpperCase() + "_" + childType.name().toUpperCase();
			if (parentType.equals(PcodeElements.ELEM_OP) &&
				(childType.equals(PcodeElements.ELEM_ADDR) ||
					childType.equals(PcodeElements.ELEM_VOID) ||
					childType.equals(PcodeElements.ELEM_IOP))) {
				if (argn == 0) {
					ex.export("E_OP_OUTPUT", name, childName);
				}
				else {
					ex.export("E_OP_INPUT", name, childName);
					ex.export("A_INPUT_INDEX", childName, Integer.toString(argn - 1));
				}
				argn++;
			}
			if (parentType.equals(PcodeElements.ELEM_BLOCK) &&
				childType.equals(PcodeElements.ELEM_OP)) {
				ex.export("A_OP_INDEX", childName, Integer.toString(opn));
				opn++;
			}
			if (parentType.equals(PcodeElements.ELEM_BLOCK) ||
				parentType.equals(PcodeElements.ELEM_STATEMENT)) {
				String astr = childType.name().toUpperCase();
				if (highVar == null && astr.equals("VARIABLE")) {
					highVar = childName;
				}
				else if (highVar != null && astr.equals("FIELD")) {
					ex.export("VARIABLE_FIELD", highVar, childName);
				}
				else if (astr.equals("SYNTAX") || astr.equals("OP")) {
					// continue
				}
				else {
					highVar = null;
				}
			}
			localDecoder.openElement();
			ex.export(fnelem, name, childName);
			iterateAttributes(childName, childType);
			iterateElements(childName, childId);
			localDecoder.closeElement(childId);
		}
	}

	private void iterateAttributes(String childName, PcodeElements childType)
			throws DecoderException {
		for (;;) {
			int attrId = localDecoder.getNextAttributeId();
			if (attrId == 0) {
				break;
			}
			PcodeAttributes attr = PcodeAttributes.find(attrId);
			String value = readValue(childType, attr);
			String funcAttr =
				"A_" + childType.name().toUpperCase() + "_" + attr.name().toUpperCase();
			boolean isAddr = childType.equals(PcodeElements.ELEM_ADDR) ||
				childType.equals(PcodeElements.ELEM_SEQNUM);
			if (isAddr && attr.equals(PcodeAttributes.ATTRIB_SPACE)) {
				ex.export(funcAttr, childName, value.substring(0, value.length() - 1));
				continue;
			}
			ex.export(funcAttr, childName, value);
			if (isAddr && (attr.equals(PcodeAttributes.ATTRIB_REF) ||
				attr.equals(PcodeAttributes.ATTRIB_OFFSET))) {
				ex.export("LOCATION_FUNC", childName,
					getFunction().getName() + "@" + getFunction().getEntryPoint());
				ex.export("LOCATION_UNIQ", childName, Integer.toString(addressUnique++));
			}
			if ((isAddr && attr.equals(PcodeAttributes.ATTRIB_OFFSET)) ||
				(childType.equals(PcodeElements.ELEM_RANGE) &&
					(attr.equals(PcodeAttributes.ATTRIB_FIRST) ||
						attr.equals(PcodeAttributes.ATTRIB_LAST)))) {
				// Convenience methods for datalog
				try {
					if (valueSet.add(value)) {
						// Negative numbers need to be converted here
						ex.export("LOCATION_NUM", value,
							Long.toString(Long.parseUnsignedLong(value)));
						ex.export("LOCATION_HEX", value,
							Long.toHexString(Long.parseUnsignedLong(value)));
					}
				}
				catch (NumberFormatException nfe) {
					Msg.error(this, nfe.getMessage());
				}
			}
		}
	}

	private String readValue(PcodeElements ctype, PcodeAttributes attr) {
		try {
			if (ctype.equals(PcodeElements.ELEM_IOP) &&
				attr.equals(PcodeAttributes.ATTRIB_VALUE)) {
				return Long.toUnsignedString(localDecoder.readUnsignedInteger());
			}
			if (ctype.equals(PcodeElements.ELEM_SPACEID) &&
				attr.equals(PcodeAttributes.ATTRIB_NAME)) {
				return Integer.toUnsignedString(localDecoder.readSpace().getSpaceID());
			}
			if (ctype.equals(PcodeElements.ELEM_HIGH) &&
				attr.equals(PcodeAttributes.ATTRIB_OFFSET)) {
				return Long.toString(localDecoder.readSignedInteger());
			}
			if (ctype.equals(PcodeElements.ELEM_COMMENT) &&
				attr.equals(PcodeAttributes.ATTRIB_OFF)) {
				return Long.toUnsignedString(localDecoder.readUnsignedInteger());
			}
			if (ctype.equals(PcodeElements.ELEM_SYMBOL) &&
				attr.equals(PcodeAttributes.ATTRIB_INDEX)) {
				return Long.toUnsignedString(localDecoder.readUnsignedInteger());
			}
		}
		catch (DecoderException de) {
			// Not a special case...fallback to attr.method.
			// If that fails, we report the error.
		}
		try {
			return switch (attr.method()) {
				case DecoderMethods.READ_BOOL -> Boolean.toString(localDecoder.readBool());
				case DecoderMethods.READ_SINT -> Long.toString(localDecoder.readSignedInteger());
				case DecoderMethods.READ_UINT -> Long
						.toUnsignedString(localDecoder.readUnsignedInteger());
				case DecoderMethods.READ_STRING -> localDecoder.readString();
				case DecoderMethods.READ_SPACE -> localDecoder.readSpace().toString();
				case DecoderMethods.READ_OPCODE -> Integer.toString(localDecoder.readOpcode());
				default -> "UNKNOWN";
			};
		}
		catch (DecoderException de) {
			Msg.error(this, de.getMessage());
		}
		return null;
	}
}
