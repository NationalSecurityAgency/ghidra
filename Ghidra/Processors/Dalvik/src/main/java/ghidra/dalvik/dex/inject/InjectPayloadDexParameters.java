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
package ghidra.dalvik.dex.inject;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.file.formats.android.dex.analyzer.DexAnalysisState;
import ghidra.file.formats.android.dex.format.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * The "uponentry" injection for a DEX method.  We simulate DEX's register stack by copying values from
 * specially designated "input" registers to the v# and vw# registers at the bottom of method's register frame.
 *
 */
public class InjectPayloadDexParameters implements InjectPayload {
	public final static int INPUT_REGISTER_START = 0x100;
	public final static int REGISTER_START = 0x1000;
	private String name;
	private String sourceName;
	private InjectParameter[] noParams;
	private boolean analysisStateRecoverable;

	public InjectPayloadDexParameters(String nm, String srcName) {
		name = nm;
		sourceName = srcName;
		noParams = new InjectParameter[0];
		analysisStateRecoverable = true;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getType() {
		return CALLMECHANISM_TYPE;
	}

	@Override
	public String getSource() {
		return sourceName;
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public InjectParameter[] getInput() {
		return noParams;
	}

	@Override
	public InjectParameter[] getOutput() {
		return noParams;
	}

	@Override
	public boolean isErrorPlaceholder() {
		return false;
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
		// not used
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		if (!analysisStateRecoverable) {
			return new PcodeOp[0];
		}
		DexAnalysisState analysisState;
		try {
			analysisState = DexAnalysisState.getState(program);
		}
		catch (IOException e) {
			Msg.error(this, e.getMessage(), e);
			analysisStateRecoverable = false;
			return new PcodeOp[0];
		}
		DexHeader header = analysisState.getHeader();
		PcodeOp[] resOps;
		Function func = program.getFunctionManager().getFunctionContaining(con.baseAddr);
		EncodedMethod encodedMethod = null;
		if (func != null) {
			encodedMethod = analysisState.getEncodedMethod(func.getEntryPoint());
		}
		if (encodedMethod == null) {
			return new PcodeOp[0];
		}
		int paramCount = 0;
		if (!encodedMethod.isStatic()) {
			paramCount += 1;			// A this pointer at least
		}
		CodeItem codeItem = encodedMethod.getCodeItem();
		int registerIndex = codeItem.getRegistersSize() - codeItem.getIncomingSize();
		MethodIDItem methodIDItem = header.getMethods().get(encodedMethod.getMethodIndex());
		int prototypeIndex = methodIDItem.getProtoIndex() & 0xffff;
		PrototypesIDItem prototype = header.getPrototypes().get(prototypeIndex);
		TypeList parameters = prototype.getParameters();
		if (parameters != null) {
			paramCount += parameters.getItems().size();
		}
		AddressSpace registerSpace = program.getAddressFactory().getAddressSpace("register");
		resOps = new PcodeOp[paramCount];
		long fromOffset = INPUT_REGISTER_START;		// Base of designated input registers
		long toOffset = REGISTER_START + 4 * registerIndex;	// Base of registers in method's frame
		int i = 0;
		if (!encodedMethod.isStatic()) {	// Copy the this pointer to the right place
			Address fromAddr = registerSpace.getAddress(fromOffset);
			Address toAddr = registerSpace.getAddress(toOffset);
			fromOffset += 4;
			toOffset += 4;
			PcodeOp op = new PcodeOp(con.baseAddr, i, PcodeOp.COPY);
			op.setInput(new Varnode(fromAddr, 4), 0);
			op.setOutput(new Varnode(toAddr, 4));
			resOps[i] = op;
			i += 1;
		}
		if (parameters != null) {
			for (TypeItem parameterTypeItem : parameters.getItems()) {
				String parameterTypeString =
					DexUtil.convertTypeIndexToString(header, parameterTypeItem.getType());
				int size;
				char firstChar = parameterTypeString.charAt(0);
				Address fromAddr = registerSpace.getAddress(fromOffset);
				Address toAddr = registerSpace.getAddress(toOffset);
				size = (firstChar == 'D' || firstChar == 'J') ? 8 : 4; // Double or Long are size 8, otherwise 4
				fromOffset += size;
				toOffset += size;
				PcodeOp op = new PcodeOp(con.baseAddr, i, PcodeOp.COPY);
				op.setInput(new Varnode(fromAddr, size), 0);
				op.setOutput(new Varnode(toAddr, size));
				resOps[i++] = op;
			}
		}
		return resOps;
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

	@Override
	public boolean isIncidentalCopy() {
		return false;
	}

	@Override
	public void saveXml(StringBuilder buffer) {
		// Provide a minimal tag so decompiler can call-back
		buffer.append("<pcode");
		SpecXmlUtils.encodeStringAttribute(buffer, "inject", "uponentry");
		SpecXmlUtils.encodeBooleanAttribute(buffer, "dynamic", true);
		buffer.append("/>\n");
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		XmlElement el = parser.start();
		String injectString = el.getAttribute("inject");
		if (injectString == null || !injectString.equals("uponentry")) {
			throw new XmlParseException("Expecting inject=\"uponentry\" attribute");
		}
		boolean isDynamic = SpecXmlUtils.decodeBoolean(el.getAttribute("dynamic"));
		if (!isDynamic) {
			throw new XmlParseException("Expecting dynamic attribute");
		}
		parser.end(el);
	}

	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		InjectPayloadDexParameters op2 = (InjectPayloadDexParameters) obj;
		if (!name.equals(op2.name)) {
			return false;
		}
		if (!sourceName.equals(op2.sourceName)) {
			return false;
		}
		return true;
	}
}
