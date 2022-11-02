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
package ghidra.program.model.lang;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.List;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.AddressXML;
import ghidra.program.model.pcode.Encoder;
import ghidra.xml.*;

/**
 * Class for context configuration information as
 * part of the compiler configuration (CompilerSpec)
 */
public final class ContextSetting {
	private Register register;  // Register being set in default context
	private BigInteger value;     // value being set in default context
	private Address startAddr; // Beginning address of context
	private Address endAddr;   // Ending address of context

	public ContextSetting(Register register, BigInteger value, Address startAddr, Address endAddr) {
		this.value = value;
		this.register = register;
		this.startAddr = startAddr;
		this.endAddr = endAddr;
	}

	/**
	 * Construct from an XML \<set> tag.  The tag is a child of either \<context_set> or \<tracked_set>
	 * which provides details of the memory range affected.
	 * @param el is the XML tag
	 * @param cspec is used to lookup register names present in the tag
	 * @param isContextReg is true for a \<context_set> parent, false for a \<tracked_set> parent
	 * @param first is the first Address in the affected memory range
	 * @param last is the last Address in the affected memory range
	 */
	private ContextSetting(XmlElement el, CompilerSpec cspec, boolean isContextReg, Address first,
			Address last) throws SleighException {
		startAddr = first;
		endAddr = last;
		String name = el.getAttribute("name");
		value = getBigInteger(el.getAttribute("val"), 0);
		register = cspec.getLanguage().getRegister(name);
		if (register == null) {
			throw new SleighException("Unknown register: " + name);
		}
		if (isContextReg) {
			if (!register.isProcessorContext()) {
				throw new SleighException("Register " + name + " is not a context register");
			}
		}
		else if (register.isProcessorContext()) {
			throw new SleighException("Unexpected context register " + name);
		}
	}

	public Register getRegister() {
		return register;
	}

	public BigInteger getValue() {
		return value;
	}

	public Address getStartAddress() {
		return startAddr;
	}

	public Address getEndAddress() {
		return endAddr;
	}

	private BigInteger getBigInteger(String valStr, long defaultValue) {
		int radix = 10;
		if (valStr.startsWith("0x") || valStr.startsWith("0X")) {
			valStr = valStr.substring(2);
			radix = 16;
		}
		try {
			return new BigInteger(valStr, radix);
		}
		catch (Exception e) {
			return BigInteger.valueOf(defaultValue);
		}
	}

	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_SET);
		encoder.writeString(ATTRIB_NAME, register.getName());
		encoder.writeString(ATTRIB_VAL, value.toString());
		encoder.closeElement(ELEM_SET);
	}

	/**
	 * Determine if this ContextSetting is equivalent to another specified instance
	 * @param obj is the other instance
	 * @return true if they are equivalent
	 */
	public boolean isEquivalent(ContextSetting obj) {
		if (!startAddr.equals(obj.startAddr)) {
			return false;
		}
		if (!endAddr.equals(obj.endAddr)) {
			return false;
		}
		if (!register.equals(obj.register)) {
			return false;
		}
		if (!value.equals(obj.value)) {
			return false;
		}
		return true;
	}

	public static void parseContextSet(List<ContextSetting> resList, XmlPullParser parser,
			CompilerSpec cspec) throws XmlParseException {
		XmlElement el = parser.start();
		boolean isContextReg;
		if (el.getName().equals("context_set")) {
			isContextReg = true;
		}
		else if (el.getName().equals("tracked_set")) {
			isContextReg = false;
		}
		else {
			throw new XmlParseException("Unknown context setting tag: " + el.getName());
		}
		AddressXML range = AddressXML.restoreRangeXml(el, cspec);
		Address firstAddr = range.getFirstAddress();
		Address lastAddr = range.getLastAddress();
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			ContextSetting ctxSetting =
				new ContextSetting(subel, cspec, isContextReg, firstAddr, lastAddr);
			parser.end(subel);
			resList.add(ctxSetting);
		}
		parser.end(el);
	}

	public static void parseContextData(List<ContextSetting> resList, XmlPullParser parser,
			CompilerSpec cspec) throws XmlParseException {
		parser.start();
		while (parser.peek().isStart()) {
			parseContextSet(resList, parser, cspec);
		}
		parser.end();
	}

	public static void encodeContextData(Encoder encoder, List<ContextSetting> ctxList)
			throws IOException {
		if (ctxList.isEmpty()) {
			return;
		}
		encoder.openElement(ELEM_CONTEXT_DATA);
		Iterator<ContextSetting> iter = ctxList.iterator();
		ContextSetting startContext = iter.next();
		boolean isContextReg = startContext.register.isProcessorContext();
		Address firstAddr = startContext.startAddr;
		Address lastAddr = startContext.endAddr;
		while (iter.hasNext()) {
			encoder.openElement(
				isContextReg ? ELEM_CONTEXT_SET : ELEM_TRACKED_SET);
			AddressXML.encodeAttributes(encoder, firstAddr, lastAddr);
			startContext.encode(encoder);
			while (iter.hasNext()) {
				startContext = iter.next();
				boolean nextIsContext = startContext.register.isProcessorContext();
				boolean shouldBreak = false;
				if (isContextReg != nextIsContext) {
					isContextReg = nextIsContext;
					shouldBreak = true;
				}
				if (!firstAddr.equals(startContext.startAddr)) {
					firstAddr = startContext.startAddr;
					shouldBreak = true;
				}
				if (!lastAddr.equals(startContext.endAddr)) {
					lastAddr = startContext.endAddr;
					shouldBreak = true;
				}
				if (shouldBreak) {
					break;
				}
				startContext.encode(encoder);
			}
			encoder.closeElement(
				isContextReg ? ELEM_CONTEXT_SET : ELEM_TRACKED_SET);
		}
		encoder.closeElement(ELEM_CONTEXT_DATA);
	}
}
