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
package ghidra.app.util.xml;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import org.xml.sax.SAXParseException;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.*;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * XML manager for register values.
 */
class RegisterValuesXmlMgr {
	private Program program;
	private MessageLog log;
	private AddressFactory factory;
	private ProgramContext context;
	private Set<String> undefinedRegisterNames;
	
	RegisterValuesXmlMgr(Program program, MessageLog log) {
		this.program = program;
		this.log = log;	
		factory = program.getAddressFactory();
		context = program.getProgramContext();
	}
	
	/**
	 * Process the entry point section of the XML file.
	 * @param parser xml reader
	 * @param monitor monitor that can be canceled
	 */
	void read(XmlPullParser parser, TaskMonitor monitor) throws SAXParseException, CancelledException { 
		undefinedRegisterNames = new HashSet<String>();
		XmlElement element = parser.next();
		if (!element.isStart() || !element.getName().equals("REGISTER_VALUES")) {
			throw new SAXParseException("Expected REGISTER_VALUES start tag", null, null, parser.getLineNumber(), parser.getColumnNumber());
		}
		
		element = parser.next();
		while (element != null && element.isStart() && element.getName().equals("REGISTER_VALUE_RANGE")) {
			if (monitor.isCancelled()) {
				throw new CancelledException();	
			}

			processRegisterValues(element, parser);

			element = parser.next();
			if (element.isStart() || !element.getName().equalsIgnoreCase("REGISTER_VALUE_RANGE")) {
				throw new SAXParseException("Expected REGISTER_VALUE_RANGE end tag", null, null, parser.getLineNumber(), parser.getColumnNumber());
			}
			
			// read next tag
			element = parser.next();
		}
		
		if (element != null && !element.getName().equals("REGISTER_VALUES")) {
			throw new SAXParseException("Expected REGISTER_VALUES end tag", null, null, parser.getLineNumber(), parser.getColumnNumber());
		}
	}
	
	/**
	 * Returns list of unique registers which do not overlap any smaller 
	 * registers.
	 */
	private List<Register> getUniqueRegisters() {
	
		ArrayList<Register> regs = new ArrayList<>(context.getRegisters());
		Collections.sort(regs, new Comparator<Register>() {
			@Override
			public int compare(Register r1, Register r2) {
				int size1 = r1.getMinimumByteSize();
				int size2 = r2.getMinimumByteSize();
				if (size1 != size2) {
					return size1 - size2;	
				}
				return r1.getOffset() - r2.getOffset(); 
			}
		});
		
		return regs;
	}

	/**
	 * Write out the XML for the Equates.
	 * @param writer writer for XML
	 * @param set address set that is either the entire program or a selection
	 * @param monitor monitor that can be canceled
	 * should be written
	 * @throws IOException
	 */
	void write(XmlWriter writer, AddressSetView set, TaskMonitor monitor) throws CancelledException {

		writer.startElement("REGISTER_VALUES");

		List<Register> regs = getUniqueRegisters();
		if (set == null) {
			set = program.getMemory();
		}
		AddressRangeIterator rangeIter = set.getAddressRanges();
		while (rangeIter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();	
			}

			AddressRange range = rangeIter.next();
		
			for (Register reg : regs) {
				AddressRangeIterator it = context.getRegisterValueAddressRanges(reg, range.getMinAddress(), range.getMaxAddress());
				while(it.hasNext()) {
					monitor.checkCanceled();
					AddressRange valueRange = it.next();
					BigInteger value = context.getValue(reg, valueRange.getMinAddress(),false);
					if (value == null) {
						continue;
					}
					XmlAttributes attr = new XmlAttributes();
					attr.addAttribute("REGISTER", reg.getName());
					attr.addAttribute("VALUE", value, true);
					attr.addAttribute("START_ADDRESS", XmlProgramUtilities.toString(valueRange.getMinAddress()));				
					attr.addAttribute("LENGTH", valueRange.getLength(), true);
					writer.writeElement("REGISTER_VALUE_RANGE", attr);
				}
			}
		}
		
		writer.endElement("REGISTER_VALUES");
	}

	private void processRegisterValues(XmlElement element, XmlPullParser parser) {
		try {
			String regName = element.getAttribute("REGISTER");
			if (regName == null) {
				throw new XmlAttributeException("REGISTER attribute missing for REGISTER_VALUE_RANGE element");
			}
			String valueStr = element.getAttribute("VALUE");
			if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
				valueStr = valueStr.substring(2);
			}
			BigInteger value = new BigInteger(valueStr, 16);
			String startAddrStr = element.getAttribute("START_ADDRESS");
			if (startAddrStr == null) {
				throw new XmlAttributeException("START_ADDRESS attribute missing for REGISTER_VALUE_RANGE element");
			}
			Address startAddr = XmlProgramUtilities.parseAddress(factory, startAddrStr);
			if (startAddr == null) {
				throw new AddressFormatException("Incompatible Register Address: " + startAddrStr);
			}
			long len = XmlUtilities.parseLong(element.getAttribute("LENGTH"));
			if (len < 1) {
				throw new XmlAttributeException("LENGTH [" + len + "] is illegal for REGISTER_VALUE_RANGE element");
			}

			Register reg = context.getRegister(regName);
			if (reg == null) {
				if (undefinedRegisterNames.add(regName)) {
					log.appendMsg("REGISTER [" + regName + "] is not defined by " + program.getLanguageID() + ", register values will be ignored");
				}
				return;
			}

			context.setValue(reg, startAddr, startAddr.addNoWrap(len - 1), value);
		} 
		catch (Exception e) {
			log.appendException(e);
		}
	}

}
