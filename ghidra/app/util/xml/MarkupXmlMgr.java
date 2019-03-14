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

import java.util.*;

import org.xml.sax.SAXParseException;

import ghidra.app.cmd.refs.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.*;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * XML manager for all references ("markup" for operand substitution).
 */
class MarkupXmlMgr {
	private Program program;
	private ReferenceManager refManager;
	private AddressFactory factory;
	private MessageLog log;
	private EquateTable equateTable;
	private Listing listing;

	MarkupXmlMgr(Program program, MessageLog log) {
		this.program = program;
		listing = program.getListing();
		refManager = program.getReferenceManager();
		equateTable = program.getEquateTable();
		this.factory = program.getAddressFactory();
		this.log = log;
	}

	///////////////////////////////////////////////////////////////////////////////////////
	//                            XML READ CURRENT DTD                                   //
	///////////////////////////////////////////////////////////////////////////////////////

	void read(XmlPullParser parser, boolean overwrite, boolean isExtLibs, boolean isFunctions,
			boolean ignoreStackReferences, TaskMonitor monitor)
			throws SAXParseException, CancelledException {
		XmlElement element = parser.next();
		if (!element.isStart() || !element.getName().equals("MARKUP")) {
			throw new SAXParseException("Expected MARKUP start tag", null, null,
				parser.getLineNumber(), parser.getColumnNumber());
		}

		element = parser.next();
		while (element.isStart()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			String tagName = element.getName().toUpperCase();
			if (tagName.equals("MEMORY_REFERENCE")) {
				processMemoryReference(element, overwrite);
			}
			else if (tagName.equals("STACK_REFERENCE")) {
				if (isFunctions && !ignoreStackReferences) {
					processStackReference(element, overwrite);
				}
			}
			else if (tagName.equals("EXT_LIBRARY_REFERENCE")) {
				if (isExtLibs) {
					processExtLibraryReference(element, overwrite);
				}
			}
			else if (tagName.equals("EQUATE_REFERENCE")) {
				processEquateReference(element, overwrite);
			}
			else if (tagName.equals("MANUAL_OPERAND")) {
				// Not yet supported
			}
			else if (tagName.equals("MANUAL_INSTRUCTION")) {
				// Not yet supported
			}
			else {
				throw new SAXParseException("Unexpected XML tag: " + tagName, null, null,
					parser.getLineNumber(), parser.getColumnNumber());
			}

			// read end of tag
			element = parser.next();
			if (element.isStart() || !element.getName().equalsIgnoreCase(tagName)) {
				throw new SAXParseException("Expected " + tagName + " end tag", null, null,
					parser.getLineNumber(), parser.getColumnNumber());
			}

			// read next tag
			element = parser.next();
		}

		if (!element.getName().equals("MARKUP")) {
			throw new SAXParseException("Expected MARKUP end tag", null, null,
				parser.getLineNumber(), parser.getColumnNumber());
		}
	}

	private RefType getDefaultRefType(Address fromAddr, Address toAddr, int opIndex) {
		CodeUnit srcCU = program.getListing().getCodeUnitAt(fromAddr);
		CodeUnit destCU = program.getListing().getCodeUnitAt(toAddr);

		if (srcCU instanceof Instruction && destCU instanceof Instruction) {
			Instruction srcInst = (Instruction) srcCU;
			FlowType ft = srcInst.getFlowType();
			if (ft.isCall() || ft.isJump()) {
				return ft;
			}
		}
		else if (srcCU instanceof Instruction && opIndex != CodeUnit.MNEMONIC) {
			Instruction srcInst = (Instruction) srcCU;
			return srcInst.getOperandRefType(opIndex);
		}

		return RefType.DATA;

		//CodeUnit srcCu = program.getListing().getCodeUnitAt(fromAddr);
		//CodeUnit destCu = program.getListing().getCodeUnitAt(toAddr);
		//if (srcCu instanceof Instruction) {
		//	Instruction instr = (Instruction)srcCu;
		//	
		//	// Use FlowType of instruction if reference to another instruction
		//	if (destCu instanceof Instruction) {
		//		refType = instr.getFlowType();
		//	}
		//	
		//	// Otherwise, use default operand reference type if operand specified
		//	else if (opIndex != CodeUnit.MNEMONIC){
		//		refType = instr.getOperandRefType(opIndex);
		//	}
		//}
		//return refType;
	}

	/**
	 * @param element
	 * @param language
	 * @param overwrite
	 */
	private void processMemoryReference(XmlElement element, boolean overwrite) {
		try {
			String fromAddrStr = element.getAttribute("ADDRESS");
			if (fromAddrStr == null) {
				throw new XmlAttributeException(
					"ADDRESS attribute missing for MEMORY_REFERENCE element");
			}
			Address fromAddr = XmlProgramUtilities.parseAddress(factory, fromAddrStr);
			if (fromAddr == null) {
				throw new AddressFormatException(
					"Incompatible Memory Reference FROM Address: " + fromAddrStr);
			}

			String toAddrStr = element.getAttribute("TO_ADDRESS");
			if (toAddrStr == null) {
				throw new XmlAttributeException(
					"TO_ADDRESS attribute missing for MEMORY_REFERENCE element");
			}
			Address toAddr = XmlProgramUtilities.parseAddress(factory, toAddrStr);
			if (toAddr == null) {
				throw new AddressFormatException(
					"Incompatible Memory Reference TO Address: " + toAddrStr);
			}

			int opIndex = CodeUnit.MNEMONIC;
			if (element.hasAttribute("OPERAND_INDEX")) {
				opIndex = XmlUtilities.parseInt(element.getAttribute("OPERAND_INDEX"));
				if (opIndex < 0) {
					throw new XmlAttributeException(
						"Illegal OPERAND_INDEX value [" + opIndex + "]");
				}
			}

			boolean userDefined = true;
			if (element.hasAttribute("USER_DEFINED")) {
				userDefined = XmlUtilities.parseBoolean(element.getAttribute("USER_DEFINED"));
			}

			boolean primary = false;
			if (element.hasAttribute("PRIMARY")) {
				primary = XmlUtilities.parseBoolean(element.getAttribute("PRIMARY"));
			}

			Address baseAddr = null;
			if (element.hasAttribute("BASE_ADDRESS")) {
				baseAddr =
					XmlProgramUtilities.parseAddress(factory, element.getAttribute("BASE_ADDRESS"));
			}

			if (!overwrite) {
				Reference existingMemRef = refManager.getReference(fromAddr, toAddr, opIndex);
				if (existingMemRef != null) {
					log.appendMsg("Memory reference already existed from [" + fromAddr + "] to [" +
						toAddr + "] on operand [" + opIndex + "]");
					return;
				}
			}

			RefType refType = getDefaultRefType(fromAddr, toAddr, opIndex);

			Command cmd = null;
			if (baseAddr != null) {
				long offset = toAddr.subtract(baseAddr);
				cmd = new AddOffsetMemRefCmd(fromAddr, toAddr, refType,
					userDefined ? SourceType.USER_DEFINED : SourceType.DEFAULT, opIndex, offset);
			}
			else {
				cmd = new AddMemRefCmd(fromAddr, toAddr, refType,
					userDefined ? SourceType.USER_DEFINED : SourceType.DEFAULT, opIndex);
			}

			cmd.applyTo(program);

			cmd = new SetPrimaryRefCmd(fromAddr, opIndex, toAddr, primary);
			cmd.applyTo(program);

		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	private void processStackReference(XmlElement element, boolean overwrite) {
		try {
			String addrStr = element.getAttribute("ADDRESS");
			if (addrStr == null) {
				throw new XmlAttributeException(
					"ADDRESS attribute missing for STACK_REFERENCE element");
			}
			Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
			if (addr == null) {
				throw new AddressFormatException(
					"Incompatible Stack Reference Address: " + addrStr);
			}
			int opIndex = CodeUnit.MNEMONIC;
			if (element.hasAttribute("OPERAND_INDEX")) {
				opIndex = XmlUtilities.parseInt(element.getAttribute("OPERAND_INDEX"));
			}
			CodeUnit cu = listing.getCodeUnitAt(addr);
			if (cu == null) {
				log.appendMsg("No codeunit at " + addr);
				return;
			}
			Reference ref = cu.getPrimaryReference(opIndex);
			if (ref != null) {
				if (!overwrite) {
					return;
				}
			}
			boolean userDefined = true;
			if (element.hasAttribute("USER_DEFINED")) {
				userDefined = XmlUtilities.parseBoolean(element.getAttribute("USER_DEFINED"));
			}
			int offset = XmlUtilities.parseInt(element.getAttribute("STACK_PTR_OFFSET"));

			AddStackRefCmd addCmd = new AddStackRefCmd(addr, opIndex, offset,
				userDefined ? SourceType.USER_DEFINED : SourceType.DEFAULT);
			addCmd.applyTo(program);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	private void processExtLibraryReference(XmlElement element, boolean overwrite) {
		try {
			String addrStr = element.getAttribute("ADDRESS");
			if (addrStr == null) {
				throw new XmlAttributeException(
					"ADDRESS attribute missing for EXT_LIBRARY_REFERENCE element");
			}
			Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
			if (addr == null) {
				throw new AddressFormatException(
					"Incompatible External Reference Address: " + addrStr);
			}
			int opIndex = CodeUnit.MNEMONIC;
			if (element.hasAttribute("OPERAND_INDEX")) {
				opIndex = XmlUtilities.parseInt(element.getAttribute("OPERAND_INDEX"));
			}
			boolean userDefined = true;
			if (element.hasAttribute("USER_DEFINED")) {
				userDefined = XmlUtilities.parseBoolean(element.getAttribute("USER_DEFINED"));
			}
// FIXME Do we need to introduce more/different external tags now? (namespaces, classes, etc.)
			String programName = element.getAttribute("LIB_PROG_NAME");
			String label = element.getAttribute("LIB_LABEL");
			Address libAddr = element.hasAttribute("LIB_ADDR")
					? factory.getAddress(element.getAttribute("LIB_ADDR"))
					: null;

			if (label == null && libAddr == null) {
				log.appendMsg("External library reference for address " + addr +
					" does not have a label or an external address specified at " +
					element.getLineNumber() + ". External reference will not be created");
				return;
			}
			CodeUnit cu = listing.getCodeUnitAt(addr);
			if (cu == null) {
				log.appendMsg("No codeunit at " + addr);
				return;
			}
			Reference ref = cu.getExternalReference(opIndex);
			if (ref != null) {
				if (!overwrite) {
					return;
				}
				program.getReferenceManager().delete(ref);
			}

// FIXME What do we need to do for externals in XML now?
// FIXME
			SetExternalRefCmd addCmd = new SetExternalRefCmd(addr, opIndex, programName, label,
				libAddr, userDefined ? SourceType.USER_DEFINED : SourceType.IMPORTED);
			addCmd.applyTo(program);

//			// if there happens to be a pointer here, then
//			// delete the memory references associated to it...
//			//
//			Data data = listing.getDataAt(addr);
//			if (data != null && data.isPointer()) {
//				Address toAddr = (Address) data.getValue();
//				if (toAddr != null) {
//					Reference mr = refManager.getReference(addr, toAddr, opIndex);
//					if (mr != null) {
//						RemoveReferenceCmd removeCmd = new RemoveReferenceCmd(mr);
//						removeCmd.applyTo(program);
//					}
//				}
//			}

		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	/**
	 * @param element
	 * @param language
	 * @param overwrite
	 */
	private void processEquateReference(XmlElement element, boolean overwrite) {
		try {
			String addrStr = element.getAttribute("ADDRESS");
			if (addrStr == null) {
				throw new XmlAttributeException(
					"ADDRESS attribute missing for EQUATE_REFERENCE element");
			}
			Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
			if (addr == null) {
				throw new AddressFormatException(
					"Incompatible Equate Reference Address: " + addrStr);
			}

			if (listing.isUndefined(addr, addr)) {
				log.appendMsg("BAD EQUATE REFERENCE: defined code unit not found at " + addr);
				return;
			}

			CodeUnit cu = listing.getCodeUnitAt(addr);
			if (cu == null) {
				log.appendMsg("No codeunit at " + addr);
				return;
			}

			String equateName = element.getAttribute("NAME");

			int opIndex = CodeUnit.MNEMONIC;

			List<Scalar> instrScalars = new LinkedList<Scalar>();
			if (element.hasAttribute("OPERAND_INDEX")) {
				opIndex = XmlUtilities.parseInt(element.getAttribute("OPERAND_INDEX"));
				if (opIndex != CodeUnit.MNEMONIC) {
					Scalar tempScalar = cu.getScalar(opIndex);
					if (tempScalar != null) {
						instrScalars.add(tempScalar);
					}
					else if (cu instanceof Instruction) {
						Instruction instr = (Instruction) cu;
						Object[] opObjects = instr.getOpObjects(opIndex);
						for (int i = 0; i < opObjects.length; i++) {
							if (opObjects[i] instanceof Scalar) {
								instrScalars.add((Scalar) opObjects[i]);
							}
						}

						if (instrScalars.size() == 0) {
							log.appendMsg("BAD EQUATE REFERENCE: operand " + "[" + opIndex +
								"] at address " + "[" + addr + "] is not a scalar.");
							return;
						}
					}
				}
			}

			long value = 0;
			if (element.hasAttribute("VALUE")) {
				value = XmlUtilities.parseLong(element.getAttribute("VALUE"));
				Scalar matchingScalar = null;
				Iterator<Scalar> itr = instrScalars.iterator();
				while (matchingScalar == null && itr.hasNext()) {
					matchingScalar = itr.next();
					if (matchingScalar.getSignedValue() != value) {
						matchingScalar = null;
					}
				}

				if (matchingScalar == null) {
					log.appendMsg("BAD EQUATE REFERENCE: equate [" + equateName + "] value [0x" +
						Long.toHexString(value) + "]" + " does not match scalar on operand [" +
						opIndex + "] at address [" + addr + "]");
					return;
				}
			}
			else if (instrScalars.size() > 0) {
				// use scalar value as default - seems like a bad idea
				Msg.warn(this, "NO VALUE SPECIFIED");
				value = instrScalars.get(0).getSignedValue();
			}
			else {
				log.appendMsg(
					"BAD EQUATE REFERENCE: either the VALUE or OPERAND_INDEX must be specified");
				return;
			}

			Equate equate = equateTable.getEquate(equateName);
			if (equate != null) {
				if (value != equate.getValue()) {
					log.appendMsg("BAD EQUATE REFERENCE: equate [" + equateName + "] value [0x" +
						Long.toHexString(value) + "] conflicts with existing equate value [0x" +
						Long.toHexString(equate.getValue()) + "].");
					return;
				}
			}
			else {
				try {
					equate = equateTable.createEquate(equateName, value);
				}
				catch (DuplicateNameException e) {
					throw new AssertException(
						"Got duplicate name while creating equate " + equateName);
				}
				catch (InvalidInputException e) {
					log.appendMsg("Invalid name for equate " + equateName);
					return;
				}
			}

			Equate existingEquate = equateTable.getEquate(addr, opIndex, equate.getValue());
			if (existingEquate != null && overwrite) {
				existingEquate.removeReference(addr, opIndex);
			}
			equate.addReference(addr, opIndex);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	///////////////////////////////////////////////////////////////////////////////////////
	//   						 XML WRITE CURRENT DTD                                   //
	///////////////////////////////////////////////////////////////////////////////////////

	void write(XmlWriter writer, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		if (set == null) {
			set = program.getMemory();
		}

		writer.startElement("MARKUP");

		monitor.setMessage("Exporting References...");
		AddressIterator iter = refManager.getReferenceSourceIterator(set, true);
		while (iter.hasNext()) {
			Reference[] refs = refManager.getReferencesFrom(iter.next());
			for (int i = 0; i < refs.length; i++) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				Reference ref = refs[i];
				if (ref.isMemoryReference()) {
					writeMemoryReference(ref, writer);
				}
			}
		}

		iter = refManager.getReferenceSourceIterator(set, true);
		while (iter.hasNext()) {
			Reference[] refs = refManager.getReferencesFrom(iter.next());
			for (int i = 0; i < refs.length; i++) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				Reference ref = refs[i];
				if (ref.isStackReference()) {
					writeStackReference((StackReference) ref, writer);
				}
			}
		}

		iter = refManager.getReferenceSourceIterator(set, true);
		while (iter.hasNext()) {
			Reference[] refs = refManager.getReferencesFrom(iter.next());
			for (int i = 0; i < refs.length; i++) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				Reference ref = refs[i];
				if (ref.isExternalReference()) {
					writeExternalReference((ExternalReference) ref, writer);
				}
			}
		}

		writeEquateReferences(writer, set, monitor);

		writer.endElement("MARKUP");
	}

	private void writeMemoryReference(Reference ref, XmlWriter writer) {

		if (ref.getSource() == SourceType.USER_DEFINED) {
			XmlAttributes attr = new XmlAttributes();
			addCommonRefAttributes(attr, ref);
			attr.addAttribute("TO_ADDRESS", XmlProgramUtilities.toString(ref.getToAddress()));
			if (ref.isOffsetReference()) {
				attr.addAttribute("BASE_ADDRESS",
					XmlProgramUtilities.toString(((OffsetReference) ref).getBaseAddress()));
			}
			else if (ref.isShiftedReference()) {

// TODO: Handle ShiftedReference

			}
			attr.addAttribute("PRIMARY", ref.isPrimary());
			writer.writeElement("MEMORY_REFERENCE", attr);
		}
	}

	private void writeStackReference(StackReference ref, XmlWriter writer) {

		if (ref.getSource() == SourceType.USER_DEFINED) {
			if (ref.isStackReference()) {
				XmlAttributes attr = new XmlAttributes();
				addCommonRefAttributes(attr, ref);
				attr.addAttribute("STACK_PTR_OFFSET", ref.getStackOffset(), true);
				writer.writeElement("STACK_REFERENCE", attr);
			}
		}
	}

	private void writeExternalReference(ExternalReference ref, XmlWriter writer) {

		XmlAttributes attr = new XmlAttributes();
		addCommonRefAttributes(attr, ref);
		ExternalLocation extLoc = ref.getExternalLocation();
		attr.addAttribute("LIB_PROG_NAME", extLoc.getLibraryName());
		String label = extLoc.getLabel();
		Address addr = extLoc.getAddress();
		if (label != null) {
			attr.addAttribute("LIB_LABEL", label);
		}
		if (addr != null) {
			attr.addAttribute("LIB_ADDR", XmlProgramUtilities.toString(addr));
		}
		writer.writeElement("EXT_LIBRARY_REFERENCE", attr);
	}

	private void writeEquateReferences(XmlWriter writer, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Exporting Equate References...");

		Iterator<Equate> iter = equateTable.getEquates();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Equate equate = iter.next();
			String name = equate.getName();
			long value = equate.getValue();
			EquateReference[] refs = equate.getReferences();
			for (int i = 0; i < refs.length; i++) {
				if (monitor.isCancelled()) {
					return;
				}
				Address addr = refs[i].getAddress();
				if (!set.contains(addr)) {
					continue;
				}
				XmlAttributes attr = new XmlAttributes();
				attr.addAttribute("ADDRESS", XmlProgramUtilities.toString(addr));
				attr.addAttribute("OPERAND_INDEX", refs[i].getOpIndex(), true);
				attr.addAttribute("NAME", name);
				attr.addAttribute("VALUE", value, true);
				writer.writeElement("EQUATE_REFERENCE", attr);
			}
		}
	}

	private void addCommonRefAttributes(XmlAttributes attr, Reference ref) {
		attr.addAttribute("ADDRESS", XmlProgramUtilities.toString(ref.getFromAddress()));
		int opIndex = ref.getOperandIndex();
		if (opIndex != CodeUnit.MNEMONIC) {
			attr.addAttribute("OPERAND_INDEX", opIndex, true);
		}
		attr.addAttribute("USER_DEFINED", ref.getSource() == SourceType.USER_DEFINED);
	}

}
