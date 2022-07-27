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

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.program.model.lang.InjectPayload.InjectParameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;
import ghidra.util.Msg;
import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;

public class PcodeInjectLibrary {
	protected SleighLanguage language;
	protected long uniqueBase;					// Current base address for new temporary registers

	private Map<String, InjectPayload> callFixupMap;		// Map of names to registered callfixups
	private Map<String, InjectPayload> callOtherFixupMap;	// Map of registered callotherfixups names to injection id
	private InjectPayload[] callOtherOverride;				// List of overridden callotherfixups
	private Map<String, InjectPayload> callMechFixupMap;	// Map of registered injectUponEntry/Return ids
	private Map<String, InjectPayload> exePcodeMap;			// Map of registered p-code scripts
	private InjectPayloadSleigh[] programPayload;			// List of Program specific payloads

	public PcodeInjectLibrary(SleighLanguage l) {
		language = l;
		uniqueBase = UniqueLayout.INJECT.getOffset(l);
		callFixupMap = new TreeMap<>();
		callOtherFixupMap = new TreeMap<>();
		callOtherOverride = null;
		callMechFixupMap = new TreeMap<>();
		exePcodeMap = new TreeMap<>();
		programPayload = null;
	}

	/**
	 * Clone a library so that a Program can extend the library without
	 * modifying the base library from Language.  InjectPayloads can be considered
	 * immutable and don't need to be cloned.
	 * @param op2 is the library to clone
	 */
	public PcodeInjectLibrary(PcodeInjectLibrary op2) {
		language = op2.language;
		uniqueBase = op2.uniqueBase;
		callFixupMap = new TreeMap<>(op2.callFixupMap);
		callOtherFixupMap = new TreeMap<>(op2.callOtherFixupMap);
		callOtherOverride = op2.callOtherOverride;
		callMechFixupMap = new TreeMap<>(op2.callMechFixupMap);
		exePcodeMap = new TreeMap<>(op2.exePcodeMap);
		programPayload = op2.programPayload;
	}

	/**
	 * @return A clone of this library
	 */
	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibrary(this);
	}

	/**
	 * @return an array of all the program specific payloads (or null)
	 */
	public InjectPayloadSleigh[] getProgramPayloads() {
		return programPayload;
	}

	/**
	 * Determine if the given payload name and type exists and is an extension
	 * of the program.
	 * @param nm is the payload name
	 * @param type is the payload type
	 * @return true if the program extension exists
	 */
	public boolean hasProgramPayload(String nm, int type) {
		if (programPayload == null) {
			return false;
		}
		for (InjectPayload payload : programPayload) {
			if (payload.getType() != type) {
				continue;
			}
			if (payload.getName().equals(nm)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if a specific payload has been overridden by a user extension
	 * @param nm is the name of the payload
	 * @param type is the type of payload
	 * @return true if the payload is overridden
	 */
	public boolean isOverride(String nm, int type) {
		if (callOtherOverride == null || type != InjectPayload.CALLOTHERFIXUP_TYPE) {
			return false;
		}
		for (InjectPayload payload : callOtherOverride) {
			if (payload.getName().equals(nm)) {
				return true;
			}
		}
		return false;
	}

	public InjectPayload getPayload(int type, String name) {
		if (name == null) {
			return null;
		}
		if (type == InjectPayload.CALLFIXUP_TYPE) {
			return callFixupMap.get(name);
		}
		else if (type == InjectPayload.CALLOTHERFIXUP_TYPE) {
			return callOtherFixupMap.get(name);
		}
		else if (type == InjectPayload.CALLMECHANISM_TYPE) {
			return callMechFixupMap.get(name);
		}
		else if (type == InjectPayload.EXECUTABLEPCODE_TYPE) {
			return exePcodeMap.get(name);
		}
		return null;
	}

	/**
	 * Convert the XML string representation of the given payload to a ConstructTpl
	 * The payload should be unattached (not already installed in the library)
	 * @param payload is the given payload whose XML should be converted
	 * @throws SleighException if there is any parsing issue
	 */
	public void parseInject(InjectPayload payload) throws SleighException {

		String sourceName = payload.getSource();
		if (sourceName == null) {
			sourceName = "unknown";
		}
		if (!(payload instanceof InjectPayloadSleigh)) {
			return;
		}
		InjectPayloadSleigh payloadSleigh = (InjectPayloadSleigh) payload;
		String pcodeText = payloadSleigh.releaseParseString();
		if (pcodeText == null) {
			return;			// Dynamic p-code generation, or already parsed
		}

		PcodeParser parser = new PcodeParser(language, uniqueBase);
		Location loc = new Location(sourceName, 1);
		InjectParameter[] input = payload.getInput();
		for (InjectParameter element : input) {
			parser.addOperand(loc, element.getName(), element.getIndex());
		}
		InjectParameter[] output = payload.getOutput();
		for (InjectParameter element : output) {
			parser.addOperand(loc, element.getName(), element.getIndex());
		}
		ConstructTpl constructTpl = parser.compilePcode(pcodeText, sourceName, 1);

		uniqueBase = parser.getNextTempOffset();

		payloadSleigh.setTemplate(constructTpl);
	}

	/**
	 * @return a list of names for all installed call-fixups
	 */
	public String[] getCallFixupNames() {
		Set<String> keySet = callFixupMap.keySet();
		String[] names = new String[keySet.size()];
		keySet.toArray(names);
		return names;
	}

	/**
	 * @return a list of names for all installed callother-fixups
	 */
	public String[] getCallotherFixupNames() {
		ArrayList<String> list = new ArrayList<>();
		for (Entry<String, InjectPayload> entry : callOtherFixupMap.entrySet()) {
			if (entry.getValue() != null) {
				list.add(entry.getKey());
			}
		}
		String[] res = new String[list.size()];
		list.toArray(res);
		return res;
	}

	public InjectContext buildInjectContext() {
		InjectContext res = new InjectContext();
		res.language = language;
		return res;
	}

	/**
	 * Determine if the language has a given user-defined op.
	 * In which case, a CALLOTHER_FIXUP can be installed for it.
	 * @param name is the putative name of the user-defined op
	 * @return true if the user-defined op exists
	 */
	public boolean hasUserDefinedOp(String name) {
		if (callOtherFixupMap.size() == 0) {
			int max = language.getNumberOfUserDefinedOpNames();
			for (int i = 0; i < max; ++i) {
				String opname = language.getUserDefinedOpName(i);
				callOtherFixupMap.put(opname, null);		// Initialize with null pcodeinjection
			}
		}
		return callOtherFixupMap.containsKey(name);
	}

	protected void registerInject(InjectPayload payload) {
		parseInject(payload);
		switch (payload.getType()) {
			case InjectPayload.CALLFIXUP_TYPE:
				if (callFixupMap.containsKey(payload.getName())) {
					throw new SleighException(
						"CallFixup registered multiple times: " + payload.getName());
				}
				callFixupMap.put(payload.getName(), payload);
				break;
			case InjectPayload.CALLOTHERFIXUP_TYPE:
				if (!hasUserDefinedOp(payload.getName())) {
					throw new SleighException(
						"Unknown callother name in <callotherfixup>: " + payload.getName());
				}
				if (callOtherFixupMap.get(payload.getName()) != null) {
					throw new SleighException(
						"Duplicate <callotherfixup> tag: " + payload.getName());
				}
				callOtherFixupMap.put(payload.getName(), payload);
				break;
			case InjectPayload.CALLMECHANISM_TYPE:
				if (callMechFixupMap.containsKey(payload.getName())) {
					throw new SleighException(
						"CallMechanism registered multiple times: " + payload.getName());
				}
				callMechFixupMap.put(payload.getName(), payload);
				break;
			case InjectPayload.EXECUTABLEPCODE_TYPE:
				if (exePcodeMap.containsKey(payload.getName())) {
					throw new SleighException(
						"Executable p-code registered multiple times: " + payload.getName());
				}
				exePcodeMap.put(payload.getName(), payload);
				break;
			default:
				throw new SleighException("Unknown p-code inject type");
		}
	}

	/**
	 * Remove a specific call mechanism payload.
	 * @param nm is the name of the payload
	 * @return true if a payload was successfully removed
	 */
	protected boolean removeMechanismPayload(String nm) {
		InjectPayload payload = callMechFixupMap.remove(nm);
		return (payload != null);
	}

	protected void uninstallProgramPayloads() {
		if (programPayload != null) {
			for (InjectPayloadSleigh payload : programPayload) {
				if (payload.type == InjectPayload.CALLFIXUP_TYPE) {
					callFixupMap.remove(payload.name);
				}
				else if (payload.type == InjectPayload.CALLOTHERFIXUP_TYPE) {
					callOtherFixupMap.put(payload.name, null);
				}
			}
			programPayload = null;
			if (callOtherOverride != null) {
				// Undo callother overrides, reinstalling the overridden payloads
				for (InjectPayload payload : callOtherOverride) {
					callOtherFixupMap.put(payload.getName(), payload);
				}
				callOtherOverride = null;
			}
		}
	}

	/**
	 * Look for user callother payloads that override an existing core fixup.
	 * Move these out of the map into the override list. Don't install user payload yet.
	 * @param userPayloads is the list of user payloads
	 */
	private void setupOverrides(List<InjectPayloadSleigh> userPayloads) {
		int count = 0;
		for (InjectPayloadSleigh payload : userPayloads) {
			if (payload.getType() == InjectPayload.CALLOTHERFIXUP_TYPE) {
				InjectPayload origPayload = callOtherFixupMap.get(payload.name);
				if (origPayload != null) {
					count += 1;
				}
			}
		}
		if (count == 0) {
			return;
		}
		callOtherOverride = new InjectPayload[count];
		count = 0;
		for (InjectPayloadSleigh payload : userPayloads) {
			if (payload.getType() == InjectPayload.CALLOTHERFIXUP_TYPE) {
				InjectPayload origPayload = callOtherFixupMap.get(payload.name);
				if (origPayload != null) {
					callOtherFixupMap.put(payload.name, null);
					callOtherOverride[count] = origPayload;
					count += 1;
				}
			}
		}
	}

	protected void registerProgramInject(List<InjectPayloadSleigh> userPayloads) {
		uninstallProgramPayloads();
		if (userPayloads.isEmpty()) {
			return;			// Leave programPayload null if there are no program payloads
		}
		setupOverrides(userPayloads);
		programPayload = new InjectPayloadSleigh[userPayloads.size()];
		int count = 0;
		for (InjectPayloadSleigh payload : userPayloads) {
			try {
				registerInject(payload);
				programPayload[count] = payload;
				count += 1;
			}
			catch (SleighException ex) {
				Msg.warn(this,
					"Error installing fixup extension: " + payload.name + ": " + ex.getMessage());
			}
		}
		if (count != programPayload.length) {
			InjectPayloadSleigh[] finalPayloads = new InjectPayloadSleigh[count];
			System.arraycopy(programPayload, 0, finalPayloads, 0, count);
			programPayload = finalPayloads;
		}
	}

	/**
	 * The main InjectPayload factory interface. This can be overloaded by derived libraries
	 * to produce custom dynamic payloads.
	 * @param sourceName is a description of the source of the payload
	 * @param name is the formal name of the payload
	 * @param tp is the type of payload:  CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc.
	 * @return the newly minted InjectPayload
	 */
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLFIXUP_TYPE) {
			return new InjectPayloadCallfixup(sourceName);
		}
		else if (tp == InjectPayload.CALLOTHERFIXUP_TYPE) {
			return new InjectPayloadCallother(sourceName);
		}
		return new InjectPayloadSleigh(name, tp, sourceName);
	}

	/**
	 * Encode the parts of the inject library that come from the compiler spec
	 * to the output stream
	 * @param encoder is the stream encoder
	 * @throws IOException for errors writing to the underlying stream
	 */
	public void encodeCompilerSpec(Encoder encoder) throws IOException {
		for (InjectPayload injectPayload : callFixupMap.values()) {
			if (injectPayload instanceof InjectPayloadSleigh) {
				((InjectPayloadSleigh) injectPayload).encode(encoder);
			}
		}
		for (InjectPayload injectPayload : callOtherFixupMap.values()) {
			if (injectPayload instanceof InjectPayloadSleigh) {
				((InjectPayloadSleigh) injectPayload).encode(encoder);
			}
		}
		for (InjectPayload injectPayload : exePcodeMap.values()) {
			if (injectPayload instanceof InjectPayloadSegment) {
				if (injectPayload.getSource().startsWith("cspec")) {
					((InjectPayloadSleigh) injectPayload).encode(encoder);
				}
			}
		}
	}

	public InjectPayload restoreXmlInject(String source, String name, int tp, XmlPullParser parser)
			throws XmlParseException {
		InjectPayload payload = allocateInject(source, name, tp);
		payload.restoreXml(parser, language);
		registerInject(payload);
		return payload;
	}

	/**
	 * Get the constant pool associated with the given Program
	 * @param program is the given Program
	 * @return the ConstantPool associated with the Program
	 * @throws IOException for issues constructing the object
	 */
	public ConstantPool getConstantPool(Program program) throws IOException {
		return null;
	}

	//methods below this point added for PcodeInjectLibraryJava:
	protected long getUniqueBase() {
		return uniqueBase;
	}

	/**
	 * Compare that this and the other library contain all equivalent payloads
	 * @param obj is the other library
	 * @return true if all payloads are equivalent
	 */
	public boolean isEquivalent(PcodeInjectLibrary obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		// Cannot compare uniqueBase as one side may not have parsed p-code
//		if (uniqueBase != op2.uniqueBase) {
//			return false;
//		}
		if (callFixupMap.size() != obj.callFixupMap.size()) {
			return false;
		}
		for (Entry<String, InjectPayload> entry : callFixupMap.entrySet()) {
			InjectPayload op2payload = obj.callFixupMap.get(entry.getKey());
			if (!entry.getValue().isEquivalent(op2payload)) {
				return false;
			}
		}
		if (callMechFixupMap.size() != obj.callMechFixupMap.size()) {
			return false;
		}
		for (Entry<String, InjectPayload> entry : callMechFixupMap.entrySet()) {
			InjectPayload op2payload = obj.callMechFixupMap.get(entry.getKey());
			if (!entry.getValue().isEquivalent(op2payload)) {
				return false;
			}
		}
		if (callOtherFixupMap.size() != obj.callOtherFixupMap.size()) {
			return false;
		}
		for (Entry<String, InjectPayload> entry : callOtherFixupMap.entrySet()) {
			InjectPayload op2payload = obj.callOtherFixupMap.get(entry.getKey());
			if (entry.getValue() != null && op2payload != null) {
				if (!entry.getValue().isEquivalent(op2payload)) {
					return false;
				}
			}
			else if (entry.getValue() != null || op2payload != null) {
				return false;
			}
		}
		if (callOtherOverride != null && obj.callOtherOverride != null) {
			if (callOtherOverride.length != obj.callOtherOverride.length) {
				return false;
			}
			for (int i = 0; i < callOtherOverride.length; ++i) {
				if (!callOtherOverride[i].isEquivalent(obj.callOtherOverride[i])) {
					return false;
				}
			}
		}
		else if (callOtherOverride == null && obj.callOtherOverride == null) {
			// continue
		}
		else {
			return false;
		}

		if (exePcodeMap.size() != obj.exePcodeMap.size()) {
			return false;
		}
		for (Entry<String, InjectPayload> entry : exePcodeMap.entrySet()) {
			InjectPayload op2payload = obj.exePcodeMap.get(entry.getKey());
			if (!entry.getValue().isEquivalent(op2payload)) {
				return false;
			}
		}
		if (programPayload != null && obj.programPayload != null) {
			if (programPayload.length != obj.programPayload.length) {
				return false;
			}
			for (int i = 0; i < programPayload.length; ++i) {
				if (!programPayload[i].isEquivalent(obj.programPayload[i])) {
					return false;
				}
			}
		}
		else if (programPayload == null && obj.programPayload == null) {
			// continue
		}
		else {
			return false;
		}
		return true;
	}
}
