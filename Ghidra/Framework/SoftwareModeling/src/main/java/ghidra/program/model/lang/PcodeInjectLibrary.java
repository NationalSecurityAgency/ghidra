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

import org.jdom.JDOMException;
import org.xml.sax.*;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slgh_compile.PcodeParser;
import ghidra.program.model.lang.InjectPayload.InjectParameter;
import ghidra.program.model.listing.Program;
import ghidra.sleigh.grammar.Location;
import ghidra.util.Msg;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

public class PcodeInjectLibrary {
	private SleighLanguage language;
	private long uniqueBase;					// Current base address for new temporary registers

	private Map<String, InjectPayload> callFixupMap;	// Map of names to registered callfixups
	private Map<String, InjectPayload> callOtherFixupMap;	// Map of registered callotherfixups names to injection id 
	private Map<String, InjectPayload> callMechFixupMap;	// Map of registered injectUponEntry/Return ids
	private Map<String, InjectPayload> exePcodeMap;			// Map of registered p-code scripts

	public PcodeInjectLibrary(SleighLanguage l) {
		language = l;
		uniqueBase = language.getUniqueBase();
		callFixupMap = new TreeMap<String, InjectPayload>();
		callOtherFixupMap = new TreeMap<String, InjectPayload>();
		callMechFixupMap = new TreeMap<String, InjectPayload>();
		exePcodeMap = new TreeMap<String, InjectPayload>();
	}

	public InjectPayload getPayload(int type, String name, Program program, String context) {
		if (name == null)
			return null;
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

	private void parseInject(InjectPayload payload) throws SleighException {

		String sourceName = payload.getSource();
		if (sourceName == null)
			sourceName = "unknown";
		if (!(payload instanceof InjectPayloadSleigh))
			return;
		InjectPayloadSleigh payloadSleigh = (InjectPayloadSleigh) payload;
		String translateSpec =
			language.buildTranslatorTag(language.getAddressFactory(), uniqueBase,
				language.getSymbolTable());

		String pcodeText = payloadSleigh.releaseParseString();
		if (pcodeText == null)
			return;			// Dynamic p-code generation
		try {
			PcodeParser parser = new PcodeParser(translateSpec);
			Location loc = new Location(sourceName, 1);
			InjectParameter[] input = payload.getInput();
			for (InjectParameter element : input)
				parser.addOperand(loc, element.getName(), element.getIndex());
			InjectParameter[] output = payload.getOutput();
			for (InjectParameter element : output)
				parser.addOperand(loc, element.getName(), element.getIndex());
			String constructTplXml =
				PcodeParser.stringifyTemplate(parser.compilePcode(pcodeText, sourceName, 1));
			if (constructTplXml == null) {
				throw new SleighException("pcode compile failed " + sourceName);
			}
			final SAXParseException[] exception = new SAXParseException[1];
			XmlPullParser xmlParser =
				XmlPullParserFactory.create(constructTplXml, sourceName, new ErrorHandler() {
					@Override
					public void warning(SAXParseException e) throws SAXException {
						Msg.warn(this, e.getMessage());
					}

					@Override
					public void fatalError(SAXParseException e) throws SAXException {
						exception[0] = e;
					}

					@Override
					public void error(SAXParseException e) throws SAXException {
						exception[0] = e;
					}
				}, false);

			ConstructTpl constructTpl = new ConstructTpl();
			constructTpl.restoreXml(xmlParser, language.getAddressFactory());
			if (exception[0] != null) {
				throw new SleighException("pcode compiler returned invalid xml " + sourceName,
					exception[0]);
			}
			OpTpl[] opTemplates = constructTpl.getOpVec();
			adjustUniqueBase(opTemplates);

			payloadSleigh.setTemplate(constructTpl);
		}
		catch (UnknownInstructionException e) {
			throw new SleighException("compiled pcode contains invalid opcode " + sourceName, e);
		}
		catch (JDOMException e) {
			throw new SleighException("pcode compile failed due to invalid translator tag " +
				sourceName, e);
		}
		catch (SAXException e) {
			throw new SleighException("pcode compiler returned invalid xml " + sourceName, e);
		}
	}

	//changed to protected for PcodeInjectLibraryJava
	protected void adjustUniqueBase(OpTpl[] opTemplates) {
		for (OpTpl opt : opTemplates) {
			VarnodeTpl out = opt.getOutput();
			if (out != null) {
				adjustUniqueBase(out);
			}
			for (VarnodeTpl in : opt.getInput()) {
				adjustUniqueBase(in);
			}
		}
	}

	private void adjustUniqueBase(VarnodeTpl v) {
		ConstTpl space = v.getSpace();
		if (!space.isUniqueSpace()) {
			return;
		}
		ConstTpl c = v.getOffset();
		long offset = c.getReal();
		if (offset >= uniqueBase) {
			uniqueBase = offset + SleighBase.MAX_UNIQUE_SIZE;
		}
	}

	public String[] getCallFixupNames() {
		Set<String> keySet = callFixupMap.keySet();
		String[] names = new String[keySet.size()];
		keySet.toArray(names);
		return names;
	}

	public InjectContext buildInjectContext() {
		InjectContext res = new InjectContext();
		res.language = language;
		return res;
	}

	protected void registerInject(InjectPayload payload) {
		switch (payload.getType()) {
			case InjectPayload.CALLFIXUP_TYPE:
				if (callFixupMap.containsKey(payload.getName())) {
					throw new SleighException(
						"CallFixup registered multiple times: " + payload.getName());
				}
				callFixupMap.put(payload.getName(), payload);
				break;
			case InjectPayload.CALLOTHERFIXUP_TYPE:
				if (callOtherFixupMap.size() == 0) {
					int max = language.getNumberOfUserDefinedOpNames();
					for (int i = 0; i < max; ++i) {
						String opname = language.getUserDefinedOpName(i);
						callOtherFixupMap.put(opname, null);		// Initialize with null pcodeinjection
					}
				}
				if (!callOtherFixupMap.containsKey(payload.getName()))
					throw new SleighException(
						"Unknown callother name in <callotherfixup>: " + payload.getName());
				if (callOtherFixupMap.get(payload.getName()) != null)
					throw new SleighException(
						"Duplicate <callotherfixup> tag: " + payload.getName());
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
		parseInject(payload);
	}

	protected InjectPayloadSleigh allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLFIXUP_TYPE)
			return new InjectPayloadCallfixup(sourceName);
		else if (tp == InjectPayload.CALLOTHERFIXUP_TYPE)
			return new InjectPayloadCallother(sourceName);
		return new InjectPayloadSleigh(name, tp, sourceName);
	}

	public InjectPayload restoreXmlInject(String source, String name, int tp,
			XmlPullParser parser) {
		InjectPayloadSleigh payload = allocateInject(source, name, tp);
		payload.restoreXml(parser);
		registerInject(payload);
		return payload;
	}

	public ConstantPool getConstantPool(Program program) throws IOException {
		return null;
	}

	//methods below this point added for PcodeInjectLibraryJava:
	protected long getUniqueBase() {
		return uniqueBase;
	}
}
