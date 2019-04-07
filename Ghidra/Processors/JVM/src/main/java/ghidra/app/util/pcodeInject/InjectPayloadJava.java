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
package ghidra.app.util.pcodeInject;

import java.io.IOException;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.*;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.javaclass.format.constantpool.AbstractConstantPoolInfoJava;
import ghidra.pcodeCPort.slgh_compile.PcodeParser;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeXMLException;
import ghidra.sleigh.grammar.Location;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

/**
 * Subclasses of this class are used to generate pcode to inject for modeling
 * java bytecode in pcode.
 *
 */

public abstract class InjectPayloadJava extends InjectPayloadCallother {
	private SleighLanguage language;
	private SAXParser saxParser;

	/**
	 * Subclasses use this method to generate pcode text for a particular java
	 * bytecode op requiring pcode injection.
	 * 
	 * @param program The program containing the op.
	 * @param context The context associated with the op.
	 * @return
	 */
	abstract String getPcodeText(Program program, String context);

	public InjectPayloadJava(String sourceName, SleighLanguage language) {
		super(sourceName);
		this.language = language;
		try {
			saxParser = getSAXParser();
		}
		catch (PcodeXMLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	SleighLanguage getLanguage() {
		return language;
	}

	InjectContext getInjectContext(Program program, String context) {
		InjectContext injectContext = new InjectContext();
		injectContext.language = language;
		try {
			injectContext.restoreXml(saxParser, context, program.getAddressFactory());
			saxParser.reset();
		}
		catch (PcodeXMLException e1) {
			Msg.info(this, e1.getMessage());
			e1.printStackTrace();
		}
		return injectContext;
	}

	AbstractConstantPoolInfoJava[] getConstantPool(Program program) {
		ConstantPoolJava cPool = null;
		try {
			cPool = new ConstantPoolJava(program);
		}
		catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cPool.getConstantPool();
	}

	//from DecompileCallback.java
	private static SAXParser getSAXParser() throws PcodeXMLException {
		try {
			SAXParserFactory saxParserFactory = XmlUtilities.createSecureSAXParserFactory(false);
			saxParserFactory.setFeature("http://xml.org/sax/features/namespaces", false);
			saxParserFactory.setFeature("http://xml.org/sax/features/validation", false);
			return saxParserFactory.newSAXParser();
		}
		catch (Exception e) {
			Msg.error(PcodeInjectLibraryJava.class, e.getMessage());
			throw new PcodeXMLException("Failed to instantiate XML parser", e);
		}
	}

	/**
	 * This method is used to generate and compile pcode for a given
	 * callotherfixup.
	 * 
	 * @param parser Used to parse pcode.
	 * @param program The program containing the callotherfixup
	 * @param context The context of the callotherfixup.
	 * @return An array of OpTpl (for passing to
	 *         PcodeInjectLibrary.adjustUniqueBase)
	 */
	public OpTpl[] getPcode(PcodeParser parser, Program program, String context) {
		String sourceName = getSource();
		Location loc = new Location(sourceName, 1);

		InjectParameter[] input = getInput();
		for (InjectParameter element : input) {
			parser.addOperand(loc, element.getName(), element.getIndex());
		}
		InjectParameter[] output = getOutput();
		for (InjectParameter element : output) {
			parser.addOperand(loc, element.getName(), element.getIndex());
		}

		String pcodeText = getPcodeText(program, context);
		String constructTplXml =
			PcodeParser.stringifyTemplate(parser.compilePcode(pcodeText, sourceName, 1));
		if (constructTplXml == null) {
			throw new SleighException("pcode compile failed " + sourceName);
		}
		final SAXParseException[] exception = new SAXParseException[1];
		XmlPullParser xmlParser = null;
		try {
			xmlParser =
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
		}
		catch (SAXException e) {
			e.printStackTrace();
		}

		ConstructTpl constructTpl = new ConstructTpl();
		try {
			constructTpl.restoreXml(xmlParser, language.getAddressFactory());
		}
		catch (UnknownInstructionException e) {
			e.printStackTrace();
		}
		if (exception[0] != null) {
			throw new SleighException("pcode compiler returned invalid xml " + sourceName,
				exception[0]);
		}
		OpTpl[] opTemplates = constructTpl.getOpVec();
		setTemplate(constructTpl);
		return opTemplates;
	}
}
