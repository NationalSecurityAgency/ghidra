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
package ghidra.pcode.exec;

import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.jdom.JDOMException;
import org.xml.sax.*;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.pcodeCPort.slgh_compile.PcodeParser;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

public class SleighProgramCompiler {
	private static final String EXPRESSION_SOURCE_NAME = "expression";

	public static PcodeParser createParser(SleighLanguage language) {
		String translatorTag =
			language.buildTranslatorTag(language.getAddressFactory(), language.getUniqueBase(),
				language.getSymbolTable());
		try {
			return new PcodeParser(translatorTag);
		}
		catch (JDOMException e) {
			throw new AssertionError(e);
		}
	}

	public static ConstructTpl compileTemplate(Language language, PcodeParser parser,
			String sourceName, String text) {
		try {
			// This is quite the conversion, no?
			String templateXml =
				PcodeParser.stringifyTemplate(
					Objects.requireNonNull(parser.compilePcode(text, EXPRESSION_SOURCE_NAME, 1)));
			MyErrorHandler eh = new MyErrorHandler();
			XmlPullParser xmlParser =
				XmlPullParserFactory.create(templateXml, EXPRESSION_SOURCE_NAME, eh, false);
			ConstructTpl template = new ConstructTpl();
			template.restoreXml(xmlParser, language.getAddressFactory());
			return template;
		}
		catch (SAXException | UnknownInstructionException e) {
			throw new AssertionError(e);
		}
	}

	public static List<PcodeOp> buildOps(Language language, ConstructTpl template)
			throws UnknownInstructionException, MemoryAccessException {
		Address zero = language.getDefaultSpace().getAddress(0);
		SleighParserContext c = new SleighParserContext(zero, zero, zero, zero);
		ParserWalker walk = new ParserWalker(c);
		PcodeEmitObjects emit = new PcodeEmitObjects(walk);

		emit.build(template, 0);
		emit.resolveRelatives();
		return List.of(emit.getPcodeOp());
	}

	/**
	 * Add extra user-op symbols to the parser's table
	 * 
	 * <p>
	 * The map cannot contain symbols whose user-op indices are already defined by the language.
	 * 
	 * @param parser the parser to modify
	 * @param symbols the map of extra symbols
	 */
	protected static void addParserSymbols(PcodeParser parser, Map<Integer, UserOpSymbol> symbols) {
		for (UserOpSymbol sym : symbols.values()) {
			parser.addSymbol(sym);
		}
	}

	public static PcodeProgram compileProgram(SleighLanguage language, String sourceName,
			List<String> lines, SleighUseropLibrary<?> library) {
		PcodeParser parser = createParser(language);
		Map<Integer, UserOpSymbol> symbols = library.getSymbols(language);
		addParserSymbols(parser, symbols);

		ConstructTpl template =
			compileTemplate(language, parser, sourceName, StringUtils.join(lines, "\n"));
		try {
			return new PcodeProgram(language, buildOps(language, template), symbols);
		}
		catch (UnknownInstructionException | MemoryAccessException e) {
			throw new AssertionError(e);
		}
	}

	public static SleighExpression compileExpression(SleighLanguage language, String expression) {
		PcodeParser parser = createParser(language);
		Map<Integer, UserOpSymbol> symbols = SleighExpression.CAPTURING.getSymbols(language);
		addParserSymbols(parser, symbols);

		ConstructTpl template = compileTemplate(language, parser, EXPRESSION_SOURCE_NAME,
			SleighExpression.RESULT_NAME + "(" + expression + ");");
		try {
			return new SleighExpression(language, buildOps(language, template), symbols);
		}
		catch (UnknownInstructionException | MemoryAccessException e) {
			throw new AssertionError(e);
		}
	}

	static class MyErrorHandler implements ErrorHandler {
		SAXParseException exc;

		@Override
		public void warning(SAXParseException e) throws SAXException {
			Msg.warn(this, e);
		}

		@Override
		public void error(SAXParseException e) throws SAXException {
			exc = e;
		}

		@Override
		public void fatalError(SAXParseException e) throws SAXException {
			exc = e;
		}
	}
}
