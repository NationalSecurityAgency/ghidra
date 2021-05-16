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
package ghidra.program.database;

import java.util.ArrayList;
import java.util.List;

import org.xml.sax.*;

import generic.stl.Pair;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.CompilerSpec.EvaluationModelType;
import ghidra.program.model.listing.*;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.*;

/**
 * Utility class for installing/removing "specification extensions" to a Program.
 * A specification extension is a program specific version of either a:
 *   - Prototype Model
 *   - Call Fixup or 
 *   - Callother Fixup
 * Normally these objects are provided by the language specific configuration files (.cspec or .pspec),
 * but this class allows additional objects to be added that are specific to the program.
 * 
 * Internally, each spec extension is stored as an XML document as a formal Program Option. Each type of
 * extension is described by a specific XML tag and is parsed as it would be in a .cspec or .pspec file.
 * The XML tags are:
 *   - \<callfixup>        - describing a Call Fixup
 *   - \<callotherfixup>   - describing a Callother Fixup
 *   - \<prototype>        - describing a typical Prototype Model
 *   - \<resolveprototype> - describing a Prototype Model merged from other models
 *   
 * Each type of object has a unique name or target, which must be specified as part of the XML tag,
 * which is referred to in this class as the extension's "formal name".  In the \<callotherfixup> tag,
 * the formal name is given by the "targetop" attribute; for all the other tags, the formal name is
 * given by the "name" attribute".
 * 
 * The parent option for all extensions is given by the static field SPEC_EXTENSION. Under the parent
 * option, each extension is stored as a string with an option name, constructed by
 * concatenating the extension's formal name with a prefix corresponding to the extension's XML tag name.
 *
 * testExtensionDocument() is used independently to extensively test whether a document
 * describes a valid extension.
 * 
 * Extensions are installed on a program via addReplaceCompilerSpecExtension().
 * Extensions are removed from a program via removeCompilerSpecExtension().
 */
public class SpecExtension {

	public final static String SPEC_EXTENSION = "Specification Extensions";
	public final static String FORMAT_VERSION_OPTIONNAME = "FormatVersion";
	public final static String VERSION_COUNTER_OPTIONNAME = "VersionCounter";
	public final static int FORMAT_VERSION = 1;		// Current version of specification XML format
	private ProgramDB program;
	private SleighLanguageValidator cspecValidator = null;

	/**
	 * The possible types of spec extensions.
	 */
	public enum Type {
		// The order is used to sort tables of extensions
		PROTOTYPE_MODEL("prototype"),
		MERGE_MODEL("resolve"),
		CALL_FIXUP("callfixup"),
		CALLOTHER_FIXUP("callotherfixup");

		private String tagName;

		private Type(String nm) {
			tagName = nm;
		}

		/**
		 * Get the XML tag name associated with the specific extension type.
		 * @return the tag name
		 */
		public String getTagName() {
			return tagName;
		}

		/**
		 * For a given extension's formal name, generate the option name used to store the extension.
		 * The option name is the tag name concatenated with the formal name, separated by '_'
		 * @param formalName is the formal name of the extension
		 * @return the option name
		 */
		public String getOptionName(String formalName) {
			return tagName + '_' + formalName;
		}
	}

	/**
	 * Helper class for collecting information about an extension XML document
	 * and constructing its option name for storage
	 */
	public static class DocInfo {
		private Type type;			// Type of extension
		private String formalName;	// Formal name extracted from the document
		private String optionName;	// Option name used to store document
		private boolean override;	// true if the extension overrides a core document

		private static String generateOptionNameFromDocument(Type type, String document)
				throws SleighException {
			int startPos, endPos;
			String tagAttribute;
			switch (type) {
				case PROTOTYPE_MODEL:
				case MERGE_MODEL:
				case CALL_FIXUP:
					tagAttribute = "name=\"";
					break;
				case CALLOTHER_FIXUP:
					tagAttribute = "targetop=\"";
					break;
				default:
					throw new SleighException("Unsupported extension type");
			}
			startPos = document.indexOf(tagAttribute, 0);
			if (startPos < 0) {
				throw new SleighException("Could not find attribute: " + tagAttribute);
			}
			startPos += tagAttribute.length();
			endPos = document.indexOf('\"', startPos);
			if (endPos < 0) {
				throw new SleighException("Bad XML document");
			}
			String formalName = document.substring(startPos, endPos);
			if (!isValidFormalName(formalName)) {
				throw new SleighException("Name of extension uses invalid characters");
			}
			return type.getOptionName(formalName);
		}

		/**
		 * Construct by directly pulling information from the XML document
		 * @param document is the entire XML document as a String
		 */
		public DocInfo(String document) {
			type = getExtensionType(document, true);
			optionName = generateOptionNameFromDocument(type, document);
			formalName = SpecExtension.getFormalName(optionName);
			override = false;
		}

		/**
		 * @return the Type of the extension
		 */
		public final Type getType() {
			return type;
		}

		/**
		 * @return the formal name of the extension
		 */
		public final String getFormalName() {
			return formalName;
		}

		/**
		 * @return the option name associated with the extension
		 */
		public final String getOptionName() {
			return optionName;
		}

		/**
		 * @return true if the extension overrides a core object
		 */
		public final boolean isOverride() {
			return override;
		}
	}

	/**
	 * Construct an extension manager attached to a specific program.
	 * Multiple add/remove/test actions can be performed.  Validator state is cached between calls.
	 * @param program is the specific Program
	 */
	public SpecExtension(Program program) {
		if (!(program instanceof ProgramDB)) {
			throw new IllegalArgumentException("only normal program supported");
		}
		this.program = (ProgramDB) program;
	}

	/**
	 * Get the extension type either from the XML tag name or the option name
	 * @param nm is the XML tag or option name
	 * @param isXML is true for an XML tag, false for an option name
	 * @return the extension type
	 * @throws SleighException if no type matches the name
	 */
	public static Type getExtensionType(String nm, boolean isXML) throws SleighException {
		int pos = 0;
		if (isXML) {
			while (pos + 1 < nm.length() && (nm.charAt(pos) != '<' || nm.charAt(pos + 1) == '?') ||
				nm.charAt(pos + 1) == '!') {
				pos += 1;
			}
			pos += 1;
		}
		if (nm.length() <= pos) {
			throw new SleighException("Unrecognized extension");
		}
		switch (nm.charAt(pos)) {
			case 'c':
				if (nm.startsWith(Type.CALL_FIXUP.getTagName(), pos)) {
					return Type.CALL_FIXUP;
				}
				else if (nm.startsWith(Type.CALLOTHER_FIXUP.getTagName(), pos)) {
					return Type.CALLOTHER_FIXUP;
				}
				break;
			case 'p':
				if (nm.startsWith(Type.PROTOTYPE_MODEL.getTagName(), pos)) {
					return Type.PROTOTYPE_MODEL;
				}
				break;
			case 'r':
				if (nm.startsWith(Type.MERGE_MODEL.getTagName(), pos)) {
					return Type.MERGE_MODEL;
				}
				break;
		}
		throw new SleighException("Unrecognized extension");
	}

	/**
	 * Check if the given option name corresponds to an extension
	 * @param nm is the given option name
	 * @return true if the name labels a spec extension
	 */
	private static boolean isCompilerProperty(String nm) {
		try {
			getExtensionType(nm, false);
			return true;
		}
		catch (SleighException ex) {
			return false;
		}
	}

	/**
	 * Get version of CompilerSpec extensions stored with the Program
	 * @param program is the given Program
	 * @return the version number
	 */
	public static int getVersionCounter(Program program) {
		Options options = program.getOptions(SPEC_EXTENSION);
		return options.getInt(VERSION_COUNTER_OPTIONNAME, 0);
	}

	/**
	 * Get all compiler spec extensions for the program. The extensions are XML documents
	 * strings, with an associated "option name" string.
	 * Return a list of (optionname,document) pairs, which may be empty
	 * @param program is the Program to get extensions for
	 * @return the list of (optionname,document) pairs
	 */
	public static List<Pair<String, String>> getCompilerSpecExtensions(Program program) {
		Options options = program.getOptions(SPEC_EXTENSION);
		List<String> optionNames = options.getOptionNames();
		ArrayList<Pair<String, String>> pairList = new ArrayList<>();
		for (String optionName : optionNames) {
			if (isCompilerProperty(optionName)) {
				String value = options.getString(optionName, null);
				if (value != null) {
					pairList.add(new Pair<>(optionName, value));
				}
			}
		}
		return pairList;
	}

	/**
	 * Get the raw string making up an extension, given its type and name
	 * @param program is the program to extract the extension from
	 * @param type is the type of extension
	 * @param name is the formal name of the extension
	 * @return the extension string or null
	 */
	public static String getCompilerSpecExtension(Program program, Type type, String name) {
		String optionName = type.getOptionName(name);
		Options options = program.getOptions(SPEC_EXTENSION);
		return options.getString(optionName, null);
	}

	/**
	 * Check the format version for spec extensions for a given program.
	 * If the program reports a version that does not match the current
	 * number attached to the running tool (FORMAT_VERSION), a VersionException is thrown
	 * @param program is the given Program
	 * @throws VersionException the reported version does not match the tool
	 */
	public static void checkFormatVersion(Program program) throws VersionException {
		Options options = program.getOptions(SPEC_EXTENSION);
		int formatVersion = options.getInt(FORMAT_VERSION_OPTIONNAME, 0);
		if (formatVersion > FORMAT_VERSION) {
			throw new VersionException("Program contains spec extensions with newer/unknown format",
				VersionException.NEWER_VERSION, false);
		}
	}

	/**
	 * Register the options system allowing spec extensions with the given Program
	 * @param program is the given Program
	 */
	public static void registerOptions(Program program) {
		if (!(program instanceof ProgramDB)) {
			Msg.error(SpecExtension.class, "Can only add extensions on a normal program");
			return;
		}
		if (!SystemUtilities.isInHeadlessMode()) {
			Options options = program.getOptions(SPEC_EXTENSION);
			options.setOptionsHelpLocation(new HelpLocation("DecompilePlugin", "ExtensionOptions"));
			options.registerOptionsEditor(new SpecExtensionEditor((ProgramDB) program));
		}
	}

	/**
	 * Get the formal name of an extension from its option name.
	 * @param optionName is the option name
	 * @return the formal name
	 */
	public static String getFormalName(String optionName) {
		return optionName.substring(optionName.indexOf('_') + 1);
	}

	/**
	 * Determine if the desired formal name is a valid identifier
	 * @param formalName is the formal name to check
	 * @return true if the name is valid
	 */
	public static boolean isValidFormalName(String formalName) {
		if (formalName.length() == 0) {
			return false;
		}
		for (int i = 0; i < formalName.length(); ++i) {
			char c = formalName.charAt(i);
			if (!Character.isLetterOrDigit(c) && c != '_' && c != '.' && c != '-') {
				return false;
			}
		}
		return true;
	}

	/**
	 * Generate an XML error handler suitable for parsing a specification document.
	 *   - Warnings are logged.
	 *   - Errors cause a SAXParseException
	 * 
	 * @param docTitle is the title of the document
	 * @return the error handler object
	 */
	private static ErrorHandler getErrorHandler(String docTitle) {
		ErrorHandler errHandler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				throw exception;
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				throw exception;
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(this, "Warning parsing '" + docTitle + "'", exception);
			}
		};
		return errHandler;
	}

	/**
	 * Parse an XML string and build the corresponding compiler spec extension object.
	 * Currently this can either be a
	 *    - PrototypeModel or
	 *    - InjectPayload
	 * 
	 * For InjectPayloadCallfixup or InjectPayloadCallother, the p-code \<body> tag
	 * is also parsed, and the caller can control whether any parse errors
	 * cause an exception or whether a dummy payload is provided instead.
	 * @param optionName is the option name the extension is attached to
	 * @param extension is the XML document as a String
	 * @param cspec is the compiler spec the new extension is for
	 * @param provideDummy if true, provide a dummy payload if necessary
	 * @return the extension object
	 * @throws SAXException is there are XML format errors
	 * @throws XmlParseException if the XML document is badly formed
	 * @throws SleighException if internal p-code does not parse
	 */
	public static Object parseExtension(String optionName, String extension, CompilerSpec cspec,
			boolean provideDummy) throws SAXException, XmlParseException, SleighException {
		ErrorHandler errHandler = getErrorHandler("extensions");
		XmlPullParser parser =
			XmlPullParserFactory.create(extension, optionName, errHandler, false);
		String elName = parser.peek().getName();
		if (elName.endsWith("prototype")) {
			PrototypeModel model;
			if (parser.peek().getName().equals("resolveprototype")) {
				PrototypeModelMerged mergemodel = new PrototypeModelMerged();
				ArrayList<PrototypeModel> curModels =
					new ArrayList<>(cspec.getCallingConventions().length);
				for (PrototypeModel curModel : cspec.getCallingConventions()) {
					curModels.add(curModel);
				}
				try {
					mergemodel.restoreXml(parser, curModels);
					model = mergemodel;
				}
				catch (XmlParseException ex) {
					if (!provideDummy) {
						throw ex;
					}
					// XML failed to parse, associate default model as a placeholder
					model = new PrototypeModelError(getFormalName(optionName),
						cspec.getDefaultCallingConvention());
				}
			}
			else {
				model = new PrototypeModel();
				try {
					model.restoreXml(parser, cspec);
				}
				catch (XmlParseException ex) {
					if (!provideDummy) {
						throw ex;
					}
					// XML failed to parse, associate default model as a placeholder
					model = new PrototypeModelError(getFormalName(optionName),
						cspec.getDefaultCallingConvention());
				}
			}
			return model;
		}
		else if (elName.equals("callfixup")) {
			String nm = parser.peek().getAttribute("name");
			PcodeInjectLibrary injectLibrary = cspec.getPcodeInjectLibrary();
			InjectPayload payload =
				injectLibrary.allocateInject(optionName, nm, InjectPayload.CALLFIXUP_TYPE);
			if (!(payload instanceof InjectPayloadSleigh)) {
				throw new XmlParseException("Cannot use attached name: " + nm);
			}
			try {
				payload.restoreXml(parser, (SleighLanguage) cspec.getLanguage());
				injectLibrary.parseInject(payload);		// Try to parse the pcode body
			}
			catch (XmlParseException ex) {
				if (!provideDummy) {
					throw ex;
				}
				// The XML parse itself failed, provide a generic placeholder
				payload = new InjectPayloadCallfixupError(cspec.getLanguage().getAddressFactory(),
					getFormalName(optionName));
			}
			catch (SleighException ex) {
				if (!provideDummy) {
					throw ex;
				}
				// The pcode body failed to parse, payload metadata, but provide dummy p-code
				payload = new InjectPayloadCallfixupError(cspec.getLanguage().getAddressFactory(),
					(InjectPayloadCallfixup) payload);
			}
			return payload;
		}
		else if (elName.equals("callotherfixup")) {
			String nm = parser.peek().getAttribute("name");
			PcodeInjectLibrary injectLibrary = cspec.getPcodeInjectLibrary();
			InjectPayload payload =
				injectLibrary.allocateInject(optionName, nm, InjectPayload.CALLOTHERFIXUP_TYPE);
			if (!(payload instanceof InjectPayloadSleigh)) {
				throw new XmlParseException("Cannot use attached name: " + nm);
			}
			try {
				payload.restoreXml(parser, (SleighLanguage) cspec.getLanguage());
				injectLibrary.parseInject(payload);
			}
			catch (XmlParseException ex) {
				if (!provideDummy) {
					throw ex;
				}
				// The XML parse itself failed, provide a generic placeholder
				payload = new InjectPayloadCallotherError(cspec.getLanguage().getAddressFactory(),
					getFormalName(optionName));
			}
			catch (SleighException ex) {
				// The p-code parse failed, keep the metadata, but provide dummy p-code
				payload = new InjectPayloadCallotherError(cspec.getLanguage().getAddressFactory(),
					(InjectPayloadCallother) payload);
			}
			return payload;
		}
		throw new XmlParseException("Unknown compiler spec extension: " + elName);
	}

	/**
	 * Check that the proposed callfixup extension does not collide with built-in fixups
	 * @param doc is info about the proposed extension
	 * @throws SleighException is there is a collision
	 */
	private void checkCallFixup(DocInfo doc) throws SleighException {
		CompilerSpec cspec = program.getCompilerSpec();
		PcodeInjectLibrary injectLibrary = cspec.getPcodeInjectLibrary();
		InjectPayload payload =
			injectLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, doc.formalName);
		if (payload == null) {
			return;
		}
		if (injectLibrary.hasProgramPayload(doc.formalName, InjectPayload.CALLFIXUP_TYPE)) {
			return;
		}
		throw new SleighException("Extension cannot replace callfixup: " + doc.formalName);
	}

	/**
	 * Check that the proposed callotherfixup extension targets a user-defined op
	 * that exists.  Check if the extension would override a built-in fixup.
	 * @param doc is info on the proposed extension
	 * @throws SleighException if the targeted op does not exist
	 */
	private void checkCallotherFixup(DocInfo doc) throws SleighException {
		CompilerSpec cspec = program.getCompilerSpec();
		PcodeInjectLibrary injectLibrary = cspec.getPcodeInjectLibrary();
		if (!injectLibrary.hasUserDefinedOp(doc.formalName)) {
			throw new SleighException("CALLOTHER_FIXUP target does not exist: " + doc.formalName);
		}
		InjectPayload payload =
			injectLibrary.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, doc.formalName);
		if (payload == null) {
			return;
		}
		if (injectLibrary.hasProgramPayload(doc.formalName, InjectPayload.CALLOTHERFIXUP_TYPE)) {
			return;
		}
		// A callother payload is allowed to override an existing core payload
		// So this check never fails, but we mark that the override is occurring
		doc.override = true;
	}

	/**
	 * Check that the proposed prototype extension does not collide with a
	 * built-in prototype.
	 * @param doc is info on the proposed prototype
	 * @throws SleighException if there is a collision
	 */
	private void checkPrototype(DocInfo doc) throws SleighException {
		CompilerSpec cspec = program.getCompilerSpec();
		PrototypeModel[] allModels = cspec.getAllModels();
		for (PrototypeModel model : allModels) {
			if (model.getName().equals(doc.formalName)) {
				if (!model.isProgramExtension()) {
					throw new SleighException(
						"Extension cannot replace prototype: " + doc.formalName);
				}
			}
		}
	}

	/**
	 * Check the given document information against existing objects already in the compiler spec.
	 * Any problem (like name collisions) causes an exception to get thrown.
	 * Checks may populate additional document information
	 * @param doc is the document information: name, type
	 * @throws SleighException if there is a problem
	 */
	private void checkExtension(DocInfo doc) throws SleighException {
		switch (doc.type) {
			case CALL_FIXUP:
				checkCallFixup(doc);
				break;
			case CALLOTHER_FIXUP:
				checkCallotherFixup(doc);
				break;
			case MERGE_MODEL:
				checkPrototype(doc);
				break;
			case PROTOTYPE_MODEL:
				checkPrototype(doc);
				break;
		}
	}

	/**
	 * Test if the given XML document describes a suitable spec extension.
	 * The document must fully parse and validate and must not conflict with the existing spec;
	 * otherwise an exception is thrown. If all tests pass, an object describing basic properties
	 * of the document is returned.
	 * @param document is the given XML document
	 * @return info about the document
	 * @throws SleighException if validity checks fail
	 * @throws XmlParseException if the XML is badly formed
	 * @throws SAXException if there are parse errors
	 */
	public DocInfo testExtensionDocument(String document)
			throws SleighException, SAXException, XmlParseException {
		DocInfo res = new DocInfo(document);
		if (cspecValidator == null) {
			cspecValidator = new SleighLanguageValidator(SleighLanguageValidator.CSPECTAG_TYPE);
		}
		cspecValidator.verify(res.optionName, document);
		checkExtension(res);
		parseExtension(res.optionName, document, program.getCompilerSpec(), false);
		return res;
	}

	/**
	 * Clean up references to a callfixup that is going to be removed
	 * @param fixupName is the name of the fixup
	 * @param monitor is a task monitor
	 * @throws CancelledException if the task is cancelled
	 */
	private void removeCallFixup(String fixupName, TaskMonitor monitor) throws CancelledException {
		FunctionManager manager = program.getFunctionManager();
		monitor.setMessage("Searching for references to " + fixupName);
		monitor.setMaximum(manager.getFunctionCount());
		FunctionIterator iter = manager.getFunctions(true);
		for (int i = 0; i < 2; ++i) {
			while (iter.hasNext()) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				Function function = iter.next();
				String currentFixup = function.getCallFixup();
				if (currentFixup != null && currentFixup.equals(fixupName)) {
					function.setCallFixup(null);
				}
			}
			if (i == 1) {
				break;
			}
			iter = manager.getExternalFunctions();
		}
	}

	/**
	 * Clean up any references to a callotherfixup that is going to be removed
	 * @param fixupName is the name of the callother fixup
	 * @param monitor is a task monitor
	 */
	private void removeCallotherFixup(String fixupName, TaskMonitor monitor) {
		// Nothing to clean up currently
	}

	/**
	 * If the indicated evaluation model matches the given name,
	 * clear the evaluation model to the default
	 * @param modelType is the indicated evaluation model
	 * @param modelName is the given name needing to be cleared
	 */
	private void clearPrototypeEvaluationModel(EvaluationModelType modelType, String modelName) {
		CompilerSpec compilerSpec = program.getCompilerSpec();
		PrototypeModel evalModel = compilerSpec.getPrototypeEvaluationModel(modelType);
		if (!evalModel.getName().equals(modelName)) {
			return;
		}
		String newName = compilerSpec.getDefaultCallingConvention().getName();
		Options options = program.getOptions(ProgramCompilerSpec.DECOMPILER_PROPERTY_LIST_NAME);
		options.setString(ProgramCompilerSpec.EVALUATION_MODEL_PROPERTY_NAME, newName);
	}

	/**
	 * Clean up references to a prototype extension that is about to be removed.
	 * Functions that use this prototype are changed to have an "unknown" prototype.
	 * @param modelName is the name of the prototype being removed
	 * @param monitor is a task monitor
	 * @throws CancelledException if the task is cancelled
	 */
	private void removePrototype(String modelName, TaskMonitor monitor) throws CancelledException {
		FunctionManager manager = program.getFunctionManager();
		monitor.setMessage("Searching for references to " + modelName);
		monitor.setMaximum(manager.getFunctionCount());
		FunctionIterator iter = manager.getFunctions(true);
		for (int i = 0; i < 2; i += 1) {
			while (iter.hasNext()) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				Function function = iter.next();
				PrototypeModel currentModel = function.getCallingConvention();
				if (currentModel != null && currentModel.getName().equals(modelName)) {
					try {
						function.setCallingConvention("unknown");
					}
					catch (InvalidInputException e) {
						// shouldn't reach here
					}
				}
			}
			if (i == 1) {
				break;
			}
			iter = manager.getExternalFunctions();
		}
		// Clear any evaluation model that matches the prototype being removed
		clearPrototypeEvaluationModel(EvaluationModelType.EVAL_CURRENT, modelName);
	}

	/**
	 * Install or replace a spec extension to the program.  The extension is presented as
	 * an XML document, from which a name is extracted.  If an extension previously existed
	 * with the same name, it is overwritten.  Otherwise the document is treated as a new
	 * extension.  Testing is performed before installation:
	 *    - Document is parsed as XML and is verified against spec grammars
	 *    - Internal p-code tags from InjectPayloads are compiled
	 *    - Name collisions are checked for
	 * @param document is the XML document describing the extension
	 * @param monitor is a task monitor
	 * @throws LockException if the caller does not exclusive access to the program
	 * @throws XmlParseException for a badly formed extension document
	 * @throws SAXException for parse errors in the extension document
	 * @throws SleighException for a document that fails verification
	 */
	public void addReplaceCompilerSpecExtension(String document, TaskMonitor monitor)
			throws LockException, SleighException, SAXException, XmlParseException {
		program.checkExclusiveAccess();
		monitor.setMessage("Testing validity of new document");
		DocInfo info = testExtensionDocument(document);
		monitor.setMessage("Installing " + info.getFormalName());
		Options specOptions = program.getOptions(SpecExtension.SPEC_EXTENSION);
		int progVersion = specOptions.getInt(SpecExtension.VERSION_COUNTER_OPTIONNAME, 0);
		progVersion = (progVersion + 1) % 0x40000000;	// Change the version number associated with the CompilerSpec
		specOptions.setString(info.getOptionName(), document);
		specOptions.setInt(SpecExtension.VERSION_COUNTER_OPTIONNAME, progVersion);
		specOptions.setInt(SpecExtension.FORMAT_VERSION_OPTIONNAME, SpecExtension.FORMAT_VERSION);
		program.installExtensions();
	}

	/**
	 * Remove the indicated spec extension from the program.
	 * Depending on the type, references to the extension are removed or altered
	 * first, to facilitate final removal of the extension.
	 * All changes are made in a single transaction that can be cancelled.
	 * @param optionName is the option name where the extension is stored
	 * @param monitor is a provided monitor that can trigger cancellation
	 * @throws LockException if the caller does not have exclusive access to the program
	 * @throws CancelledException if the caller cancels the operation via the task monitor
	 */
	public void removeCompilerSpecExtension(String optionName, TaskMonitor monitor)
			throws LockException, CancelledException {
		program.checkExclusiveAccess();
		Type type = SpecExtension.getExtensionType(optionName, false);
		Options specOptions = program.getOptions(SpecExtension.SPEC_EXTENSION);
		if (!specOptions.contains(optionName)) {
			throw new SleighException("Extension does not exist: " + optionName);
		}
		int progVersion = specOptions.getInt(SpecExtension.VERSION_COUNTER_OPTIONNAME, 0);
		progVersion = (progVersion + 1) % 0x40000000;	// Change version number associated with the CompilerSpec
		String extName = SpecExtension.getFormalName(optionName);
		switch (type) {
			case CALL_FIXUP:
				removeCallFixup(extName, monitor);
				break;
			case CALLOTHER_FIXUP:
				removeCallotherFixup(extName, monitor);
				break;
			case MERGE_MODEL:
				removePrototype(extName, monitor);
				break;
			case PROTOTYPE_MODEL:
				removePrototype(extName, monitor);
				break;
		}
		specOptions.removeOption(optionName);
		specOptions.setInt(SpecExtension.VERSION_COUNTER_OPTIONNAME, progVersion);
		program.installExtensions();
	}
}
