/* ###
 * IP: GHIDRA
 * NOTE: lots of reference to the decompiler here (comments)
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
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;

import org.xml.sax.*;

import generic.jar.ResourceFile;
import generic.stl.Pair;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.AddressXML;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

/**
 * BasicCompilerSpec implements the CompilerSpec interface based on static information
 * from a particular .cspec file.  Typically the .cspec file is read in once by a Language
 * object whenever a new or opened Program indicates a particular language and compiler.
 * The BasicCompilerSpec is owned by the Language and (parts of it) may be reused by
 * multiple Programs.
 */
public class BasicCompilerSpec implements CompilerSpec {

	public static final String STACK_SPACE_NAME = "stack";
	public static final String JOIN_SPACE_NAME = "join";
	public static final String OTHER_SPACE_NAME = "OTHER";

	//must match AddrSpace enum (see space.hh)
	public static final int CONSTANT_SPACE_INDEX = 0;
	public static final int OTHER_SPACE_INDEX = 1;

	private final CompilerSpecDescription description;
	private String sourceName;
	private final SleighLanguage language;
	private DataOrganizationImpl dataOrganization;
	private List<ContextSetting> ctxsetting = new ArrayList<>();
	protected PrototypeModel defaultModel;
	protected PrototypeModel evalCurrentModel;		// Default model used to evaluate current function
	protected PrototypeModel evalCalledModel;		// Default model used to evaluate a called function
	protected PrototypeModel[] allmodels;			// All models
	protected PrototypeModel[] models;				// All models excluding merge models
	private boolean copiedThisModel;				// true if __thiscall is copied from default model
	private Register stackPointer;		// Register holding the stack pointer
	private AddressSpace stackSpace;
	private AddressSpace stackBaseSpace;
	private AddressSpace joinSpace;
	private boolean stackGrowsNegative = true;
	private boolean reverseJustifyStack = false;
	private Map<String, Pair<AddressSpace, String>> spaceBases;
	private List<Pair<String, Pair<Long, Long>>> extraRanges;
	protected PcodeInjectLibrary pcodeInject;
	private AddressSet globalSet;		// Set of addresses the decompiler considers "global" in scope
	private LinkedHashMap<String, String> properties = new LinkedHashMap<>();
	private Map<String, PrototypeModel> callingConventionMap = null;
	private boolean aggressiveTrim;		// Does decompiler aggressively trim sign extensions
	private List<Varnode> preferSplit;	// List of registers the decompiler prefers to split
	private AddressSet noHighPtr;		// Memory regions the decompiler treats as not addressable
	private AddressSet readOnlySet;		// (Additional) memory ranges the decompiler treats as read-only
	private Varnode returnAddress;		// Register/memory where decompiler expects return address to be stored
	private int funcPtrAlign;			// Alignment of function pointers,  0=no alignment (default)
	private List<Pair<AddressSpace, Integer>> deadCodeDelay;
	private List<AddressRange> inferPtrBounds;	// Restrictions on where decompiler can infer pointers

	/**
	 * Construct the specification from an XML stream.  This is currently only used for testing.
	 * @param description is the .ldefs description matching this specification
	 * @param language is the language that owns the specification
	 * @param stream is the XML stream
	 * @throws XmlParseException for badly formed XML
	 * @throws SAXException for syntax errors in the XML
	 * @throws IOException for errors accessing the stream
	 */
	public BasicCompilerSpec(CompilerSpecDescription description, SleighLanguage language,
			InputStream stream) throws XmlParseException, SAXException, IOException {
		this.description = description;
		this.language = language;
		buildInjectLibrary();
		this.dataOrganization = DataOrganizationImpl.getDefaultOrganization(language);

		ErrorHandler errHandler = getErrorHandler("test");
		XmlPullParser parser = XmlPullParserFactory.create(stream, "testpath", errHandler, false);
		initialize("testpath", parser);
	}

	/**
	 * Read in the specification from an XML file.
	 * @param description is the .ldefs description associated with the specification
	 * @param language is the language owning the specification
	 * @param cspecFile is the XML file
	 * @throws CompilerSpecNotFoundException for any form of error preventing the specification from being loaded.
	 */
	public BasicCompilerSpec(CompilerSpecDescription description, SleighLanguage language,
			final ResourceFile cspecFile) throws CompilerSpecNotFoundException {
		this.description = description;
		this.language = language;
		buildInjectLibrary();
		this.dataOrganization = DataOrganizationImpl.getDefaultOrganization(language);
		Exception parseException = null;

		ErrorHandler errHandler = getErrorHandler(cspecFile.toString());
		InputStream stream;
		try {
			SleighLanguageValidator.validateCspecFile(cspecFile);

			stream = cspecFile.getInputStream();
			XmlPullParser parser =
				XmlPullParserFactory.create(stream, cspecFile.getAbsolutePath(), errHandler, false);
			initialize(cspecFile.getAbsolutePath(), parser);
			stream.close();

			if (models == null || models.length == 0) {
				throw new SAXException("No prototype models defined");
			}
		}
		catch (SleighException e) {
			parseException = e;
			Throwable cause = e.getCause();		// Recover the cause (from the validator exception)
			if (cause != null) {
				if (cause instanceof SAXException || cause instanceof IOException) {
					parseException = (Exception) cause;
				}
			}
		}
		catch (IOException | SAXException | XmlParseException e) {
			parseException = e;
		}

		if (parseException != null) {
			throw new CompilerSpecNotFoundException(language.getLanguageID(),
				description.getCompilerSpecID(), cspecFile.getName(), parseException);
		}
	}

	/**
	 * Clone the spec so that program can safely extend it without affecting the base
	 * spec from Language.
	 * @param op2 is the spec to clone
	 */
	protected BasicCompilerSpec(BasicCompilerSpec op2) {
		language = op2.language;
		description = op2.description;
		// PrototypeModel is immutable but the map may change, so callingConventionMap
		// should only be added to through addThisCallingConvention() and modelXrefs()
		callingConventionMap = op2.callingConventionMap;
		ctxsetting = op2.ctxsetting;		// ContextSetting can be considered immutable
		dataOrganization = op2.dataOrganization;	// DataOrganizationImpl can be considered immutable
		evalCurrentModel = op2.evalCurrentModel;	// PrototypeModel is immutable
		evalCalledModel = op2.evalCalledModel;
		defaultModel = op2.defaultModel;
		allmodels = op2.allmodels;
		copiedThisModel = op2.copiedThisModel;
		globalSet = op2.globalSet;		// May need to clone if \<global> tag becomes user extendable
		joinSpace = op2.joinSpace;		// AddressSpace is immutable
		models = op2.models;
		pcodeInject = op2.pcodeInject.clone();
		properties = op2.properties;	// Currently an immutable map
		reverseJustifyStack = op2.reverseJustifyStack;
		sourceName = op2.sourceName;
		spaceBases = op2.spaceBases;	// Currently an immutable map
		extraRanges = op2.extraRanges;	// Currently an immutable map
		stackBaseSpace = op2.stackBaseSpace;
		stackGrowsNegative = op2.stackGrowsNegative;
		stackPointer = op2.stackPointer;	// Register is immutable
		stackSpace = op2.stackSpace;
		aggressiveTrim = op2.aggressiveTrim;
		preferSplit = op2.preferSplit;	// immutable set
		noHighPtr = op2.noHighPtr;		// immutable set
		readOnlySet = op2.readOnlySet;	// immutable set
		returnAddress = op2.returnAddress;
		funcPtrAlign = op2.funcPtrAlign;
		deadCodeDelay = op2.deadCodeDelay;
		inferPtrBounds = op2.inferPtrBounds;
	}

	/**
	 * Generate an XML error handler suitable for parsing a specification document.
	 *   - Warnings are logged.
	 *   - Errors cause a SAXParseException
	 * 
	 * @param docTitle is the title of the document
	 * @return the error handler object
	 */
	protected static ErrorHandler getErrorHandler(String docTitle) {
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

	private void initialize(String srcName, XmlPullParser parser) throws XmlParseException {
		this.sourceName = srcName;
		spaceBases = null;
		extraRanges = null;
		globalSet = new AddressSet();
		preferSplit = null;
		noHighPtr = null;
		readOnlySet = null;
		defaultModel = null;
		allmodels = null;
		models = null;
		stackPointer = null;
		aggressiveTrim = false;
		returnAddress = null;
		funcPtrAlign = 0;
		deadCodeDelay = null;
		inferPtrBounds = null;
		copiedThisModel = false;

		restoreXml(parser);
	}

	@SuppressWarnings("unchecked")
	private void buildInjectLibrary() {
		String classname =
			language.getProperty(GhidraLanguagePropertyKeys.PCODE_INJECT_LIBRARY_CLASS);
		if (classname == null) {
			pcodeInject = new PcodeInjectLibrary(language);		// This is the default implementation
		}
		else {
			try {
				Class<?> c = Class.forName(classname);
				if (!PcodeInjectLibrary.class.isAssignableFrom(c)) {
					Msg.error(this,
						"Language " + language.getLanguageID() + " does not specify a valid " +
							GhidraLanguagePropertyKeys.PCODE_INJECT_LIBRARY_CLASS);
					throw new RuntimeException(classname + " does not implement interface " +
						PcodeInjectLibrary.class.getName());
				}
				Class<? extends PcodeInjectLibrary> injectLibraryClass =
					(Class<? extends PcodeInjectLibrary>) c;
				Constructor<? extends PcodeInjectLibrary> constructor =
					injectLibraryClass.getConstructor(SleighLanguage.class);
				pcodeInject = constructor.newInstance(language);
			}
			catch (Exception e) {
				Msg.error(this,
					"Language " + language.getLanguageID() + " does not specify a valid " +
						GhidraLanguagePropertyKeys.PCODE_INJECT_LIBRARY_CLASS);
				throw new RuntimeException("Failed to instantiate " + classname + " for language " +
					language.getLanguageID(), e);
			}
		}
		List<InjectPayloadSleigh> additionalInject = language.getAdditionalInject();
		if (additionalInject != null) {
			for (InjectPayloadSleigh payload : additionalInject) {
				pcodeInject.registerInject(payload);
			}
		}
	}

	private void addThisCallConventionIfMissing(List<PrototypeModel> modelList,
			String defaultName) {
		if (defaultName == null) {
			return;
		}
		boolean foundThisCall = false;
		PrototypeModel defModel = null;
		for (PrototypeModel model : modelList) {
			if (CALLING_CONVENTION_thiscall.equals(model.name)) {
				foundThisCall = true;
			}
			if (defaultName.equals(model.name)) {
				defModel = model;
			}
		}
		if (defModel != null && !foundThisCall) {
			PrototypeModel thisModel = new PrototypeModel(CALLING_CONVENTION_thiscall, defModel);
			modelList.add(thisModel);
			copiedThisModel = true;
		}
	}

	/**
	 * Convenience method to marshal this entire object, via saveXml, into a String object.
	 * @return a String containing this entire spec as an XML document.
	 */
	public String getXMLString() {
		StringBuilder buffer = new StringBuilder();
		saveXml(buffer);
		return buffer.toString();
	}

	@Override
	public void applyContextSettings(DefaultProgramContext programContext) {
		for (ContextSetting cs : ctxsetting) {
			RegisterValue registerValue = new RegisterValue(cs.getRegister(), cs.getValue());
			programContext.setDefaultValue(registerValue, cs.getStartAddress(), cs.getEndAddress());
		}
	}

	@Override
	public CompilerSpecID getCompilerSpecID() {
		return description.getCompilerSpecID();
	}

	@Override
	public boolean doesCDataTypeConversions() {
		return true;		// There are currently no compiler specs that do not need to do the conversion
	}

	void addContextSetting(Register reg, BigInteger value, Address begad, Address endad) {
		ctxsetting.add(new ContextSetting(reg, value, begad, endad));
	}

	@Override
	public PrototypeModel[] getCallingConventions() {
		return models;
	}

	@Override
	public PrototypeModel getCallingConvention(String name) {
		return callingConventionMap.get(name);
	}

	@Override
	public PrototypeModel[] getAllModels() {
		return allmodels;
	}

	@Override
	public PrototypeModel getDefaultCallingConvention() {
		return defaultModel;
	}

	@Override
	public DecompilerLanguage getDecompilerOutputLanguage() {
		return DecompilerLanguage.C_LANGUAGE;
	}

	@Override
	public PrototypeModel getPrototypeEvaluationModel(EvaluationModelType modelType) {
		switch (modelType) {
			case EVAL_CURRENT:
				return evalCurrentModel;
			case EVAL_CALLED:
				return evalCalledModel;
		}
		return null;
	}

	@Override
	public Register getStackPointer() {
		return stackPointer;
	}

	@Override
	public boolean isStackRightJustified() {
		return (language.isBigEndian() && !reverseJustifyStack) ||
			(!language.isBigEndian() && reverseJustifyStack);
	}

	@Override
	public AddressSpace getStackSpace() {
		return stackSpace;
	}

	@Override
	public AddressSpace getStackBaseSpace() {
		return stackBaseSpace;
	}

	@Override
	public boolean stackGrowsNegative() {
		return stackGrowsNegative;
	}

	@Override
	public boolean isGlobal(Address addr) {
		AddressSpace space = addr.getAddressSpace();
		if (space.isOverlaySpace()) {
			addr = ((OverlayAddressSpace) space).translateAddress(addr, true);
		}
		return globalSet.contains(addr);
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	@Override
	public CompilerSpecDescription getCompilerSpecDescription() {
		return description;
	}

	@Override
	public AddressSpace getAddressSpace(String spaceName) {
		AddressSpace space;
		if (STACK_SPACE_NAME.equals(spaceName)) {
			space = stackSpace;
		}
		else if (JOIN_SPACE_NAME.equals(spaceName)) {
			if (joinSpace == null) {
				// This is a special address space that is only used internally to represent bonded registers
				joinSpace =
					new GenericAddressSpace(JOIN_SPACE_NAME, 64, AddressSpace.TYPE_JOIN, 10);
			}
			space = joinSpace;
		}
		else {
			space = language.getAddressFactory().getAddressSpace(spaceName);
		}
		if (spaceName.equals(OTHER_SPACE_NAME)) {
			space = AddressSpace.OTHER_SPACE;
		}
		if (space == null) {
			throw new SleighException("Unknown address space: " + spaceName);
		}
		return space;
	}

	/**
	 * Build the model arrays given a complete list of models.
	 * The array -models- contains all normal PrototypeModel objects
	 * The array -allmodels- contains all models, including merge models.
	 * 
	 * @param modelList is the complete list of models
	 */
	private void buildModelArrays(List<PrototypeModel> modelList) {
		int fullcount = 0;
		int resolvecount = 0;
		for (PrototypeModel model : modelList) {
			fullcount += 1;
			if (model.isMerged()) {
				resolvecount += 1;
			}
		}
		models = new PrototypeModel[fullcount - resolvecount];
		allmodels = new PrototypeModel[fullcount];
		int i = 0;
		int j = 0;
		for (PrototypeModel model : modelList) {
			if (model.isMerged()) {
				allmodels[fullcount - resolvecount + j] = model;
				j += 1;
			}
			else {
				models[i] = model;
				allmodels[i] = model;
				i += 1;
			}

		}
	}

	/**
	 * Establish cross referencing to prototype models.
	 * All xrefs are regenerated from a single complete list of PrototypeModels
	 * 
	 * @param modelList is the complete list of models
	 * @param defaultName is the name to use for the default model (or null)
	 * @param evalCurrent is the name to use for evaluating the current function (or null)
	 * @param evalCalled is the name to use for evaluating called functions (or null)
	 */
	protected void modelXrefs(List<PrototypeModel> modelList, String defaultName,
			String evalCurrent, String evalCalled) {
		buildModelArrays(modelList);
		callingConventionMap = new HashMap<>();
		for (PrototypeModel model : models) {
			String name = model.getName();
			if (name != null) {
				callingConventionMap.put(name, model);
			}
		}

		defaultModel = null;
		if (defaultName != null) {
			defaultModel = callingConventionMap.get(defaultName);
		}
		evalCurrentModel = defaultModel; // The default evaluation is to assume default model
		evalCalledModel = defaultModel;

		for (PrototypeModel evalmodel : allmodels) {
			if (evalCurrent != null && evalmodel.getName().equals(evalCurrent)) {
				evalCurrentModel = evalmodel;
			}
			if (evalCalled != null && evalmodel.getName().equals(evalCalled)) {
				evalCalledModel = evalmodel;
			}
		}
	}

	/**
	 * Marshal this entire specification to an XML stream.  An XML document is written with
	 * root tag \<compiler_spec>.
	 * @param buffer is the XML stream
	 */
	public void saveXml(StringBuilder buffer) {
		buffer.append("<compiler_spec>\n");
		saveProperties(buffer);
		dataOrganization.saveXml(buffer);
		ContextSetting.buildContextDataXml(buffer, ctxsetting);
		if (aggressiveTrim) {
			buffer.append("<aggressivetrim");
			SpecXmlUtils.encodeBooleanAttribute(buffer, "signext", aggressiveTrim);
			buffer.append("/>\n");
		}
		if (stackPointer != null) {
			buffer.append("<stackpointer");
			SpecXmlUtils.encodeStringAttribute(buffer, "register", stackPointer.getName());
			SpecXmlUtils.encodeStringAttribute(buffer, "space", stackBaseSpace.getName());
			if (reverseJustifyStack) {
				SpecXmlUtils.encodeBooleanAttribute(buffer, "reversejustify", reverseJustifyStack);
			}
			if (!stackGrowsNegative) {
				SpecXmlUtils.encodeStringAttribute(buffer, "growth", "positive");
			}
			buffer.append("/>\n");
		}
		saveSpaceBases(buffer);
		saveMemoryTags(buffer, "global", globalSet);
		saveReturnAddress(buffer);			// Must come before PrototypeModels
		pcodeInject.saveCompilerSpecXml(buffer);
		if (defaultModel != null) {
			buffer.append("<default_proto>\n");
			defaultModel.saveXml(buffer, pcodeInject);
			buffer.append("</default_proto>\n");
		}
		for (PrototypeModel model : allmodels) {
			if (model == defaultModel) {
				continue;		// Already emitted
			}
			if (copiedThisModel && model.hasThisPointer() &&
				model.name.equals(CALLING_CONVENTION_thiscall)) {
				continue;		// Don't need to emit the copy
			}
			model.saveXml(buffer, pcodeInject);
		}
		if (evalCurrentModel != null && evalCurrentModel != defaultModel) {
			buffer.append("<eval_current_prototype");
			SpecXmlUtils.encodeStringAttribute(buffer, "name", evalCurrentModel.name);
			buffer.append("/>\n");
		}
		if (evalCalledModel != null && evalCalledModel != defaultModel) {
			buffer.append("<eval_called_prototype");
			SpecXmlUtils.encodeStringAttribute(buffer, "name", evalCalledModel.name);
			buffer.append("/>\n");
		}
		savePreferSplit(buffer);
		saveMemoryTags(buffer, "nohighptr", noHighPtr);
		saveMemoryTags(buffer, "readonly", readOnlySet);
		if (funcPtrAlign != 0) {
			buffer.append("<funcptr");
			SpecXmlUtils.encodeSignedIntegerAttribute(buffer, "align", funcPtrAlign);
			buffer.append("/>\n");
		}
		saveDeadCodeDelay(buffer);
		saveInferPtrBounds(buffer);
		buffer.append("</compiler_spec>");
	}

	/**
	 * Initialize this object from an XML stream.  A single \<compiler_spec> tag is expected.
	 * @param parser is the XML stream
	 * @throws XmlParseException for badly formed XML
	 */
	private void restoreXml(XmlPullParser parser) throws XmlParseException {
		List<PrototypeModel> modelList = new ArrayList<>();
		boolean seenDefault = false;
		String defaultName = null;
		String evalCurrentPrototype = null;
		String evalCalledPrototype = null;

		parser.start("compiler_spec");
		while (parser.peek().isStart()) {
			String name = parser.peek().getName();
			if (name.equals("properties")) {
				restoreProperties(parser);
			}
			else if (name.equals("data_organization")) {
				dataOrganization.restoreXml(parser);
			}
			else if (name.equals("callfixup")) {
				String nm = parser.peek().getAttribute("name");
				pcodeInject.restoreXmlInject(sourceName, nm, InjectPayload.CALLFIXUP_TYPE, parser);
			}
			else if (name.equals("callotherfixup")) {
				String nm = parser.peek().getAttribute("targetop");
				pcodeInject.restoreXmlInject(sourceName, nm, InjectPayload.CALLOTHERFIXUP_TYPE,
					parser);
			}
			else if (name.equals("context_data")) {
				ContextSetting.parseContextData(ctxsetting, parser, this);
			}
			else if (name.equals("stackpointer")) {
				setStackPointer(parser);
			}
			else if (name.equals("spacebase")) {
				restoreSpaceBase(parser);
			}
			else if (name.equals("global")) {
				restoreMemoryTags("global", parser, globalSet);
			}
			else if (name.equals("default_proto")) {
				parser.start();
				PrototypeModel model = addPrototypeModel(modelList, parser);
				parser.end();
				if (!seenDefault) {
					defaultName = model.name;
					seenDefault = true;
				}
			}
			else if (name.equals("prototype")) {
				PrototypeModel model = addPrototypeModel(modelList, parser);
				if (defaultName == null) {
					defaultName = model.name;
				}
			}
			else if (name.equals("resolveprototype")) {
				addPrototypeModel(modelList, parser);
			}
			else if (name.equals("eval_current_prototype")) {
				evalCurrentPrototype = parser.start().getAttribute("name");
				parser.end();
			}
			else if (name.equals("eval_called_prototype")) {
				evalCalledPrototype = parser.start().getAttribute("name");
				parser.end();
			}
			else if (name.equals("segmentop")) {
				String source = "cspec: " + language.getLanguageID().getIdAsString();
				InjectPayloadSleigh payload = new InjectPayloadSegment(source);
				payload.restoreXml(parser, language);
				pcodeInject.registerInject(payload);
			}
			else if (name.equals("aggressivetrim")) {
				XmlElement el = parser.start();
				aggressiveTrim = SpecXmlUtils.decodeBoolean(el.getAttribute("signext"));
				parser.end(el);
			}
			else if (name.equals("prefersplit")) {
				restorePreferSplit(parser);
			}
			else if (name.equals("nohighptr")) {
				noHighPtr = new AddressSet();
				restoreMemoryTags("nohighptr", parser, noHighPtr);
			}
			else if (name.equals("readonly")) {
				readOnlySet = new AddressSet();
				restoreMemoryTags("readonly", parser, readOnlySet);
			}
			else if (name.equals("returnaddress")) {
				restoreReturnAddress(parser);
			}
			else if (name.equals("funcptr")) {
				XmlElement subel = parser.start();
				funcPtrAlign = SpecXmlUtils.decodeInt(subel.getAttribute("align"));
				parser.end(subel);
			}
			else if (name.equals("deadcodedelay")) {
				restoreDeadCodeDelay(parser);
			}
			else if (name.equals("inferptrbounds")) {
				restoreInferPtrBounds(parser);
			}
			else {
				XmlElement el = parser.start();
				parser.discardSubTree(el);
			}
		}
		parser.end();

		if (stackPointer == null) {
			stackSpace = new GenericAddressSpace(STACK_SPACE_NAME,
				language.getDefaultSpace().getSize(),
				language.getDefaultSpace().getAddressableUnitSize(), AddressSpace.TYPE_STACK, 0);
		}
		addThisCallConventionIfMissing(modelList, defaultName);
		modelXrefs(modelList, defaultName, evalCurrentPrototype, evalCalledPrototype);
	}

	private void saveProperties(StringBuilder buffer) {
		if (properties.isEmpty()) {
			return;
		}
		buffer.append("<properties>\n");
		for (Entry<String, String> property : properties.entrySet()) {
			buffer.append("<property");
			SpecXmlUtils.encodeStringAttribute(buffer, "key", property.getKey());
			SpecXmlUtils.encodeStringAttribute(buffer, "value", property.getValue());
			buffer.append("/>\n");
		}
		buffer.append("</properties>\n");
	}

	private void restoreProperties(XmlPullParser parser) {
		parser.start();
		while (parser.peek().isStart()) {
			XmlElement el = parser.start();
			if (el.getName().equals("property")) {
				String key = el.getAttribute("key");
				String value = el.getAttribute("value");
				properties.put(key, value);
				parser.end(el);
			}
			else {
				parser.discardSubTree(el);
			}
		}
		parser.end();
	}

	private void saveSpaceBases(StringBuilder buffer) {
		if (spaceBases == null) {
			return;
		}
		for (Entry<String, Pair<AddressSpace, String>> entry : spaceBases.entrySet()) {
			buffer.append("<spacebase");
			SpecXmlUtils.encodeStringAttribute(buffer, "name", entry.getKey());
			SpecXmlUtils.encodeStringAttribute(buffer, "register", entry.getValue().second);
			SpecXmlUtils.encodeStringAttribute(buffer, "space", entry.getValue().first.getName());
			buffer.append("/>\n");
		}
	}

	private void restoreSpaceBase(XmlPullParser parser) {
		if (spaceBases == null) {
			spaceBases = new TreeMap<>();
		}
		XmlElement el = parser.start();
		String name = el.getAttribute("name");
		Register reg = language.getRegister(el.getAttribute("register"));
		if (reg == null) {
			throw new SleighException("Unknown register: " + name);
		}
		String spaceName = el.getAttribute("space");
		if (language.getAddressFactory().getAddressSpace(name) != null ||
			spaceBases.containsKey(name)) {
			throw new SleighException("Duplicate space name: " + name);
		}
		AddressSpace space = getAddressSpace(spaceName);
		spaceBases.put(name, new Pair<>(space, reg.getName()));
		parser.end(el);
	}

	private void saveReturnAddress(StringBuilder buffer) {
		if (returnAddress == null) {
			return;
		}
		buffer.append("<returnaddress>\n");
		buffer.append("<varnode");
		AddressXML.appendAttributes(buffer, returnAddress.getAddress(), returnAddress.getSize());
		buffer.append("/>\n");
		buffer.append("</returnaddress>\n");
	}

	private void restoreReturnAddress(XmlPullParser parser) throws XmlParseException {
		XmlElement el = parser.start();
		XmlElement subel = parser.start();
		AddressXML addrSized = AddressXML.restoreXml(subel, this);
		returnAddress = addrSized.getVarnode();
		parser.end(subel);
		parser.end(el);
	}

	private void readExtraRange(XmlElement el, String spcName, String tagName) {
		AddressSpace addressSpace = spaceBases.get(spcName).first;
		long first = 0;
		long last = -1;
		boolean seenLast = false;
		String attrvalue = el.getAttribute("first");
		if (attrvalue != null) {
			first = SpecXmlUtils.decodeLong(attrvalue);
		}
		attrvalue = el.getAttribute("last");
		if (attrvalue != null) {
			last = SpecXmlUtils.decodeLong(attrvalue);
			seenLast = true;
		}
		if (!seenLast) {
			last = addressSpace.getMaxAddress().getOffset();
		}
		if (extraRanges == null) {
			extraRanges = new ArrayList<>();
		}
		extraRanges.add(new Pair<>(tagName + '_' + spcName, new Pair<>(first, last)));
	}

	private void saveExtraRanges(StringBuilder buffer, String tagName) {
		if (extraRanges == null) {
			return;
		}
		for (Pair<String, Pair<Long, Long>> entry : extraRanges) {
			if (!entry.first.startsWith(tagName)) {
				continue;
			}
			String spcName = entry.first.substring(entry.first.indexOf('_') + 1);
			long first = entry.second.first;
			long last = entry.second.second;
			boolean useFirst = (first != 0);
			boolean useLast = (last != -1);
			buffer.append("<range");
			SpecXmlUtils.encodeStringAttribute(buffer, "space", spcName);
			if (useFirst) {
				SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "first", first);
			}
			if (useLast) {
				SpecXmlUtils.encodeUnsignedIntegerAttribute(buffer, "last", last);
			}
			buffer.append("/>\n");
		}
	}

	private void saveMemoryTags(StringBuilder buffer, String tagName, AddressSet addrSet) {
		if (addrSet == null) {
			return;
		}
		buffer.append('<').append(tagName).append(">\n");
		AddressRangeIterator iter = addrSet.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			buffer.append("<range");
			AddressXML.appendAttributes(buffer, range.getMinAddress(), range.getMaxAddress());
			buffer.append("/>\n");
		}
		saveExtraRanges(buffer, tagName);
		buffer.append("</").append(tagName).append(">\n");
	}

	private void restoreMemoryTags(String tagName, XmlPullParser parser, AddressSet addrSet)
			throws XmlParseException {
		parser.start(tagName);
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			String name = subel.getName();
			if (name.equals("range") || name.equals("register")) {
				String spcName = subel.getAttribute("space");
				if (spcName != null && spaceBases != null && spaceBases.containsKey(spcName)) {
					readExtraRange(subel, spcName, tagName);
				}
				else {
					AddressXML range = AddressXML.restoreRangeXml(subel, this);
					Address firstAddress = range.getFirstAddress();
					Address lastAddress = range.getLastAddress();
					AddressRange addrRange = new AddressRangeImpl(firstAddress, lastAddress);
					addrSet.add(addrRange);
				}
			}
			else {
				throw new XmlParseException("Unexpected <" + tagName + "> sub-tag: " + name);
			}
			parser.end(subel);
		}
		parser.end();
	}

	private void restorePreferSplit(XmlPullParser parser) throws XmlParseException {
		XmlElement el = parser.start();
		String styleString = el.getAttribute("style");
		if (styleString == null || !styleString.equals("inhalf")) {
			throw new XmlParseException("Unknown prefersplit strategy");
		}
		preferSplit = new ArrayList<>();
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			AddressXML addrSized = AddressXML.restoreXml(subel, this);
			parser.end(subel);
			preferSplit.add(addrSized.getVarnode());
		}
		parser.end(el);
	}

	private void savePreferSplit(StringBuilder buffer) {
		if (preferSplit == null || preferSplit.isEmpty()) {
			return;
		}
		buffer.append("<prefersplit style=\"inhalf\">\n");
		for (Varnode varnode : preferSplit) {
			buffer.append("<varnode");
			AddressXML.appendAttributes(buffer, varnode.getAddress(), varnode.getSize());
			buffer.append("/>\n");
		}
		buffer.append("</prefersplit>\n");
	}

	private void restoreDeadCodeDelay(XmlPullParser parser) {
		if (deadCodeDelay == null) {
			deadCodeDelay = new ArrayList<>();
		}
		XmlElement el = parser.start();
		AddressSpace space = getAddressSpace(el.getAttribute("space"));
		int delay = SpecXmlUtils.decodeInt(el.getAttribute("delay"));
		deadCodeDelay.add(new Pair<>(space, delay));
		parser.end(el);
	}

	private void saveDeadCodeDelay(StringBuilder buffer) {
		if (deadCodeDelay == null) {
			return;
		}
		for (Pair<AddressSpace, Integer> pair : deadCodeDelay) {
			buffer.append("<deadcodedelay");
			SpecXmlUtils.encodeStringAttribute(buffer, "space", pair.first.getName());
			SpecXmlUtils.encodeSignedIntegerAttribute(buffer, "delay", pair.second.intValue());
			buffer.append("/>\n");
		}
	}

	private void restoreInferPtrBounds(XmlPullParser parser) throws XmlParseException {
		if (inferPtrBounds == null) {
			inferPtrBounds = new ArrayList<>();
		}
		XmlElement el = parser.start();
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			AddressXML addrSized = AddressXML.restoreRangeXml(subel, this);
			AddressRange addrRange =
				new AddressRangeImpl(addrSized.getFirstAddress(), addrSized.getLastAddress());
			inferPtrBounds.add(addrRange);
			parser.end(subel);
		}
		parser.end(el);
	}

	private void saveInferPtrBounds(StringBuilder buffer) {
		if (inferPtrBounds == null) {
			return;
		}
		buffer.append("<inferptrbounds>\n");
		for (AddressRange addrRange : inferPtrBounds) {
			buffer.append("<range");
			AddressXML.appendAttributes(buffer, addrRange.getMinAddress(),
				addrRange.getMaxAddress());
			buffer.append("/>\n");
		}
		buffer.append("</inferptrbounds>\n");
	}

	private void setStackPointer(XmlPullParser parser) {
		XmlElement el = parser.start();
		String regName = el.getAttribute("register");
		stackPointer = language.getRegister(regName);
		if (stackPointer == null) {
			throw new SleighException("Unknown register: " + regName);
		}
		String baseSpaceName = el.getAttribute("space");
		stackBaseSpace = getAddressSpace(baseSpaceName);
		if (stackBaseSpace == null) {
			throw new SleighException("Undefined base stack space: " + baseSpaceName);
		}
		int stackSpaceSize = Math.min(stackPointer.getBitLength(), stackBaseSpace.getSize());
		stackSpace = new GenericAddressSpace(STACK_SPACE_NAME, stackSpaceSize,
			stackBaseSpace.getAddressableUnitSize(), AddressSpace.TYPE_STACK, 0);
		String reverseJustifyStr = el.getAttribute("reversejustify");
		if (reverseJustifyStr != null) {
			reverseJustifyStack = getBooleanValue(reverseJustifyStr);
		}
		String growth = el.getAttribute("growth");
		if (growth == null || growth.equals("negative")) {
			stackGrowsNegative = true;
		}
		else if (growth.equals("positive")) {
			stackGrowsNegative = false;
		}
		else {
			throw new SleighException(
				"Bad stack growth " + growth + " should be 'positive' or 'negative'");
		}
		parser.end(el);
	}

	private boolean getBooleanValue(String booleanStr) {
		return "1".equals(booleanStr) || "true".equalsIgnoreCase(booleanStr);
	}

//	private int getIntegerValue(String valStr, int defaultValue) {
//		int radix = 10;
//        if (valStr.startsWith("0x") || valStr.startsWith("0X")) {
//        	valStr = valStr.substring(2);
//            radix = 16;
//        }
//        try {
//            return Integer.parseInt(valStr, radix);
//        }
//        catch (Exception e) {
//            return defaultValue;
//        }
//	}

	private PrototypeModel addPrototypeModel(List<PrototypeModel> modelList, XmlPullParser parser)
			throws XmlParseException {
		PrototypeModel model;
		if (parser.peek().getName().equals("resolveprototype")) {
			PrototypeModelMerged mergemodel = new PrototypeModelMerged();
			mergemodel.restoreXml(parser, modelList);
			model = mergemodel;
		}
		else {
			model = new PrototypeModel();
			model.restoreXml(parser, this);
		}
		modelList.add(model);
		return model;
	}

	@Override
	public DataOrganization getDataOrganization() {
		return dataOrganization;
	}

	@Override
	public PrototypeModel matchConvention(GenericCallingConvention genericCallingConvention) {
		if (genericCallingConvention == GenericCallingConvention.unknown) {
			return defaultModel;
		}
		for (PrototypeModel model : models) {
			if (model.getGenericCallingConvention() == genericCallingConvention) {
				return model;
			}
		}
		return defaultModel;
	}

	@Override
	public PrototypeModel findBestCallingConvention(Parameter[] params) {
		if (!evalCurrentModel.isMerged()) {
			return evalCurrentModel;
		}
		return ((PrototypeModelMerged) evalCurrentModel).selectModel(params);
	}

	@Override
	public String getProperty(String key) {
		return properties.get(key);
	}

	@Override
	public Set<String> getPropertyKeys() {
		return Collections.unmodifiableSet(properties.keySet());
	}

	@Override
	public String getProperty(String key, String defaultString) {
		if (properties.containsKey(key)) {
			return properties.get(key);
		}
		return defaultString;
	}

	@Override
	public boolean getPropertyAsBoolean(String key, boolean defaultBoolean) {
		if (properties.containsKey(key)) {
			return Boolean.parseBoolean(properties.get(key));
		}
		return defaultBoolean;
	}

	@Override
	public int getPropertyAsInt(String key, int defaultInt) {
		if (properties.containsKey(key)) {
			return Integer.parseInt(properties.get(key));
		}
		return defaultInt;
	}

	@Override
	public boolean hasProperty(String key) {
		return properties.containsKey(key);
	}

	@Override
	public PcodeInjectLibrary getPcodeInjectLibrary() {
		return pcodeInject;
	}

	/**
	 * Remove any call mechanism injections associated with the given list of PrototypeModels
	 * @param modelList is the given list
	 */
	protected void removeProgramMechanismPayloads(Collection<PrototypeModel> modelList) {
		for (PrototypeModel model : modelList) {
			if (model.hasInjection()) {
				pcodeInject.removeMechanismPayload(model.getInjectName());
			}
		}
	}

	/**
	 * Register Program based InjectPayloads with the p-code library.
	 * This allows derived classes to extend the library
	 * @param injectExtensions is the list of payloads to register
	 */
	protected void registerProgramInject(List<InjectPayloadSleigh> injectExtensions) {
		pcodeInject.registerProgramInject(injectExtensions);
	}

	/**
	 * Mark a given PrototypeModel as a Program specific extension
	 * @param model is the given PrototypeModel
	 */
	protected static void markPrototypeAsExtension(PrototypeModel model) {
		model.isExtension = true;
	}

	@Override
	public boolean equals(Object obj) {
		BasicCompilerSpec op2 = (BasicCompilerSpec) obj;
		if (aggressiveTrim != op2.aggressiveTrim || copiedThisModel != op2.copiedThisModel) {
			return false;
		}
		if (!dataOrganization.equals(op2.dataOrganization)) {
			return false;
		}
		if (!ctxsetting.equals(op2.ctxsetting)) {
			return false;
		}
		if (!SystemUtilities.isEqual(deadCodeDelay, op2.deadCodeDelay)) {
			return false;
		}
		if (defaultModel != null) {
			if (op2.defaultModel == null) {
				return false;
			}
			if (!defaultModel.name.equals(op2.defaultModel.name)) {
				return false;
			}
		}
		else if (op2.defaultModel != null) {
			return false;
		}
		if (evalCalledModel != null) {
			if (op2.evalCalledModel == null) {
				return false;
			}
			if (!evalCalledModel.name.equals(op2.evalCalledModel.name)) {
				return false;
			}
		}
		else if (op2.evalCalledModel != null) {
			return false;
		}
		if (evalCurrentModel != null) {
			if (op2.evalCurrentModel == null) {
				return false;
			}
			if (!evalCurrentModel.name.equals(op2.evalCurrentModel.name)) {
				return false;
			}
		}
		else if (op2.evalCurrentModel != null) {
			return false;
		}
		if (allmodels.length != op2.allmodels.length) {
			return false;
		}
		if (!SystemUtilities.isArrayEqual(allmodels, op2.allmodels)) {
			return false;
		}
		if (!SystemUtilities.isEqual(extraRanges, op2.extraRanges)) {
			return false;
		}
		if (funcPtrAlign != op2.funcPtrAlign) {
			return false;
		}
		if (!globalSet.equals(op2.globalSet)) {
			return false;
		}
		if (!SystemUtilities.isEqual(inferPtrBounds, op2.inferPtrBounds)) {
			return false;
		}
		if (!SystemUtilities.isEqual(noHighPtr, op2.noHighPtr)) {
			return false;
		}
		if (!pcodeInject.equals(op2.pcodeInject)) {
			return false;
		}
		if (!SystemUtilities.isEqual(preferSplit, op2.preferSplit)) {
			return false;
		}
		if (!properties.equals(op2.properties)) {
			return false;
		}
		if (!SystemUtilities.isEqual(readOnlySet, op2.readOnlySet)) {
			return false;
		}
		if (!SystemUtilities.isEqual(returnAddress, op2.returnAddress)) {
			return false;
		}
		if (reverseJustifyStack != op2.reverseJustifyStack) {
			return false;
		}
		if (!SystemUtilities.isEqual(spaceBases, op2.spaceBases)) {
			return false;
		}
		if (!SystemUtilities.isEqual(stackBaseSpace, op2.stackBaseSpace)) {
			return false;
		}
		if (stackGrowsNegative != op2.stackGrowsNegative) {
			return false;
		}
		if (!SystemUtilities.isEqual(stackPointer, op2.stackPointer)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		int hash = language.getLanguageID().hashCode();
		hash = 79 * description.getCompilerSpecID().hashCode() + hash;
		return hash;
	}
}
