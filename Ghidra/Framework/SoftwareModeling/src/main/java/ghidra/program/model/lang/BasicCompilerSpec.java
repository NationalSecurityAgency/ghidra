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

import java.io.*;
import java.lang.reflect.Constructor;
import java.math.BigInteger;
import java.util.*;

import org.xml.sax.*;

import docking.options.editor.StringWithChoicesEditor;
import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

public class BasicCompilerSpec implements CompilerSpec {

	public static final String DECOMPILER_PROPERTY_LIST_NAME = "Decompiler";
	public static final String DECOMPILER_OUTPUT_LANGUAGE = "Output Language";
	public final static DecompilerLanguage DECOMPILER_OUTPUT_DEF = DecompilerLanguage.C_LANGUAGE;
	public final static String DECOMPILER_OUTPUT_DESC =
		"Select the source language output by the decompiler.";
	private static final String EVALUATION_MODEL_PROPERTY_NAME = "Prototype Evaluation";

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
	private PrototypeModel defaultModel;
	private PrototypeModel defaultEvaluationModel;
	private PrototypeModel[] models;
	private PrototypeModel[] evalmodels;
	private Register stackPointer;
	private AddressSpace stackSpace;
	private AddressSpace stackBaseSpace;
	private AddressSpace joinSpace;
	private boolean stackGrowsNegative = true;
	private boolean reverseJustifyStack = false;
	private Map<String, AddressSpace> spaceBases = new HashMap<>();
	private PcodeInjectLibrary pcodeInject;
	private AddressSet globalSet;
	private LinkedHashMap<String, String> properties = new LinkedHashMap<>();
	private Map<String, PrototypeModel> callingConventionMap = new HashMap<>();
	private String[] evaluationModelChoices;
	private String specString;
	private ResourceFile specFile;

	private Exception parseException;

	public BasicCompilerSpec(CompilerSpecDescription description, SleighLanguage language,
			final ResourceFile cspecFile) throws CompilerSpecNotFoundException {
		this.description = description;
		this.language = language;
		buildInjectLibrary();
		this.dataOrganization = DataOrganizationImpl.getDefaultOrganization(language);
		specString = null;
		specFile = cspecFile;

		ErrorHandler errHandler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				parseException = exception;
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				parseException = exception;
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(this, "Warning parsing '" + cspecFile + "'", exception);
			}
		};

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
		catch (FileNotFoundException e) {
			parseException = e;
		}
		catch (IOException e) {
			parseException = e;
		}
		catch (SAXException e) {
			parseException = e;
		}
		catch (XmlParseException e) {
			parseException = e;
		}

		if (parseException != null) {
			throw new CompilerSpecNotFoundException(language.getLanguageID(),
				description.getCompilerSpecID(), cspecFile.getName(), parseException);
		}
	}

	private void initialize(String sourceName, XmlPullParser parser) throws XmlParseException {
		this.sourceName = sourceName;
		globalSet = new AddressSet();
		defaultModel = null;
		models = new PrototypeModel[0];

		restoreXml(parser);

		addThisCallConventionIfMissing();
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
				pcodeInject.registerInject(payload.clone());
			}
		}
	}

	private void addThisCallConventionIfMissing() {
		boolean foundThisCall = false;
		for (PrototypeModel model : models) {
			if (CALLING_CONVENTION_thiscall.equals(model.getName())) {
				foundThisCall = true;
				break;
			}
		}
		if (defaultModel != null && !foundThisCall) {
			PrototypeModel[] newModels = new PrototypeModel[models.length + 1];
			System.arraycopy(models, 0, newModels, 0, models.length);
			PrototypeModel thisModel =
				new PrototypeModel(CALLING_CONVENTION_thiscall, defaultModel);
			callingConventionMap.put(CALLING_CONVENTION_thiscall, thisModel);
			newModels[models.length] = thisModel;
			models = newModels;
		}
	}

	public String getCompilerSpecString() throws FileNotFoundException, IOException {
		if (specString != null) {
			return specString;
		}
		InputStreamReader reader = new InputStreamReader(specFile.getInputStream());
		char[] cbuf = new char[1024];

		StringBuffer buf = new StringBuffer();
		int curlen = reader.read(cbuf);
		while (curlen > 0) {
			buf.append(cbuf, 0, curlen);
			curlen = reader.read(cbuf);
		}
		reader.close();
		specString = buf.toString();
		return specString;
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
	public PrototypeModel getDefaultCallingConvention() {
		return defaultModel;
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
	public PrototypeModel[] getNamedCallingConventions() {
		PrototypeModel[] tmpNamed = new PrototypeModel[models.length];
		int current = 0;
		for (int i = 0; i < tmpNamed.length; i++) {
			if (models[i].getName() != null) {
				tmpNamed[current++] = models[i];
			}
		}
		PrototypeModel[] named = new PrototypeModel[current];
		System.arraycopy(tmpNamed, 0, named, 0, current);
		return named;
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

	//
	// .cspec parsing (only those portions of the spec needed are actually processed)
	//

	private Register getRegister(String registerName) {
		Register reg = language.getRegister(registerName);
		if (reg == null) {
			throw new SleighException("Unknown register: " + registerName);
		}
		return reg;
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
	 * Build up the choice strings for all the evaluation methods
	 */
	private void establishEvaluationModelChoices(PrototypeModel defaultEvaluationModel) {

		// Make sure the default evaluation model occurs at the top of the evalmodels list
		int defaultnum = -1;
		for (int i = 0; i < evalmodels.length; ++i) {
			if (evalmodels[i] == defaultEvaluationModel) {
				defaultnum = i;
			}
		}

		if (defaultnum > 0) {
			PrototypeModel tmp = evalmodels[defaultnum];
			for (int i = defaultnum; i > 0; --i) {
				// Push everybody down to make room for default at top
				evalmodels[i] = evalmodels[i - 1];
			}
			evalmodels[0] = tmp;
		}

		// Now build a list of menu strings with 1-1 correspondence to models in evalmodels 
		evaluationModelChoices = new String[evalmodels.length];
		for (int i = 0; i < evalmodels.length; ++i) {
			String name = evalmodels[i].getName();
			if (name == null) {
				if (i == 0) {
					name = "default";
				}
				else {
					name = "spec" + Integer.toString(i);
				}
			}
			evaluationModelChoices[i] = name;
		}
	}

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
		evalmodels = new PrototypeModel[fullcount];
		int i = 0;
		int j = 0;
		for (PrototypeModel model : modelList) {
			if (model.isMerged()) {
				evalmodels[fullcount - resolvecount + j] = model;
				j += 1;
			}
			else {
				models[i] = model;
				evalmodels[i] = model;
				i += 1;
			}

		}
	}

	private void restoreXml(XmlPullParser parser) throws XmlParseException {
		stackPointer = null;
		List<PrototypeModel> modelList = new ArrayList<>();
		String evalCurrentPrototype = null;

		parser.start("compiler_spec");
		while (parser.peek().isStart()) {
			String name = parser.peek().getName();
			if (name.equals("properties")) {
				readProperties(parser);
			}
			else if (name.equals("data_organization")) {
				restoreDataOrganization(parser);
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
				restoreContextData(parser);
			}
			else if (name.equals("stackpointer")) {
				setStackPointer(parser);
			}
			else if (name.equals("spacebase")) {
				restoreSpaceBase(parser);
			}
			else if (name.equals("global")) {
				restoreGlobal(parser);
			}
			else if (name.equals("default_proto")) {
				parser.start();
				addPrototypeModel(modelList, parser, true);
				parser.end();
			}
			else if (name.equals("prototype")) {
				addPrototypeModel(modelList, parser, false);
			}
			else if (name.equals("resolveprototype")) {
				addPrototypeModel(modelList, parser, false);
			}
			else if (name.equals("eval_current_prototype")) {
				evalCurrentPrototype = parser.start().getAttribute("name");
				parser.end();
			}
			else if (name.equals("segmentop")) {
				XmlElement el = parser.start();
				InjectPayloadSleigh payload = language.parseSegmentOp(el, parser);
				parser.end();
				pcodeInject.registerInject(payload);
			}
			else {
				XmlElement el = parser.start();
				parser.discardSubTree(el);
			}
		}

		if (stackPointer == null) {
			stackSpace = new GenericAddressSpace(STACK_SPACE_NAME,
				language.getDefaultSpace().getSize(),
				language.getDefaultSpace().getAddressableUnitSize(), AddressSpace.TYPE_STACK, 0);
		}

		buildModelArrays(modelList);
		// populate nameToModelMap
		for (PrototypeModel model : models) {
			String name = model.getName();
			if (name != null) {
				callingConventionMap.put(name, model);
			}
		}

		defaultEvaluationModel = defaultModel; // The default evaluation is to assume default model

		if (evalCurrentPrototype != null) {		// Look for an explicit default evaluation
			for (PrototypeModel evalmodel : evalmodels) {
				if (evalmodel.getName().equals(evalCurrentPrototype)) {
					defaultEvaluationModel = evalmodel;
					break;
				}
			}
		}
		establishEvaluationModelChoices(defaultEvaluationModel);
		parser.end();
	}

	private void readProperties(XmlPullParser parser) {
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

	private void restoreDataOrganization(XmlPullParser parser) throws XmlParseException {

		parser.start();
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			String name = subel.getName();

			if (name.equals("char_type")) {
				String boolStr = subel.getAttribute("signed");
				dataOrganization.setCharIsSigned(SpecXmlUtils.decodeBoolean(boolStr));
				parser.end(subel);
				continue;
			}

			String value = subel.getAttribute("value");

			if (name.equals("absolute_max_alignment")) {
				dataOrganization.setAbsoluteMaxAlignment(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("machine_alignment")) {
				dataOrganization.setMachineAlignment(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("default_alignment")) {
				dataOrganization.setDefaultAlignment(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("default_pointer_alignment")) {
				dataOrganization.setDefaultPointerAlignment(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("pointer_size")) {
				dataOrganization.setPointerSize(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("pointer_shift")) {
				dataOrganization.setPointerShift(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("char_size")) {
				dataOrganization.setCharSize(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("wchar_size")) {
				dataOrganization.setWideCharSize(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("short_size")) {
				dataOrganization.setShortSize(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("integer_size")) {
				dataOrganization.setIntegerSize(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("long_size")) {
				dataOrganization.setLongSize(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("long_long_size")) {
				dataOrganization.setLongLongSize(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("float_size")) {
				dataOrganization.setFloatSize(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("double_size")) {
				dataOrganization.setDoubleSize(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("long_double_size")) {
				dataOrganization.setLongDoubleSize(SpecXmlUtils.decodeInt(value));
			}
			else if (name.equals("size_alignment_map")) {
				dataOrganization.clearSizeAlignmentMap();
				while (parser.peek().isStart()) {
					XmlElement subsubel = parser.start();
					int size = SpecXmlUtils.decodeInt(subsubel.getAttribute("size"));
					int alignment = SpecXmlUtils.decodeInt(subsubel.getAttribute("alignment"));
					dataOrganization.setSizeAlignment(size, alignment);
					parser.end(subsubel);
				}
			}
			else if (name.equals("bitfield_packing")) {
				dataOrganization.setBitFieldPacking(parseBitFieldPacking(parser));
			}
			parser.end(subel);
		}

		parser.end();
	}

	private BitFieldPacking parseBitFieldPacking(XmlPullParser parser) {
		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl();
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			String name = subel.getName();
			String value = subel.getAttribute("value");

			if (name.equals("use_MS_convention")) {
				bitFieldPacking.setUseMSConvention(SpecXmlUtils.decodeBoolean(value));
			}
			else if (name.equals("type_alignment_enabled")) {
				bitFieldPacking.setTypeAlignmentEnabled(SpecXmlUtils.decodeBoolean(value));
			}
			else if (name.equals("zero_length_boundary")) {
				bitFieldPacking.setZeroLengthBoundary(SpecXmlUtils.decodeInt(value));
			}

			parser.end(subel);
		}
		return bitFieldPacking;
	}

	private void restoreSpaceBase(XmlPullParser parser) {
		XmlElement el = parser.start();
		String name = el.getAttribute("name");
		getRegister(el.getAttribute("register"));
		String spaceName = el.getAttribute("space");
		if (language.getAddressFactory().getAddressSpace(name) != null ||
			spaceBases.containsKey(name)) {
			throw new SleighException("Duplicate space name: " + name);
		}
		AddressSpace space = getAddressSpace(spaceName);
		spaceBases.put(name, space);
		parser.end(el);
	}

	private void restoreGlobal(XmlPullParser parser) {
		parser.start();
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			String name = subel.getName();
			if (name.equals("range")) {
				AddressRange range = getAddressRange(subel);
				if (range != null) {
					globalSet.add(range);
				}
			}
			else if (name.equals("register")) {
				String regName = subel.getAttribute("name");
				Register reg = getRegister(regName);
				globalSet.addRange(reg.getAddress(),
					reg.getAddress().add(reg.getMinimumByteSize() - 1));
			}
			parser.end(subel);
		}
		parser.end();
	}

	private void restoreContextData(XmlPullParser parser) {
		parser.start();
		while (parser.peek().isStart()) {
			String name = parser.peek().getName();
			if (name.equals("context_set")) {
				addContextSet(parser);
			}
			else if (name.equals("tracked_set")) {
				addTrackedSet(parser);
			}
		}
		parser.end();
	}

	private void addTrackedSet(XmlPullParser parser) {
		XmlElement el = parser.start();
		AddressRange range = getAddressRange(el);
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			ctxsetting.add(getContextSetting(subel, range, false));
			parser.end(subel);
		}
		parser.end(el);
	}

	private void addContextSet(XmlPullParser parser) {
		XmlElement el = parser.start();

		AddressRange range = getAddressRange(el);
		while (parser.peek().isStart()) {
			XmlElement subel = parser.start();
			ctxsetting.add(getContextSetting(subel, range, true));
			parser.end(subel);
		}
		parser.end(el);
	}

	private ContextSetting getContextSetting(XmlElement setElement, AddressRange range,
			boolean isContextReg) {
		String name = setElement.getAttribute("name");
		BigInteger val = getBigInteger(setElement.getAttribute("val"), 0);
		Register reg = getRegister(name);
		if (isContextReg) {
			if (!reg.isProcessorContext()) {
				throw new SleighException("Register " + name + " is not a context register");
			}
		}
		else if (reg.isProcessorContext()) {
			throw new SleighException("Unexpected context register " + name);
		}
		return new ContextSetting(reg, val, range.getMinAddress(), range.getMaxAddress());
	}

	/**
	 * Returns address range defined by spacified set element
	 * or null if range corresponds to a virtual space (i.e., spacebase).
	 * @param setParentElement
	 */
	private AddressRange getAddressRange(XmlElement setParentElement) {
		String spaceName = setParentElement.getAttribute("space");
		if (spaceBases.containsKey(spaceName)) {
			return null;
		}
		AddressSpace addrspace = getAddressSpace(spaceName);
		long first = addrspace.getMinAddress().getOffset();
		long last = addrspace.getMaxAddress().getOffset();
		String valstring = setParentElement.getAttribute("first");
		if (valstring != null) {
			first = SpecXmlUtils.decodeLong(valstring);
		}
		valstring = setParentElement.getAttribute("last");
		if (valstring != null) {
			last = SpecXmlUtils.decodeLong(valstring);
		}
		Address firstAddress = addrspace.getAddress(first);
		Address lastAddress = addrspace.getAddress(last);
		return new AddressRangeImpl(firstAddress, lastAddress);
	}

	private void setStackPointer(XmlPullParser parser) {
		XmlElement el = parser.start();
		stackPointer = getRegister(el.getAttribute("register"));
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

	private void addPrototypeModel(List<PrototypeModel> modelList, XmlPullParser parser,
			boolean isDefault) throws XmlParseException {
		PrototypeModel model;
		if (parser.peek().getName().equals("resolveprototype")) {
			PrototypeModelMerged mergemodel = new PrototypeModelMerged();
			mergemodel.restoreXml(parser, modelList, stackGrowsNegative);
			model = mergemodel;
		}
		else {
			model = new PrototypeModel();
			model.restoreXml(parser, this, stackGrowsNegative);
		}
		if (defaultModel == null || isDefault) {
			defaultModel = model;
		}
		modelList.add(model);
	}

	@Override
	public DataOrganization getDataOrganization() {
		return dataOrganization;
	}

	private String getPrototypeEvaluationModelChoice(Program program) {
		Options options = program.getOptions(DECOMPILER_PROPERTY_LIST_NAME);
		return options.getString(EVALUATION_MODEL_PROPERTY_NAME, (String) null);
	}

	@Override
	public Object getPrototypeEvaluationModel(Program program) {

		String modelName = getPrototypeEvaluationModelChoice(program);

		// Names in evaluationModelChoices must directly correspond to PrototypeModel in evalmodels
		for (int i = 0; i < evaluationModelChoices.length; ++i) {
			if (evaluationModelChoices[i].equals(modelName)) {
				return evalmodels[i];
			}
		}
		return null;
	}

	@Override
	public DecompilerLanguage getDecompilerOutputLanguage(Program program) {
		Options options = program.getOptions(DECOMPILER_PROPERTY_LIST_NAME);
		if (options.contains(DECOMPILER_OUTPUT_LANGUAGE)) {
			return options.getEnum(DECOMPILER_OUTPUT_LANGUAGE, DECOMPILER_OUTPUT_DEF);
		}
		return DECOMPILER_OUTPUT_DEF;
	}

	@Override
	public void registerProgramOptions(Program program) {

		// NOTE: Any changes to the option name/path must be handled carefully since
		// old property values will remain in the program.  There is currently no support
		// for upgrading/moving old property values.

		Options decompilerPropertyList = program.getOptions(DECOMPILER_PROPERTY_LIST_NAME);
		decompilerPropertyList
				.setOptionsHelpLocation(new HelpLocation("DecompilePlugin", "ProgramOptions"));
		decompilerPropertyList.registerOption(EVALUATION_MODEL_PROPERTY_NAME,
			OptionType.STRING_TYPE, evaluationModelChoices[0],
			new HelpLocation("DecompilePlugin", "OptionProtoEval"),
			"Select the default function prototype/evaluation model to be used during Decompiler analysis",
			new StringWithChoicesEditor(evaluationModelChoices));

		if (decompilerPropertyList.contains(DECOMPILER_OUTPUT_LANGUAGE)) {
			decompilerPropertyList.registerOption(DECOMPILER_OUTPUT_LANGUAGE, DECOMPILER_OUTPUT_DEF,
				null, DECOMPILER_OUTPUT_DESC);

		}

		Options analysisPropertyList =
			program.getOptions(Program.ANALYSIS_PROPERTIES + ".Decompiler Parameter ID");
		analysisPropertyList.createAlias(EVALUATION_MODEL_PROPERTY_NAME, decompilerPropertyList,
			EVALUATION_MODEL_PROPERTY_NAME);
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
		if (!defaultEvaluationModel.isMerged()) {
			return defaultEvaluationModel;
		}
		return ((PrototypeModelMerged) defaultEvaluationModel).selectModel(params);
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
	 * Adds and enables an option to have the decompiler display java.
	 * @param program to be enabled
	 */
	public static void enableJavaLanguageDecompilation(Program program) {
		Options decompilerPropertyList =
			program.getOptions(BasicCompilerSpec.DECOMPILER_PROPERTY_LIST_NAME);
		decompilerPropertyList.registerOption(BasicCompilerSpec.DECOMPILER_OUTPUT_LANGUAGE,
			BasicCompilerSpec.DECOMPILER_OUTPUT_DEF, null,
			BasicCompilerSpec.DECOMPILER_OUTPUT_DESC);
		decompilerPropertyList.setEnum(BasicCompilerSpec.DECOMPILER_OUTPUT_LANGUAGE,
			DecompilerLanguage.JAVA_LANGUAGE);
	}
}
