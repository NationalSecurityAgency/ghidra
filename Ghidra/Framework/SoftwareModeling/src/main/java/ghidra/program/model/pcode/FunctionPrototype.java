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
package ghidra.program.model.pcode;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

/**
 * 
 *
 * High-level prototype of a function based on Varnodes, describing the inputs and outputs
 * of this function.
 */
public class FunctionPrototype {

	private LocalSymbolMap localsyms; // Prototype backed by symbol map
	private String modelname; // Name of prototype model
	private String injectname; // Name of pcode inject associated with this prototype
	private DataType returntype; // Output parameter
	private VariableStorage returnstorage;	// Where the output value is stored
	private ParameterDefinition[] params; // Internally backed prototype. Only non-null if localsyms is null
	private boolean modellock;	// Is the prototype model locked
	private boolean voidinputlock; // Is the input prototype locked
	private boolean outputlock; // Is the return type locked
	private boolean dotdotdot; // Does this function accept variable argument lists
	private int extrapop; // How much extra stackspace must be popped off (after call)
	private boolean isinline; // Function should be inlined by the decompiler
	private boolean noreturn; // Calls to this function do not return
	private boolean custom;	// Uses custom storage for parameters
	private boolean hasThis;	// Function has a method this pointer
	private boolean isConstruct;	// Function is an object contructor
	private boolean isDestruct;		// Function is an object destructor

	/**
	 * Construct a FunctionPrototype backed by a local symbolmap.
	 * This is only a partial initialization.  It is intended to be followed either by
	 * grabFromFunction() or readPrototypeXML()
	 * 
	 * @param ls is the LocalSymbolMap backing the prototype
	 * @param func is the function using the symbolmap
	 */
	public FunctionPrototype(LocalSymbolMap ls, Function func) {
		localsyms = ls;
		modelname = null;
		injectname = null;
		returntype = null;
		returnstorage = null;
		params = null;
		modellock = false;
		voidinputlock = false;
		outputlock = false;
		dotdotdot = func.hasVarArgs();
		isinline = func.isInline();
		noreturn = func.hasNoReturn();
		custom = func.hasCustomVariableStorage();
		hasThis = false;
		isConstruct = false;
		isDestruct = false;
		extrapop = PrototypeModel.UNKNOWN_EXTRAPOP;
	}

	/**
	 * Construct an internally backed prototype based on a FunctionSignature prototype
	 * @param proto  is the FunctionSignature used to internally back input parameters
	 * @param cspec  is the compiler spec used to pick prototype model
	 * @param voidimpliesdotdotdot set to true if a void prototype is interpreted as varargs
	 */
	public FunctionPrototype(FunctionSignature proto, CompilerSpec cspec,
			boolean voidimpliesdotdotdot) {
		modelname = proto.getCallingConventionName();
		PrototypeModel model = cspec.matchConvention(modelname);
		localsyms = null;
		injectname = null;
		returntype = proto.getReturnType();
		returnstorage = null;
		params = proto.getArguments();
		modellock = true;
		voidinputlock = ((params == null) || (params.length == 0));
		outputlock = true;
		dotdotdot = proto.hasVarArgs();
		isinline = false;
		noreturn = proto.hasNoReturn();
		custom = false;
		extrapop = model.getExtrapop();
		hasThis = model.hasThisPointer();
		isConstruct = false;
		isDestruct = false;
		// FIXME: If the FunctionDefinition has no parameters
		// we may want to force the void on the decompiler, but
		// there are some types in the library like FARPROC
		// that have a void body, but are intended as a generic
		// function pointer, in which case forcing the void
		// causes the decompiler to drop real parameters.
		// At the moment, we turn on varargs if there are no params
		if (voidimpliesdotdotdot && voidinputlock) {
			dotdotdot = true;
		}
	}

	/**
	 * Populate Function Prototype from information attached to a function in the Program DB.
	 * 
	 * @param f is the function to grab prototype from
	 * @param overrideExtrapop is the override value to use for extrapop
	 * @param doOverride is true if the override value should be used
	 */
	void grabFromFunction(Function f, int overrideExtrapop, boolean doOverride) {
		modelname = f.getCallingConventionName();
		PrototypeModel protoModel = f.getCallingConvention();
		if (protoModel == null) {
			protoModel = f.getProgram().getCompilerSpec().getDefaultCallingConvention();
		}
		hasThis = protoModel.hasThisPointer();
		modellock = !f.hasUnknownCallingConventionName();
		injectname = f.getCallFixup();
		voidinputlock = false;
		Parameter returnparam = f.getReturn();
		returntype = returnparam.getDataType();
		returnstorage = returnparam.getVariableStorage();

		SourceType sigSource = f.getSignatureSource();
		if (sigSource != SourceType.DEFAULT) {
			outputlock = DataType.DEFAULT != returntype;
		}
		else {
			outputlock = false;
		}

		if ((returnstorage == null) || (!returnstorage.isValid())) {	// Unassigned or otherwise invalid storage
			outputlock = false;
			returnstorage = VariableStorage.VOID_STORAGE;		// Treat as unlocked void
			returntype = VoidDataType.dataType;
		}
		voidinputlock =
			(f.getSignatureSource() != SourceType.DEFAULT) && f.getParameterCount() == 0;
		dotdotdot = f.hasVarArgs();
		isinline = f.isInline();
		noreturn = f.hasNoReturn() | isNoReturnInjection(f, injectname);
		custom = f.hasCustomVariableStorage();

		// This assumes that the Purge is the value popped from the excluding normal
		// calling conventions.
		// In the spec file extrapop is the overall stack change including the extra purged bytes
		// stackshift is the normal stack change because of a call.
		//
		int purge = f.getStackPurgeSize();
		if (doOverride) {
			extrapop = overrideExtrapop;
		}
		else {
			if (purge == Function.INVALID_STACK_DEPTH_CHANGE ||
				purge == Function.UNKNOWN_STACK_DEPTH_CHANGE) {
				extrapop = protoModel.getExtrapop();
			}
			else {
				extrapop = purge + protoModel.getStackshift();
			}
		}
	}

	/**
	 * check if the code injection does not return
	 */
	private boolean isNoReturnInjection(Function f, String fixupname) {
		if (fixupname == null) {
			return false;
		}
		// if the callfixup has no fallthru, set the noreturn property too
		Program program = f.getProgram();
		InjectPayload callFixup = program.getCompilerSpec()
				.getPcodeInjectLibrary()
				.getPayload(InjectPayload.CALLFIXUP_TYPE, fixupname);
		if (callFixup == null) {
			return false;
		}
		return !callFixup.isFallThru();
	}

	/**
	 * @return the number of defined parameters for this function prototype
	 */
	public int getNumParams() {
		if (localsyms != null) {
			return localsyms.getNumParams();
		}
		return params.length;
	}

	/**
	 * @param i i'th parameter index
	 * @return the i'th HighParam to this function prototype or null
	 * if this prototype is not backed by a LocalSymbolMap
	 */
	public HighSymbol getParam(int i) {
		if (localsyms != null) {
			return localsyms.getParamSymbol(i);
		}
		return null;
	}

	/**
	 * @return parameter definitions if prototype was produced
	 * from a FunctionSignature or null if backed by a 
	 * LocalSymbolMap
	 */
	public ParameterDefinition[] getParameterDefinitions() {
		return params != null ? params.clone() : null;
	}

	/**
	 * @return true if this prototype is backed by a LocalSymbolMap, or 
	 * false if generated from a FunctionSignature.
	 */
	public boolean isBackedByLocalSymbolMap() {
		return localsyms != null;
	}

	/**
	 * @return the return type for the function
	 */
	public DataType getReturnType() {
		return returntype;
	}

	/**
	 * @return the return storage for the function
	 */
	public VariableStorage getReturnStorage() {
		return returnstorage;
	}

	/**
	 * @return the number of extra bytes popped off by this functions return
	 */
	public int getExtraPop() {
		return extrapop;
	}

	/**
	 * @return true if this function has variable arguments
	 */
	public boolean isVarArg() {
		return dotdotdot;
	}

	/**
	 * @return true if this function should be inlined by the decompile
	 */
	public boolean isInline() {
		return isinline;
	}

	/**
	 * @return true if calls to this function do not return
	 */
	public boolean hasNoReturn() {
		return noreturn;
	}

	/**
	 * @return true if this function is a method taking a 'this' pointer as a parameter
	 */
	public boolean hasThisPointer() {
		return hasThis;
	}

	/**
	 * @return true if this function is an (object-oriented) constructor
	 */
	public boolean isConstructor() {
		return isConstruct;
	}

	/**
	 * @return true if this function is an (object-oriented) destructor
	 */
	public boolean isDestructor() {
		return isDestruct;
	}

	/**
	 * @return calling convention model name specific to the associated compiler spec
	 */
	public String getModelName() {
		return modelname;
	}

	/**
	 * Encode this function prototype to a stream.
	 * @param encoder is the stream encoder
	 * @param dtmanage is the DataTypeManager for building type reference tags
	 * @throws IOException for errors in the underlying stream
	 */
	public void encodePrototype(Encoder encoder, PcodeDataTypeManager dtmanage) throws IOException {
		encoder.openElement(ELEM_PROTOTYPE);
		if (extrapop == PrototypeModel.UNKNOWN_EXTRAPOP) {
			encoder.writeString(ATTRIB_EXTRAPOP, "unknown");
		}
		else {
			encoder.writeSignedInteger(ATTRIB_EXTRAPOP, extrapop);
		}
		encoder.writeString(ATTRIB_MODEL, modelname);
		if (modellock) {
			encoder.writeBool(ATTRIB_MODELLOCK, modellock);
		}
		if (dotdotdot) {
			encoder.writeBool(ATTRIB_DOTDOTDOT, dotdotdot);
		}
		if (voidinputlock) {
			encoder.writeBool(ATTRIB_VOIDLOCK, voidinputlock);
		}
		if (isinline) {
			encoder.writeBool(ATTRIB_INLINE, isinline);
		}
		if (noreturn) {
			encoder.writeBool(ATTRIB_NORETURN, noreturn);
		}
		if (custom) {
			encoder.writeBool(ATTRIB_CUSTOM, custom);
		}
		if (isConstruct) {
			encoder.writeBool(ATTRIB_CONSTRUCTOR, isConstruct);
		}
		if (isDestruct) {
			encoder.writeBool(ATTRIB_DESTRUCTOR, isDestruct);
		}
		encoder.openElement(ELEM_RETURNSYM);
		if (outputlock) {
			encoder.writeBool(ATTRIB_TYPELOCK, outputlock);
		}
		int sz = returntype.getLength();
		if (sz < 0) {
			Msg.warn(this, "Bad returntype size");
			sz = 1;
		}
		if ((returnstorage != null) && returnstorage.isValid() &&
			(!returnstorage.isVoidStorage())) {
			int logicalsize = 0;		// Assume logicalsize of return matches datatype size
			if (sz != returnstorage.size()) {	// If the sizes do no match
				logicalsize = sz;		// force the logical size on the varnode
			}
			AddressXML.encode(encoder, returnstorage.getVarnodes(), logicalsize);
		}
		else {
			// Decompiler will use model for storage.  Don't specify where return type is stored
			encoder.openElement(ELEM_ADDR);
			encoder.closeElement(ELEM_ADDR);
		}

		dtmanage.encodeTypeRef(encoder, returntype, sz);
		encoder.closeElement(ELEM_RETURNSYM);
		if (injectname != null) {
			encoder.openElement(ELEM_INJECT);
			encoder.writeString(ATTRIB_CONTENT, injectname);
			encoder.closeElement(ELEM_INJECT);
		}
		if (params != null) {
			encoder.openElement(ELEM_INTERNALLIST);
			for (ParameterDefinition param : params) {
				encoder.openElement(ELEM_PARAM);
				String name = param.getName();
				DataType dt = param.getDataType();
				boolean namelock = false;
				if ((name != null) && (name.length() > 0)) {
					encoder.writeString(ATTRIB_NAME, name);
					namelock = true;
				}
				encoder.writeBool(ATTRIB_TYPELOCK, true);
				encoder.writeBool(ATTRIB_NAMELOCK, namelock);
				encoder.openElement(ELEM_ADDR);
				encoder.closeElement(ELEM_ADDR);	// Blank address
				sz = dt.getLength();
				if (sz < 0) {
					sz = 1;
				}
				dtmanage.encodeTypeRef(encoder, dt, sz);
				encoder.closeElement(ELEM_PARAM);
			}
			encoder.closeElement(ELEM_INTERNALLIST);
		}
		encoder.closeElement(ELEM_PROTOTYPE);
	}

	/**
	 * Decode the function prototype from a {@code <prototype>} element in the stream.
	 * @param decoder is the stream decoder
	 * @param pcodeFactory is used to resolve data-type and address space references
	 * @throws DecoderException for invalid encodings
	 */
	public void decodePrototype(Decoder decoder, PcodeFactory pcodeFactory)
			throws DecoderException {
		PcodeDataTypeManager dtmanage = pcodeFactory.getDataTypeManager();
		int node = decoder.openElement(ELEM_PROTOTYPE);
		modelname = decoder.readString(ATTRIB_MODEL);
		PrototypeModel protoModel =
			dtmanage.getProgram().getCompilerSpec().getCallingConvention(modelname);
		hasThis = (protoModel == null) ? false : protoModel.hasThisPointer();
		extrapop = (int) decoder.readSignedIntegerExpectString(ATTRIB_EXTRAPOP, "unknown",
			PrototypeModel.UNKNOWN_EXTRAPOP);
		modellock = false;
		dotdotdot = false;
		voidinputlock = false;
		isinline = false;
		noreturn = false;
		custom = false;
		isConstruct = false;
		isDestruct = false;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == ATTRIB_MODELLOCK.id()) {
				modellock = decoder.readBool();
			}
			else if (attribId == ATTRIB_DOTDOTDOT.id()) {
				dotdotdot = decoder.readBool();
			}
			else if (attribId == ATTRIB_VOIDLOCK.id()) {
				voidinputlock = decoder.readBool();
			}
			else if (attribId == ATTRIB_INLINE.id()) {
				isinline = decoder.readBool();
			}
			else if (attribId == ATTRIB_NORETURN.id()) {
				noreturn = decoder.readBool();
			}
			else if (attribId == ATTRIB_CUSTOM.id()) {
				custom = decoder.readBool();
			}
			else if (attribId == ATTRIB_CONSTRUCTOR.id()) {
				isConstruct = decoder.readBool();
			}
			else if (attribId == ATTRIB_DESTRUCTOR.id()) {
				isDestruct = decoder.readBool();
			}
		}
		int retel = decoder.openElement(ELEM_RETURNSYM);
		outputlock = false;
		for (;;) {
			int attribId = decoder.getNextAttributeId();
			if (attribId == 0) {
				break;
			}
			if (attribId == ATTRIB_TYPELOCK.id()) {
				outputlock = decoder.readBool();
			}
		}

		int addrel = decoder.openElement(ELEM_ADDR);
		returnstorage = AddressXML.decodeStorageFromAttributes(-1, decoder, pcodeFactory);
		decoder.closeElement(addrel);
		returntype = dtmanage.decodeDataType(decoder);
		decoder.closeElement(retel);

		decoder.closeElementSkipping(node);
	}

}
