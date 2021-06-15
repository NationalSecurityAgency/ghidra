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
package mdemangler;

import java.util.Iterator;

import ghidra.app.util.demangler.*;
import ghidra.program.model.lang.CompilerSpec;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.MDVarArgsType;
import mdemangler.datatype.complex.*;
import mdemangler.datatype.modifier.*;
import mdemangler.functiontype.*;
import mdemangler.naming.*;
import mdemangler.object.*;
import mdemangler.template.MDTemplateNameAndArguments;
import mdemangler.typeinfo.*;

/**
 * A new built-from-scratch class for demangling debug symbols created using
 * Microsoft Visual Studio.
 */
public class MDMangGhidra extends MDMang {

	private DemangledObject objectResult;
	private DemangledDataType dataTypeResult;

	private String mangledSource;
	private String demangledSource;

	public DemangledObject getObject() {
		return objectResult;
	}

	public DemangledDataType getDataType() {
		return dataTypeResult;
	}

	@Override
	public MDParsableItem demangle(String mangledArg, boolean demangleOnlyKnownPatterns)
			throws MDException {
		// TODO: Could possibly just ignore "demangleOnlyKnownpatterns"
		if (demangleOnlyKnownPatterns) {
			if (!(mangledArg.startsWith("?") || mangledArg.startsWith(".") ||
				mangledArg.startsWith("__") || (mangledArg.charAt(0) < 'a') ||
				(mangledArg.charAt(0) > 'z') || (mangledArg.charAt(0) < 'A') ||
				(mangledArg.charAt(0) > 'Z'))) {
				return null;
			}
		}

		this.mangledSource = mangledArg;

		MDParsableItem returnedItem = super.demangle(mangledArg, true);

		this.demangledSource = item.toString();

		objectResult = processItem();
		return returnedItem;
	}

	public DemangledType processNamespace(MDQualifiedName qualifiedName) {
		return processNamespace(qualifiedName.getQualification());
	}

	private DemangledType processNamespace(MDQualification qualification) {
		Iterator<MDQualifier> it = qualification.iterator();
		if (!it.hasNext()) {
			return null;
		}

		MDQualifier qual = it.next();
		DemangledType type = new DemangledType(mangledSource, demangledSource, qual.toString());
		DemangledType parentType = type;
		while (it.hasNext()) {
			qual = it.next();
			DemangledType newType;
			if (qual.isNested()) {
				String subMangled = qual.getNested().getMangled();
				newType = new DemangledType(subMangled, demangledSource, qual.toString());
			}
			else {
				newType = new DemangledType(mangledSource, demangledSource, qual.toString());
			}
			parentType.setNamespace(newType);
			parentType = newType;
		}
		return type;
	}

	private DemangledObject processItem() {
		objectResult = null;
		if (item instanceof MDObjectReserved) {
			objectResult = processObjectReserved((MDObjectReserved) item);
		}
		else if (item instanceof MDObjectCodeView) {
			objectResult = processObjectCPP((MDObjectCPP) item);
			objectResult.setSpecialPrefix(((MDObjectCodeView) item).getPrefix());
		}
		else if (item instanceof MDObjectCPP) { // Base class of MDObjectBracket/MDObjectCodeView.
			objectResult = processObjectCPP((MDObjectCPP) item);
		}
		else if (item instanceof MDObjectC) {
			objectResult = processObjectC((MDObjectC) item);
		}
		else if (item instanceof MDDataType) {
			// TODO: how do we fix this? DemangledDataType extends DemangledType, but not
			// DemangleObject...
			dataTypeResult = processDataType(null, (MDDataType) item);
			// object = getDemangledDataType();
		}
		else if (item instanceof MDTemplateNameAndArguments) {
			objectResult = processTemplate((MDTemplateNameAndArguments) item);
		}
		return objectResult;
	}

	private DemangledObject processObjectReserved(MDObjectReserved objectReserved) {
		DemangledObject object = null;
		if (objectReserved.getClass().equals(MDObjectReserved.class)) {
			//Testing if the class is not a derived class of MDObjectReserved;
			// In other words, is it exactly a MDObjectReserved?
			// If so, then return null, which will allow it to get processed
			// outside of the demangler.
			return null;
		}
		if (objectReserved instanceof MDObjectBracket) {
			MDObjectBracket objectBracket = (MDObjectBracket) objectReserved;
			MDObjectCPP objectCPP = objectBracket.getObjectCPP();
			object = processObjectCPP(objectCPP);
			object.setSpecialPrefix(((MDObjectBracket) item).getPrefix());
		}
		//TODO: put other objectReserved derivative types here and return something that Ghidra can use.
		else {
			object =
				new DemangledUnknown(mangledSource, demangledSource, objectReserved.toString());
		}
		return object;
	}

	private DemangledObject processObjectC(MDObjectC objectC) {
		// We are returning null here because we do not want Ghidra to put up a plate
		//  comment for a standard C symbol.
		//  FUTURE WORK: After discussion, easiest way to deal with this for now (without
		//    exploding work into other demanglers) is to keep the "return null" for now.
		//    The problem is with the DemangledObject making a revision of the
		//    success/failure of demangling by doing a comparison of the input string to
		//    the output string in the applyTo() method.  In a previous encoding, I moved
		//    this logic into other demanglers and set a flag in DemangledObject, that way
		//    my MDMangGhidra could set a flag to succeed when we have a C-language variable
		//    (vs. C++) where the input == output is valid.  We didn't like this pattern.
		//    The better way forward, which will require digging into the other demanglers
		//    further (keeping this for future work), is to throw an exception on failure
		//    instead of returning null as well as pushing this success/failure logic
		//    upstream (where I was attempting to put it) and removing the input == output
		//    test from DemangledObject; an object is only returned upon success and no
		//    rescinding of the success determination is made later.
		return null;
		// Following is the code that we had originally intended to use.
		// DemangledVariable variable = new DemangledVariable(objectC.toString());
		// return variable;
	}

	private DemangledObject processObjectCPP(MDObjectCPP objectCPP) {
		MDTypeInfo typeinfo = objectCPP.getTypeInfo();
		DemangledObject resultObject = null;
		if (typeinfo != null) {
			if (typeinfo instanceof MDVariableInfo) {
				DemangledVariable variable;
				MDVariableInfo variableInfo = (MDVariableInfo) typeinfo;
				MDType mdtype = variableInfo.getMDType();
				DemangledDataType dt = processDataType(null, (MDDataType) mdtype);
				if ("std::nullptr_t".equals(dt.getName())) {
					variable = new DemangledVariable(mangledSource, demangledSource, "");
				}
				else {
					variable =
						new DemangledVariable(mangledSource, demangledSource, objectCPP.getName());
					variable.setNamespace(processNamespace(objectCPP.getQualfication()));
				}
				variable.setDatatype(dt);
				resultObject = variable;
				variable.setConst(variableInfo.isConst());
				variable.setVolatile(variableInfo.isVolatile());
				variable.setPointer64(variableInfo.isPointer64());
				if (variableInfo.isRestrict()) {
					variable.setRestrict();
				}
				if (variableInfo.isUnaligned()) {
					variable.setUnaligned();
				}
				variable.setBasedName(variableInfo.getBasedName());
				if (variableInfo.isMember()) {
					variable.setMemberScope(variableInfo.getMemberScope());
				}
			}
			else if (typeinfo instanceof MDFunctionInfo) {
				if (typeinfo.getSpecialHandlingCode() == 'F') {
					resultObject = new DemangledUnknown(mangledSource, demangledSource, null);
				}
				else {
					DemangledFunction function =
						new DemangledFunction(mangledSource, demangledSource, objectCPP.getName());
					function.setNamespace(processNamespace(objectCPP.getQualfication()));
					resultObject = function;
					objectResult = processFunction((MDFunctionInfo) typeinfo, function);
					// Any other special values to be set?
					if (typeinfo instanceof MDMemberFunctionInfo) {
						if (typeinfo instanceof MDVCall) {
							// Empty for now--placeholder for possible future logic.
						}
						else if (typeinfo instanceof MDVFAdjustor) {
							// Empty for now--placeholder for possible future logic.
						}
						else if (typeinfo instanceof MDVtordisp) {
							// Empty for now--placeholder for possible future logic.
						}
						else if (typeinfo instanceof MDVtordispex) {
							// Empty for now--placeholder for possible future logic.
						}
						else {
							// plain member function
						}
					}
					else {
						// global function
					}
				}
			}
			else if (typeinfo instanceof MDVxTable) { //Includes VFTable, VBTable, and RTTI4
				MDVxTable vxtable = (MDVxTable) typeinfo;
				DemangledVariable variable =
					new DemangledVariable(mangledSource, demangledSource, objectCPP.getName());
				variable.setNamespace(processNamespace(objectCPP.getQualfication()));
				variable.setConst(vxtable.isConst());
				variable.setVolatile(vxtable.isVolatile());
				variable.setPointer64(vxtable.isPointer64());
				resultObject = variable;
				// The following code would be an alternative, depending on whether we get
				//  customer complaints or other fall-out from having created a variable here.
				//resultObject = new DemangledUnknown();
			}
			else if (typeinfo instanceof AbstractMDMetaClass) { //Includes all RTTI, except RTTI4
				DemangledVariable variable =
					new DemangledVariable(mangledSource, demangledSource, objectCPP.getName());
				variable.setNamespace(processNamespace(objectCPP.getQualfication()));
				resultObject = variable;
				// The following code would be an alternative, depending on whether we get
				//  customer complaints or other fall-out from having created a variable here.
				//resultObject = new DemangledUnknown();
			}
			else if (typeinfo instanceof MDGuard) {
				DemangledVariable variable =
					new DemangledVariable(mangledSource, demangledSource, objectCPP.getName());
				variable.setNamespace(processNamespace(objectCPP.getQualfication()));
				resultObject = variable;
				// The following code would be an alternative, depending on whether we get
				//  customer complaints or other fall-out from having created a variable here.
				//resultObject = new DemangledUnknown();
			}
			else {
				// Any others (e.g., case '9')
				DemangledVariable variable =
					new DemangledVariable(mangledSource, demangledSource, objectCPP.getName());
				variable.setNamespace(processNamespace(objectCPP.getQualfication()));
				resultObject = variable;
				// The following code would be an alternative, depending on whether we get
				//  customer complaints or other fall-out from having created a variable here.
				//resultObject = new DemangledUnknown();
			}
			if (typeinfo.isPrivate()) {
				resultObject.setVisibilty("private");
			}
			else if (typeinfo.isProtected()) {
				resultObject.setVisibilty("protected");
			}
			else if (typeinfo.isPublic()) {
				resultObject.setVisibilty("public");
			}
			resultObject.setStatic(typeinfo.isStatic());
			resultObject.setVirtual(typeinfo.isVirtual());
			resultObject.setThunk(typeinfo.isThunk());
			if (typeinfo.isExternC()) {
				resultObject.setSpecialPrefix("extern \"C\"");
			}
		}
		else {
			String baseName = objectCPP.getName();
			if (objectCPP.isString()) {
				MDString mstring = objectCPP.getMDString();
				DemangledString demangledString =
					new DemangledString(mangledSource, demangledSource, mstring.getName(),
						mstring.toString(), mstring.getLength(), mstring.isUnicode());
				resultObject = demangledString;
			}
			else if (baseName.length() != 0) {
				DemangledVariable variable;
				variable = new DemangledVariable(mangledSource, demangledSource, baseName);
				variable.setNamespace(processNamespace(objectCPP.getQualfication()));
				resultObject = variable;
			}
		}
		return resultObject;
		// //Various RTTI types (MDType '8' or '9')
		// DemangledVariable variable =
		// new
		// DemangledVariable(objectCPP.getQualifiedName().getBasicName().toString());
		// variable.setNamespace(processNamespace(objectCPP.getQualifiedName()));
		// return variable;
		// TODO: fill in lots of object.____ items
		// object.setVisibilty(typeinfo.g);
		// object.setConst(isConst);
	}

	// I think that this is a kludge. The mapping of MDTemplateNameAndArguments
	// doesn't match
	// well to the current DemangledObject hierarchy.
	private DemangledVariable processTemplate(MDTemplateNameAndArguments template) {
		DemangledVariable variable =
			new DemangledVariable(mangledSource, demangledSource, template.toString());
		// NO NAMESPACE for high level template: variable.setNamespace(XXX);
		// DemangledTemplate objectTemplate = new DemangledTemplate();
		// DemangledDataType dataType = new DemangledDataType((String) null);
		// MDTemplateArgumentsList args = template.getArgumentsList();
		// if (args != null) {
		// for (int index = 0; index < args.getNumArgs(); index++) {
		// objectTemplate.addParameter(processDataType(null, (MDDataType)
		// args.getArg(index)));
		// }
		// }
		// dataType.setTemplate(objectTemplate);
		// variable.setDatatype(dataType);
		return variable;
	}

	private DemangledFunction processFunction(MDFunctionInfo functionInfo,
			DemangledFunction function) {
		MDFunctionType functionType = (MDFunctionType) functionInfo.getMDType();
		String convention = functionType.getCallingConvention().toString();
		if ("__cdecl".equals(convention) && functionInfo.isMember() && !functionInfo.isStatic()) {
			// TODO: ultimately the presence of a 'this' parareter will not be keyed
			// to the calling convention, but for now we need to force it
			convention = CompilerSpec.CALLING_CONVENTION_thiscall;
		}
		function.setCallingConvention(convention);
		if (functionType.hasReturn() && functionType.getReturnType() != null) {
			MDDataType retType = functionType.getReturnType();
			if (!retType.toString().isEmpty()) {
				function.setReturnType(processDataType(null, retType));
			}
		}
		MDArgumentsList args = functionType.getArgumentsList();
		if (functionType.hasArgs() && args != null) {
			for (int index = 0; index < args.getNumArgs(); index++) {
				function.addParameter(processDataType(null, args.getArg(index)));
			}
		}
		if (functionType.isTypeCast()) {
			function.setTypeCast();
		}
		// function.setVirtual(functionType.isVirtual());
		// function.setStatic(functionType.isStatic());
		// if (functionType.isPrivate()) {
		// function.setVisibilty("private");
		// }
		// else if (functionType.isProtected()) {
		// function.setVisibilty("protected");
		// }
		// else if (functionType.isPublic()) {
		// function.setVisibilty("public");
		// }

		// TODO: fix this kludge. Need to add appropriate suffixes to  DemangledFunction (look
		// at DemangledFunctionPointer?). Missing other possible suffixes from
		// functionType.getCVMod().
		// String suffix = "";
		MDCVMod thisPointerCVMod = functionType.getThisPointerCVMod();
		if (thisPointerCVMod != null) {
			if (thisPointerCVMod.isConst()) {
				function.setTrailingConst();
			}
			if (thisPointerCVMod.isVolatile()) {
				function.setTrailingVolatile();
			}
			if (thisPointerCVMod.isPointer64()) {
				function.setTrailingPointer64();
			}
			if (thisPointerCVMod.isRestricted()) {
				function.setTrailingRestrict();
			}
			if (thisPointerCVMod.isUnaligned()) {
				function.setTrailingUnaligned();
			}
		}
		MDThrowAttribute ta = functionType.getThrowAttribute();
		if (ta != null) {
			function.setThrowAttribute(ta.toString());
		}

		// TODO: fill in lots of function.____ items
		return function;
	}

	private DemangledFunctionPointer processDemangledFunctionPointer(MDPointerType pointerType) {
		DemangledFunctionPointer functionPointer =
			new DemangledFunctionPointer(mangledSource, demangledSource);
		MDFunctionType functionType = (MDFunctionType) pointerType.getReferencedType();
		functionPointer.setCallingConvention(functionType.getCallingConvention().toString());
		functionPointer.setModifier(pointerType.getCVMod().toString());
		if (functionType.hasReturn() && functionType.getReturnType() != null) {
			functionPointer.setReturnType(processDataType(null, functionType.getReturnType()));
		}
		MDArgumentsList args = functionType.getArgumentsList();
		if (functionType.hasArgs() && args != null) {
			for (int index = 0; index < args.getNumArgs(); index++) {
				functionPointer.addParameter(processDataType(null, args.getArg(index)));
			}
		}
		MDCVMod thisPointerCVMod = functionType.getThisPointerCVMod();
		if (thisPointerCVMod != null) {
			if (thisPointerCVMod.isConst()) {
				functionPointer.setConst();
			}
			if (thisPointerCVMod.isVolatile()) {
				functionPointer.setVolatile();
			}
			if (thisPointerCVMod.isPointer64()) {
				functionPointer.setTrailingPointer64();
			}
			if (thisPointerCVMod.isRestricted()) {
				functionPointer.setTrailingRestrict();
			}
			if (thisPointerCVMod.isUnaligned()) {
				functionPointer.setTrailingUnaligned();
			}
		}
		// TODO: fill in lots of functionPointer.____ items
		return functionPointer;
	}

	private DemangledFunctionReference processDemangledFunctionReference(MDModifierType refType) {
		if (!((refType instanceof MDReferenceType) || (refType instanceof MDDataRefRefType))) {
			return null; // Not planning on anything else yet.
		}
		DemangledFunctionReference functionReference =
			new DemangledFunctionReference(mangledSource, demangledSource);
		MDFunctionType functionType = (MDFunctionType) refType.getReferencedType();
		functionReference.setCallingConvention(functionType.getCallingConvention().toString());
		functionReference.setModifier(refType.getCVMod().toString());
		if (functionType.hasReturn() && functionType.getReturnType() != null) {
			functionReference.setReturnType(processDataType(null, functionType.getReturnType()));
		}
		MDArgumentsList args = functionType.getArgumentsList();
		if (functionType.hasArgs() && args != null) {
			for (int index = 0; index < args.getNumArgs(); index++) {
				functionReference.addParameter(processDataType(null, args.getArg(index)));
			}
		}
		// TODO: fill in lots of functionReference.____ items
		return functionReference;
	}

	private DemangledFunctionIndirect processDemangledFunctionIndirect(
			MDFunctionIndirectType functionIndirectType) {
		DemangledFunctionIndirect functionDefinition =
			new DemangledFunctionIndirect(mangledSource, demangledSource);
		MDFunctionType functionType = (MDFunctionType) functionIndirectType.getReferencedType();
		functionDefinition.setCallingConvention(functionType.getCallingConvention().toString());
		functionDefinition.setModifier(functionIndirectType.getCVMod().toString());
		functionDefinition.incrementPointerLevels();
		if (functionType.hasReturn() && functionType.getReturnType() != null) {
			functionDefinition.setReturnType(processDataType(null, functionType.getReturnType()));
		}
		MDArgumentsList args = functionType.getArgumentsList();
		if (functionType.hasArgs() && args != null) {
			for (int index = 0; index < args.getNumArgs(); index++) {
				functionDefinition.addParameter(processDataType(null, args.getArg(index)));
			}
		}
		// TODO: fill in lots of functionIndirect.____ items
		return functionDefinition;
	}

	// The following is/might be a kludge: using DemangledFunctionIndirect to see if it will
	// hold the things that we need; regardless, the follow-on use of the DemangledFunction
	// indirect might be clouded between the real, two underlying types.
	private DemangledFunctionIndirect processDemangledFunctionQuestion(
			MDModifierType modifierType) {
		DemangledFunctionIndirect functionDefinition =
			new DemangledFunctionIndirect(mangledSource, demangledSource);
		MDFunctionType functionType = (MDFunctionType) modifierType.getReferencedType();
		functionDefinition.setCallingConvention(functionType.getCallingConvention().toString());
		functionDefinition.setModifier(modifierType.getCVMod().toString());
		functionDefinition.incrementPointerLevels();
		if (functionType.hasReturn() && functionType.getReturnType() != null) {
			functionDefinition.setReturnType(processDataType(null, functionType.getReturnType()));
		}
		MDArgumentsList args = functionType.getArgumentsList();
		if (functionType.hasArgs() && args != null) {
			for (int index = 0; index < args.getNumArgs(); index++) {
				functionDefinition.addParameter(processDataType(null, args.getArg(index)));
			}
		}
		// TODO: fill in lots of functionIndirect.____ items
		return functionDefinition;
	}

	// Passing "DemangledDataType resultDataType" in is a kludge, as this is done so
	// incrementPointerLevels() can be used, but doing this recursion like this loses all
	// storageClass information from the various nested pointers and such. TODO: need to add
	// a "pointer type" with a contained "referenced data type" to DemangledObject (perhaps
	// PointerObject?)
	private DemangledDataType processDataType(DemangledDataType resultDataType,
			MDDataType datatype) {
		if (resultDataType == null) {
			resultDataType =
				new DemangledDataType(mangledSource, demangledSource, getDataTypeName(datatype));
		}
		if (datatype.isSpecifiedSigned()) {
			// Returns true if default signed or specified signed. TODO: There is no place to
			// capture default signed versus specified signed (i.e., there are three types of
			// char: default signed, specified signed, and unsigned)
			resultDataType.setSigned();
		}
		if (datatype.isUnsigned()) {
			resultDataType.setUnsigned();
		}

		// Bunch of else-ifs for exclusive types
		if (datatype instanceof MDModifierType) {
			MDModifierType modifierType = (MDModifierType) datatype;
			// if (modifierType.isBased()) {
			// resultDataType.set___();
			// modifierType.getCVMod().getBasedName();
			// }
			if (modifierType.isConst()) {
				resultDataType.setConst();
			}
			if (modifierType.isVolatile()) {
				resultDataType.setVolatile();
			}
			if (modifierType.isPointer64()) {
				resultDataType.setPointer64();
			}
			if (modifierType.isRestrict()) {
				resultDataType.setRestrict();
			}
			if (modifierType.isUnaligned()) {
				resultDataType.setUnaligned();
			}
			resultDataType.setBasedName(modifierType.getBasedName());
			// if (modifierType.isMember()) {
			resultDataType.setMemberScope(modifierType.getMemberScope());
			// }
			// TODO: fix. Following is a kludge because DemangledObject has no  DemangledReference
			// with corresponding referencedType.
			if (modifierType instanceof MDArrayBasicType) {
				resultDataType.setArray(1);
				if ((modifierType.getReferencedType() instanceof MDFunctionType)) {
					// MDType ref = modifierType.getReferencedType();
					// TODO: A demangled function reference is needed here.
					// DemangledFunction function = new
					// DemangledFunction(objectCPP.getQualifiedName().getBasicName().toString());
					// function.setNamespace(processNamespace(objectCPP.getQualifiedName()));
					// //resultObject = function;
					// return processFunction(ref, resultDataType);
				}
				else if (modifierType.getReferencedType() instanceof MDDataType) {
					return processDataType(resultDataType,
						(MDDataType) modifierType.getReferencedType());
				}
				else {
					// Empty for now--placeholder for possible future logic.
				}
			}
			else if (modifierType instanceof MDPointerType) {
				if ((modifierType.getReferencedType() instanceof MDFunctionType)) {
					// TODO---------what are we returning... need to work on called routine.
					DemangledFunctionPointer fp =
						processDemangledFunctionPointer((MDPointerType) modifierType);
					// TODO: fix. Following is a kludge because DemangledObject  has no
					// DemangledPointer with corresponding referencedType.
					for (int i = 0; i < resultDataType.getPointerLevels(); i++) {
						fp.incrementPointerLevels();
					}
					if (resultDataType.isConst()) {
						fp.setConst();
					}
					if (resultDataType.isVolatile()) {
						fp.setVolatile();
					}
					if (resultDataType.isPointer64()) {
						fp.setPointer64();
					}
					return fp;
				}
				// modifierType.getArrayString();
				// resultDataType.setArray();
				//Processing the referenced type (for Ghidra, and then setting attributes on it)
				processDataType(resultDataType, (MDDataType) modifierType.getReferencedType());
				resultDataType.incrementPointerLevels();
				if (modifierType.getCVMod().isConst()) {
					resultDataType.setConst();
				}
				if (modifierType.getCVMod().isVolatile()) {
					resultDataType.setVolatile();
				}
				if (modifierType.getCVMod().isPointer64()) {
					resultDataType.setPointer64();
				}
				return resultDataType;
			}
			// TODO: fix. Following is a kludge because DemangledObject has no
			// DemangledReference
			// with corresponding referencedType.
			else if (modifierType instanceof MDReferenceType) {
				// TODO---------what are we returning... need to work on called
				// routine.
				if ((modifierType.getReferencedType() instanceof MDFunctionType)) {
					DemangledFunctionReference fr = processDemangledFunctionReference(modifierType);
					// TODO: fix. Following is a kludge because DemangledObject has no
					// DemangledPointer with corresponding referencedType.
					for (int i = 0; i < resultDataType.getPointerLevels(); i++) {
						fr.incrementPointerLevels();
					}
					if (resultDataType.isConst()) {
						fr.setConst();
					}
					if (resultDataType.isVolatile()) {
						fr.setVolatile();
					}
					if (resultDataType.isPointer64()) {
						fr.setPointer64();
					}
					return fr;
				}
				//Processing the referenced type (for Ghidra, and then setting attributes on it)
				processDataType(resultDataType, (MDDataType) modifierType.getReferencedType());
				resultDataType.setReference(); // Not sure if we should do/use this.
				if (modifierType.getCVMod().isConst()) {
					resultDataType.setConst();
				}
				if (modifierType.getCVMod().isVolatile()) {
					resultDataType.setVolatile();
				}
				if (modifierType.getCVMod().isPointer64()) {
					resultDataType.setPointer64();
				}
				return resultDataType;
			}
			// TODO: fix. Following is a kludge because DemangledObject has no DemangledReference
			// with corresponding referencedType.
			else if (modifierType instanceof MDFunctionIndirectType) {
				// TODO---------what are we returning... need to work on called routine.
				DemangledFunctionIndirect fd =
					processDemangledFunctionIndirect((MDFunctionIndirectType) modifierType);
				for (int i = 0; i < resultDataType.getPointerLevels(); i++) {
					fd.incrementPointerLevels();
				}
				if (resultDataType.isConst()) {
					fd.setConst();
				}
				if (resultDataType.isVolatile()) {
					fd.setVolatile();
				}
				if (resultDataType.isPointer64()) {
					fd.setPointer64();
				}
				return fd;
			}
			else if (modifierType instanceof MDPointerRefDataType) {
				resultDataType.setName(getDataTypeName(datatype));
				// Not sure if this is the correct thing to do for MDPointerRefDataType, but we
				// are just going to assign the referred-to type:
				//Processing the referenced type (for Ghidra, and then setting attributes on it)
				return processDataType(resultDataType,
					(MDDataType) modifierType.getReferencedType());
			}
			else if (modifierType instanceof MDDataReferenceType) {
				// Not sure if this is the correct thing to do for MDDataReferenceType, but we
				// are just going to assign the referred-to type:
				//Processing the referenced type (for Ghidra, and then setting attributes on it)
				processDataType(resultDataType, (MDDataType) modifierType.getReferencedType());
				if (modifierType.getCVMod().isConst()) {
					resultDataType.setConst();
				}
				if (modifierType.getCVMod().isVolatile()) {
					resultDataType.setVolatile();
				}
				return resultDataType;
			}
			else if (modifierType instanceof MDDataRefRefType) {
				if ((modifierType.getReferencedType() instanceof MDFunctionType)) {
					resultDataType.setName(getDataTypeName(datatype));
					// TODO---------what are we returning... need to work on called routine.
					DemangledFunctionReference fr = processDemangledFunctionReference(modifierType);
					// TODO: fix. Following is a kludge because DemangledObject has no
					// DemangledPointer with corresponding referencedType.
					for (int i = 0; i < resultDataType.getPointerLevels(); i++) {
						fr.incrementPointerLevels();
					}
					if (resultDataType.isConst()) {
						fr.setConst();
					}
					if (resultDataType.isVolatile()) {
						fr.setVolatile();
					}
					if (resultDataType.isPointer64()) {
						fr.setPointer64();
					}
					return fr;
				}
				//Processing the referenced type (for Ghidra, and then setting attributes on it)
				processDataType(resultDataType, (MDDataType) modifierType.getReferencedType());
				resultDataType.setReference(); // Not sure if we should do/use this.
				if (modifierType.getCVMod().isConst()) {
					resultDataType.setConst();
				}
				if (modifierType.getCVMod().isVolatile()) {
					resultDataType.setVolatile();
				}
				if (modifierType.getCVMod().isPointer64()) {
					resultDataType.setPointer64();
				}
				return resultDataType;
			}
			else if (modifierType instanceof MDStdNullPtrType) {
				resultDataType.setName(datatype.toString());
			}
			else {
				// not pointer, reference, or array type
				if ((modifierType.getReferencedType() instanceof MDFunctionType)) {
					// TODO---------what are we returning... need to work on called routine.
					DemangledFunctionIndirect fx = processDemangledFunctionQuestion(modifierType);
					// TODO: fix. Following is a kludge because DemangledObject has no
					// DemangledPointer with corresponding referencedType.
					if (resultDataType.isConst()) {
						fx.setConst();
					}
					if (resultDataType.isVolatile()) {
						fx.setVolatile();
					}
					if (resultDataType.isPointer64()) {
						fx.setPointer64();
					}
					return fx;
				}
				// resultDataType.incrementPointerLevels();//Not sure if we should do/use this.
				DemangledDataType dataType =
					processDataType(resultDataType, (MDDataType) modifierType.getReferencedType());
				if (modifierType.getCVMod().isConst()) {
					resultDataType.setConst();
				}
				if (modifierType.getCVMod().isVolatile()) {
					resultDataType.setVolatile();
				}
				if (modifierType.getCVMod().isPointer64()) {
					resultDataType.setPointer64();
				}
				return dataType;
			}
		}
		else if (datatype instanceof MDComplexType) {
			MDComplexType complexType = (MDComplexType) datatype;
			// Hope this is correct... will return "class" or other
			resultDataType.setName(complexType.getNamespace().getName());
			// TODO: setNamespace() wants a "DemangledType" for a namespace.
			// Two problems:
			// 1) we don't have an appropriate method to use
			// 2) not sure DemangledType is appropriate; in MDComplexType we have an
			// MDQualification--not an MDQualifiedName
			resultDataType.setNamespace(processNamespace(complexType.getNamespace()));

			// Bunch of else-ifs for exclusive types
			if (datatype instanceof MDEnumType) {
				resultDataType.setEnum();
				// Put in underlying type (for sizing too).
				MDEnumType enumType = (MDEnumType) datatype;
				resultDataType.setEnumType(enumType.getUnderlyingFullTypeName());
			}
			else if (datatype instanceof MDClassType) {
				resultDataType.setClass();
			}
			else if (datatype instanceof MDStructType) {
				resultDataType.setStruct();
			}
			else if (datatype instanceof MDUnionType) {
				resultDataType.setUnion();
			}
			else if (datatype instanceof MDCoclassType) {
				resultDataType.setCoclass();
			}
			else if (datatype instanceof MDCointerfaceType) {
				resultDataType.setCointerface();
			}
		}
		else if (datatype instanceof MDReferenceType) {
			resultDataType.setReference();
		}
		else if (datatype instanceof MDArrayBasicType) {
			resultDataType.setArray(1);
		}
		else if (datatype instanceof MDVarArgsType) {
			resultDataType.setVarArgs();
		}
		else {
			// MDDataType
			// TODO MDW64Type needs repeated reference type parsing, just as modifier types need
			// them.
			resultDataType.setName(getDataTypeName(datatype));
		}
		// TODO: No place to indicate a general pointer--we can indicate Pointer64
		// TODO: Not sure if anything fits this: resultDataType.setComplex();
		// TODO: resultDataType.setTemplate(); //TODO: Not sure templates are data types
		// according to how MSFT demangles them.
		// TODO: resultDataType.setTemplate(null); //TODO: Not sure templates are data types
		// according to how MSFT demangles them.

		return resultDataType;
	}

	/**
	 * Returns either a formal type name or a representative type name to fill into a
	 * MangledDataType if the formal name is blank
	 * @return the name
	 */
	private String getDataTypeName(MDDataType dataType) {
		String name = dataType.getName();
		if (name.isBlank()) {
			return dataType.toString();
		}
		return name;
	}
}

/******************************************************************************/
/******************************************************************************/
