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
package ghidra.app.util.demangler.microsoft;

import java.util.Iterator;

import ghidra.app.util.demangler.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.symbol.SourceType;
import mdemangler.*;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.MDVarArgsType;
import mdemangler.datatype.complex.*;
import mdemangler.datatype.extended.MDArrayReferencedType;
import mdemangler.datatype.modifier.*;
import mdemangler.functiontype.*;
import mdemangler.naming.*;
import mdemangler.object.*;
import mdemangler.template.MDTemplateNameAndArguments;
import mdemangler.typeinfo.*;

/**
 * A utility class to aid the MicrosoftDemangler
 * <p>
 * The contents of this class that do the processing came from {@link MDMangGhidra}, and will
 * likely go through future rounds of clean-up.  {@link MDMangGhidra}, an extension of
 * {@link MDMang}, might eventually be removed.
 */
public class MicrosoftDemanglerUtil {

	private MicrosoftDemanglerUtil() {
		// purposefully empty
	}

	/**
	 * Method to convert an {@link MDParsableItem} into a {@link DemangledObject}.  This method
	 * is not appropriate for {@link MDDataType} and some other types of {@link MDParsableItem}
	 * @param item the item to convert
	 * @param mangled the original mangled string
	 * @param originalDemangled the original demangled string
	 * @return the {@link DemangledObject} result
	 * @throws DemangledException up issue converting to a {@link DemangledObject}
	 */
	static DemangledObject convertToDemangledObject(MDParsableItem item, String mangled,
			String originalDemangled)
			throws DemangledException {
		return processItem(item, mangled, originalDemangled);
	}

	/**
	 * Method to convert an {@link MDDataType} into a {@link DemangledDataType}.  Demangler
	 * needs to have already run to process the type before calling this method
	 * @param type the type to convert
	 * @param mangled the mangled string
	 * @param originalDemangled the original demangled string
	 * @return the result
	 */
	static DemangledDataType convertToDemangledDataType(MDDataType type, String mangled,
			String originalDemangled) {
		return processDataType(null, type, mangled, originalDemangled);
	}

	//==============================================================================================

	private static Demangled processNamespace(MDQualifiedName qualifiedName, String mangled,
			String demangledSource) {
		return processNamespace(qualifiedName.getQualification(), mangled, demangledSource);
	}

	private static Demangled processNamespace(MDQualification qualification, String mangled,
			String demangledSource) {
		Iterator<MDQualifier> it = qualification.iterator();
		if (!it.hasNext()) {
			return null;
		}

		MDQualifier qual = it.next();
		Demangled type = getDemangled(qual, mangled, demangledSource);
		Demangled current = type;
		// Note that qualifiers come in reverse order, from most refined to root being the last
		while (it.hasNext()) {
			qual = it.next();
			Demangled parent = getDemangled(qual, mangled, demangledSource);
			current.setNamespace(parent);
			current = parent;
		}
		return type;
	}

	private static Demangled getDemangled(MDQualifier qual, String mangled,
			String demangledSource) {
		Demangled demangled = null;
		if (qual.isNested()) {
			String subMangled = qual.getNested().getMangled();
			MDObjectCPP obj = qual.getNested().getNestedObject();
			if (!obj.isHashObject()) {
				MDTypeInfo typeInfo = obj.getTypeInfo();
				MDType type = typeInfo.getMDType();
				if (type instanceof MDDataType dt) {
					demangled = new DemangledType(subMangled, qual.toString(), qual.toString());
				}
				else if (type instanceof MDFunctionType ft) {
					// We currently cannot handle functions as part of a namespace, so we will just
					// treat the demangled function namespace string as a plain namespace.
					//demangled = new DemangledFunction(subMangled, qual.toString(), qual.toString());
					demangled =
						new DemangledNamespaceNode(subMangled, qual.toString(), qual.toString());
				}
			}
			if (demangled == null) {
				demangled =
					new DemangledNamespaceNode(subMangled, qual.toString(), qual.toString());
			}
		}
		else if (qual.isAnon()) {
			String orig = qual.getAnonymousName();
			demangled = new DemangledNamespaceNode(mangled, orig, qual.toString());
		}
		else if (qual.isInterface()) {
			// TODO: need to do better; setting namespace for now
			demangled = new DemangledNamespaceNode(mangled, qual.toString(), qual.toString());
		}
		else if (qual.isNameQ()) {
			// TODO: need to do better; setting namespace for now, as it looks like interface
			demangled = new DemangledNamespaceNode(mangled, qual.toString(), qual.toString());
		}
		else if (qual.isNameC()) {
			// TODO: need to do better; setting type for now, but not processed yet and not sure
			//  what it is
			demangled = new DemangledType(mangled, qual.toString(), qual.toString());
		}
		else if (qual.isLocalNamespace()) {
			String local =
				MDMangUtils.createStandardLocalNamespaceNode(qual.getLocalNamespaceNumber());
			demangled = new DemangledNamespaceNode(mangled, qual.toString(), local);
		}
		else {
			demangled = new DemangledNamespaceNode(mangled, qual.toString(), qual.toString());
		}
		return demangled;
	}

	private static DemangledObject processItem(MDParsableItem item, String mangled,
			String demangledSource) throws DemangledException {
		DemangledObject result = null;
		if (item instanceof MDObjectReserved) {
			result = processObjectReserved((MDObjectReserved) item, mangled, demangledSource);
		}
		else if (item instanceof MDObjectCodeView codeView) {
			result = processObjectCPP(codeView, mangled, demangledSource);
			result.setSpecialPrefix(codeView.getPrefix());
		}
		else if (item instanceof MDObjectCPP objCpp) { // Base class of MDObjectBracket/MDObjectCodeView.
			result = processObjectCPP(objCpp, mangled, demangledSource);
		}
		else if (item instanceof MDObjectC objC) {
			result = processObjectC(objC, mangled, demangledSource);
		}
		else if (item instanceof MDDataType dataType) {
			// TODO: how do we fix this? DemangledDataType extends DemangledType, but not
			// DemangleObject...
			throw new DemangledException("DemangledDataType instead of DemangledObject");
			//result = processDataType(null, dataType, mangled, demangledSource);
			// object = getDemangledDataType();
		}
		else if (item instanceof MDTemplateNameAndArguments templateNameAndArgs) {
			result = processTemplate(templateNameAndArgs, mangled, demangledSource);
		}
		return result;
	}

	private static DemangledObject processObjectReserved(
			MDObjectReserved objectReserved,
			String mangled, String demangledSource) {
		DemangledObject object = null;
		if (objectReserved.getClass().equals(MDObjectReserved.class)) {
			//Testing if the class is not a derived class of MDObjectReserved;
			// In other words, is it exactly a MDObjectReserved?
			// If so, then return null, which will allow it to get processed
			// outside of the demangler.
			return null;
		}
		if (objectReserved instanceof MDObjectBracket objectBracket) {
			MDObjectCPP objectCPP = objectBracket.getObjectCPP();
			object = processObjectCPP(objectCPP, mangled, demangledSource);
			object.setSpecialPrefix(objectBracket.getPrefix());
		}
		//TODO: put other objectReserved derivative types here and return something that Ghidra
		// can use.
		else {
			object =
				new DemangledUnknown(mangled, demangledSource, objectReserved.toString());
		}
		return object;
	}

	private static DemangledObject processObjectC(MDObjectC objectC, String mangled,
			String demangledSource) {
		// 20240905: modification to MDObjectC to processing C-style mangling has been added.
		//  If null is returned here, then we have a standard variable.
		DemangledFunction demangledFunction =
			processObjectCFunction(objectC, mangled, demangledSource);
		if (demangledFunction != null) {
			return demangledFunction;
		}
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

	private static DemangledFunction processObjectCFunction(MDObjectC objectC, String mangled,
			String demangledSource) {
		String callingConvention = objectC.getCallingConvention();
		if (callingConvention == null) {
			// null means it is a standard variable; not a function
			return null;
		}
		DemangledFunction function =
			new DemangledFunction(mangled, demangledSource, objectC.getName());
		// Setting the signature SourceType to DEFAULT allows us to set the calling convention
		// without changing or locking in parameters or return type.
		function.setSignatureSourceType(SourceType.DEFAULT);
		function.setCallingConvention(callingConvention);
		return function;
	}

	private static DemangledObject processObjectCPP(MDObjectCPP objectCPP, String mangled,
			String demangledSource) {
		MDTypeInfo typeinfo = objectCPP.getTypeInfo();
		DemangledObject result = null;
		if (typeinfo != null) {
			if (typeinfo instanceof MDVariableInfo) {
				DemangledVariable variable;
				MDVariableInfo variableInfo = (MDVariableInfo) typeinfo;
				MDType mdtype = variableInfo.getMDType();
				DemangledDataType dt =
					processDataType(null, (MDDataType) mdtype, mangled, demangledSource);
				if ("std::nullptr_t".equals(dt.getName())) {
					variable = new DemangledVariable(mangled, demangledSource, "");
				}
				else {
					variable =
						new DemangledVariable(mangled, demangledSource, objectCPP.getName());
					variable.setNamespace(
						processNamespace(objectCPP.getQualification(), mangled, demangledSource));
				}
				variable.setDatatype(dt);
				result = variable;
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
					result = new DemangledUnknown(mangled, demangledSource, null);
				}
				else {
					DemangledFunction function =
						new DemangledFunction(mangled, demangledSource, objectCPP.getName());
					function.setSignatureSourceType(SourceType.IMPORTED);
					function.setNamespace(
						processNamespace(objectCPP.getQualification(), mangled, demangledSource));
					result = function;
					processFunction((MDFunctionInfo) typeinfo, function, mangled,
						demangledSource);
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
					new DemangledVariable(mangled, demangledSource, objectCPP.getName());
				variable.setNamespace(
					processNamespace(objectCPP.getQualification(), mangled, demangledSource));
				variable.setConst(vxtable.isConst());
				variable.setVolatile(vxtable.isVolatile());
				variable.setPointer64(vxtable.isPointer64());
				result = variable;
				// The following code would be an alternative, depending on whether we get
				//  customer complaints or other fall-out from having created a variable here.
				//resultObject = new DemangledUnknown();
			}
			else if (typeinfo instanceof AbstractMDMetaClass) { //Includes all RTTI, except RTTI4
				DemangledVariable variable =
					new DemangledVariable(mangled, demangledSource, objectCPP.getName());
				variable.setNamespace(
					processNamespace(objectCPP.getQualification(), mangled, demangledSource));
				result = variable;
				// The following code would be an alternative, depending on whether we get
				//  customer complaints or other fall-out from having created a variable here.
				//resultObject = new DemangledUnknown();
			}
			else if (typeinfo instanceof MDGuard) {
				DemangledVariable variable =
					new DemangledVariable(mangled, demangledSource, objectCPP.getName());
				variable.setNamespace(
					processNamespace(objectCPP.getQualification(), mangled, demangledSource));
				result = variable;
				// The following code would be an alternative, depending on whether we get
				//  customer complaints or other fall-out from having created a variable here.
				//resultObject = new DemangledUnknown();
			}
			else {
				// Any others (e.g., case '9')
				DemangledVariable variable =
					new DemangledVariable(mangled, demangledSource, objectCPP.getName());
				variable.setNamespace(
					processNamespace(objectCPP.getQualification(), mangled, demangledSource));
				result = variable;
				// The following code would be an alternative, depending on whether we get
				//  customer complaints or other fall-out from having created a variable here.
				//resultObject = new DemangledUnknown();
			}
			if (typeinfo.isPrivate()) {
				result.setVisibilty("private");
			}
			else if (typeinfo.isProtected()) {
				result.setVisibilty("protected");
			}
			else if (typeinfo.isPublic()) {
				result.setVisibilty("public");
			}
			result.setStatic(typeinfo.isStatic());
			result.setVirtual(typeinfo.isVirtual());
			result.setThunk(typeinfo.isThunk());
			if (typeinfo.isExternC()) {
				result.setSpecialPrefix("extern \"C\"");
			}
		}
		else {
			String baseName = objectCPP.getName();
			if (objectCPP.isString()) {
				MDString mstring = objectCPP.getMDString();
				DemangledString demangledString =
					new DemangledString(mangled, demangledSource, mstring.getName(),
						mstring.toString(), mstring.getLength(), mstring.isUnicode());
				result = demangledString;
			}
			else if (baseName.length() != 0) {
				DemangledVariable variable;
				variable = new DemangledVariable(mangled, demangledSource, baseName);
				variable.setNamespace(
					processNamespace(objectCPP.getQualification(), mangled, demangledSource));
				result = variable;
			}
		}
		return result;
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
	private static DemangledVariable processTemplate(MDTemplateNameAndArguments template,
			String mangled, String demangledSource) {
		DemangledVariable variable =
			new DemangledVariable(mangled, demangledSource, template.toString());
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

	private static DemangledFunction processFunction(MDFunctionInfo functionInfo,
			DemangledFunction function, String mangled, String demangledSource) {
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
				function.setReturnType(processDataType(null, retType, mangled, demangledSource));
			}
		}
		MDArgumentsList args = functionType.getArgumentsList();
		if (functionType.hasArgs() && args != null) {
			for (int index = 0; index < args.getNumArgs(); index++) {
				function.addParameter(
					new DemangledParameter(
						processDataType(null, args.getArg(index), mangled, demangledSource)));
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

	private static DemangledFunctionPointer processDemangledFunctionPointer(
			MDPointerType pointerType, String mangled, String demangledSource) {
		DemangledFunctionPointer functionPointer =
			new DemangledFunctionPointer(mangled, demangledSource);
		MDFunctionType functionType = (MDFunctionType) pointerType.getReferencedType();
		functionPointer.setCallingConvention(functionType.getCallingConvention().toString());
		functionPointer.setModifier(pointerType.getCVMod().toString());
		if (functionType.hasReturn() && functionType.getReturnType() != null) {
			functionPointer.setReturnType(
				processDataType(null, functionType.getReturnType(), mangled, demangledSource));
		}
		MDArgumentsList args = functionType.getArgumentsList();
		if (functionType.hasArgs() && args != null) {
			for (int index = 0; index < args.getNumArgs(); index++) {
				functionPointer.addParameter(
					processDataType(null, args.getArg(index), mangled, demangledSource));
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

	private static DemangledFunctionReference processDemangledFunctionReference(
			MDModifierType refType, String mangled, String demangledSource) {
		if (!((refType instanceof MDReferenceType) ||
			(refType instanceof MDDataRightReferenceType))) {
			return null; // Not planning on anything else yet.
		}
		DemangledFunctionReference functionReference =
			new DemangledFunctionReference(mangled, demangledSource);
		MDFunctionType functionType = (MDFunctionType) refType.getReferencedType();
		functionReference.setCallingConvention(functionType.getCallingConvention().toString());
		functionReference.setModifier(refType.getCVMod().toString());
		if (functionType.hasReturn() && functionType.getReturnType() != null) {
			functionReference.setReturnType(
				processDataType(null, functionType.getReturnType(), mangled, demangledSource));
		}
		MDArgumentsList args = functionType.getArgumentsList();
		if (functionType.hasArgs() && args != null) {
			for (int index = 0; index < args.getNumArgs(); index++) {
				functionReference.addParameter(
					processDataType(null, args.getArg(index), mangled, demangledSource));
			}
		}
		// TODO: fill in lots of functionReference.____ items
		return functionReference;
	}

	private static DemangledFunctionIndirect processDemangledFunctionIndirect(
			MDFunctionIndirectType functionIndirectType, String mangled, String demangledSource) {
		DemangledFunctionIndirect functionDefinition =
			new DemangledFunctionIndirect(mangled, demangledSource);
		MDFunctionType functionType = (MDFunctionType) functionIndirectType.getReferencedType();
		functionDefinition.setCallingConvention(functionType.getCallingConvention().toString());
		functionDefinition.setModifier(functionIndirectType.getCVMod().toString());
		functionDefinition.incrementPointerLevels();
		if (functionType.hasReturn() && functionType.getReturnType() != null) {
			functionDefinition.setReturnType(
				processDataType(null, functionType.getReturnType(), mangled, demangledSource));
		}
		MDArgumentsList args = functionType.getArgumentsList();
		if (functionType.hasArgs() && args != null) {
			for (int index = 0; index < args.getNumArgs(); index++) {
				functionDefinition.addParameter(
					processDataType(null, args.getArg(index), mangled, demangledSource));
			}
		}
		// TODO: fill in lots of functionIndirect.____ items
		return functionDefinition;
	}

	// The following is/might be a kludge: using DemangledFunctionIndirect to see if it will
	// hold the things that we need; regardless, the follow-on use of the DemangledFunction
	// indirect might be clouded between the real, two underlying types.
	private static DemangledFunctionIndirect processDemangledFunctionQuestion(
			MDModifierType modifierType, String mangled, String demangledSource) {
		DemangledFunctionIndirect functionDefinition =
			new DemangledFunctionIndirect(mangled, demangledSource);
		MDFunctionType functionType = (MDFunctionType) modifierType.getReferencedType();
		functionDefinition.setCallingConvention(functionType.getCallingConvention().toString());
		functionDefinition.setModifier(modifierType.getCVMod().toString());
		functionDefinition.incrementPointerLevels();
		if (functionType.hasReturn() && functionType.getReturnType() != null) {
			functionDefinition.setReturnType(
				processDataType(null, functionType.getReturnType(), mangled, demangledSource));
		}
		MDArgumentsList args = functionType.getArgumentsList();
		if (functionType.hasArgs() && args != null) {
			for (int index = 0; index < args.getNumArgs(); index++) {
				functionDefinition.addParameter(
					processDataType(null, args.getArg(index), mangled, demangledSource));
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
	private static DemangledDataType processDataType(DemangledDataType resultDataType,
			MDDataType datatype, String mangled, String demangledSource) {
		if (resultDataType == null) {
			resultDataType =
				new DemangledDataType(mangled, demangledSource, getDataTypeName(datatype));
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
						(MDDataType) modifierType.getReferencedType(), mangled, demangledSource);
				}
				else {
					// Empty for now--placeholder for possible future logic.
				}
			}
			else if (modifierType instanceof MDPointerType) {
				if ((modifierType.getReferencedType() instanceof MDFunctionType)) {
					// TODO---------what are we returning... need to work on called routine.
					DemangledFunctionPointer fp =
						processDemangledFunctionPointer((MDPointerType) modifierType, mangled,
							demangledSource);
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
				DemangledDataType newResult =
					processDataType(resultDataType, (MDDataType) modifierType.getReferencedType(),
						mangled, demangledSource);
				newResult.incrementPointerLevels();
				if (modifierType.getCVMod().isConst()) {
					newResult.setConst();
				}
				if (modifierType.getCVMod().isVolatile()) {
					newResult.setVolatile();
				}
				if (modifierType.getCVMod().isPointer64()) {
					newResult.setPointer64();
				}
				return newResult;
			}
			// TODO: fix. Following is a kludge because DemangledObject has no
			// DemangledReference
			// with corresponding referencedType.
			else if (modifierType instanceof MDReferenceType) {
				// TODO---------what are we returning... need to work on called
				// routine.
				if ((modifierType.getReferencedType() instanceof MDFunctionType)) {
					DemangledFunctionReference fr =
						processDemangledFunctionReference(modifierType, mangled, demangledSource);
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
				DemangledDataType newResult =
					processDataType(resultDataType, (MDDataType) modifierType.getReferencedType(),
						mangled, demangledSource);
				newResult.setLValueReference();
				if (modifierType.getCVMod().isConst()) {
					newResult.setConst();
				}
				if (modifierType.getCVMod().isVolatile()) {
					newResult.setVolatile();
				}
				if (modifierType.getCVMod().isPointer64()) {
					newResult.setPointer64();
				}
				return newResult;
			}
			// TODO: fix. Following is a kludge because DemangledObject has no DemangledReference
			// with corresponding referencedType.
			else if (modifierType instanceof MDFunctionIndirectType) {
				// TODO---------what are we returning... need to work on called routine.
				DemangledFunctionIndirect fd =
					processDemangledFunctionIndirect((MDFunctionIndirectType) modifierType, mangled,
						demangledSource);
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
					(MDDataType) modifierType.getReferencedType(), mangled, demangledSource);
			}
			else if (modifierType instanceof MDDataReferenceType) {
				// Not sure if this is the correct thing to do for MDDataReferenceType, but we
				// are just going to assign the referred-to type:
				//Processing the referenced type (for Ghidra, and then setting attributes on it)
				processDataType(resultDataType, (MDDataType) modifierType.getReferencedType(),
					mangled, demangledSource);
				if (modifierType.getCVMod().isConst()) {
					resultDataType.setConst();
				}
				if (modifierType.getCVMod().isVolatile()) {
					resultDataType.setVolatile();
				}
				return resultDataType;
			}
			else if (modifierType instanceof MDDataRightReferenceType) {
				if ((modifierType.getReferencedType() instanceof MDFunctionType)) {
					resultDataType.setName(getDataTypeName(datatype));
					// TODO---------what are we returning... need to work on called routine.
					DemangledFunctionReference fr =
						processDemangledFunctionReference(modifierType, mangled, demangledSource);
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
				processDataType(resultDataType, (MDDataType) modifierType.getReferencedType(),
					mangled, demangledSource);
				resultDataType.setRValueReference();
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
			else {
				// not pointer, reference, or array type
				if ((modifierType.getReferencedType() instanceof MDFunctionType)) {
					// TODO---------what are we returning... need to work on called routine.
					DemangledFunctionIndirect fx =
						processDemangledFunctionQuestion(modifierType, mangled, demangledSource);
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
					processDataType(resultDataType, (MDDataType) modifierType.getReferencedType(),
						mangled, demangledSource);
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
			resultDataType.setNamespace(
				processNamespace(complexType.getNamespace(), mangled, demangledSource));

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
			resultDataType.setLValueReference();
		}
		else if (datatype instanceof MDArrayBasicType) {
			resultDataType.setArray(1);
		}
		else if (datatype instanceof MDVarArgsType) {
			resultDataType.setVarArgs();
		}
		else if (datatype instanceof MDArrayReferencedType arrRefType) {
			return processDataType(resultDataType, arrRefType.getReferencedType(), mangled,
				demangledSource);
		}
		else if (datatype instanceof MDStdNullPtrType) {
			resultDataType.setName(datatype.toString());
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
	private static String getDataTypeName(MDDataType dataType) {
		String name = dataType.getName();
		if (!name.isBlank()) {
			return name;
		}
		name = dataType.getTypeName();
		if (!name.isBlank()) {
			return name;
		}
		return dataType.toString();
	}

}
