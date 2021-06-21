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
package ghidra.app.util.pdb.pdbapplicator;

import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.SymbolPathParser;
import ghidra.app.util.bin.format.pdb.DefaultCompositeMember;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/*
 * Non java-doc:
 * Some truths:
 *   For AbstractMsCompositeType: do not count on "count" to be zero when MsProperty is forward
 *     reference (we have seen example of count==0 and not forward reference, though the majority
 *     of the time the two go hand-in-hand.  When these did not equate, it might have been when
 *     there was no need for a forward reference and possibly only one definition--this would
 *     require a closer look).
 */
/**
 * Applier for {@link AbstractCompositeMsType} types.
 */
public class CompositeTypeApplier extends AbstractComplexTypeApplier {

	// DO NOT DELETE.  Might eliminate one path or might make an analyzer option.
	private static boolean applyBaseClasses = true;
	//private static boolean applyBaseClasses = false;

	private CppCompositeType classType;

//	private final static DataType NO_TYPE_DATATYPE =
//		new TypedefDataType("<NoType>", Undefined1DataType.dataType);
//
	private Map<Integer, String> componentComments;

	private List<DefaultPdbUniversalMember> members;

	/**
	 * Constructor for composite type applier, for transforming a composite into a
	 * Ghidra DataType.
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @param msType {@link AbstractCompositeMsType} to process.
	 */
	public CompositeTypeApplier(PdbApplicator applicator, AbstractCompositeMsType msType) {
		super(applicator, msType);
		String fullPathName = msType.getName();
		symbolPath = new SymbolPath(SymbolPathParser.parse(fullPathName));
	}

	CppCompositeType getClassType() {
		if (definitionApplier != null) {
			return ((CompositeTypeApplier) definitionApplier).getClassTypeInternal();
		}
		return classType;
	}

	CppCompositeType getClassTypeInternal() {
		return classType;
	}

	List<DefaultPdbUniversalMember> getMembers() {
		return members;
	}

	// Mapping of forwardReference/definition must be done prior to this call.
	private void getOrCreateComposite() {
		if (dataType != null) {
			return;
		}

		AbstractComplexTypeApplier alternativeApplier = getAlternativeTypeApplier();
		if (alternativeApplier != null) {
			dataType = alternativeApplier.getDataTypeInternal();
			classType = ((CompositeTypeApplier) alternativeApplier).getClassTypeInternal();
		}
		if (dataType != null) {
			return;
		}

		dataType = createEmptyComposite((AbstractCompositeMsType) msType);
		String mangledName = ((AbstractCompositeMsType) msType).getMangledName();
		classType = new CppCompositeType((Composite) dataType, mangledName);
		classType.setName(getName());
		classType.setSize(PdbApplicator.bigIntegerToInt(applicator, getSize()));
		if (msType instanceof AbstractClassMsType) {
			classType.setClass();
		}
		else if (msType instanceof AbstractStructureMsType) {
			classType.setStruct();
		}
		else if (msType instanceof AbstractUnionMsType) {
			classType.setUnion();
		}
		classType.setFinal(isFinal());

	}

	@Override
	void apply() throws PdbException, CancelledException {

		getOrCreateComposite();

		Composite composite = (Composite) dataType;

		AbstractCompositeMsType type = (AbstractCompositeMsType) msType;
		MsProperty property = type.getMsProperty();
		if (property.isForwardReference() && definitionApplier != null) {
			return;
		}
		if (!(composite instanceof CompositeDataTypeImpl)) {
			return; // A resolved version exists (multiple definitions).
		}
		applyOrDeferForDependencies();
	}

	@Override
	void resolve() {

		// NOTE: Until we know better we do not want to explicitly
		// apply nested composite datatypes and allow them to be 
		// created as-needed (e.g., function definition).  This is
		// done to minimize duplication of anonymous/unnamed nested
		// composites since the parent composite reconstruction performed
		// by DefaultCompositeMember will generate such nested composites.

		// TODO: Dome some output comparisons with and without the !isNested()
		// test which is intended to ignore nested anonymous composites.

		if (!isForwardReference() && !isNested()) {
			super.resolve();
		}
	}

	private void applyOrDeferForDependencies() throws PdbException, CancelledException {
		AbstractCompositeMsType type = (AbstractCompositeMsType) msType;
		MsProperty property = type.getMsProperty();
		if (property.isForwardReference() && definitionApplier != null) {
			return;
		}

		// Add self
		applicator.addApplierDependency(this);

		// Add any dependees: base classes and members
		FieldListTypeApplier fieldListApplier = FieldListTypeApplier.getFieldListApplierSpecial(
			applicator, type.getFieldDescriptorListRecordNumber());

		// Currently do not need this dependency, as we currently do not need any contents
		// of the base class for filling in this class
		for (MsTypeApplier baseApplierIterated : fieldListApplier.getBaseClassList()) {
			if (baseApplierIterated instanceof BaseClassTypeApplier) {
				BaseClassTypeApplier baseTypeApplier = (BaseClassTypeApplier) baseApplierIterated;
				MsTypeApplier applier =
					applicator.getTypeApplier(baseTypeApplier.getBaseClassRecordNumber());
				if (applier instanceof CompositeTypeApplier) {
					CompositeTypeApplier dependencyApplier =
						((CompositeTypeApplier) applier).getDependencyApplier();
					applicator.addApplierDependency(this, dependencyApplier);
//					CompositeTypeApplier defApplier =
//						((CompositeTypeApplier) applier).getDefinitionApplier();
//					if (defApplier != null) {
//						applicator.addApplierDependency(this, defApplier);
//					}
//					else {
//						applicator.addApplierDependency(this, applier);
//					}
					setDeferred();
				}
			}
		}
		for (MsTypeApplier memberTypeApplierIterated : fieldListApplier.getMemberList()) {
			applicator.checkCanceled();
			if (memberTypeApplierIterated instanceof MemberTypeApplier) {
				MemberTypeApplier memberTypeApplier = (MemberTypeApplier) memberTypeApplierIterated;
				MsTypeApplier fieldApplier = memberTypeApplier.getFieldTypeApplier();
				recurseAddDependency(fieldApplier);
			}
//			if (memberTypeApplierIterated instanceof NestedTypeApplier) {
//				recurseAddDependency(memberTypeApplierIterated);
//			}
			else if (memberTypeApplierIterated instanceof VirtualFunctionTablePointerTypeApplier) {
				applicator.addApplierDependency(this, memberTypeApplierIterated);
			}
		}
		if (!isDeferred()) {
			applyInternal();
		}
	}

	private void recurseAddDependency(MsTypeApplier dependee)
			throws CancelledException, PdbException {
		// TODO: evaluate this and make changes... this work might be being taken care of in
		//  ModifierTypeApplier
		if (dependee instanceof ModifierTypeApplier) {
			ModifierTypeApplier modifierApplier = (ModifierTypeApplier) dependee;
			recurseAddDependency(modifierApplier.getModifiedTypeApplier());
		}
		else if (dependee instanceof CompositeTypeApplier) {
			CompositeTypeApplier defApplier =
				((CompositeTypeApplier) dependee).getDefinitionApplier(CompositeTypeApplier.class);
			if (defApplier != null) {
				applicator.addApplierDependency(this, defApplier);
			}
			else {
				applicator.addApplierDependency(this, dependee);
			}
			setDeferred();
		}
		// TODO: evaluate this and make changes... this work might be being taken care of in
		//  ArrayTypeApplier
		else if (dependee instanceof ArrayTypeApplier) {
			applicator.addApplierDependency(this, dependee);
			setDeferred();
		}
//		else if (dependee instanceof NestedTypeApplier) {
//			NestedTypeApplier nestedTypeApplier = (NestedTypeApplier) dependee;
//			AbstractMsTypeApplier nestedDefinitionApplier =
//				nestedTypeApplier.getNestedTypeDefinitionApplier();
//			// Need to make sure that "this" class id dependent on all elements composing the
//			// nested definition, but we need to create the nested definition during the
//			// creation of this class. (NestedTypeApplier and NestedTypeMsType do not really
//			// have their own RecordNumber).
//			applicator.addApplierDependency(this, nestedDefinitionApplier);
//			setDeferred();
//		}
		else if (dependee instanceof BitfieldTypeApplier) {
			RecordNumber recNum =
				((AbstractBitfieldMsType) ((BitfieldTypeApplier) dependee).getMsType()).getElementRecordNumber();
			MsTypeApplier underlyingApplier = applicator.getTypeApplier(recNum);
			if (underlyingApplier instanceof EnumTypeApplier) {
				applicator.addApplierDependency(this, underlyingApplier);
				setDeferred();
			}
		}
		//We are assuming that bitfields on typedefs will not be defined.
	}

	private void applyInternal() throws CancelledException, PdbException {

		if (isApplied()) {
			return;
		}
		Composite composite = (Composite) dataType;

		AbstractCompositeMsType type = (AbstractCompositeMsType) msType;

		boolean applyCpp = applyBaseClasses;
		if (type instanceof AbstractUnionMsType) {
			applyCpp = false;
			if (hasBaseClasses()) {
				pdbLogAndInfoMessage(this,
					"Unexpected base classes for union type: " + type.getName());
			}
		}
		if (applyCpp) {
			applyCpp(composite, type);
		}
		else {
			applyBasic(composite, type);
		}
		setApplied();
	}

	//==============================================================================================
	private void applyBasic(Composite composite, AbstractCompositeMsType type)
			throws CancelledException, PdbException {

		//boolean isClass = (type instanceof AbstractClassMsType || actsLikeClass(applicator, type));
		boolean isClass = (type instanceof AbstractClassMsType);

		int size = getSizeInt();

		// Fill in composite definition details.
		FieldListTypeApplier fieldListApplier = FieldListTypeApplier.getFieldListApplierSpecial(
			applicator, type.getFieldDescriptorListRecordNumber());

		clearComponents(composite);
		members = new ArrayList<>();
		componentComments = new HashMap<>();

		addMembers(composite, fieldListApplier);

		if (!DefaultCompositeMember.applyDataTypeMembers(composite, isClass, size, members,
			msg -> reconstructionWarn(msg), applicator.getCancelOnlyWrappingMonitor())) {
			clearComponents(composite);
		}

		setComponentComments(composite);
	}

	private void setComponentComments(Composite composite) {
		if (composite instanceof Structure) {
			Structure structure = (Structure) composite;
			for (Map.Entry<Integer, String> entry : componentComments.entrySet()) {
				DataTypeComponent component = structure.getComponentAt(entry.getKey());
				if (component == null) {
					pdbLogAndInfoMessage(this, "Could not set comment for 'missing' componenent " +
						entry.getKey() + " for: " + structure.getName());
					return;
				}
				component.setComment(entry.getValue());
			}
		}
	}

	//==============================================================================================
	private void applyCpp(Composite composite, AbstractCompositeMsType type)
			throws PdbException, CancelledException {
		// Fill in composite definition details.
		FieldListTypeApplier fieldListApplier = FieldListTypeApplier.getFieldListApplierSpecial(
			applicator, type.getFieldDescriptorListRecordNumber());
		clearComponents(composite);
		members = new ArrayList<>(); // TODO: temporary for old "basic" mechanism
		componentComments = new HashMap<>(); // TODO: temporary for old "basic" mechanism

		addClassTypeBaseClasses(composite, fieldListApplier);
		addMembers(composite, fieldListApplier);

		if (!classType.validate()) {
			// TODO: Investigate.  We should do this check for some classes somewhere.  Should
			// we do it here.  Set breakpoint here to investigate.
		}
		classType.createLayout(applicator.getPdbApplicatorOptions().getCompositeLayout(),
			applicator.getVbtManager(), applicator.getCancelOnlyWrappingMonitor());
	}

	//==============================================================================================
	private void reconstructionWarn(String msg) {
		//TODO: if statement/contents temporary
		if (msg.contains("failed to align") && hasHiddenComponents()) {
			msg = msg.replaceFirst("PDB", "PDB CLASS");
		}
		Msg.warn(this, msg);
	}

	//==============================================================================================
	@Override
	void deferredApply() throws PdbException, CancelledException {
		if (isDeferred()) {
			applyInternal();
		}
	}

	//==============================================================================================
	//==============================================================================================
	@Override
	CompositeTypeApplier getDependencyApplier() {
		if (definitionApplier != null && definitionApplier instanceof CompositeTypeApplier) {
			return (CompositeTypeApplier) definitionApplier;
		}
		return this;
	}

	String getName() {
		return getMsType().getName();
	}

	@Override
	DataType getDataType() {
		if (resolved) {
			return resolvedDataType;
		}
		getOrCreateComposite();
		return dataType;
	}

	@Override
	DataType getCycleBreakType() {
		if (isForwardReference() && definitionApplier != null && definitionApplier.isApplied()) {
			return definitionApplier.getDataType();
		}
		return dataType;
	}

	boolean hasUniqueName() {
		return ((AbstractCompositeMsType) msType).getMsProperty().hasUniqueName();
	}

	@Override
	BigInteger getSize() {
		return ((AbstractCompositeMsType) getDependencyApplier().getMsType()).getSize();
	}

	// TODO: 
	// Taken from PdbUtil without change.  Would have had to change access on class PdbUtil and
	//  this ensureSize method to public to make it accessible.  Can revert to using PdbUtil
	//  once we move this new module from Contrib to Features/PDB.
	final static void clearComponents(Composite composite) {
		if (composite instanceof Structure) {
			((Structure) composite).deleteAll();
		}
		else {
			while (composite.getNumComponents() > 0) {
				composite.delete(0);
			}
		}
	}

	private Composite createEmptyComposite(AbstractCompositeMsType type) {

		SymbolPath fixedPath = getFixedSymbolPath();
		CategoryPath categoryPath = applicator.getCategory(fixedPath.getParent());

		Composite composite;
		if (type instanceof AbstractClassMsType) {
			applicator.predefineClass(fixedPath);
			composite = new StructureDataType(categoryPath, fixedPath.getName(), 0,
				applicator.getDataTypeManager());
		}
		else if (type instanceof AbstractStructureMsType) {
			composite = new StructureDataType(categoryPath, fixedPath.getName(), 0,
				applicator.getDataTypeManager());
		}
		else if (type instanceof AbstractUnionMsType) {
			composite = new UnionDataType(categoryPath, fixedPath.getName(),
				applicator.getDataTypeManager());
		}
		else { // InterfaceMsType
			String message = "Unsupported datatype (" + type.getClass().getSimpleName() + "): " +
				fixedPath.getPath();
			applicator.appendLogMsg(message);
			return null;
		}
		return composite;
	}

	private boolean hasBaseClasses() {
		AbstractCompositeMsType defType;
		if (definitionApplier == null) {
			if (isForwardReference()) {
				return false;
			}
			defType = (AbstractCompositeMsType) msType;
		}
		else {
			defType = (AbstractCompositeMsType) definitionApplier.getMsType();
		}
		MsTypeApplier applier =
			applicator.getTypeApplier(defType.getFieldDescriptorListRecordNumber());
		if (!(applier instanceof FieldListTypeApplier)) {
			return false;
		}
		FieldListTypeApplier fieldListApplier = (FieldListTypeApplier) applier;
		AbstractFieldListMsType fieldListType =
			((AbstractFieldListMsType) fieldListApplier.getMsType());
		if (fieldListType.getBaseClassList().size() != 0) {
			return true;
		}
		return (fieldListType.getBaseClassList().size() != 0);
	}

	private boolean hasHiddenComponents() {
		AbstractCompositeMsType defType;
		if (definitionApplier == null) {
			if (isForwardReference()) {
				return false;
			}
			defType = (AbstractCompositeMsType) msType;
		}
		else {
			defType = (AbstractCompositeMsType) definitionApplier.getMsType();
		}

		// Note: if a "class" only has structure fields--does not have member functions, base
		//  class, virtual inheritance, etc., then it acts like a structure, meaning that there
		//  should be no extra fields for pvft, pvbt, base and virtual class components.
		//  So... it might not be good to return "true" for just checking if the type is an
		//  instanceof AbstractClassMsType.

		MsTypeApplier applier =
			applicator.getTypeApplier(defType.getFieldDescriptorListRecordNumber());
		if (!(applier instanceof FieldListTypeApplier)) {
			return false;
		}
		FieldListTypeApplier fieldListApplier = (FieldListTypeApplier) applier;
		AbstractFieldListMsType fieldListType =
			((AbstractFieldListMsType) fieldListApplier.getMsType());

		return (fieldListType.getMethodList().size() != 0 ||
			fieldListType.getBaseClassList().size() != 0);
	}

	private void addClassTypeBaseClasses(Composite composite, FieldListTypeApplier fieldListApplier)
			throws PdbException {

		AbstractCompositeMsType type = (AbstractCompositeMsType) msType;

		for (MsTypeApplier baseApplierIterated : fieldListApplier.getBaseClassList()) {
			if (!(baseApplierIterated instanceof BaseClassTypeApplier)) {
				applicator.appendLogMsg(baseApplierIterated.getClass().getSimpleName() +
					" seen where BaseClassTypeApplier expected for " + type.getName());
				continue;
			}
			BaseClassTypeApplier baseTypeApplier = (BaseClassTypeApplier) baseApplierIterated;
			MsTypeApplier baseClassTypeApplier =
				applicator.getTypeApplier(baseTypeApplier.getBaseClassRecordNumber());
			if (!(baseClassTypeApplier instanceof CompositeTypeApplier)) {
				applicator.appendLogMsg(baseApplierIterated.getClass().getSimpleName() +
					" seen where CompositeTypeApplier expected for " + type.getName());
				continue;
			}

			AbstractMsType baseClassMsType = baseTypeApplier.getMsType();
			if (baseClassMsType instanceof AbstractBaseClassMsType) {
				applyDirectBaseClass((AbstractBaseClassMsType) baseClassMsType);
			}
			else if (baseClassMsType instanceof AbstractVirtualBaseClassMsType) {
				applyDirectVirtualBaseClass((AbstractVirtualBaseClassMsType) baseClassMsType);
			}
			else if (baseClassMsType instanceof AbstractIndirectVirtualBaseClassMsType) {
				applyIndirectVirtualBaseClass(
					(AbstractIndirectVirtualBaseClassMsType) baseClassMsType);
			}
			else {
				throw new AssertException(
					"Unknown base class type: " + baseClassMsType.getClass().getSimpleName());
			}
		}
	}

	private void applyDirectBaseClass(AbstractBaseClassMsType base) throws PdbException {
		CppCompositeType underlyingClassType =
			getUnderlyingClassType(base.getBaseClassRecordNumber());
		if (underlyingClassType == null) {
			return;
		}
		ClassFieldMsAttributes atts = base.getAttributes();
		int offset = PdbApplicator.bigIntegerToInt(applicator, base.getOffset());
		classType.addDirectBaseClass(underlyingClassType, convertAttributes(atts), offset);
	}

	private void applyDirectVirtualBaseClass(AbstractVirtualBaseClassMsType base)
			throws PdbException {
		CppCompositeType underlyingCt = getUnderlyingClassType(base.getBaseClassRecordNumber());
		if (underlyingCt == null) {
			return;
		}
		DataType vbtptr =
			getVirtualBaseTablePointerDataType(base.getVirtualBasePointerRecordNumber());
		ClassFieldMsAttributes atts = base.getAttributes();
		int basePointerOffset =
			PdbApplicator.bigIntegerToInt(applicator, base.getBasePointerOffset());
		int offsetFromVbt = PdbApplicator.bigIntegerToInt(applicator, base.getBaseOffsetFromVbt());
		classType.addDirectVirtualBaseClass(underlyingCt, convertAttributes(atts),
			basePointerOffset, vbtptr, offsetFromVbt);
	}

	private void applyIndirectVirtualBaseClass(AbstractIndirectVirtualBaseClassMsType base)
			throws PdbException {
		CppCompositeType underlyingCt = getUnderlyingClassType(base.getBaseClassRecordNumber());
		if (underlyingCt == null) {
			return;
		}
		DataType vbtptr =
			getVirtualBaseTablePointerDataType(base.getVirtualBasePointerRecordNumber());
		ClassFieldMsAttributes atts = base.getAttributes();
		int basePointerOffset =
			PdbApplicator.bigIntegerToInt(applicator, base.getBasePointerOffset());
		int offsetFromVbt = PdbApplicator.bigIntegerToInt(applicator, base.getBaseOffsetFromVbt());
		classType.addIndirectVirtualBaseClass(underlyingCt, convertAttributes(atts),
			basePointerOffset, vbtptr, offsetFromVbt);
	}

	private CppCompositeType getUnderlyingClassType(RecordNumber recordNumber) {
		MsTypeApplier baseUnderlyingApplier = applicator.getTypeApplier(recordNumber);
		if (!(baseUnderlyingApplier instanceof CompositeTypeApplier)) {
			applicator.appendLogMsg(baseUnderlyingApplier.getClass().getSimpleName() +
				" seen where CompositeTypeApplier expected for base class.");
			return null;
		}
		CompositeTypeApplier baseApplier = (CompositeTypeApplier) baseUnderlyingApplier;
		CppCompositeType underlyingClassType = baseApplier.getClassType();
		if (underlyingClassType == null) {
			applicator.appendLogMsg("Underlying base class type is null.");
		}
		return underlyingClassType;
	}

	private DataType getVirtualBaseTablePointerDataType(RecordNumber recordNumber) {
		MsTypeApplier vbptrApplier = applicator.getTypeApplier(recordNumber);
		if (vbptrApplier != null) {
			if (vbptrApplier instanceof PointerTypeApplier) {
				return vbptrApplier.getDataType();
			}
		}
		applicator.appendLogMsg("Generating a generic Virtual Base Table Pointer.");
		return new PointerDataType();
	}

	private static CppCompositeType.ClassFieldAttributes convertAttributes(
			ClassFieldMsAttributes atts) {
		CppCompositeType.Access myAccess;
		switch (atts.getAccess()) {
			case PUBLIC:
				myAccess = CppCompositeType.Access.PUBLIC;
				break;
			case PROTECTED:
				myAccess = CppCompositeType.Access.PROTECTED;
				break;
			case PRIVATE:
				myAccess = CppCompositeType.Access.PRIVATE;
				break;
			default:
				myAccess = CppCompositeType.Access.BLANK;
				break;
		}
		CppCompositeType.Property myProperty;
		switch (atts.getProperty()) {
			case VIRTUAL:
				myProperty = CppCompositeType.Property.VIRTUAL;
				break;
			case STATIC:
				myProperty = CppCompositeType.Property.STATIC;
				break;
			case FRIEND:
				myProperty = CppCompositeType.Property.FRIEND;
				break;
			default:
				myProperty = CppCompositeType.Property.BLANK;
				break;
		}
		return new CppCompositeType.ClassFieldAttributes(myAccess, myProperty);
	}

	private void addMembers(Composite composite, FieldListTypeApplier fieldListApplier) {

		AbstractCompositeMsType type = (AbstractCompositeMsType) msType;

		for (MsTypeApplier memberTypeApplierIterated : fieldListApplier.getMemberList()) {
			boolean handled = true;
			if (memberTypeApplierIterated instanceof MemberTypeApplier) {
				MemberTypeApplier memberTypeApplier = (MemberTypeApplier) memberTypeApplierIterated;
				String memberName = memberTypeApplier.getName();

				int offset =
					PdbApplicator.bigIntegerToInt(applicator, memberTypeApplier.getOffset());
				ClassFieldMsAttributes memberAttributes = memberTypeApplier.getAttribute();
				memberAttributes.getAccess(); // TODO: do something with this and other attributes
				MsTypeApplier fieldApplier = memberTypeApplier.getFieldTypeApplier();

				if (fieldApplier instanceof CompositeTypeApplier) {
					CompositeTypeApplier defApplier =
						((CompositeTypeApplier) fieldApplier).getDefinitionApplier(
							CompositeTypeApplier.class);
					if (defApplier != null) {
						fieldApplier = defApplier;
					}
				}
				DataType fieldDataType = fieldApplier.getDataType();
				boolean isFlexibleArray;
				if (fieldApplier instanceof ArrayTypeApplier) {
					isFlexibleArray = ((ArrayTypeApplier) fieldApplier).isFlexibleArray();
				}
				else {
					isFlexibleArray = false;
				}
				if (fieldDataType == null) {
					if (fieldApplier instanceof PrimitiveTypeApplier &&
						((PrimitiveTypeApplier) fieldApplier).isNoType()) {
						DefaultPdbUniversalMember member = new DefaultPdbUniversalMember(applicator,
							memberName, fieldApplier, offset);
						members.add(member);
						componentComments.put(offset, "NO_TYPE");
					}
					else {
						applicator.appendLogMsg("PDB Warning: No conversion for " + memberName +
							" " + fieldApplier.getMsType().getClass().getSimpleName() +
							" in composite " + composite.getName());
					}
				}
				else {
					DefaultPdbUniversalMember member =
						new DefaultPdbUniversalMember(applicator, memberName, fieldApplier, offset);
					members.add(member);
					classType.addMember(memberName, fieldDataType, isFlexibleArray,
						convertAttributes(memberAttributes), offset);
				}
			}
			else if (memberTypeApplierIterated instanceof EnumerateTypeApplier) {
				EnumerateTypeApplier enumerateTypeApplier =
					(EnumerateTypeApplier) memberTypeApplierIterated;
				String fieldName = enumerateTypeApplier.getName();
				Numeric numeric = enumerateTypeApplier.getNumeric();
				// TODO: some work
				pdbLogAndInfoMessage(this,
					"Don't know how to apply EnumerateTypeApplier fieldName " + fieldName +
						" and value " + numeric + " within " + msType.getName());
			}
			else if (memberTypeApplierIterated instanceof VirtualFunctionTablePointerTypeApplier) {
				VirtualFunctionTablePointerTypeApplier vtPtrApplier =
					(VirtualFunctionTablePointerTypeApplier) memberTypeApplierIterated;
				String vftPtrMemberName = vtPtrApplier.getMemberName();
				int offset = vtPtrApplier.getOffset();
				DefaultPdbUniversalMember member = new DefaultPdbUniversalMember(applicator,
					vftPtrMemberName, vtPtrApplier, offset);
				members.add(member);
				//classType.addMember(vftPtrMemberName, vtPtrApplier.getDataType(), false, offset);
				classType.addVirtualFunctionTablePointer(vftPtrMemberName,
					vtPtrApplier.getDataType(), offset);
			}
			else if (memberTypeApplierIterated instanceof NestedTypeApplier) {
				// Need to make sure that "this" class id dependent on all elements composing the
				// nested definition, but we need to create the nested definition during the
				// creation of this class. (NestedTypeApplier and NestedTypeMsType do not really
				// have their own RecordNumber).
				// 20200114: think this is a nested typedef.
				NestedTypeApplier nestedTypeApplier = (NestedTypeApplier) memberTypeApplierIterated;
				String memberTypeName = nestedTypeApplier.getTypeName();
				String memberName = nestedTypeApplier.getMemberName();  // use this
				// TODO: we are assuming that the offset is zero (0) for the call.  Need to dig
				//  more to confirm this.  Is ever anything but just one nested type?  The pdb.exe
				//  generates these all at offset 0.
				// TODO: Nested types are currently an issue for
				//  DefaultCompositeMember.applyDataTypeMembers().
				//  Need to investigate what to do here.  It could be just when the specific
				//  composite is a member of itself.
				if (type.getName().equals(memberTypeName)) {
					// We are skipping because we've had issues and do not know what is going on
					//  at the moment. (I think they were dependency issues... been a while.)
					//  See not above the "if" condition.
//					pdbLogAndInfoMessage(this, "Skipping Composite Nested type member: " +
//						memberName + " within " + type.getName());
					// TODO: Investigate.  What does it mean when the internally defined type
					//  conficts with the name of the outer type.
					continue;
				}
				// TODO: believe the thing to do is to show that these are types that are
				//  defined within the namespace of this containing type.  This might be
				//  the place to do it... that is if we don't identify them separately
				//  falling under the namespace of this composite.

//				AbstractMsTypeApplier nestedDefinitionApplier =
//					nestedTypeApplier.getNestedTypeDefinitionApplier().getDependencyApplier();
//
//				DataType ndt = nestedDefinitionApplier.getDataType(); //use this
//				int ndtl = ndt.getLength(); //use this
//
//				AbstractMsType ndms = nestedTypeApplier.getMsType();
//
//				BigInteger val = nestedTypeApplier.getSize();
//				int offset = 0; // ???? TODO..,
//				DataType nt = nestedTypeApplier.getDataType();
//				ClassFieldMsAttributes a = nestedTypeApplier.getAttributes();
//
//				// TODO: hoping this is right... 20200521... how/where do we get offset?
//				Default2PdbMember member =
//					new Default2PdbMember(applicator, memberName, nestedDefinitionApplier, offset);
//				members.add(member);
			}
			else if (memberTypeApplierIterated instanceof NoTypeApplier) {
				AbstractMsType msNoType = memberTypeApplierIterated.getMsType();
				if (msNoType instanceof AbstractStaticMemberMsType) {
					// TODO: Investigate anything that hits here (set break point), see if we
					//  see dot apply the information.  If so, probably should create an applier
					//  for the contained MS type.
				}
				else {
					handled = false;
				}
			}
			else {
				handled = false;
			}
			if (!handled) {
				applicator.appendLogMsg(
					memberTypeApplierIterated.getClass().getSimpleName() + " with contained " +
						memberTypeApplierIterated.getMsType().getClass().getSimpleName() +
						" unexpected for " + msType.getName());
			}
		}
	}

//	/**
//	 * <code>NoType</code> provides ability to hang NoType into a composite type by faking
//	 * it with a zero-length bitfield.  This is a bit of a kludge
//	 * This will be transformed to a normal BitFieldDataType when cloned.
//	 */
//	private class NoType extends PdbBitField {
//		private NoType(PdbApplicator applicator) throws InvalidDataTypeException {
//			super(new CharDataType(applicator.getDataTypeManager()), 0, 0);
//		}
//	}
//
}
