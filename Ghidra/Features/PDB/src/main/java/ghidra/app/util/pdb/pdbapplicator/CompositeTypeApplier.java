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

	// Intended for: AbstractCompositeMsType
	/**
	 * Constructor for composite type applier, for transforming a composite into a
	 * Ghidra DataType
	 * @param applicator {@link DefaultPdbApplicator} for which this class is working
	 */
	public CompositeTypeApplier(DefaultPdbApplicator applicator) {
		super(applicator);
	}

	CppCompositeType getClassType(AbstractMsType type) {
		return applicator.getClassType(type);
	}

	private ComboType create(AbstractCompositeMsType type) {
		AbstractCompositeMsType defType = getDefinitionType(type, AbstractCompositeMsType.class);
		SymbolPath fixedSp = getFixedSymbolPath(defType);
		CategoryPath categoryPath = applicator.getCategory(fixedSp.getParent());
		return createComposite(applicator, fixedSp.getName(), defType, categoryPath, fixedSp);
	}

	private record ComboType(Composite dt, CppCompositeType ct) {}

	// DefaultPdbApplicator is passed in for bigIntegerToInt...
	//  TODO: find a better way... maybe eventually eliminate PdbMsgLog
	private static ComboType createComposite(DefaultPdbApplicator myApplicator, String name,
			AbstractCompositeMsType compositeMsType, CategoryPath categoryPath,
			SymbolPath fixedSymbolPath) {

		Composite myComposite;
		CppCompositeType myClassType;

		String mangledName = compositeMsType.getMangledName();

		if (compositeMsType instanceof AbstractClassMsType) {
			myApplicator.predefineClass(fixedSymbolPath);
			myComposite = new StructureDataType(categoryPath, fixedSymbolPath.getName(), 0,
				myApplicator.getDataTypeManager());
			myClassType = new CppCompositeType(myComposite, mangledName);
			myClassType.setClass();
		}
		else if (compositeMsType instanceof AbstractStructureMsType) {
			myComposite = new StructureDataType(categoryPath, fixedSymbolPath.getName(), 0,
				myApplicator.getDataTypeManager());
			myClassType = new CppCompositeType(myComposite, mangledName);
			myClassType.setStruct();
		}
		else if (compositeMsType instanceof AbstractUnionMsType) {
			myComposite = new UnionDataType(categoryPath, fixedSymbolPath.getName(),
				myApplicator.getDataTypeManager());
			myClassType = new CppCompositeType(myComposite, mangledName);
			myClassType.setUnion();
		}
		else { // InterfaceMsType
			String message = "Unsupported datatype (" + compositeMsType.getClass().getSimpleName() +
				"): " + fixedSymbolPath.getPath();
			myApplicator.appendLogMsg(message);
			return null;
		}
		myClassType.setName(name);
		myClassType.setSize(myApplicator.bigIntegerToInt(compositeMsType.getSize()));
		myClassType.setFinal(compositeMsType.getMsProperty().isSealed());

		return new ComboType(myComposite, myClassType);
	}

	@Override
	DataType apply(AbstractMsType type, FixupContext fixupContext, boolean breakCycle)
			throws PdbException, CancelledException {
		return apply((AbstractCompositeMsType) type, fixupContext, breakCycle);
	}

	private void applyInternal(ComboType combo, AbstractCompositeMsType type,
			FixupContext fixupContext, boolean breakCycle) throws CancelledException, PdbException {
		FieldListTypeApplier fieldListApplier = FieldListTypeApplier
				.getFieldListApplierSpecial(applicator, type.getFieldDescriptorListRecordNumber());
		FieldListTypeApplier.FieldLists lists =
			fieldListApplier.getFieldLists(type.getFieldDescriptorListRecordNumber());
		if (type instanceof AbstractUnionMsType) {
			applyBasic(combo, type, lists, fixupContext, breakCycle);
		}
		else {
			applyCpp(combo, type, lists, fixupContext, breakCycle);
		}
	}

	//==============================================================================================
	private void applyBasic(ComboType combo, AbstractCompositeMsType type,
			FieldListTypeApplier.FieldLists lists, FixupContext fixupContext, boolean breakCycle)
			throws CancelledException, PdbException {
		Composite composite = combo.dt();
		CppCompositeType classType = combo.ct();
		boolean isClass = (type instanceof AbstractClassMsType);
		int size = getSizeInt(type);
		clearComponents(composite);
		List<DefaultPdbUniversalMember> myMembers = new ArrayList<>();
		addVftPtrs(composite, classType, lists.vftPtrs(), type, myMembers, fixupContext,
			breakCycle);
		addMembers(composite, classType, lists.nonstaticMembers(), type, myMembers, fixupContext,
			breakCycle);

		if (!DefaultCompositeMember.applyDataTypeMembers(composite, isClass, size, myMembers,
			msg -> reconstructionWarn(msg, hasHiddenComponents(lists)),
			applicator.getCancelOnlyWrappingMonitor())) {
			clearComponents(composite);
		}
	}

	//==============================================================================================
	private void applyCpp(ComboType combo, AbstractCompositeMsType type,
			FieldListTypeApplier.FieldLists lists, FixupContext fixupContext, boolean breakCycle)
			throws PdbException, CancelledException {
		Composite composite = combo.dt();
		CppCompositeType classType = combo.ct();
		clearComponents(composite);
		List<DefaultPdbUniversalMember> myMembers = new ArrayList<>();
		addClassTypeBaseClassesNew(composite, classType, lists.bases(), type, fixupContext,
			breakCycle);
		addVftPtrs(composite, classType, lists.vftPtrs(), type, myMembers, fixupContext,
			breakCycle);
		addMembers(composite, classType, lists.nonstaticMembers(), type, myMembers, fixupContext,
			breakCycle);

		if (!classType.validate()) {
			// TODO: Investigate.  We should do this check for some classes somewhere.  Should
			// we do it here.  Set breakpoint here to investigate.
		}
		classType.createLayout(applicator.getPdbApplicatorOptions().getCompositeLayout(),
			applicator.getVbtManager(), applicator.getCancelOnlyWrappingMonitor());
	}

	//==============================================================================================
	private void reconstructionWarn(String msg, boolean hasHiddenComponents) {
		if (msg.contains("failed to align") && hasHiddenComponents) {
			msg = msg.replaceFirst("PDB", "PDB CLASS");
		}
		Msg.warn(this, msg);
	}

	//==============================================================================================
	BigInteger getSize(AbstractCompositeMsType type) {
		AbstractCompositeMsType definition = getDefinitionType(type);
		return definition.getSize();
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

	private boolean hasHiddenComponents(FieldListTypeApplier.FieldLists lists) {
		return (lists.methods().size() != 0 || lists.bases().size() != 0);
	}

	private void addClassTypeBaseClassesNew(Composite composite, CppCompositeType myClassType,
			List<AbstractMsType> msBases, AbstractMsType type, FixupContext fixupContext,
			boolean breakCycle) throws PdbException, CancelledException {

		AbstractCompositeMsType cType = (AbstractCompositeMsType) type;

		for (AbstractMsType baseType : msBases) {

			MsTypeApplier baseApplier = applicator.getTypeApplier(baseType);
			if (!(baseApplier instanceof BaseClassTypeApplier baseTypeApplier)) {
				applicator.appendLogMsg(baseApplier.getClass().getSimpleName() +
					" seen where BaseClassTypeApplier expected for " + cType.getName());
				continue;
			}

			if (baseType instanceof AbstractBaseClassMsType baseClassType) {
				applyDirectBaseClass(baseClassType, myClassType, fixupContext);
			}
			else if (baseType instanceof AbstractVirtualBaseClassMsType virtualBaseClassType) {
				applyDirectVirtualBaseClass(virtualBaseClassType, myClassType, fixupContext,
					breakCycle);
			}
			else if (baseType instanceof AbstractIndirectVirtualBaseClassMsType indirectVirtualBaseClassType) {
				applyIndirectVirtualBaseClass(indirectVirtualBaseClassType, myClassType,
					fixupContext, breakCycle);
			}
			else {
				throw new AssertException(
					"Unknown base class type: " + baseType.getClass().getSimpleName());
			}
		}
	}

	private void applyDirectBaseClass(AbstractBaseClassMsType base, CppCompositeType myClassType,
			FixupContext fixupContext) throws PdbException, CancelledException {
		CppCompositeType underlyingClassType =
			getUnderlyingClassType(base.getBaseClassRecordNumber(), fixupContext);
		if (underlyingClassType == null) {
			return;
		}
		ClassFieldMsAttributes atts = base.getAttributes();
		int offset = applicator.bigIntegerToInt(base.getOffset());
		myClassType.addDirectBaseClass(underlyingClassType, convertAttributes(atts), offset);
	}

	private void applyDirectVirtualBaseClass(AbstractVirtualBaseClassMsType base,
			CppCompositeType myClassType, FixupContext fixupContext, boolean breakCycle)
			throws PdbException, CancelledException {
		CppCompositeType underlyingCt =
			getUnderlyingClassType(base.getBaseClassRecordNumber(), fixupContext);
		if (underlyingCt == null) {
			return;
		}
		DataType vbtptr = getVirtualBaseTablePointerDataType(
			base.getVirtualBasePointerRecordNumber(), fixupContext, breakCycle);
		ClassFieldMsAttributes atts = base.getAttributes();
		int basePointerOffset = applicator.bigIntegerToInt(base.getBasePointerOffset());
		int offsetFromVbt = applicator.bigIntegerToInt(base.getBaseOffsetFromVbt());
		myClassType.addDirectVirtualBaseClass(underlyingCt, convertAttributes(atts),
			basePointerOffset, vbtptr, offsetFromVbt);
	}

	private void applyIndirectVirtualBaseClass(AbstractIndirectVirtualBaseClassMsType base,
			CppCompositeType myClassType, FixupContext fixupContext, boolean breakCycle)
			throws PdbException, CancelledException {
		CppCompositeType underlyingCt =
			getUnderlyingClassType(base.getBaseClassRecordNumber(), fixupContext);
		if (underlyingCt == null) {
			return;
		}
		DataType vbtptr = getVirtualBaseTablePointerDataType(
			base.getVirtualBasePointerRecordNumber(), fixupContext, breakCycle);
		ClassFieldMsAttributes atts = base.getAttributes();
		int basePointerOffset = applicator.bigIntegerToInt(base.getBasePointerOffset());
		int offsetFromVbt = applicator.bigIntegerToInt(base.getBaseOffsetFromVbt());
		myClassType.addIndirectVirtualBaseClass(underlyingCt, convertAttributes(atts),
			basePointerOffset, vbtptr, offsetFromVbt);
	}

	private CppCompositeType getUnderlyingClassType(RecordNumber recordNumber,
			FixupContext fixupContext) throws CancelledException, PdbException {

		AbstractMsType type = applicator.getPdb().getTypeRecord(recordNumber);
		if (!(type instanceof AbstractCompositeMsType comp)) {
			applicator.appendLogMsg(type.getClass().getSimpleName() +
				" seen where Composite Type expected for base class.");
			return null;
		}
		// not sure if need to do this.  TODO: evaluate
		applicator.getProcessedDataType(recordNumber, fixupContext, false);

		MsTypeApplier baseUnderlyingApplier = applicator.getTypeApplier(recordNumber);
		if (!(baseUnderlyingApplier instanceof CompositeTypeApplier)) {
			applicator.appendLogMsg(baseUnderlyingApplier.getClass().getSimpleName() +
				" seen where CompositeTypeApplier expected for base class.");
			return null;
		}
		CompositeTypeApplier baseApplier = (CompositeTypeApplier) baseUnderlyingApplier;
		CppCompositeType underlyingClassType = baseApplier.getClassType(type);
		if (underlyingClassType == null) {
			applicator.appendLogMsg("Underlying base class type is null.");
		}
		return underlyingClassType;
	}

	private DataType getVirtualBaseTablePointerDataType(RecordNumber recordNumber,
			FixupContext fixupContext, boolean breakCycle) throws CancelledException, PdbException {
		DataType dt = applicator.getProcessedDataType(recordNumber, fixupContext, breakCycle);
		if (dt != null) {
			return dt;
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

	private void addMembers(Composite composite, CppCompositeType myClassType,
			List<AbstractMemberMsType> msMembers, AbstractCompositeMsType type,
			List<DefaultPdbUniversalMember> myMembers, FixupContext fixupContext,
			boolean breakCycle) throws CancelledException, PdbException {

		for (int index = 0; index < msMembers.size(); index++) {
			applicator.checkCancelled();
			AbstractMemberMsType memberType = msMembers.get(index);
			DefaultPdbUniversalMember member =
				getNonStaticMember(composite, memberType, index, fixupContext, breakCycle);
			DataType dt = member.getDataType().getDataType();
			if (applicator.isPlaceholderType(dt)) {
				fixupContext.putFixup(index);
			}
			myMembers.add(member);
			myClassType.addMember(member.getName(), dt, member.isZeroLengthArray(),
				member.getAttributes(), member.getOffset(), member.getComment());
		}
	}

	private void addVftPtrs(Composite composite, CppCompositeType myClassType,
			List<AbstractVirtualFunctionTablePointerMsType> msVftPtrs, AbstractCompositeMsType type,
			List<DefaultPdbUniversalMember> myMembers, FixupContext fixupContext,
			boolean breakCycle) throws CancelledException, PdbException {
		for (AbstractVirtualFunctionTablePointerMsType vftPtr : msVftPtrs) {
			MsTypeApplier applierIterated = applicator.getTypeApplier(vftPtr);
			if (applierIterated instanceof VirtualFunctionTablePointerTypeApplier vtPtrApplier) {
				DefaultPdbUniversalMember member =
					getVftPtrMember(vftPtr, vtPtrApplier, fixupContext, breakCycle);
				myMembers.add(member);
				myClassType.addVirtualFunctionTablePointer(member.getName(),
					member.getDataType().getDataType(), member.getOffset());
			}
		}
	}

	// We broke up the big addMembers() method that had static and non-static members, along with
	//  vftptrs, and the items in this method.  These were not really processed in the older
	//  method, but we wanted to capture the types that still possible
	private void addOthers(Composite composite, CppCompositeType myClassType,
			List<AbstractMsType> msMembers, AbstractCompositeMsType type,
			List<DefaultPdbUniversalMember> myMembers, FixupContext fixupContext)
			throws CancelledException, PdbException {

		for (AbstractMsType typeIterated : msMembers) {
			MsTypeApplier applierIterated = applicator.getTypeApplier(typeIterated);
			if (applierIterated instanceof EnumerateTypeApplier enumerateApplier &&
				typeIterated instanceof AbstractEnumerateMsType enumerateType) {
				processEnumerate(type, enumerateApplier, enumerateType);
			}
			else if (applierIterated instanceof NestedTypeApplier nestedTypeApplier) {
				processNestedType(type, nestedTypeApplier, typeIterated);
			}
			else if (applierIterated instanceof NoTypeApplier) {
				if (typeIterated instanceof AbstractStaticMemberMsType) {
					// TODO: Investigate anything that hits here (set break point), see if we
					//  see dot apply the information.  If so, probably should create an applier
					//  for the contained MS type.
				}
				else {
					processNotHandled(composite, applierIterated, typeIterated);
				}
			}
			else {
				processNotHandled(composite, applierIterated, typeIterated);
			}
		}

	}

	private DefaultPdbUniversalMember getNonStaticMember(Composite container,
			AbstractMemberMsType memberMsType, int ordinal, FixupContext fixupContext,
			boolean breakCycle) throws CancelledException, PdbException {

		MsTypeApplier applier = applicator.getTypeApplier(memberMsType);
		if (!(applier instanceof MemberTypeApplier memberApplier)) {
			throw new PdbException("Member applier expected");
		}

		String memberName = memberMsType.getName();
		int offset = applicator.bigIntegerToInt(memberMsType.getOffset());

		ClassFieldMsAttributes memberAttributes = memberMsType.getAttribute();
		memberAttributes.getAccess(); // TODO: do something with this and other attributes

		AbstractMsType fieldType =
			applicator.getPdb().getTypeRecord(memberMsType.getFieldTypeRecordNumber());
		MsTypeApplier fieldApplier = applicator.getTypeApplier(fieldType);

		String memberComment = null;
		DataType fieldDataType = applicator.getProcessedDataType(
			memberMsType.getFieldTypeRecordNumber(), fixupContext, breakCycle);
		if (fieldApplier instanceof PointerTypeApplier ptrApplier) {
			AbstractPointerMsType pointerType = (AbstractPointerMsType) fieldType;
			memberComment = ptrApplier.getPointerCommentField(pointerType, fixupContext);
		}

		boolean isZeroLengthArray = (fieldDataType instanceof Array &&
			fieldApplier instanceof ArrayTypeApplier arrayApplier &&
			arrayApplier.isFlexibleArray(fieldType));

		DefaultPdbUniversalMember member = new DefaultPdbUniversalMember(memberName, fieldDataType,
			isZeroLengthArray, offset, convertAttributes(memberAttributes), memberComment);
		return member;
	}

	private DefaultPdbUniversalMember getVftPtrMember(
			AbstractVirtualFunctionTablePointerMsType type,
			VirtualFunctionTablePointerTypeApplier vtPtrApplier, FixupContext fixupContext,
			boolean breakCycle) throws CancelledException, PdbException {
		String vftPtrMemberName = vtPtrApplier.getMemberName(type);
		int offset = vtPtrApplier.getOffset(type);
		DataType dt = vtPtrApplier.apply(type, fixupContext, breakCycle);
		return new DefaultPdbUniversalMember(vftPtrMemberName, dt, offset);
	}

	private void processEnumerate(AbstractCompositeMsType type, EnumerateTypeApplier applier,
			AbstractEnumerateMsType enumerateType) {
		String fieldName = enumerateType.getName();
		Numeric numeric = enumerateType.getNumeric();
		// TODO: some work
		pdbLogAndInfoMessage(this, "Don't know how to apply EnumerateTypeApplier fieldName " +
			fieldName + " and value " + numeric + ".");
	}

	private void processNestedType(AbstractCompositeMsType type,
			NestedTypeApplier nestedTypeApplier, AbstractMsType enumerateType) {
		// Need to make sure that "this" class id dependent on all elements composing the
		// nested definition, but we need to create the nested definition during the
		// creation of this class. (NestedTypeApplier and NestedTypeMsType do not really
		// have their own RecordNumber).
		// 20200114: think this is a nested typedef.
		String memberTypeName = enumerateType.getName();
//		String memberName = nestedTypeApplier.getMemberName();  // use this
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
//			pdbLogAndInfoMessage(this, "Skipping Composite Nested type member: " +
//				memberName + " within " + type.getName());
			// TODO: Investigate.  What does it mean when the internally defined type
			//  conflicts with the name of the outer type.
		}
		// TODO: believe the thing to do is to show that these are types that are
		//  defined within the namespace of this containing type.  This might be
		//  the place to do it... that is if we don't identify them separately
		//  falling under the namespace of this composite.

	}

	private void processNotHandled(Composite composite, MsTypeApplier applier,
			AbstractMsType memberType) {
		applicator.appendLogMsg(applier.getClass().getSimpleName() + " with contained " +
			memberType.getClass().getSimpleName() + " unexpected for " + composite.getName());
	}

	//==============================================================================================
	DataType fixup(AbstractCompositeMsType type, Map<Integer, DataType> contextMap)
			throws CancelledException, PdbException {
		DataType dt = applicator.getDataType(type);
		if (dt instanceof DataTypeImpl || !(dt instanceof Composite)) {
			throw new PdbException("Can only fixup Composite DB ");
		}
		return null;
	}

	//==============================================================================================
	DataType apply(AbstractCompositeMsType type, FixupContext fixupContext, boolean breakCycle)
			throws CancelledException, PdbException {

		int typeNumber = type.getRecordNumber().getNumber();
		int mappedNumber = applicator.getMappedComplexType(typeNumber);
		DataType existingDt = applicator.getDataType(mappedNumber);
		if (existingDt != null) {
			return existingDt;
		}

		AbstractMsType msType =
			applicator.getPdb().getTypeRecord(RecordNumber.typeRecordNumber(mappedNumber));
		if (!(msType instanceof AbstractCompositeMsType)) {
			throw new PdbException("PDB processing error");
		}
		type = (AbstractCompositeMsType) msType;

		CppCompositeType myClassType = getClassType(type);
		ComboType combo;
		Composite composite;
		if (myClassType == null) {
			combo = create(type);
			composite = combo.dt();
			myClassType = combo.ct();
			applicator.putClassType(type, myClassType);
		}
		else {
			composite = myClassType.getComposite();
			combo = new ComboType(composite, myClassType);
		}

		applyInternal(combo, type, fixupContext, breakCycle);

		composite = (Composite) applicator.resolve(composite);
		applicator.putDataType(mappedNumber, composite);
		return composite;
	}

	private AbstractCompositeMsType getDefinitionType(AbstractComplexMsType type) {
		return getDefinitionType(type, AbstractCompositeMsType.class);
	}

	public void fixUp(FixupContext fixupContext) throws PdbException, CancelledException {

		Integer indexNumber = fixupContext.peekFixupRecord();
		if (indexNumber == null) {
			return;
		}

		AbstractMsType t =
			applicator.getPdb().getTypeRecord(RecordNumber.typeRecordNumber(indexNumber));
		if (!(t instanceof AbstractComplexMsType type)) {
			throw new PdbException("error");
		}
		AbstractCompositeMsType defType = getDefinitionType(type);

		DataType dataType = applicator.getDataType(indexNumber);
		if (dataType == null) {
			applicator.appendLogMsg("Null type for index: " + indexNumber);
			return;
		}
		if (dataType instanceof DataTypeImpl) {
			applicator.appendLogMsg("Impl type for index: " + indexNumber);
			return;
		}
		if (!(dataType instanceof Composite compositeDB)) {
			applicator.appendLogMsg("Composite expected type for index: " + indexNumber);
			return;
		}

		FieldListTypeApplier fieldListApplier = FieldListTypeApplier.getFieldListApplierSpecial(
			applicator, defType.getFieldDescriptorListRecordNumber());
		FieldListTypeApplier.FieldLists lists =
			fieldListApplier.getFieldLists(defType.getFieldDescriptorListRecordNumber());

		List<AbstractMemberMsType> msMembers = lists.nonstaticMembers();

		List<Integer> fixupIndices = fixupContext.getFixups();
		for (int index : fixupIndices) {
			applicator.checkCancelled();
			AbstractMemberMsType memberType = msMembers.get(index);
			// Using a null FixupContext signifies "doing" vs. creating fixups.
			DefaultPdbUniversalMember member =
				getNonStaticMember(compositeDB, memberType, index, null, false);
			replaceComponentDataType(compositeDB, member);
		}
	}

	private void replaceComponentDataType(Composite compositeDB, DefaultPdbUniversalMember member)
			throws CancelledException, PdbException {
		DataType dt = member.getDataType().getDataType();
		if (applicator.isPlaceholderPointer(dt)) {
			throw new PdbException("Placeholder pointer not expected");
		}
		if (!recurseReplacement(compositeDB, 0, member)) {
			/**
			 * We want to throw the exception below, but for now, we are only making a warning.
			 *  This is because we have a situation where we still do not accurately map
			 *  definitions with forward references and when this causes a size calculation within
			 *  the {@link ArrayTypeApplier}, we fill in the array with dummy undefined1 types,
			 *  which can cause the replacement issue here.  When that gets fixed, the warning
			 *  here should be replaced with the PdbException.
			 */
			Msg.warn(this,
				"PDB: Unable to replace placeholder component of: " + compositeDB.getName());
//			throw new PdbException(
//				"Unable to replace placeholder component of: " + compositeDB.getName());
		}
	}

	private boolean recurseReplacement(Composite compositeDB, int baseOffset,
			DefaultPdbUniversalMember member) throws CancelledException, PdbException {
		DataTypeComponent[] components = compositeDB.getDefinedComponents();
		for (DataTypeComponent component : components) {
			if (member.getOffset() > baseOffset + component.getEndOffset()) {
				continue;
			}
			if (member.getOffset() < baseOffset + component.getOffset()) {
				continue;
			}
			DataType componentDt = component.getDataType();
			// We would normally just check for a union, expecting any other component to be
			//  a fully defined datatype, but using DefaultPdbUniveralMember to unflatten
			//  a union can result in nested structures that are not otherwise resolved.  Thus,
			//  we must check for any composite: union or structure.
			if (!applicator.isPlaceholderType(componentDt) &&
				componentDt instanceof Composite nestedComposite) {
				if (recurseReplacement(nestedComposite, baseOffset + component.getOffset(),
					member)) {
					return true;
				}
				continue;
			}
			if (applicator.isPlaceholderType(componentDt) &&
				component.getFieldName().equals(member.getName()) &&
				member.getOffset() == baseOffset + component.getOffset()) {
				DataType replacementDt = member.getDataType().getDataType();
				int length = replacementDt.getLength();
				if (length != componentDt.getLength()) {
					throw new PdbException("Mismatch component type length on replacement: " +
						replacementDt.getName());
				}
				int ordinal = component.getOrdinal();
				replaceComponent(compositeDB, ordinal, replacementDt);
				return true;
			}
		}
		return false;
	}

	private static void replaceComponent(Composite composite, int ordinal, DataType newType)
			throws PdbException {
		if (composite instanceof Structure struct) {
			DataTypeComponent dtc = struct.getComponent(ordinal);
			struct.replace(ordinal, newType, newType.getLength(), dtc.getFieldName(),
				dtc.getComment());
		}
		else if (composite instanceof Union union) {
			DataTypeComponent dtc = union.getComponent(ordinal);
			union.delete(ordinal);
			union.insert(ordinal, newType, newType.getLength(), dtc.getFieldName(),
				dtc.getComment());
		}
		else {
			throw new PdbException("Not struct or union: " + composite.getClass().getSimpleName());
		}
	}

}
