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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb.DefaultCompositeMember;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.app.util.pdb.pdbapplicator.ClassFieldAttributes.Access;
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
	 * Constructor for composite type applier, for transforming a composite into a Ghidra DataType
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

		int size = myApplicator.bigIntegerToInt(compositeMsType.getSize());

		if (compositeMsType instanceof AbstractClassMsType) {
			myApplicator.predefineClass(fixedSymbolPath);
			myComposite = new StructureDataType(categoryPath, fixedSymbolPath.getName(), size,
				myApplicator.getDataTypeManager());
			myClassType = new CppCompositeType(myComposite, mangledName);
			myClassType.setClass();
		}
		else if (compositeMsType instanceof AbstractStructureMsType) {
			myComposite = new StructureDataType(categoryPath, fixedSymbolPath.getName(), size,
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
		myClassType.setSize(size);
		myClassType.setFinal(compositeMsType.getMsProperty().isSealed());

		return new ComboType(myComposite, myClassType);
	}

	@Override
	boolean apply(AbstractMsType type) throws PdbException, CancelledException {
		return apply((AbstractCompositeMsType) type);
	}

	private boolean applyInternal(ComboType combo, AbstractCompositeMsType type)
			throws CancelledException, PdbException {
		FieldListTypeApplier fieldListApplier = FieldListTypeApplier
				.getFieldListApplierSpecial(applicator, type.getFieldDescriptorListRecordNumber());
		FieldListTypeApplier.FieldLists lists =
			fieldListApplier.getFieldLists(type.getFieldDescriptorListRecordNumber());
		if (!precheckOrScheduleDependencies(lists)) {
			return false;
		}

		if (type instanceof AbstractUnionMsType) {
			applyBasic(combo, type, lists);
		}
		else {
			applyCpp(combo, type, lists);
		}
		return true;
	}

	//==============================================================================================
	private void applyBasic(ComboType combo, AbstractCompositeMsType type,
			FieldListTypeApplier.FieldLists lists)
			throws CancelledException, PdbException {
		Composite composite = combo.dt();
		CppCompositeType classType = combo.ct();
		boolean isClass = (type instanceof AbstractClassMsType);
		int size = getSizeInt(type);
		clearComponents(composite);
		List<DefaultPdbUniversalMember> myMembers = new ArrayList<>();
		addVftPtrs(composite, classType, lists.vftPtrs(), type, myMembers);
		addMembers(composite, classType, lists.nonstaticMembers(), type, myMembers);

		if (!DefaultCompositeMember.applyDataTypeMembers(composite, isClass, size, myMembers,
			msg -> reconstructionWarn(msg, hasHiddenComponents(lists)),
			applicator.getCancelOnlyWrappingMonitor())) {
			clearComponents(composite);
		}
	}

	//==============================================================================================
	private void applyCpp(ComboType combo, AbstractCompositeMsType type,
			FieldListTypeApplier.FieldLists lists)
			throws PdbException, CancelledException {
		Composite composite = combo.dt();
		CppCompositeType classType = combo.ct();
		clearComponents(composite);
		List<DefaultPdbUniversalMember> myMembers = new ArrayList<>();
		addClassTypeBaseClasses(composite, classType, lists.bases(), type);
		addVftPtrs(composite, classType, lists.vftPtrs(), type, myMembers);
		addMembers(composite, classType, lists.nonstaticMembers(), type, myMembers);

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

	private void addClassTypeBaseClasses(Composite composite, CppCompositeType myClassType,
			List<AbstractMsType> msBases, AbstractMsType type)
			throws PdbException, CancelledException {

		AbstractCompositeMsType cType = (AbstractCompositeMsType) type;
		ClassFieldAttributes.Access defaultAccess =
			(type instanceof AbstractClassMsType) ? ClassFieldAttributes.Access.PRIVATE
					: ClassFieldAttributes.Access.PUBLIC;

		for (AbstractMsType baseType : msBases) {
			applicator.checkCancelled();
			MsTypeApplier baseApplier = applicator.getTypeApplier(baseType);
			if (!(baseApplier instanceof BaseClassTypeApplier baseTypeApplier)) {
				applicator.appendLogMsg(baseApplier.getClass().getSimpleName() +
					" seen where BaseClassTypeApplier expected for " + cType.getName());
				continue;
			}

			if (baseType instanceof AbstractBaseClassMsType baseClassType) {
				applyDirectBaseClass(baseClassType, myClassType, defaultAccess);
			}
			else if (baseType instanceof AbstractVirtualBaseClassMsType virtualBaseClassType) {
				applyDirectVirtualBaseClass(virtualBaseClassType, myClassType, defaultAccess);
			}
			else if (baseType instanceof AbstractIndirectVirtualBaseClassMsType indirectVirtualBaseClassType) {
				applyIndirectVirtualBaseClass(indirectVirtualBaseClassType, myClassType,
					defaultAccess);
			}
			else {
				throw new AssertException(
					"Unknown base class type: " + baseType.getClass().getSimpleName());
			}
		}
	}

	private void applyDirectBaseClass(AbstractBaseClassMsType base, CppCompositeType myClassType,
			Access defaultAccess)
			throws PdbException {
		CppCompositeType underlyingClassType =
			getUnderlyingClassType(base.getBaseClassRecordNumber());
		if (underlyingClassType == null) {
			return;
		}
		ClassFieldMsAttributes atts = base.getAttributes();
		int offset = applicator.bigIntegerToInt(base.getOffset());
		myClassType.addDirectBaseClass(underlyingClassType,
			ClassFieldAttributes.convert(atts, defaultAccess), offset);
	}

	private void applyDirectVirtualBaseClass(AbstractVirtualBaseClassMsType base,
			CppCompositeType myClassType, Access defaultAccess) throws PdbException {
		CppCompositeType underlyingCt =
			getUnderlyingClassType(base.getBaseClassRecordNumber());
		if (underlyingCt == null) {
			return;
		}
		DataType vbtptr = getVirtualBaseTablePointerDataType(
			base.getVirtualBasePointerRecordNumber());
		ClassFieldMsAttributes atts = base.getAttributes();
		int basePointerOffset = applicator.bigIntegerToInt(base.getBasePointerOffset());
		int offsetFromVbt = applicator.bigIntegerToInt(base.getBaseOffsetFromVbt());
		myClassType.addDirectVirtualBaseClass(underlyingCt,
			ClassFieldAttributes.convert(atts, defaultAccess),
			basePointerOffset, vbtptr, offsetFromVbt);
	}

	private void applyIndirectVirtualBaseClass(AbstractIndirectVirtualBaseClassMsType base,
			CppCompositeType myClassType, Access defaultAccess) throws PdbException {
		CppCompositeType underlyingCt =
			getUnderlyingClassType(base.getBaseClassRecordNumber());
		if (underlyingCt == null) {
			return;
		}
		DataType vbtptr =
			getVirtualBaseTablePointerDataType(base.getVirtualBasePointerRecordNumber());
		ClassFieldMsAttributes atts = base.getAttributes();
		int basePointerOffset = applicator.bigIntegerToInt(base.getBasePointerOffset());
		int offsetFromVbt = applicator.bigIntegerToInt(base.getBaseOffsetFromVbt());
		myClassType.addIndirectVirtualBaseClass(underlyingCt,
			ClassFieldAttributes.convert(atts, defaultAccess),
			basePointerOffset, vbtptr, offsetFromVbt);
	}

	private CppCompositeType getUnderlyingClassType(RecordNumber recordNumber) {

		AbstractMsType type = applicator.getTypeRecord(recordNumber);
		if (!(type instanceof AbstractCompositeMsType comp)) {
			applicator.appendLogMsg(type.getClass().getSimpleName() +
				" seen where Composite Type expected for base class.");
			return null;
		}

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

	private DataType getVirtualBaseTablePointerDataType(RecordNumber recordNumber)
			throws PdbException {
		DataType dataType = applicator.getDataType(recordNumber);
		if (dataType == null) {
			throw new PdbException("Type not processed for record: " + recordNumber);
		}
		return dataType;
	}

	private void addMembers(Composite composite, CppCompositeType myClassType,
			List<AbstractMemberMsType> msMembers, AbstractCompositeMsType type,
			List<DefaultPdbUniversalMember> myMembers)
			throws CancelledException, PdbException {
		ClassFieldAttributes.Access defaultAccess =
			(type instanceof AbstractClassMsType) ? ClassFieldAttributes.Access.PRIVATE
					: ClassFieldAttributes.Access.PUBLIC;
		for (int index = 0; index < msMembers.size(); index++) {
			applicator.checkCancelled();
			AbstractMemberMsType memberType = msMembers.get(index);
			DefaultPdbUniversalMember member =
				getNonStaticMember(composite, defaultAccess, memberType, index);
			DataType dt = member.getDataType().getDataType();
			myMembers.add(member);
			myClassType.addMember(member.getName(), dt, member.isZeroLengthArray(),
				member.getAttributes(), member.getOffset(), member.getComment());
		}
	}

	// Does not use applier... goes straight to vftptr type
	private void addVftPtrs(Composite composite, CppCompositeType myClassType,
			List<AbstractVirtualFunctionTablePointerMsType> msVftPtrs, AbstractCompositeMsType type,
			List<DefaultPdbUniversalMember> myMembers)
			throws CancelledException, PdbException {
		for (AbstractVirtualFunctionTablePointerMsType vftPtr : msVftPtrs) {
			applicator.checkCancelled();
			RecordNumber recordNumber = vftPtr.getPointerTypeRecordNumber();
			DataType dataType = applicator.getDataType(recordNumber);
			if (dataType == null) {
				throw new PdbException("Type not processed for record: " + recordNumber);
			}
			int offset = vftPtr.getOffset();
			String vftPtrMemberName = vftPtr.getName();
			DefaultPdbUniversalMember member =
				new DefaultPdbUniversalMember(vftPtrMemberName, dataType, offset);
			myMembers.add(member);
			myClassType.addVirtualFunctionTablePointer(member.getName(),
				member.getDataType().getDataType(), member.getOffset());
		}
	}

	/**
	 * Uses {@link DefaultPdbApplicator#getDataTypeOrSchedule(RecordNumber)}) on all underlying
	 *  types to ensure that the types get scheduled... and detects whether any types were not yet
	 *  available so that this composite type is denoted as not done.
	 * @param lists the lists of all underlying types
	 * @return {@code true} if all underlying types are already available
	 * @throws PdbException upon processing issue
	 * @throws CancelledException upon user cancellation
	 */
	private boolean precheckOrScheduleDependencies(FieldListTypeApplier.FieldLists lists)
			throws PdbException, CancelledException {
		boolean done = true;
		for (AbstractMsType base : lists.bases()) {
			applicator.checkCancelled();
			if (base instanceof AbstractBaseClassMsType bc) {
				RecordNumber recordNumber = bc.getBaseClassRecordNumber();
				DataType dt = applicator.getDataTypeOrSchedule(recordNumber);
				if (dt == null) {
					done = false;
				}
			}
			else if (base instanceof AbstractVirtualBaseClassMsType vbc) {
				RecordNumber recordNumber = vbc.getVirtualBasePointerRecordNumber();
				DataType dt = applicator.getDataTypeOrSchedule(recordNumber);
				if (dt == null) {
					done = false;
				}
				recordNumber = vbc.getBaseClassRecordNumber();
				dt = applicator.getDataTypeOrSchedule(recordNumber);
				if (dt == null) {
					done = false;
				}
			}
			else if (base instanceof AbstractIndirectVirtualBaseClassMsType ivbc) {
				RecordNumber recordNumber = ivbc.getVirtualBasePointerRecordNumber();
				DataType dt = applicator.getDataTypeOrSchedule(recordNumber);
				if (dt == null) {
					done = false;
				}
				recordNumber = ivbc.getBaseClassRecordNumber();
				dt = applicator.getDataTypeOrSchedule(recordNumber);
				if (dt == null) {
					done = false;
				}
			}
			else {
				throw new PdbException("Unhandled type: " + base.getClass().getSimpleName());
			}
		}
		for (AbstractMsType method : lists.methods()) {
			applicator.checkCancelled();
			if (method instanceof AbstractOneMethodMsType oneMethod) {
				RecordNumber recordNumber = oneMethod.getProcedureTypeRecordNumber();
				DataType dt = applicator.getDataTypeOrSchedule(recordNumber);
				if (dt == null) {
					done = false;
				}
			}
			else if (method instanceof AbstractOverloadedMethodMsType overloadedMethod) {
				RecordNumber recordNumber = overloadedMethod.getTypeMethodListRecordNumber();
				AbstractMsType msType = applicator.getTypeRecord(recordNumber);
				if (msType instanceof AbstractMethodListMsType methodList) {
					List<AbstractMethodRecordMs> methodRecords = methodList.getList();
					for (AbstractMethodRecordMs methodRecord : methodRecords) {
						recordNumber = methodRecord.getProcedureTypeRecordNumber();
						DataType dt = applicator.getDataTypeOrSchedule(recordNumber);
						if (dt == null) {
							done = false;
						}
					}
				}
			}
			else {
				throw new PdbException("Unhandled type: " + method.getClass().getSimpleName());
			}
		}
		// Might cause problems, so remove until understood and possibly needed
//		for (AbstractNestedTypeMsType nested : lists.nestedTypes()) {
//			applicator.checkCancelled();
//			RecordNumber recordNumber = nested.getNestedTypeDefinitionRecordNumber();
//			DataType dt = applicator.getDataTypeOrSchedule(recordNumber);
//			if (dt == null) {
//				done = false;
//			}
//		}
		for (AbstractMemberMsType nonstaticMember : lists.nonstaticMembers()) {
			applicator.checkCancelled();
			RecordNumber recordNumber = nonstaticMember.getFieldTypeRecordNumber();
			DataType dt = applicator.getDataTypeOrSchedule(recordNumber);
			if (dt == null) {
				done = false;
			}
		}
		for (AbstractStaticMemberMsType staticMember : lists.staticMembers()) {
			applicator.checkCancelled();
			RecordNumber recordNumber = staticMember.getFieldTypeRecordNumber();
			DataType dt = applicator.getDataTypeOrSchedule(recordNumber);
			if (dt == null) {
				done = false;
			}
		}

		// Not doing enumerates for now... look at EnumTypeApplier, too, regarding how to deal
		//  with not storing a type with applicator.putDataType and yet getting removed from or
		//  not being added to the "todo" schedule.
//		for (AbstractEnumerateMsType enumerate : lists.enumerates()) {
//			applicator.checkCancelled();
//			RecordNumber recordNumber = enumerate.getRecordNumber();
//			DataType dt = applicator.getDataTypeOrSchedule(recordNumber);
//			if (dt == null) {
//				done = false;
//			}
//		}
		for (AbstractVirtualFunctionTablePointerMsType msVftPtr : lists.vftPtrs()) {
			applicator.checkCancelled();
			RecordNumber recordNumber = msVftPtr.getPointerTypeRecordNumber();
			DataType dt = applicator.getDataTypeOrSchedule(recordNumber);
			if (dt == null) {
				done = false;
			}
		}
		return done;
	}

	private DefaultPdbUniversalMember getNonStaticMember(Composite container,
			Access defaultAccess, AbstractMemberMsType memberMsType, int ordinal)
			throws CancelledException, PdbException {

		MsTypeApplier applier = applicator.getTypeApplier(memberMsType);
		if (!(applier instanceof MemberTypeApplier memberApplier)) {
			throw new PdbException("Member applier expected");
		}

		String memberName = memberMsType.getName();
		int offset = applicator.bigIntegerToInt(memberMsType.getOffset());

		ClassFieldMsAttributes memberAttributes = memberMsType.getAttribute();
		memberAttributes.getAccess(); // TODO: do something with this and other attributes

		RecordNumber typeRecordNumber = memberMsType.getFieldTypeRecordNumber();
		AbstractMsType fieldType = applicator.getTypeRecord(typeRecordNumber);
		MsTypeApplier fieldApplier = applicator.getTypeApplier(fieldType);

		String memberComment = null;
		RecordNumber fieldRecordNumber = memberMsType.getFieldTypeRecordNumber();
		DataType fieldDataType = applicator.getDataType(fieldRecordNumber);
		if (fieldDataType == null) {
			throw new PdbException("Type not processed for record: " + fieldRecordNumber);
		}
		else if (fieldApplier instanceof PointerTypeApplier ptrApplier) {
			// The above placeholder could be a pointer, but then we wouldn't be getting
			//  a comment here anyways, so the "else" is perfect... we don't want to overwrite
			//  the placeholder comment
			AbstractPointerMsType pointerType = (AbstractPointerMsType) fieldType;
			memberComment = ptrApplier.getPointerCommentField(pointerType);
		}

		boolean isZeroLengthArray = (fieldDataType instanceof Array &&
			fieldApplier instanceof ArrayTypeApplier arrayApplier &&
			arrayApplier.isFlexibleArray(fieldType));

		DefaultPdbUniversalMember member = new DefaultPdbUniversalMember(memberName, fieldDataType,
			isZeroLengthArray, offset,
			ClassFieldAttributes.convert(memberAttributes, defaultAccess), memberComment);
		return member;
	}

	// Not yet working: not sure of the work we will do
	private void processEnumerate(AbstractCompositeMsType type, EnumerateTypeApplier applier,
			AbstractEnumerateMsType enumerateType) {
		String fieldName = enumerateType.getName();
		Numeric numeric = enumerateType.getNumeric();
		// TODO: some work
		pdbLogAndInfoMessage(this, "Don't know how to apply EnumerateTypeApplier fieldName " +
			fieldName + " and value " + numeric + ".");
	}

	// Not yet working: not sure of the work we will do
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

	//==============================================================================================
	boolean apply(AbstractCompositeMsType type) throws CancelledException, PdbException {

		RecordNumber recordNumber = type.getRecordNumber();

		AbstractMsType msType = applicator.getMappedTypeRecord(recordNumber);
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
			// Since we are delaying resolve, we should be able to store this data type earlier...
			//  which is what I'm now doing before applyInternal().  This should save doing some
			//  fixups (e.g., where my ball of types wants a pointer to this particular type).
			// Composite is only type that we store before it is finished... this does cycle-break
			//  in two ways...
			//  1) from the data type perspective, a pointer can always find the underlying type
			//    if it is a composite, thus whatever cycles can be created from composites are
			//    taken care of
			//  2) from a processing perspective, we allow dependencies to get trickled up on the
			//    processing todo stack if they are not found in the applicator map.  This could
			//    cause processing oscillation because of dependencies, but since we push the
			//    type here, it will always be found in the map and never trickled upward
			applicator.putDataType(msType, composite);
		}
		else {
			composite = myClassType.getComposite();
			combo = new ComboType(composite, myClassType);
		}

		return applyInternal(combo, type);
	}

	private AbstractCompositeMsType getDefinitionType(AbstractComplexMsType type) {
		return getDefinitionType(type, AbstractCompositeMsType.class);
	}

}
