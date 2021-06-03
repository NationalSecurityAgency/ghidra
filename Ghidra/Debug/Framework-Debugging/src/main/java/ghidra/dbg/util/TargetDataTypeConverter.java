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
package ghidra.dbg.util;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import java.util.stream.Collectors;

import ghidra.async.AsyncFence;
import ghidra.dbg.attributes.*;
import ghidra.dbg.target.TargetDataTypeMember;
import ghidra.dbg.target.TargetNamedDataType;
import ghidra.dbg.util.PathUtils.TargetObjectKeyComparator;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

public class TargetDataTypeConverter {
	protected static class ConvertedMember {
		protected final TargetDataTypeMember member;
		protected final DataType type;

		public ConvertedMember(TargetDataTypeMember member, DataType type) {
			this.member = member;
			this.type = type;
		}
	}

	protected abstract static class TwoPhased<T> {
		public static <T> TwoPhased<T> completedTwo(T val) {
			TwoPhased<T> result = new TwoPhased<>() {
				@Override
				protected void doStart() {
					completeOne(val);
					completeTwo();
				}
			};
			result.start();
			return result;
		}

		protected final CompletableFuture<T> one = new CompletableFuture<>();
		protected final CompletableFuture<T> two = new CompletableFuture<>();

		protected final Set<TwoPhased<?>> deps = new HashSet<>();

		protected boolean started = false;

		public void start() {
			synchronized (this) {
				if (started) {
					return;
				}
				started = true;
			}
			doStart();
		}

		protected abstract void doStart();

		protected void chainExc(CompletableFuture<?> chain) {
			chain.exceptionally(ex -> {
				completeExceptionally(ex);
				return null;
			});
		}

		protected void chainExc(TwoPhased<?> chain) {
			chainExc(chain.one);
			chainExc(chain.two);
		}

		public void completeOne(T val) {
			one.complete(val);
		}

		public void completeTwo() {
			if (!one.isDone()) {
				throw new IllegalStateException("Phase one hasn't completed");
			}
			try {
				two.complete(one.get());
			}
			catch (InterruptedException e) {
				throw new AssertionError(e);
			}
			catch (ExecutionException e) {
				two.completeExceptionally(e.getCause());
			}
		}

		public void completeExceptionally(Throwable ex) {
			one.completeExceptionally(ex);
			two.completeExceptionally(ex);
		}

		public <U> TwoPhased<U> thenApply(Function<? super T, ? extends U> func) {
			TwoPhased<T> tp = this;
			return new TwoPhased<>() {
				@Override
				protected void doStart() {
					deps.add(tp);
					chainExc(tp.one.thenAccept(t -> completeOne(func.apply(t))));
					chainExc(tp.two.thenAccept(__ -> completeTwo()));
				}
			};
		}

		private void collectDeps(Set<TwoPhased<?>> allDeps) {
			for (TwoPhased<?> d : deps) {
				if (allDeps.add(d)) {
					d.collectDeps(allDeps);
				}
			}
		}

		protected CompletableFuture<T> depTwos() {
			Set<TwoPhased<?>> allDeps = new HashSet<>();
			collectDeps(allDeps);
			return CompletableFuture
					.allOf(allDeps.stream().map(tp -> tp.two).toArray(CompletableFuture[]::new))
					.thenCompose(__ -> two);
		}
	}

	protected final DataTypeManager dtm;
	protected final Map<TargetDataType, TwoPhased<? extends DataType>> types = new HashMap<>();

	protected boolean explainedOffsetDisagreement = false;

	protected class TwoPhasedComposite<T extends CompositeDataTypeImpl>
			extends TwoPhased<T> {

		protected final T type;
		protected final TargetNamedDataType tNamed;

		protected final Map<String, ConvertedMember> subs =
			new TreeMap<>(TargetObjectKeyComparator.ELEMENT);

		public TwoPhasedComposite(T type, TargetNamedDataType tNamed) {
			this.type = type;
			this.tNamed = tNamed;
		}

		@Override
		protected synchronized void doStart() {
			one.complete(type);
			try {
				chainExc(tNamed.getMembers().thenAccept(this::procMembers));
			}
			catch (Throwable e) {
				completeExceptionally(e);
			}
		}

		private void procMembers(Collection<? extends TargetDataTypeMember> members) {
			// TODO: Figure out attributes 
			AsyncFence fence = new AsyncFence();
			for (TargetDataTypeMember f : members) {
				TwoPhased<? extends DataType> dep = convertTwoPhased(f.getDataType());
				deps.add(dep);
				fence.include(dep.two.thenAccept(tField -> {
					subs.put(f.getIndex(), new ConvertedMember(f, tField));
				}));
			}
			chainExc(fence.ready().thenAccept(this::procSubs));
		}

		protected void procSubs(Void __) {
			for (Map.Entry<String, ConvertedMember> s : subs.entrySet()) {
				ConvertedMember conv = s.getValue();
				DataTypeComponent component =
					type.add(conv.type, -1, conv.member.getMemberName(), null);
				long fOff = conv.member.getOffset();
				int cOff = component.getOffset();
				if (fOff != -1 && fOff != cOff) {
					Msg.warn(this, "Offset disagreement during conversion of " +
						conv.member + ". " + fOff + " != " + cOff);
					explainOffsetDisagreement();
				}
			}
			completeTwo();
		}
	}

	public TargetDataTypeConverter() {
		this(null);
	}

	public TargetDataTypeConverter(DataTypeManager dtm) {
		this.dtm = dtm;
	}

	protected synchronized void explainOffsetDisagreement() {
		if (!explainedOffsetDisagreement) {
			explainedOffsetDisagreement = true;
			Msg.warn(this, "Offset disagreement happens likely because the destination " +
				"data type manager has a pointer size different than the source target.");
		}
	}

	public CompletableFuture<? extends DataType> convertTargetDataType(TargetDataType type) {
		return convertTwoPhased(type).depTwos();
	}

	protected TwoPhased<? extends DataType> convertTwoPhased(TargetDataType type) {
		TwoPhased<? extends DataType> conv;
		synchronized (types) {
			conv = types.get(type);
			if (conv != null) {
				return conv;
			}
			conv = doConvertTargetDataType(type);
			types.put(type, conv);
		}
		conv.start();
		return conv;
	}

	/**
	 * TODO
	 * 
	 * Diagnostic only, please.
	 * 
	 * @return
	 */
	public Set<TargetDataType> getPendingOne() {
		synchronized (types) {
			return types.entrySet()
					.stream()
					.filter(e -> !e.getValue().one.isDone())
					.map(e -> e.getKey())
					.collect(Collectors.toSet());
		}
	}

	/**
	 * TODO
	 * 
	 * Diagnostic only, please.
	 * 
	 * @return
	 */
	public Set<TargetDataType> getPendingTwo() {
		synchronized (types) {
			return types.entrySet()
					.stream()
					.filter(e -> !e.getValue().two.isDone())
					.map(e -> e.getKey())
					.collect(Collectors.toSet());
		}
	}

	protected TwoPhased<? extends DataType> doConvertTargetDataType(TargetDataType type) {
		if (type instanceof TargetNamedDataType) {
			TargetNamedDataType tNamed = (TargetNamedDataType) type;
			return convertTargetNamedDataType(tNamed);
		}
		if (type instanceof TargetArrayDataType) {
			TargetArrayDataType tArray = (TargetArrayDataType) type;
			return convertTargetArrayDataType(tArray);
		}
		if (type instanceof TargetBitfieldDataType) {
			TargetBitfieldDataType tBitfield = (TargetBitfieldDataType) type;
			return convertTargetBitfieldDataType(tBitfield);
		}
		if (type instanceof TargetPointerDataType) {
			TargetPointerDataType tPointer = (TargetPointerDataType) type;
			return convertTargetPointerDataType(tPointer);
		}
		if (type instanceof TargetPrimitiveDataType) {
			TargetPrimitiveDataType tPrimitive = (TargetPrimitiveDataType) type;
			return convertTargetPrimitiveDataType(tPrimitive);
		}
		throw new AssertionError("Do not know how to convert " + type);
	}

	protected TwoPhased<? extends DataType> convertTargetNamedDataType(
			TargetNamedDataType type) {
		/**
		 * NOTE: Convention is named data types are each indexed (in the parent namespace) with its
		 * defining keyword (or something close), e.g., "struct myStruct", not just "myStruct".
		 * Whatever the case, the actual type name cannot contain spaces and should be the final
		 * space-separated token in its index. It can be the sole token, but the index must be
		 * unique within the namespace.
		 */
		String parts[] = type.getIndex().split("\\s+");
		String name = parts[parts.length - 1];
		switch (type.getTypeKind()) {
			case ENUM:
				return convertTargetEnumDataType(name, type);
			case FUNCTION:
				return convertTargetFunctionDataType(name, type);
			case STRUCT:
				return convertTargetStructDataType(name, type);
			case TYPEDEF:
				return convertTargetTypedefDataType(name, type);
			case UNION:
				return convertTargetUnionDataType(name, type);
			default:
				throw new AssertionError("Do not know how to convert " + type);
		}
	}

	protected TwoPhased<EnumDataType> convertTargetEnumDataType(String name,
			TargetNamedDataType tEnum) {
		return new TwoPhased<>() {
			final EnumDataType type =
				new EnumDataType(CategoryPath.ROOT, name, tEnum.getTypedAttributeNowByName(
					TargetNamedDataType.ENUM_BYTE_LENGTH_ATTRIBUTE_NAME, Integer.class, 4), dtm);

			@Override
			protected void doStart() {
				completeOne(type);
				chainExc(tEnum.getMembers().thenAccept(this::procMembers));
			}

			private void procMembers(Collection<? extends TargetDataTypeMember> members) {
				for (TargetDataTypeMember c : members) {
					type.add(c.getMemberName(), c.getPosition());
				}
				completeTwo();
			}
		};
	}

	protected TwoPhased<FunctionDefinitionDataType> convertTargetFunctionDataType(String name,
			TargetNamedDataType tFunction) {
		return new TwoPhased<>() {
			final Map<String, ParameterDefinitionImpl> args =
				new TreeMap<>(TargetObjectKeyComparator.ELEMENT);
			final FunctionDefinitionDataType type =
				new FunctionDefinitionDataType(name, dtm);

			@Override
			protected void doStart() {
				completeOne(type);
				chainExc(tFunction.getMembers().thenAccept(this::procMembers));
			}

			private void procMembers(Collection<? extends TargetDataTypeMember> members) {
				AsyncFence fence = new AsyncFence();
				for (TargetDataTypeMember p : members) {
					TwoPhased<? extends DataType> dep = convertTwoPhased(p.getDataType());
					deps.add(dep);
					fence.include(dep.two.thenAccept(t -> {
						if (TargetNamedDataType.FUNCTION_RETURN_INDEX.equals(p.getIndex())) {
							type.setReturnType(t);
						}
						else {
							args.put(p.getIndex(),
								new ParameterDefinitionImpl(p.getMemberName(), t, null));
						}
					}));
				}
				chainExc(fence.ready().thenAccept(this::procArgs));
			}

			private void procArgs(Void __) {
				type.setArguments(args.values().toArray(new ParameterDefinitionImpl[args.size()]));
				completeTwo();
			}
		};
	}

	protected TwoPhased<StructureDataType> convertTargetStructDataType(String name,
			TargetNamedDataType tStruct) {
		return new TwoPhasedComposite<>(new StructureDataType(name, 0, dtm), tStruct);
	}

	protected TwoPhased<UnionDataType> convertTargetUnionDataType(String name,
			TargetNamedDataType tUnion) {
		return new TwoPhasedComposite<>(new UnionDataType(CategoryPath.ROOT, name, dtm), tUnion);
	}

	protected TwoPhased<TypedefDataType> convertTargetTypedefDataType(String name,
			TargetNamedDataType tTypedef) {
		return new TwoPhased<>() {
			@Override
			protected void doStart() {
				chainExc(tTypedef.getMembers().thenAccept(this::procMembers));
			}

			private void procMembers(Collection<? extends TargetDataTypeMember> members) {
				if (members.isEmpty()) {
					Msg.warn(this, "Typedef did not provide definition. Defaulting.");
					procDef(DataType.DEFAULT);
					procTwo(null);
					return;
				}
				if (members.size() != 1) {
					Msg.warn(this, "Typedef provided multiple definitions. Taking first.");
				}
				TargetDataTypeMember d = members.iterator().next();
				TwoPhased<? extends DataType> dep = convertTwoPhased(d.getDataType());
				deps.add(dep);
				chainExc(dep.one.thenAccept(this::procDef));
				chainExc(dep.two.thenAccept(this::procTwo));
			}

			private void procDef(DataType cDef) {
				completeOne(new TypedefDataType(CategoryPath.ROOT, name, cDef, dtm));
			}

			private void procTwo(DataType __) {
				completeTwo();
			}
		};
	}

	protected TwoPhased<ArrayDataType> convertTargetArrayDataType(
			TargetArrayDataType tArray) {
		return convertTwoPhased(tArray.getElementType()).thenApply(cElem -> {
			return new ArrayDataType(cElem, tArray.getElementCount(), cElem.getLength(), dtm);
		});
	}

	protected static class ConvertedTargetBitfieldDataType extends BitFieldDataType {
		protected ConvertedTargetBitfieldDataType(DataType baseDataType, int bitSize, int bitOffset)
				throws InvalidDataTypeException {
			super(baseDataType, bitSize, bitOffset);
		}
	}

	protected TwoPhased<ConvertedTargetBitfieldDataType> convertTargetBitfieldDataType(
			TargetBitfieldDataType tBitfield) {
		return convertTwoPhased(tBitfield.getFieldType()).thenApply(cField -> {
			// TODO: Test these on the reference SCTL implementation.
			// There's probably corrections on both sides of this interface
			try {
				return new ConvertedTargetBitfieldDataType(cField, tBitfield.getBitLength(),
					tBitfield.getLeastBitPosition());
			}
			catch (InvalidDataTypeException e) {
				throw new AssertionError(e);
			}
		});
	}

	protected TwoPhased<PointerDataType> convertTargetPointerDataType(
			TargetPointerDataType tPointer) {
		TwoPhased<PointerDataType> cPointer =
			convertTwoPhased(tPointer.getReferentType()).thenApply(cRef -> {
				return new PointerDataType(cRef, dtm);
			});
		// The pointer can complete even though the referent is incomplete
		cPointer.one.thenAccept(__ -> cPointer.completeTwo());
		return cPointer;
	}

	protected TwoPhased<DataType> convertTargetPrimitiveDataType(
			TargetPrimitiveDataType tPrimitive) {
		return TwoPhased.completedTwo(doConvertTargetPrimitiveDataType(tPrimitive));
	}

	protected DataType doConvertTargetPrimitiveDataType(TargetPrimitiveDataType tPrimitive) {
		switch (tPrimitive.getKind()) {
			case UNDEFINED:
				return Undefined.getUndefinedDataType(tPrimitive.getLength());
			case VOID:
				if (tPrimitive.getLength() != 0) {
					Msg.warn(this, "Ignoring non-zero length for void data type");
				}
				return VoidDataType.dataType;
			case UINT:
				return AbstractIntegerDataType.getUnsignedDataType(tPrimitive.getLength(), dtm);
			case SINT:
				return AbstractIntegerDataType.getSignedDataType(tPrimitive.getLength(), dtm);
			case FLOAT:
				return AbstractFloatDataType.getFloatDataType(tPrimitive.getLength(), dtm);
			case COMPLEX:
				return AbstractComplexDataType.getComplexDataType(tPrimitive.getLength(), dtm);
		}
		throw new IllegalArgumentException("Do not know how to convert " + tPrimitive);
	}
}
