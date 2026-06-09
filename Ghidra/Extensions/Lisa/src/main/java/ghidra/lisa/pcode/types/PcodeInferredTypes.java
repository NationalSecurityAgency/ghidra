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
package ghidra.lisa.pcode.types;

import static org.apache.commons.collections4.CollectionUtils.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import ghidra.lisa.pcode.locations.PcodeLocation;
import ghidra.program.model.pcode.PcodeOp;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.lattices.Satisfiability;
import it.unive.lisa.analysis.nonrelational.value.BaseNonRelationalTypeDomain;
import it.unive.lisa.analysis.nonrelational.value.TypeEnvironment;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.symbolic.value.*;
import it.unive.lisa.symbolic.value.operator.binary.BinaryOperator;
import it.unive.lisa.symbolic.value.operator.binary.TypeCast;
import it.unive.lisa.symbolic.value.operator.ternary.TernaryOperator;
import it.unive.lisa.symbolic.value.operator.unary.UnaryOperator;
import it.unive.lisa.type.*;
import it.unive.lisa.util.representation.*;

public class PcodeInferredTypes implements BaseNonRelationalTypeDomain<PcodeInferredTypes> {

	private static final PcodeInferredTypes BOTTOM =
		new PcodeInferredTypes(null, Collections.emptySet());

	private final Set<Type> elements;

	private final boolean isTop;

	/**
	 * Builds the inferred types. The object built through this constructor
	 * represents an empty set of types.
	 */
	public PcodeInferredTypes() {
		this(null, (Set<Type>) null);
	}

	/**
	 * Builds the inferred types, representing only the given {@link Type}.
	 * 
	 * @param typeSystem the type system knowing about the types of the program
	 *                       where this element is created
	 * @param type       the type to be included in the set of inferred types
	 */
	public PcodeInferredTypes(
			TypeSystem typeSystem,
			Type type) {
		this(typeSystem, Collections.singleton(type));
	}

	/**
	 * Builds the inferred types, representing only the given set of
	 * {@link Type}s.
	 * 
	 * @param typeSystem the type system knowing about the types of the program
	 *                       where this element is created
	 * @param types      the types to be included in the set of inferred types
	 */
	public PcodeInferredTypes(
			TypeSystem typeSystem,
			Set<Type> types) {
		this(typeSystem != null && types.equals(typeSystem.getTypes()), types);
	}

	/**
	 * Builds the inferred types, representing only the given set of
	 * {@link Type}s.
	 * 
	 * @param isTop whether or not the set of types represents all possible
	 *                  types
	 * @param types the types to be included in the set of inferred types
	 */
	public PcodeInferredTypes(
			boolean isTop,
			Set<Type> types) {
		this.elements = types;
		this.isTop = isTop;
	}

	@Override
	public Set<Type> getRuntimeTypes() {
		if (elements == null)
			Collections.emptySet();
		return elements;
	}

	@Override
	public PcodeInferredTypes top() {
		return new PcodeInferredTypes(true, null);
	}

	@Override
	public boolean isTop() {
		return BaseNonRelationalTypeDomain.super.isTop() || isTop;
	}

	@Override
	public PcodeInferredTypes bottom() {
		return BOTTOM;
	}

	@Override
	public boolean isBottom() {
		return BaseNonRelationalTypeDomain.super.isBottom() || BOTTOM.elements.equals(elements);
	}

	@Override
	public String toString() {
		return representation().toString();
	}

	@Override
	public StructuredRepresentation representation() {
		if (isTop())
			return Lattice.topRepresentation();

		if (isBottom())
			return Lattice.bottomRepresentation();

		return new SetRepresentation(elements, StringRepresentation::new);
	}

	@Override
	public PcodeInferredTypes evalIdentifier(
			Identifier id,
			TypeEnvironment<PcodeInferredTypes> environment,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		PcodeInferredTypes eval =
			BaseNonRelationalTypeDomain.super.evalIdentifier(id, environment, pp, oracle);
		if (!eval.isTop())
			return eval;
		TypeSystem types = pp.getProgram().getTypes();
		return new PcodeInferredTypes(types, id.getStaticType().allInstances(types));
	}

	@Override
	public PcodeInferredTypes evalPushAny(
			PushAny pushAny,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		TypeSystem types = pp.getProgram().getTypes();
		if (pushAny.getStaticType().isUntyped())
			return new PcodeInferredTypes(true, types.getTypes());
		return new PcodeInferredTypes(types, pushAny.getStaticType().allInstances(types));
	}

	@Override
	public PcodeInferredTypes evalPushInv(
			PushInv pushInv,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		return bottom();
	}

	@Override
	public PcodeInferredTypes evalNullConstant(
			ProgramPoint pp,
			SemanticOracle oracle) {
		return new PcodeInferredTypes(pp.getProgram().getTypes(), NullType.INSTANCE);
	}

	@Override
	public PcodeInferredTypes evalNonNullConstant(
			Constant constant,
			ProgramPoint pp,
			SemanticOracle oracle) {
		return new PcodeInferredTypes(pp.getProgram().getTypes(), constant.getStaticType());
	}

	@Override
	public PcodeInferredTypes evalUnaryExpression(
			UnaryOperator operator,
			PcodeInferredTypes arg,
			ProgramPoint pp,
			SemanticOracle oracle) {
		TypeSystem types = pp.getProgram().getTypes();
		Set<Type> elems = arg.isTop() ? types.getTypes() : arg.elements;
		Set<Type> inferred = operator.typeInference(types, elems);
		if (inferred.isEmpty())
			return BOTTOM;
		return new PcodeInferredTypes(types, inferred);
	}

	@Override
	public PcodeInferredTypes evalBinaryExpression(
			BinaryOperator operator,
			PcodeInferredTypes left,
			PcodeInferredTypes right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		TypeSystem types = pp.getProgram().getTypes();
		Set<Type> lelems = left.isTop() ? types.getTypes() : left.elements;
		Set<Type> relems = right.isTop() ? types.getTypes() : right.elements;
		Set<Type> inferred = operator.typeInference(types, lelems, relems);
		if (inferred.isEmpty())
			return BOTTOM;
		return new PcodeInferredTypes(types, inferred);
	}

	@Override
	public PcodeInferredTypes evalTernaryExpression(
			TernaryOperator operator,
			PcodeInferredTypes left,
			PcodeInferredTypes middle,
			PcodeInferredTypes right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		TypeSystem types = pp.getProgram().getTypes();
		Set<Type> lelems = left.isTop() ? types.getTypes() : left.elements;
		Set<Type> melems = middle.isTop() ? types.getTypes() : middle.elements;
		Set<Type> relems = right.isTop() ? types.getTypes() : right.elements;
		Set<Type> inferred = operator.typeInference(types, lelems, melems, relems);
		if (inferred.isEmpty())
			return BOTTOM;
		return new PcodeInferredTypes(types, inferred);
	}

	@Override
	public Satisfiability satisfiesBinaryExpression(
			BinaryOperator operator,
			PcodeInferredTypes left,
			PcodeInferredTypes right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		TypeSystem types = pp.getProgram().getTypes();
		Set<Type> lelems = left.isTop() ? types.getTypes() : left.elements;
		Set<Type> relems = right.isTop() ? types.getTypes() : right.elements;
		PcodeLocation ploc = (PcodeLocation) pp.getLocation();
		PcodeOp op = ploc.op;
		int opcode = op.getOpcode();
		if (opcode == PcodeOp.INT_EQUAL || opcode == PcodeOp.FLOAT_EQUAL ||
			opcode == PcodeOp.INT_NOTEQUAL || opcode == PcodeOp.FLOAT_NOTEQUAL) {
			Set<Type> lfiltered =
				lelems.stream().filter(Type::isTypeTokenType).collect(Collectors.toSet());
			Set<Type> rfiltered =
				relems.stream().filter(Type::isTypeTokenType).collect(Collectors.toSet());

			if (lelems.size() != lfiltered.size() || relems.size() != rfiltered.size())
				// if there is at least one element that is not a type
				// token, than we cannot reason about it
				return Satisfiability.UNKNOWN;

			if (opcode == PcodeOp.INT_EQUAL || opcode == PcodeOp.FLOAT_EQUAL) {
				if (lelems.size() == 1 && lelems.equals(relems))
					// only one element, and it is the same
					return Satisfiability.SATISFIED;
				else if (intersection(lelems, relems).isEmpty() &&
					!typeTokensIntersect(lfiltered, rfiltered))
					// no common elements, they cannot be equal
					return Satisfiability.NOT_SATISFIED;
				else
					// we don't know really
					return Satisfiability.UNKNOWN;
			}
			if (intersection(lelems, relems).isEmpty() &&
				!typeTokensIntersect(lfiltered, rfiltered))
				// no common elements, they cannot be equal
				return Satisfiability.SATISFIED;
			else if (lelems.size() == 1 && lelems.equals(relems))
				// only one element, and it is the same
				return Satisfiability.NOT_SATISFIED;
			else
				// we don't know really
				return Satisfiability.UNKNOWN;

		}
		else if (opcode == PcodeOp.CAST) {
			if (evalBinaryExpression(TypeCast.INSTANCE, left, right, pp, oracle).isBottom())
				// no common types, the check will always fail
				return Satisfiability.NOT_SATISFIED;
			AtomicBoolean mightFail = new AtomicBoolean();
			Set<Type> set = types.cast(lelems, relems, mightFail);
			if (lelems.equals(set) && !mightFail.get())
				// if all the types stayed in 'set' then the there is no
				// execution that reach the expression with a type that cannot
				// be casted, and thus this is a tautology
				return Satisfiability.SATISFIED;

			// sometimes yes, sometimes no
			return Satisfiability.UNKNOWN;
		}
		return Satisfiability.UNKNOWN;
	}

	/**
	 * Checks whether or not the two given set of type tokens intersects,
	 * meaning that there exists at least one type token {@code t1} from
	 * {@code lfiltered} and one type token {@code t2} from {@code rfiltered}
	 * such that {@code t1.getTypes().intersects(t2.getTypes())}.<br>
	 * <br>
	 * Note that all types in both sets received as parameters are assumed to be
	 * {@link TypeTokenType}s, hence no type check is performed before
	 * converting them.
	 * 
	 * @param lfiltered the first set of type tokens
	 * @param rfiltered the second set of type tokens
	 * 
	 * @return {@code true} if the sets of tokens intersect
	 * 
	 * @throws NullPointerException if one of the types is not a
	 *                                  {@link TypeTokenType} (this is due to
	 *                                  the conversion)
	 */
	static boolean typeTokensIntersect(
			Set<Type> lfiltered,
			Set<Type> rfiltered) {
		for (Type l : lfiltered)
			for (Type r : rfiltered)
				if (!intersection(l.asTypeTokenType().getTypes(), r.asTypeTokenType().getTypes())
						.isEmpty())
					return true;

		return false;
	}

	@Override
	public PcodeInferredTypes lubAux(
			PcodeInferredTypes other)
			throws SemanticException {
		Set<Type> lub = new HashSet<>(elements);
		lub.addAll(other.elements);
		return new PcodeInferredTypes(null, lub);
	}

	@Override
	public boolean lessOrEqualAux(
			PcodeInferredTypes other)
			throws SemanticException {
		return other.elements.containsAll(elements);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((elements == null) ? 0 : elements.hashCode());
		result = prime * result + (isTop ? 1231 : 1237);
		return result;
	}

	@Override
	public boolean equals(
			Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		PcodeInferredTypes other = (PcodeInferredTypes) obj;
		if (elements == null) {
			if (other.elements != null)
				return false;
		}
		else if (!elements.equals(other.elements))
			return false;
		if (isTop != other.isTop)
			return false;
		return true;
	}

	@Override
	public PcodeInferredTypes evalTypeCast(
			BinaryExpression cast,
			PcodeInferredTypes left,
			PcodeInferredTypes right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		TypeSystem types = pp.getProgram().getTypes();
		Set<Type> lelems = left.isTop() ? types.getTypes() : left.elements;
		Set<Type> relems = right.isTop() ? types.getTypes() : right.elements;
		Set<Type> inferred = cast.getOperator().typeInference(types, lelems, relems);
		if (inferred.isEmpty())
			return BOTTOM;
		return new PcodeInferredTypes(types, inferred);
	}

	@Override
	public PcodeInferredTypes evalTypeConv(
			BinaryExpression conv,
			PcodeInferredTypes left,
			PcodeInferredTypes right,
			ProgramPoint pp,
			SemanticOracle oracle) {
		TypeSystem types = pp.getProgram().getTypes();
		Set<Type> lelems = left.isTop() ? types.getTypes() : left.elements;
		Set<Type> relems = right.isTop() ? types.getTypes() : right.elements;
		Set<Type> inferred = conv.getOperator().typeInference(types, lelems, relems);
		if (inferred.isEmpty())
			return BOTTOM;
		return new PcodeInferredTypes(types, inferred);
	}
}
