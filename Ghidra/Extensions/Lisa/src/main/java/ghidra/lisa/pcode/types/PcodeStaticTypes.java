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

import java.util.Collections;
import java.util.Set;

import ghidra.lisa.pcode.statements.PcodeBinaryOperator;
import ghidra.program.model.pcode.PcodeOp;
import it.unive.lisa.analysis.*;
import it.unive.lisa.analysis.lattices.Satisfiability;
import it.unive.lisa.analysis.nonrelational.inference.InferredValue;
import it.unive.lisa.analysis.nonrelational.value.BaseNonRelationalTypeDomain;
import it.unive.lisa.analysis.nonrelational.value.TypeEnvironment;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.program.cfg.statement.Expression;
import it.unive.lisa.symbolic.value.*;
import it.unive.lisa.symbolic.value.operator.binary.BinaryOperator;
import it.unive.lisa.type.*;
import it.unive.lisa.util.representation.StringRepresentation;
import it.unive.lisa.util.representation.StructuredRepresentation;

/**
 * An {@link InferredValue} holding a set of {@link Type}s, representing the
 * inferred runtime types of an {@link Expression}.
 * 
 * <p>
 * @author <a href="mailto:luca.negrini@unive.it">Luca Negrini</a>
 */
public class PcodeStaticTypes implements BaseNonRelationalTypeDomain<PcodeStaticTypes> {

	private static final PcodeStaticTypes BOTTOM = new PcodeStaticTypes(null, null);

	private final Type type;

	private final TypeSystem types;

	/**
	 * Builds the inferred types. The object built through this constructor
	 * represents an empty set of types.
	 */
	public PcodeStaticTypes() {
		this(null, Untyped.INSTANCE);
	}

	/**
	 * Builds the inferred types, representing only the given {@link Type}.
	 * 
	 * @param types the type system knowing about the types of the program where
	 *                  this element is created
	 * @param type  the type to be included in the set of inferred types
	 */
	PcodeStaticTypes(
			TypeSystem types,
			Type type) {
		this.type = type;
		this.types = types;
	}

	@Override
	public Set<Type> getRuntimeTypes() {
		if (this.isBottom())
			Collections.emptySet();
		return type.allInstances(types);
	}

	@Override
	public PcodeStaticTypes top() {
		return new PcodeStaticTypes(types, Untyped.INSTANCE);
	}

	@Override
	public boolean isTop() {
		return type == Untyped.INSTANCE;
	}

	@Override
	public PcodeStaticTypes bottom() {
		return BOTTOM;
	}

	@Override
	public StructuredRepresentation representation() {
		if (isTop())
			return Lattice.topRepresentation();

		if (isBottom())
			return Lattice.bottomRepresentation();

		return new StringRepresentation(type.toString());
	}

	@Override
	public PcodeStaticTypes evalIdentifier(
			Identifier id,
			TypeEnvironment<PcodeStaticTypes> environment,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		PcodeStaticTypes eval =
			BaseNonRelationalTypeDomain.super.evalIdentifier(id, environment, pp, oracle);
		if (!eval.isTop() && !eval.isBottom())
			return eval;
		return new PcodeStaticTypes(pp.getProgram().getTypes(), id.getStaticType());
	}

	@Override
	public PcodeStaticTypes evalPushAny(
			PushAny pushAny,
			ProgramPoint pp,
			SemanticOracle oracle) {
		return new PcodeStaticTypes(pp.getProgram().getTypes(), pushAny.getStaticType());
	}

	@Override
	public PcodeStaticTypes evalPushInv(
			PushInv pushInv,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		return new PcodeStaticTypes(pp.getProgram().getTypes(), pushInv.getStaticType());
	}

	@Override
	public PcodeStaticTypes evalNullConstant(
			ProgramPoint pp,
			SemanticOracle oracle) {
		return new PcodeStaticTypes(pp.getProgram().getTypes(), NullType.INSTANCE);
	}

	@Override
	public PcodeStaticTypes evalNonNullConstant(
			Constant constant,
			ProgramPoint pp,
			SemanticOracle oracle) {
		return new PcodeStaticTypes(pp.getProgram().getTypes(), constant.getStaticType());
	}

	@Override
	public PcodeStaticTypes eval(
			ValueExpression expression,
			TypeEnvironment<PcodeStaticTypes> environment,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		if (expression instanceof BinaryExpression) {
			TypeSystem etypes = pp.getProgram().getTypes();
			BinaryExpression binary = (BinaryExpression) expression;
			if (binary.getOperator() instanceof PcodeBinaryOperator poperator) {
				PcodeOp op = poperator.getOp();
				int opcode = op.getOpcode();
				if (opcode == PcodeOp.CAST) {
					PcodeStaticTypes left = null, right = null;
					try {
						left = eval((ValueExpression) binary.getLeft(), environment, pp, oracle);
						right = eval((ValueExpression) binary.getRight(), environment, pp, oracle);
					}
					catch (ClassCastException e) {
						throw new SemanticException(expression + " is not a value expression");
					}
					Set<Type> lelems = left.type.allInstances(etypes);
					Set<Type> relems = right.type.allInstances(etypes);
					Set<Type> inferred = binary.getOperator().typeInference(etypes, lelems, relems);
					if (inferred.isEmpty())
						return BOTTOM;
					return new PcodeStaticTypes(pp.getProgram().getTypes(),
						Type.commonSupertype(inferred, Untyped.INSTANCE));
				}
			}
		}

		return new PcodeStaticTypes(pp.getProgram().getTypes(), expression.getStaticType());
	}

	@Override
	public Satisfiability satisfiesBinaryExpression(
			BinaryOperator operator,
			PcodeStaticTypes left,
			PcodeStaticTypes right,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		TypeSystem stypes = pp.getProgram().getTypes();
		Set<Type> lelems = left.type.allInstances(stypes);
		Set<Type> relems = right.type.allInstances(stypes);
		return new PcodeInferredTypes().satisfiesBinaryExpression(operator,
			new PcodeInferredTypes(stypes, lelems),
			new PcodeInferredTypes(stypes, relems), pp, oracle);
	}

	@Override
	public PcodeStaticTypes lubAux(
			PcodeStaticTypes other)
			throws SemanticException {
		return new PcodeStaticTypes(types, type.commonSupertype(other.type));
	}

	@Override
	public boolean lessOrEqualAux(
			PcodeStaticTypes other)
			throws SemanticException {
		return type.canBeAssignedTo(other.type);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((type == null) ? 0 : type.hashCode());
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
		PcodeStaticTypes other = (PcodeStaticTypes) obj;
		if (type == null) {
			if (other.type != null)
				return false;
		}
		else if (!type.equals(other.type))
			return false;
		return true;
	}
}
