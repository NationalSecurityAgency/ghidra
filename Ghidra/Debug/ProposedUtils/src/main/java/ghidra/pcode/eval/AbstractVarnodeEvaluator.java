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
package ghidra.pcode.eval;

import java.util.HashMap;
import java.util.Map;

import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.*;
import ghidra.pcode.opbehavior.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * An abstract implementation of {@link VarnodeEvaluator}
 * 
 * <p>
 * Unlike {@link PcodeExecutor} this abstract class is not explicitly bound to a p-code state nor
 * arithmetic. Instead it defines abstract methods for accessing "leaf" varnodes and evaluating ops.
 * To evaluate a varnode, it first checks if the varnode is a leaf, which is defined by an extension
 * class. If it is, it converts the static address to a dynamic one and invokes the appropriate
 * value getter. An extension class would likely implement those getters using a
 * {@link PcodeExecutorState}. If the varnode is not a leaf, the evaluator will ascend by examining
 * its defining p-code op, evaluate its input varnodes recursively and then compute the output using
 * the provided p-code arithmetic. This implementation maintains a map of evaluated varnodes and
 * their values so that any intermediate varnode is evaluated just once. Note that the evaluation
 * algorithm assumes their are no cycles in the AST, which should be the case by definition.
 *
 * @param <T> the type of values resulting from evaluation
 */
public abstract class AbstractVarnodeEvaluator<T> implements VarnodeEvaluator<T> {
	/**
	 * Concatenate the given values
	 * 
	 * @param sizeTotal the expected output size in bytes
	 * @param upper the value of the left (more significant) piece
	 * @param lower the value of the right (less significant) piece
	 * @param sizeLower the size of the lower piece
	 * @return the result of concatenation
	 */
	protected abstract T catenate(int sizeTotal, T upper, T lower, int sizeLower);

	/**
	 * Check if the given varnode is a leaf in the evaluation
	 * 
	 * <p>
	 * This allows the extension class to determine the base case when recursively ascending the
	 * AST.
	 * 
	 * @param vn the varnode
	 * @return true to treat the varnode as a base case, or false to ascend to its defining p-code
	 *         op
	 */
	protected abstract boolean isLeaf(Varnode vn);

	/**
	 * Resolve a (static) stack offset to its physical (dynamic) address in the frame
	 * 
	 * <p>
	 * When a leaf varnode is a stack address, this is used to map it to a physical address before
	 * invoking {@link #evaluateMemory(Address, int)}.
	 * 
	 * @param offset the offset
	 * @return the address in target memory
	 */
	protected abstract Address applyBase(long offset);

	/**
	 * Map the given static address to dynamic
	 * 
	 * <p>
	 * When a leaf varnode is a memory address, this is used to map it to a dynamic address before
	 * invoking {@link #evaluateMemory(Address, int)}. This is needed in case the module has been
	 * relocated in the dynamic context. Note this is not used to translate register or stack
	 * addresses, since those are abstract concepts. Stack addresses are translated using
	 * {@link #applyBase(long)}, the result of which should already be a dynamic address.
	 * 
	 * @param program the program specifying the static context
	 * @param address the address in the static context
	 * @return the address in the dynamic context
	 */
	protected Address translateMemory(Program program, Address address) {
		return address;
	}

	/**
	 * Evaluate a leaf varnode
	 * 
	 * <p>
	 * This method translates the varnode accordingly and delegates the evaluation, indirectly, to
	 * {@link #evaluateMemory(Address, int)}. Notable exceptions are constants, which are just
	 * evaluated to their immediate value, and unique variables, which cannot ordinarily be leaves.
	 * 
	 * @param program the program defining the static context
	 * @param vn the varnode
	 * @return the value obtained from the dynamic context
	 */
	protected T evaluateLeaf(Program program, Varnode vn) {
		Address address = vn.getAddress();
		if (address.isConstantAddress()) {
			return evaluateConstant(vn.getOffset(), vn.getSize());
		}
		else if (address.isRegisterAddress()) {
			return evaluateRegister(address, vn.getSize());
		}
		else if (address.isStackAddress()) {
			return evaluateStack(address.getOffset(), vn.getSize());
		}
		else if (address.isMemoryAddress()) {
			return evaluateMemory(translateMemory(program, address), vn.getSize());
		}
		else if (address.isUniqueAddress()) {
			return evaluateUnique(vn.getOffset(), vn.getSize());
		}
		else {
			throw new PcodeExecutionException("Unrecognized address space in " + vn);
		}
	}

	/**
	 * Evaluate a varnode, which could be either a leaf or a branch
	 * 
	 * <p>
	 * This method is invoked by {@link #evaluateVarnode(Program, Varnode, Map)} when the value has
	 * not already been computed. Only that method should invoke this one directly.
	 * 
	 * @param program the program defining the static context
	 * @param vn the varnode
	 * @param already a cache of already-evaluated varnodes and their values
	 * @return the value
	 */
	protected T doEvaluateVarnode(Program program, Varnode vn, Map<Varnode, T> already) {
		if (isLeaf(vn)) {
			return evaluateLeaf(program, vn);
		}
		return evaluateBranch(program, vn, already);
	}

	/**
	 * Evaluate a varnode, which could be either a leaf or a branch, taking its cached value if
	 * available
	 * 
	 * @param program the program defining the static context
	 * @param vn the varnode
	 * @param already a cache of already-evaluated varnodes and their values
	 * @return the value
	 */
	protected T evaluateVarnode(Program program, Varnode vn, Map<Varnode, T> already) {
		// computeIfAbsent does nto work because of the recursion. Will get CME.
		if (already.containsKey(vn)) {
			return already.get(vn);
		}
		T result = doEvaluateVarnode(program, vn, already);
		already.put(vn, result);
		return result;
	}

	/**
	 * Evaluate a varnode
	 * 
	 * @param program the program containing the varnode
	 * @param vn the varnode to evaluate
	 * @return the value of the varnode
	 */
	@Override
	public T evaluateVarnode(Program program, Varnode vn) {
		return evaluateVarnode(program, vn, new HashMap<>());
	}

	/**
	 * Evaluate variable storage, providing an "identity" value
	 * 
	 * @param program the program containing the variable storage
	 * @param storage the storage to evaluate
	 * @param identity the value if storage had no varnodes
	 * @return the value of the storage
	 */
	protected T evaluateStorage(Program program, VariableStorage storage, T identity) {
		int total = storage.size();
		T value = identity;
		for (Varnode vn : storage.getVarnodes()) {
			T piece = evaluateVarnode(program, vn);
			value = catenate(total, value, piece, vn.getSize());
		}
		return value;
	}

	/**
	 * Evaluate the given varnode's defining p-code op
	 * 
	 * @param program the program defining the static context
	 * @param vn the varnode
	 * @param already a cache of already-evaluated varnodes and their values
	 * @return the value
	 */
	protected T evaluateBranch(Program program, Varnode vn, Map<Varnode, T> already) {
		PcodeOp def = vn.getDef();
		if (def == null || def.getOutput() != vn) {
			throw new PcodeExecutionException("No defining p-code op for " + vn);
		}
		return evaluateOp(program, def, already);
	}

	/**
	 * Evaluate a constant
	 * 
	 * @param value the constant value
	 * @param size the size of the value in bytes
	 * @return the value as a {@link T}
	 */
	protected abstract T evaluateConstant(long value, int size);

	/**
	 * Evaluate the given register variable
	 * 
	 * @param address the address of the register
	 * @param size the size of the variable in bytes
	 * @return the value
	 */
	protected T evaluateRegister(Address address, int size) {
		return evaluateMemory(address, size);
	}

	/**
	 * Evaluate the given stack variable
	 * 
	 * @param offset the stack offset of the variable
	 * @param size the size of the variable in bytes
	 * @return the value
	 */
	protected T evaluateStack(long offset, int size) {
		return evaluateMemory(applyBase(offset), size);
	}

	/**
	 * Evaluate a variable in memory
	 * 
	 * <p>
	 * By default all register, stack, and memory addresses are directed here. Register addresses
	 * are passed through without modification. Stack addresses will have the frame base applied via
	 * {@link #applyBase(long)}, and memory addresses will be mapped through
	 * {@link #translateMemory(Program, Address)}.
	 * 
	 * @param address the address of the variable
	 * @param size the size of the variable in bytes
	 * @return the value
	 */
	protected abstract T evaluateMemory(Address address, int size);

	/**
	 * Evaluate a unique variable
	 * 
	 * <p>
	 * This is only invoked when trying to evaluate a leaf, which should never occur for a unique
	 * variable. Thus, by default, this throws a {@link PcodeExecutionException}.
	 * 
	 * @param long the offset of the variable
	 * @param size the size of the variable in bytes
	 * @return the value
	 */
	protected T evaluateUnique(long offset, int size) {
		throw new PcodeExecutionException(
			String.format("Cannot evaluate unique $U%x:%d", offset, size));
	}

	/**
	 * Evaluate a variable whose offset is of type {@link T}
	 * 
	 * <p>
	 * The three parameters {@code space}, {@code offset}, and {@code size} imitate the varnode
	 * triple, except that the offset is abstract. This is typically invoked for a
	 * {@link PcodeOp#LOAD}, i.e., a dereference.
	 * 
	 * @param program the program defining the static context
	 * @param space the address space of the variable
	 * @param offset the offset of the variable
	 * @param size the size of the variable in bytes
	 * @param already a cache of already-evaluated varnodes and their values
	 * @return the value
	 */
	protected abstract T evaluateAbstract(Program program, AddressSpace space, T offset, int size,
			Map<Varnode, T> already);

	/**
	 * Evaluate a unary op
	 * 
	 * <p>
	 * This evaluates the input varnode then computes the output value.
	 * 
	 * @param program the program defining the static context
	 * @param op the op whose output to evaluate
	 * @param unOp the concrete behavior of the op
	 * @param already a cache of already-evaluated varnodes and their values
	 * @return the output value
	 */
	protected abstract T evaluateUnaryOp(Program program, PcodeOp op, UnaryOpBehavior unOp,
			Map<Varnode, T> already);

	/**
	 * Evaluate a binary op
	 * 
	 * <p>
	 * This evaluates the input varnodes then computes the output value.
	 * 
	 * @param program the program defining the static context
	 * @param op the op whose output to evaluate
	 * @param binOp the concrete behavior of the op
	 * @param already a cache of already-evaluated varnodes and their values
	 * @return the output value
	 */
	protected abstract T evaluateBinaryOp(Program program, PcodeOp op, BinaryOpBehavior binOp,
			Map<Varnode, T> already);

	/**
	 * Evaluate a {@link PcodeOp#PTRADD} op
	 * 
	 * @param program the program defining the static context
	 * @param op the op whose output to evaluate
	 * @param already a cache of already-evaluated varnodes and their values
	 * @return the output value
	 */
	protected abstract T evaluatePtrAdd(Program program, PcodeOp op, Map<Varnode, T> already);

	/**
	 * Evaluate a {@link PcodeOp#PTRSUB} op
	 * 
	 * @param program the program defining the static context
	 * @param op the op whose output to evaluate
	 * @param already a cache of already-evaluated varnodes and their values
	 * @return the output value
	 */
	protected abstract T evaluatePtrSub(Program program, PcodeOp op, Map<Varnode, T> already);

	/**
	 * Assert that a varnode is constant and get its value as an integer.
	 * 
	 * <p>
	 * Here "constant" means a literal or immediate value. It does not read from the state.
	 * 
	 * @param vn the varnode
	 * @return the value
	 */
	protected int getIntConst(Varnode vn) {
		if (!vn.isConstant()) {
			throw new IllegalArgumentException(vn + " is not a constant");
		}
		return (int) vn.getAddress().getOffset();
	}

	/**
	 * Evaluate a {@link PcodeOp#LOAD} op
	 * 
	 * @param program the program defining the static context
	 * @param op the op whose output to evaluate
	 * @param already a cache of already-evaluated varnodes and their values
	 * @return the output value
	 */
	protected abstract T evaluateLoad(Program program, PcodeOp op, Map<Varnode, T> already);

	@Override
	public T evaluateOp(Program program, PcodeOp op) {
		return evaluateOp(program, op, new HashMap<>());
	}

	/**
	 * Like {@link #evaluateOp(Program, PcodeOp)}, but uses a cache
	 * 
	 * @param program the program defining the static context
	 * @param op the op whose output to evaluate
	 * @param already a cache of already-evaluated varnodes and their values
	 * @return the output value
	 */
	protected T evaluateOp(Program program, PcodeOp op, Map<Varnode, T> already) {
		OpBehavior b = OpBehaviorFactory.getOpBehavior(op.getOpcode());
		if (b == null) {
			return badOp(op);
		}
		if (b instanceof UnaryOpBehavior unOp) {
			return evaluateUnaryOp(program, op, unOp, already);
		}
		if (b instanceof BinaryOpBehavior binOp) {
			return evaluateBinaryOp(program, op, binOp, already);
		}
		switch (op.getOpcode()) {
			case PcodeOp.LOAD:
				return evaluateLoad(program, op, already);
			case PcodeOp.PTRADD:
				return evaluatePtrAdd(program, op, already);
			case PcodeOp.PTRSUB:
				return evaluatePtrSub(program, op, already);
			default:
				return badOp(op);
		}
	}

	/**
	 * The method invoked when an unrecognized or unsupported operator is encountered
	 * 
	 * @param op the op
	 * @return the value, but this usually throws an exception
	 */
	protected T badOp(PcodeOp op) {
		switch (op.getOpcode()) {
			case PcodeOp.UNIMPLEMENTED:
				throw new LowlevelError(
					"Encountered an unimplemented instruction at " +
						op.getSeqnum().getTarget());
			default:
				throw new LowlevelError(
					"Unsupported p-code op at " + op.getSeqnum().getTarget() + ": " + op);
		}
	}
}
