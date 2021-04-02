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
package ghidra.app.plugin.assembler;

import java.util.Collection;

import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * The primary interface for performing assembly in Ghidra.
 * 
 * <p>
 * Use the {@link Assemblers} class to obtain a suitable implementation for a given program or
 * language.
 */
public interface Assembler {
	/**
	 * Assemble a sequence of instructions and place them at the given address.
	 * 
	 * <p>
	 * This method is only valid if the assembler is bound to a program. An instance may optionally
	 * implement this method without a program binding. In that case, the returned iterator will
	 * refer to pseudo instructions.
	 * 
	 * <p>
	 * NOTE: There must be an active transaction on the bound program for this method to succeed.
	 * 
	 * @param at the location where the resulting instructions should be placed
	 * @param listing a new-line separated or array sequence of instructions
	 * @return an iterator over the resulting instructions
	 * @throws AssemblySyntaxException a textual instruction is non well-formed
	 * @throws AssemblySemanticException a well-formed instruction cannot be assembled
	 * @throws MemoryAccessException there is an issue writing the result to program memory
	 * @throws AddressOverflowException the resulting block is beyond the valid address range
	 */
	public InstructionIterator assemble(Address at, String... listing)
			throws AssemblySyntaxException,
			AssemblySemanticException, MemoryAccessException, AddressOverflowException;

	/**
	 * Assemble a line instruction at the given address.
	 * 
	 * <p>
	 * This method is valid with or without a bound program. Even if bound, the program is not
	 * modified; however, the appropriate context information is taken from the bound program.
	 * Without a program, the language's default context is taken at the given location.
	 * 
	 * @param at the location of the start of the instruction
	 * @param line the textual assembly code
	 * @return the binary machine code, suitable for placement at the given address
	 * @throws AssemblySyntaxException the textual instruction is not well-formed
	 * @throws AssemblySemanticException the the well-formed instruction cannot be assembled
	 */
	public byte[] assembleLine(Address at, String line)
			throws AssemblySyntaxException, AssemblySemanticException;

	/**
	 * Assemble a line instruction at the given address, assuming the given context.
	 * 
	 * <p>
	 * This method works like {@link #assembleLine(Address, String)} except that it allows you to
	 * override the assumed context at that location.
	 * 
	 * @param at the location of the start of the instruction
	 * @param line the textual assembly code
	 * @param ctx the context register value at the start of the instruction
	 * @return the results of semantic resolution (from all parse results)
	 * @throws AssemblySyntaxException the textual instruction is not well-formed
	 * @throws AssemblySemanticException the well-formed instruction cannot be assembled
	 */
	public byte[] assembleLine(Address at, String line, AssemblyPatternBlock ctx)
			throws AssemblySemanticException, AssemblySyntaxException;

	/**
	 * Parse a line instruction.
	 * 
	 * <p>
	 * Generally, you should just use {@link #assembleLine(Address, String)}, but if you'd like
	 * access to the parse trees outside of an {@link AssemblySelector}, then this may be an
	 * acceptable option. Most notably, this is an excellent way to obtain suggestions for
	 * auto-completion.
	 * 
	 * <p>
	 * Each item in the returned collection is either a complete parse tree, or a syntax error
	 * Because all parse paths are attempted, it's possible to get many mixed results. For example,
	 * The input line may be a valid instruction; however, there may be suggestions to continue the
	 * line toward another valid instruction.
	 * 
	 * @param line the line (or partial line) to parse
	 * @return the results of parsing
	 */
	public Collection<AssemblyParseResult> parseLine(String line);

	/**
	 * Resolve a given parse tree at the given address, assuming the given context
	 * 
	 * <p>
	 * Each item in the returned collection is either a completely resolved instruction, or a
	 * semantic error. Because all resolutions are attempted, it's possible to get many mixed
	 * results.
	 * 
	 * <p>
	 * NOTE: The resolved instructions are given as masks and values. Where the mask does not cover,
	 * you can choose any value.
	 * 
	 * @param parse a parse result giving a valid tree
	 * @param at the location of the start of the instruction
	 * @param ctx the context register value at the start of the instruction
	 * @return the results of semantic resolution
	 */
	public AssemblyResolutionResults resolveTree(AssemblyParseResult parse, Address at,
			AssemblyPatternBlock ctx);

	/**
	 * Resolve a given parse tree at the given address.
	 * 
	 * <p>
	 * Each item in the returned collection is either a completely resolved instruction, or a
	 * semantic error. Because all resolutions are attempted, it's possible to get many mixed
	 * results.
	 * 
	 * <p>
	 * NOTE: The resolved instructions are given as masks and values. Where the mask does not cover,
	 * you can choose any value.
	 * 
	 * @param parse a parse result giving a valid tree
	 * @param at the location of the start of the instruction
	 * @return the results of semantic resolution
	 */
	public AssemblyResolutionResults resolveTree(AssemblyParseResult parse, Address at);

	/**
	 * Assemble a line instruction at the given address.
	 * 
	 * <p>
	 * This method works like {@link #resolveLine(Address, String, AssemblyPatternBlock)}, except
	 * that it derives the context using {@link #getContextAt(Address)}.
	 * 
	 * @param at the location of the start of the instruction
	 * @param line the textual assembly code
	 * @return the collection of semantic resolution results
	 * @throws AssemblySyntaxException the textual instruction is not well-formed
	 */
	public AssemblyResolutionResults resolveLine(Address at, String line)
			throws AssemblySyntaxException;

	/**
	 * Assemble a line instruction at the given address, assuming the given context.
	 * 
	 * <p>
	 * This method works like {@link #assembleLine(Address, String, AssemblyPatternBlock)}, except
	 * that it returns all possible resolutions for the parse trees that pass the
	 * {@link AssemblySelector}.
	 * 
	 * @param at the location of the start of the instruction
	 * @param line the textual assembly code
	 * @param ctx the context register value at the start of the instruction
	 * @return the collection of semantic resolution results
	 * @throws AssemblySyntaxException the textual instruction is not well-formed
	 */
	public AssemblyResolutionResults resolveLine(Address at, String line, AssemblyPatternBlock ctx)
			throws AssemblySyntaxException;

	/**
	 * Place a resolved (and fully-masked) instruction into the bound program.
	 * 
	 * <p>
	 * This method is not valid without a program binding. Also, this method must be called during a
	 * program database transaction.
	 * 
	 * @param res the resolved and fully-masked instruction
	 * @param at the location of the start of the instruction
	 * @return the new {@link Instruction} code unit
	 * @throws MemoryAccessException there is an issue writing the result to program memory
	 */
	public Instruction patchProgram(AssemblyResolvedConstructor res, Address at)
			throws MemoryAccessException;

	/**
	 * Place instruction bytes into the bound program.
	 * 
	 * <p>
	 * This method is not valid without a program binding. Also, this method must be called during a
	 * program database transaction.
	 * 
	 * @param insbytes the instruction data
	 * @param at the location of the start of the instruction
	 * @return an iterator over the disassembled instructions
	 * @throws MemoryAccessException there is an issue writing the result to program memory
	 */
	public InstructionIterator patchProgram(byte[] insbytes, Address at)
			throws MemoryAccessException;

	/**
	 * Get the context at a given address
	 * 
	 * <p>
	 * If there is a program binding, this will extract the actual context at the given address.
	 * Otherwise, it will obtain the default context at the given address for the language.
	 * 
	 * @param addr the address
	 * @return the context
	 */
	public AssemblyPatternBlock getContextAt(Address addr);
}
