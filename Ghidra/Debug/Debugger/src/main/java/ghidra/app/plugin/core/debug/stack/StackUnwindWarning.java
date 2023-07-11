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
package ghidra.app.plugin.core.debug.stack;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;

/**
 * A warning issued while unwinding a stack
 * 
 * <p>
 * This is designed to avoid the untamed bucket of messages that a warning set usually turns into.
 * In essence, it's still a bucket of messages; however, each type is curated and has some logic for
 * how it interacts with other messages and additional instances of itself.
 */
public interface StackUnwindWarning {
	/**
	 * A warning that can be combined with other instances of itself
	 * 
	 * @param <T> the same type as me (recursive)
	 */
	interface Combinable<T extends StackUnwindWarning> {
		String summarize(Collection<T> all);
	}

	/**
	 * Get the message for display
	 * 
	 * @return the message
	 */
	String getMessage();

	/**
	 * Check if the given warning can be omitted on account of this warning
	 * 
	 * <p>
	 * Usually, the unwinder should be careful not to emit unnecessary warnings, but at times that
	 * can be difficult, and its proper implementation may complicate the actual unwind logic. This
	 * allows the unnecessary warning to be removed afterward.
	 * 
	 * @param other the other warning
	 * @return true if this warning deems the other unnecessary
	 */
	default boolean moots(StackUnwindWarning other) {
		return false;
	}

	/**
	 * For diagnostics, report any error details indicated by this warning, usually via {@link Msg}.
	 */
	default void reportDetails() {
	}

	/**
	 * The unwind analyzer could not find an exit path from the frame's program counter.
	 */
	public record NoReturnPathStackUnwindWarning(Address pc) implements StackUnwindWarning {
		@Override
		public String getMessage() {
			return "Could not find a path from " + pc + " to a return";
		}

		@Override
		public boolean moots(StackUnwindWarning other) {
			return other instanceof OpaqueReturnPathStackUnwindWarning;
		}
	}

	/**
	 * The unwind analyzer discovered at last one exit path, but none could be analyzed.
	 */
	public record OpaqueReturnPathStackUnwindWarning(Address pc, Exception last)
			implements StackUnwindWarning {
		@Override
		public String getMessage() {
			return "Could not analyze any path from " + pc + " to a return.\nLast error: " +
				last.getMessage();
		}

		@Override
		public void reportDetails() {
			Msg.showError(this, null, "Details", getMessage(), last);
		}
	}

	/**
	 * While analyzing instructions, the unwind analyzer encountered a call to a function whose
	 * effect on the stack is unknown.
	 * 
	 * <p>
	 * The analyzer does not descend into calls or otherwise implement inter-procedural analysis.
	 * Instead, it relies on analysis already performed by Ghidra's other analyzers and/or the human
	 * user. The analyzer will assume a reasonable default.
	 */
	public record UnknownPurgeStackUnwindWarning(Function function)
			implements StackUnwindWarning, Combinable<UnknownPurgeStackUnwindWarning> {
		@Override
		public String getMessage() {
			return "Function " + function + " has unknown/invalid stack purge";
		}

		@Override
		public String summarize(Collection<UnknownPurgeStackUnwindWarning> all) {
			Stream<String> sortedDisplay =
				all.stream().map(w -> w.function.getName(false)).sorted();
			if (all.size() > 7) {
				return "Functions " +
					sortedDisplay.limit(7).collect(Collectors.joining(", ")) +
					", ... have unknown/invalid stack purge.";
			}
			return "Functions " + sortedDisplay.collect(Collectors.joining(", ")) +
				" have unknown/invalid stack purge.";
		}
	}

	/**
	 * While analyzing instructions, the unwind analyzer encountered a call to a function whose
	 * convention is not known.
	 * 
	 * <p>
	 * The analyzer will assume the default convention for the program's compiler.
	 */
	public record UnspecifiedConventionStackUnwindWarning(Function function)
			implements StackUnwindWarning, Combinable<UnspecifiedConventionStackUnwindWarning> {
		@Override
		public String getMessage() {
			return "Function " + function + " has unspecified convention. Using default";
		}

		@Override
		public String summarize(Collection<UnspecifiedConventionStackUnwindWarning> all) {
			Stream<String> sortedDisplay =
				all.stream().map(w -> w.function.getName(false)).sorted();
			if (all.size() > 7) {
				return "Functions " +
					sortedDisplay.limit(7).collect(Collectors.joining(", ")) +
					", ... have unspecified convention.";
			}
			return "Functions " + sortedDisplay.collect(Collectors.joining(", ")) +
				" have unspecified convention.";
		}
	}

	/**
	 * While analyzing an indirect call, using the decompiler, the unwind analyzer obtained multiple
	 * high {@link PcodeOp#CALL} or {@link PcodeOp#CALLIND} p-code ops.
	 * 
	 * <p>
	 * Perhaps this should be replaced by an assertion, but failing fast may not be a good approach
	 * for this case.
	 */
	public record MultipleHighCallsStackUnwindWarning(List<PcodeOpAST> found)
			implements StackUnwindWarning {
		@Override
		public String getMessage() {
			return "Caller generated multiple decompiled calls. How?: " + found;
		}
	}

	/**
	 * Similar to {@link MultipleHighCallsStackUnwindWarning}, except no high call p-code ops.
	 */
	public record NoHighCallsStackUnwindWarning(PcodeOp op) implements StackUnwindWarning {
		@Override
		public String getMessage() {
			return "Caller generated no decompiled calls. How?:" + op;
		}
	}

	/**
	 * While analyzing an indirect call, the target's type was not a function pointer.
	 */
	public record UnexpectedTargetTypeStackUnwindWarning(DataType type)
			implements StackUnwindWarning {
		@Override
		public String getMessage() {
			return "Indirect call target has unexpected type: " + type;
		}
	}

	/**
	 * While analyzing an indirect call, couldn't get the function signature because its input
	 * doesn't have a high variable.
	 */
	public record NoHighVariableFromTargetPointerTypeUnwindWarning(VarnodeAST vn)
			implements StackUnwindWarning {
		@Override
		public String getMessage() {
			return "Input of indirect call target has no high variable: " + vn;
		}
	}

	/**
	 * While analyzing an indirect call, the signature could not be derived from call-site context.
	 */
	public record CouldNotRecoverSignatureStackUnwindWarning(PcodeOpAST op)
			implements StackUnwindWarning {
		@Override
		public String getMessage() {
			return "Could not recover signature of indirect call: " + op;
		}
	}

	/**
	 * A custom warning, either because a specific type is too onerous, or because the message was
	 * deserialized and the specific type and info cannot be recovered.
	 */
	public record CustomStackUnwindWarning(String message) implements StackUnwindWarning {
		@Override
		public String getMessage() {
			return message;
		}
	}
}
