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
package ghidra.dbg.sctl.client;

import java.util.Set;

import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.sctl.protocol.consts.Evkind;

/**
 * Utilities for calling {@link SctlTargetThread#traceEvents(Mode, Set)}
 */
public interface SctlTrace {
	/**
	 * Constants specifying "enable" or "disable"
	 */
	public enum Mode {
		/**
		 * Disable events
		 */
		CLEAR(Evkind.Eclear),
		/**
		 * Enable events
		 */
		SET(Evkind.Eset);

		public final Evkind kind;

		Mode(Evkind kind) {
			this.kind = kind;
		}
	}

	/**
	 * Events to select from
	 */
	public enum Event {
		/**
		 * Immediately preceding and following system calls
		 */
		SYSCALL(Evkind.Esyscall),
		/**
		 * Immediately following POSIX {@code exec()}
		 */
		EXEC(Evkind.Eexec),
		/**
		 * Immediately following POSIX {@code fork()}
		 */
		FORK(Evkind.Efork),
		/**
		 * Immediately following Linux (@code clone()}
		 */
		CLONE(Evkind.Eclone),
		/**
		 * Pending a signal
		 */
		SIGNAL(Evkind.Esignal),
		/**
		 * Upon exit
		 */
		EXIT(Evkind.Eexit),
		/**
		 * Immediately upon a trap point
		 */
		TRAP(Evkind.Etrap),
		/**
		 * Immediately upon a snap point
		 */
		SNAP(Evkind.Esnap),
		/**
		 * Enable context transfer after a step
		 */
		STEPCTX(Evkind.Estepctx),
		/**
		 * Immediately following a module load
		 */
		LOAD(Evkind.Eload),
		/**
		 * Immediately following a module unload
		 */
		UNLOAD(Evkind.Eunload);

		public final Evkind kind;

		Event(Evkind kind) {
			this.kind = kind;
		}
	}

	/**
	 * Convert mode and event selections to protocol flags
	 * 
	 * @param mode whether to enable or disable the events
	 * @param events the events to enable to disable
	 * @return the set of flags
	 */
	public static BitmaskSet<Evkind> toFlags(Mode mode, Set<Event> events) {
		BitmaskSet<Evkind> flags = BitmaskSet.of();
		flags.add(mode.kind);
		for (Event ev : events) {
			flags.add(ev.kind);
		}
		return flags;
	}
}
