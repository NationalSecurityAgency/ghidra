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
package ghidra.dbg.sctl.protocol.common.notify;

import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.comm.packet.annot.BitmaskEncoded;
import ghidra.comm.packet.annot.WithFlag;
import ghidra.comm.packet.fields.PacketField;
import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.sctl.protocol.AbstractSctlNotify;
import ghidra.dbg.sctl.protocol.consts.Evkind;

/**
 * Format for the {@code Aevent} SCTL message
 * 
 * This parses the flags and each applicable event. It is unclear how many events can be present in
 * one message. Though, the documentation seems to imply exactly one must be present.
 */
public class SctlEventNotify extends AbstractSctlNotify {
	/**
	 * For unmarshalling
	 */
	public SctlEventNotify() {
	}

	/**
	 * Construct an {@code Aevent} message with the one given event details
	 * 
	 * Additional events may be added using {@link #addOrSetDetails(AbstractSctlEventNotification)}.
	 * Note that more than one event may not be within the official specification. The proper flags
	 * will be set during message encoding.
	 * 
	 * @param ctlid the CTLID of the affected thread
	 * @param details the event details
	 */
	public SctlEventNotify(long ctlid, AbstractSctlEventNotification details) {
		this(ctlid, details, null);
	}

	/**
	 * Construct an {@code Aevent} message with the one given event details and additional flags
	 * 
	 * The event flags will be set during message encoding. The provided flags are set in addition
	 * to required event flag(s). Note: If an event flag is provided in {@code addFlags}, but that
	 * event is not actually present in the details, it will be cleared while encoding.
	 * 
	 * @param ctlid the CTLID of the affected thread
	 * @param details the event details
	 * @param addFlags additional flags to set
	 */
	public SctlEventNotify(long ctlid, AbstractSctlEventNotification details,
			BitmaskSet<Evkind> addFlags) {
		this.ctlid = ctlid;
		this.flags = addFlags;
		addOrSetDetails(details);
	}

	public void clearDetails() {
		syscall = null;
		trap = null;
		snap = null;
		fork = null;
		clone = null;
		exec = null;
		exit = null;
		signal = null;
		load = null;
		unload = null;
	}

	public void addOrSetDetails(AbstractSctlEventNotification details) {
		if (details == null) {
			return;
		}
		else if (details instanceof SctlSyscallNotification) {
			syscall = (SctlSyscallNotification) details;
		}
		else if (details instanceof SctlTrapNotification) {
			trap = (SctlTrapNotification) details;
		}
		else if (details instanceof AbstractSctlSnapNotification) {
			snap = (AbstractSctlSnapNotification) details;
		}
		else if (details instanceof AbstractSctlForkNotification) {
			fork = (AbstractSctlForkNotification) details;
		}
		else if (details instanceof SctlCloneNotification) {
			clone = (SctlCloneNotification) details;
		}
		else if (details instanceof SctlExecNotification) {
			exec = (SctlExecNotification) details;
		}
		else if (details instanceof SctlExitNotification) {
			exit = (SctlExitNotification) details;
		}
		else if (details instanceof SctlSignalNotification) {
			signal = (SctlSignalNotification) details;
		}
		else if (details instanceof SctlLoadNotification) {
			load = (SctlLoadNotification) details;
		}
		else if (details instanceof SctlUnloadNotification) {
			unload = (SctlUnloadNotification) details;
		}
	}

	private static <T> void addIfNotNull(Set<T> set, T t) {
		if (t != null) {
			set.add(t);
		}
	}

	// There should really only be one anyway
	public Set<AbstractSctlEventNotification> getAllEvents() {
		Set<AbstractSctlEventNotification> all = new LinkedHashSet<>();
		addIfNotNull(all, syscall);
		addIfNotNull(all, trap);
		addIfNotNull(all, snap);
		addIfNotNull(all, fork);
		addIfNotNull(all, clone);
		addIfNotNull(all, exec);
		addIfNotNull(all, exit);
		addIfNotNull(all, signal);
		addIfNotNull(all, load);
		addIfNotNull(all, unload);
		return all;
	}

	@PacketField
	public long ctlid;

	@PacketField
	@BitmaskEncoded(universe = Evkind.class)
	public BitmaskSet<Evkind> flags;

	@PacketField
	@WithFlag(by = "flags", flag = "Esyscall")
	public SctlSyscallNotification syscall;

	@PacketField
	@WithFlag(by = "flags", flag = "Etrap")
	public SctlTrapNotification trap;

	@PacketField
	@WithFlag(by = "flags", flag = "Esnap")
	public AbstractSctlSnapNotification snap;

	@PacketField
	@WithFlag(by = "flags", flag = "Efork")
	public AbstractSctlForkNotification fork;

	@PacketField
	@WithFlag(by = "flags", flag = "Eclone")
	public SctlCloneNotification clone;

	@PacketField
	@WithFlag(by = "flags", flag = "Eexec")
	public SctlExecNotification exec;

	@PacketField
	@WithFlag(by = "flags", flag = "Eexit")
	public SctlExitNotification exit;

	@PacketField
	@WithFlag(by = "flags", flag = "Esignal")
	public SctlSignalNotification signal;

	@PacketField
	@WithFlag(by = "flags", flag = "Eload")
	public SctlLoadNotification load;

	@PacketField
	@WithFlag(by = "flags", flag = "Eunload")
	public SctlUnloadNotification unload;
}
