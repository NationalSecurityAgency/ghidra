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
package ghidra.dbg.sctl.protocol.common.reply;

import java.util.List;
import java.util.Map;

import ghidra.comm.packet.Packet;
import ghidra.comm.packet.annot.*;
import ghidra.comm.packet.fields.PacketField;
import ghidra.dbg.sctl.protocol.AbstractSctlReply;
import ghidra.dbg.sctl.protocol.common.SctlString;
import ghidra.dbg.sctl.protocol.consts.Lkind;
import ghidra.dbg.sctl.protocol.consts.Vkind;
import ghidra.dbg.sctl.protocol.types.SelSctlTypeName;

/**
 * Format for the {@code Renumloc} SCTL message
 */
public class SctlEnumerateLocalsReply extends AbstractSctlReply {
	// This is currently untested, i.e., I do not know how reference sctl behaves.

	@PacketField
	public long nl;

	@PacketField
	@RepeatedField
	@CountedByField("nl")
	public List<Local> locs;

	public static class Local extends Packet {
		@PacketField
		public SctlString id;

		@PacketField
		public SelSctlTypeName tname;

		@PacketField
		public Vkind kind;

		@PacketField
		public SelLocalExpr lexpr;
	}

	public static abstract class AbstractLocalExpr extends Packet {
		// Empty
	}

	public static class SelLocalExpr extends Packet {
		public static final Map<Lkind, Class<? extends AbstractLocalExpr>> KIND_MAP =
			typeMap(Lkind.class, AbstractLocalExpr.class) //
					.put(Lkind.Lreg, LocalRegisterExpr.class) //
					.put(Lkind.Lderef, LocalDereferenceExpr.class) //
					.put(Lkind.Ladd, LocalAddExpr.class) //
					.put(Lkind.Lsub, LocalSubExpr.class) //
					.put(Lkind.Lulit, LocalUnsignedLiteralExpr.class) //
					.put(Lkind.Lslit, LocalSignedLiteralExpr.class) //
					.build();

		@PacketField
		public Lkind kind;

		@PacketField
		@TypedByField(by = "kind", map = "KIND_MAP")
		public AbstractLocalExpr expr;
	}

	public static class LocalRegisterExpr extends AbstractLocalExpr {
		@PacketField
		public byte no; // register number, target-dependent
	}

	public static class LocalDereferenceExpr extends AbstractLocalExpr {
		@PacketField
		public SelLocalExpr lexpr;
	}

	public static class AbstractLocalBiExpr extends AbstractLocalExpr {
		@PacketField
		public SelLocalExpr lexpr1;

		@PacketField
		public SelLocalExpr lexpr2;
	}

	public static class LocalAddExpr extends AbstractLocalBiExpr {
		// No content
	}

	public static class LocalSubExpr extends AbstractLocalBiExpr {
		// No content
	}

	public static abstract class AbstractLocalLiteralExpr extends AbstractLocalExpr {
		@PacketField
		public long val;
	}

	public static class LocalUnsignedLiteralExpr extends AbstractLocalLiteralExpr {
		// No content
	}

	public static class LocalSignedLiteralExpr extends AbstractLocalLiteralExpr {
		// No content
	}
}
