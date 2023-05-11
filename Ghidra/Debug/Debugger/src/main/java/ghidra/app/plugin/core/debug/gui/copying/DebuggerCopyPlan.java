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
package ghidra.app.plugin.core.debug.gui.copying;

import java.util.*;

import javax.swing.JCheckBox;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.service.breakpoint.ProgramBreakpoint;
import ghidra.app.util.viewer.listingpanel.PropertyBasedBackgroundColorModel;
import ghidra.program.database.IntRangeMap;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DebuggerCopyPlan {
	public interface Copier {
		String getName();

		boolean isAvailable(TraceProgramView from, Program into);

		Collection<Copier> getRequires();

		Collection<Copier> getRequiredBy();

		boolean isRequiresInitializedMemory();

		void copy(TraceProgramView from, AddressRange fromRange, Program into, Address intoAddress,
				TaskMonitor monitor) throws Exception;
	}

	public enum AllCopiers implements Copier {
		BYTES("Bytes", List.of()) {
			@Override
			public boolean isRequiresInitializedMemory() {
				return true;
			}

			@Override
			public void copy(TraceProgramView from, AddressRange fromRange, Program into,
					Address intoAddress, TaskMonitor monitor) throws Exception {
				// This is perhaps too heavy handed....
				into.getListing()
						.clearCodeUnits(intoAddress, intoAddress.add(fromRange.getLength() - 1),
							false);
				byte[] buf = new byte[4096];
				AddressRangeChunker chunker = new AddressRangeChunker(fromRange, buf.length);
				for (AddressRange chunk : chunker) {
					monitor.checkCancelled();
					Address addr = chunk.getMinAddress();
					int len = (int) chunk.getLength();
					from.getMemory().getBytes(addr, buf, 0, len);
					long off = addr.subtract(fromRange.getMinAddress());
					Address dest = intoAddress.add(off);
					into.getMemory().setBytes(dest, buf, 0, len);
				}
			}
		},
		STATE("State (as colors)", List.of()) {
			@Override
			public void copy(TraceProgramView from, AddressRange fromRange, Program into,
					Address intoAddress, TaskMonitor monitor) throws Exception {
				IntRangeMap map =
					into.getIntRangeMap(PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
				if (map == null) {
					map = into.createIntRangeMap(
						PropertyBasedBackgroundColorModel.COLOR_PROPERTY_NAME);
				}
				AddressSet rngAsSet = new AddressSet(fromRange);
				TraceMemoryManager mm = from.getTrace().getMemoryManager();
				AddressSetView knownSet = mm.getAddressesWithState(from.getSnap(), rngAsSet,
					s -> s == TraceMemoryState.KNOWN);
				AddressSetView errorSet = mm.getAddressesWithState(from.getSnap(), rngAsSet,
					s -> s == TraceMemoryState.ERROR);
				AddressSetView staleSet = rngAsSet.subtract(knownSet).subtract(errorSet);
				setShifted(map, fromRange.getMinAddress(), intoAddress, errorSet,
					DebuggerResources.COLOR_BACKGROUND_ERROR.getRGB());
				setShifted(map, fromRange.getMinAddress(), intoAddress, staleSet,
					DebuggerResources.COLOR_BACKGROUND_STALE.getRGB());
			}

			public void setShifted(IntRangeMap map, Address src, Address dst, AddressSetView set,
					int value) {
				for (AddressRange rng : set) {
					long offMin = rng.getMinAddress().subtract(src);
					long offMax = rng.getMaxAddress().subtract(src);
					Address dMin = dst.add(offMin);
					Address dMax = dst.add(offMax);
					map.setValue(dMin, dMax, value);
				}
			}
		},
		INSTRUCTIONS("Instructions", List.of(BYTES)) {
			@Override
			protected boolean checkAvailable(TraceProgramView from, Program into) {
				return into == null || from.getLanguage() == into.getLanguage();
			}

			@Override
			public void copy(TraceProgramView from, AddressRange fromRange, Program into,
					Address intoAddress, TaskMonitor monitor) throws Exception {
				Listing intoListing = into.getListing();
				for (Instruction ins : from.getListing()
						.getInstructions(new AddressSet(fromRange), true)) {
					monitor.checkCancelled();
					if (!ins.getPrototype().getLanguage().equals(into.getLanguage())) {
						// Filter out "guest" instructions
						continue;
					}
					long off = ins.getMinAddress().subtract(fromRange.getMinAddress());
					Address dest = intoAddress.add(off);
					intoListing.createInstruction(dest, ins.getPrototype(), ins, ins);
				}
			}
		},
		DATA("Data", List.of()) {
			@Override
			protected boolean checkAvailable(TraceProgramView from, Program into) {
				return into == null || sameDataOrganization(from, into);
			}

			@Override
			public void copy(TraceProgramView from, AddressRange fromRange, Program into,
					Address intoAddress, TaskMonitor monitor)
					throws Exception {
				Listing intoListing = into.getListing();
				for (Data data : from.getListing()
						.getDefinedData(new AddressSet(fromRange), true)) {
					monitor.checkCancelled();
					long off = data.getMinAddress().subtract(fromRange.getMinAddress());
					Address dest = intoAddress.add(off);
					DataType dt = data.getDataType();
					if (!(dt instanceof DynamicDataType)) {
						intoListing.createData(dest, dt, data.getLength());
					}
				}
			}
		},
		DYNAMIC_DATA("Dynamic Data", List.of(BYTES)) {
			@Override
			protected boolean checkAvailable(TraceProgramView from, Program into) {
				return into == null || sameDataOrganization(from, into);
			}

			@Override
			public void copy(TraceProgramView from, AddressRange fromRange, Program into,
					Address intoAddress, TaskMonitor monitor) throws Exception {
				Listing intoListing = into.getListing();
				for (Data data : from.getListing()
						.getDefinedData(new AddressSet(fromRange), true)) {
					monitor.checkCancelled();
					long off = data.getMinAddress().subtract(fromRange.getMinAddress());
					Address dest = intoAddress.add(off);
					DataType dt = data.getDataType();
					if (dt instanceof DynamicDataType) {
						intoListing.createData(dest, dt, data.getLength());
					}
				}
			}
		},
		LABELS("Labels", List.of()) {
			@Override
			public void copy(TraceProgramView from, AddressRange fromRange, Program into,
					Address intoAddress, TaskMonitor monitor) throws Exception {
				SymbolTable intoTable = into.getSymbolTable();
				for (Symbol label : from.getSymbolTable()
						.getSymbols(new AddressSet(fromRange), SymbolType.LABEL, true)) {
					monitor.checkCancelled();
					if (label.getSource() == SourceType.DEFAULT) {
						continue;
					}
					long off = label.getAddress().subtract(fromRange.getMinAddress());
					Address dest = intoAddress.add(off);
					Namespace destNs =
						findOrCopyNamespace(label.getParentNamespace(), intoTable, into);
					try {
						intoTable.createLabel(dest, label.getName(), destNs, label.getSource());
					}
					catch (InvalidInputException e) {
						throw new AssertionError(e);
					}
				}
			}

			private Namespace findOrCopyNamespace(Namespace ns, SymbolTable intoTable,
					Program into) throws Exception {
				if (ns.isGlobal()) {
					return into.getGlobalNamespace();
				}
				Namespace destParent =
					findOrCopyNamespace(ns.getParentNamespace(), intoTable, into);
				return intoTable.getOrCreateNameSpace(destParent, ns.getName(),
					ns.getSymbol().getSource());
			}
		},
		BREAKPOINTS("Breakpoints (as bookmarks)", List.of()) {
			@Override
			public void copy(TraceProgramView from, AddressRange fromRange, Program into,
					Address intoAddress, TaskMonitor monitor) throws Exception {
				for (TraceBreakpoint bpt : from.getTrace()
						.getBreakpointManager()
						.getBreakpointsIntersecting(Lifespan.at(from.getSnap()), fromRange)) {
					monitor.checkCancelled();
					long off = bpt.getMinAddress().subtract(fromRange.getMinAddress());
					Address dest = intoAddress.add(off);
					ProgramBreakpoint pb =
						new ProgramBreakpoint(into, dest, bpt.getLength(), bpt.getKinds());
					if (bpt.isEnabled(from.getSnap())) {
						pb.enable();
					}
					else {
						pb.disable();
					}
					pb.setEmuSleigh(bpt.getEmuSleigh());
				}
			}
		},
		BOOKMARKS("Bookmarks", List.of()) {
			@Override
			public void copy(TraceProgramView from, AddressRange fromRange, Program into,
					Address intoAddress, TaskMonitor monitor) throws Exception {
				BookmarkManager intoBookmarks = into.getBookmarkManager();
				Iterator<Bookmark> bit =
					from.getBookmarkManager().getBookmarksIterator(fromRange.getMinAddress(), true);
				while (bit.hasNext()) {
					monitor.checkCancelled();
					Bookmark bm = bit.next();
					if (bm.getAddress().compareTo(fromRange.getMaxAddress()) > 0) {
						break;
					}
					BookmarkType type = bm.getType();
					long off = bm.getAddress().subtract(fromRange.getMinAddress());
					Address dest = intoAddress.add(off);
					BookmarkType destType = intoBookmarks.getBookmarkType(type.getTypeString());
					if (destType == null) {
						destType = intoBookmarks.defineType(type.getTypeString(), type.getIcon(),
							type.getMarkerColor(), type.getMarkerPriority());
					}
					intoBookmarks.setBookmark(dest, destType.getTypeString(), bm.getCategory(),
						bm.getComment());
				}
			}
		},
		REFERENCES("References (memory only)", List.of()) {
			@Override
			public void copy(TraceProgramView from, AddressRange fromRange, Program into,
					Address intoAddress, TaskMonitor monitor) throws Exception {
				ReferenceManager intoRefs = into.getReferenceManager();
				for (Reference ref : from.getReferenceManager()
						.getReferenceIterator(fromRange.getMinAddress())) {
					monitor.checkCancelled();
					if (ref.getFromAddress().compareTo(fromRange.getMaxAddress()) > 0) {
						break;
					}
					if (ref.getSource() == SourceType.DEFAULT) {
						continue;
					}
					// TODO: Other kinds of references?
					if (!ref.isMemoryReference()) {
						continue;
					}
					// Requiring both ends to be in copied range
					if (!fromRange.contains(ref.getToAddress())) {
						continue;
					}

					// NB. "from" is overloaded here
					long offFrom = ref.getFromAddress().subtract(fromRange.getMinAddress());
					long offTo = ref.getToAddress().subtract(fromRange.getMinAddress());
					Address destFrom = intoAddress.add(offFrom);
					Address destTo = intoAddress.add(offTo);
					intoRefs.addMemoryReference(destFrom, destTo, ref.getReferenceType(),
						ref.getSource(), ref.getOperandIndex());
				}
			}
		},
		COMMENTS("Comments", List.of()) {
			@Override
			public void copy(TraceProgramView from, AddressRange fromRange, Program into,
					Address intoAddress, TaskMonitor monitor) throws Exception {
				Listing fromListing = from.getListing();
				Listing intoListing = into.getListing();
				for (Address addr : fromListing.getCommentAddressIterator(new AddressSet(fromRange),
					true)) {
					monitor.checkCancelled();
					long off = addr.subtract(fromRange.getMinAddress());
					Address dest = intoAddress.add(off);
					// Ugly, but there's not MAX/MIN_COMMENT_TYPE
					for (int i = CodeUnit.EOL_COMMENT; i <= CodeUnit.REPEATABLE_COMMENT; i++) {
						String comment = fromListing.getComment(i, addr);
						if (comment == null) {
							continue;
						}
						intoListing.setComment(dest, i, comment);
					}
				}
			}
		};

		protected boolean sameDataOrganization(Program p1, Program p2) {
			DataOrganization dataOrg1 = p1.getDataTypeManager().getDataOrganization();
			DataOrganization dataOrg2 = p2.getDataTypeManager().getDataOrganization();
			return dataOrg1.equals(dataOrg2);
		}

		public static final List<Copier> VALUES;
		static {
			List<AllCopiers> asList = Arrays.asList(values());
			Collections.sort(asList, Comparator.comparing(AllCopiers::getName));
			VALUES = Collections.unmodifiableList(asList);
		}

		final String name;
		final Collection<Copier> requires;
		final Collection<Copier> requiredBy = new HashSet<>();

		private AllCopiers(String name, Collection<AllCopiers> requires) {
			this.name = name;
			this.requires = Collections.unmodifiableCollection(requires);
			for (AllCopiers req : requires) {
				req.requiredBy.add(this);
			}
		}

		protected boolean checkAvailable(TraceProgramView from, Program into) {
			return true;
		}

		@Override
		public boolean isAvailable(TraceProgramView from, Program into) {
			return checkAvailable(from, into) &&
				getRequires().stream().allMatch(c -> c.isAvailable(from, into));
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public Collection<Copier> getRequires() {
			return requires;
		}

		@Override
		public Collection<Copier> getRequiredBy() {
			return requiredBy;
		}

		@Override
		public boolean isRequiresInitializedMemory() {
			return false;
		}
	}

	protected final Map<Copier, JCheckBox> checkBoxes = new LinkedHashMap<>();

	public DebuggerCopyPlan() {
		for (Copier copier : getAllCopiers()) {
			JCheckBox cb = new JCheckBox(copier.getName());
			Collection<Copier> requires = copier.getRequires();
			Collection<Copier> requiredBy = copier.getRequiredBy();
			if (!requires.isEmpty() || !requiredBy.isEmpty()) {
				cb.addActionListener(e -> {
					if (cb.isSelected()) {
						for (Copier req : requires) {
							checkBoxes.get(req).setSelected(true);
						}
					}
					else {
						for (Copier dep : requiredBy) {
							checkBoxes.get(dep).setSelected(false);
						}
					}
				});
			}
			checkBoxes.put(copier, cb);
		}
	}

	public Collection<Copier> getAllCopiers() {
		return AllCopiers.VALUES;
	}

	public JCheckBox getCheckBox(Copier copier) {
		return checkBoxes.get(copier);
	}

	public void selectAll() {
		for (JCheckBox cb : checkBoxes.values()) {
			cb.setSelected(true);
		}
	}

	public void selectNone() {
		for (JCheckBox cb : checkBoxes.values()) {
			cb.setSelected(false);
		}
	}

	public void execute(TraceProgramView from, AddressRange fromRange, Program into,
			Address intoAddress, TaskMonitor monitor) throws Exception {
		for (Copier copier : getAllCopiers()) {
			if (!copier.isAvailable(from, into)) {
				continue;
			}
			if (!checkBoxes.get(copier).isSelected()) {
				continue;
			}
			copier.copy(from, fromRange, into, intoAddress, monitor);
		}
	}

	public void syncCopiersEnabled(TraceProgramView from, Program dest) {
		for (Map.Entry<Copier, JCheckBox> ent : checkBoxes.entrySet()) {
			ent.getValue().setEnabled(ent.getKey().isAvailable(from, dest));
		}
	}

	public boolean isRequiresInitializedMemory(TraceProgramView from, Program dest) {
		return checkBoxes.entrySet().stream().anyMatch(ent -> {
			Copier copier = ent.getKey();
			return copier.isRequiresInitializedMemory() &&
				copier.isAvailable(from, dest) && ent.getValue().isSelected();
		});
	}
}
