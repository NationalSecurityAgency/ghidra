/* ###
 * IP: GHIDRA
 * REVIEWED: YES
 * NOTE: Refernence typo is being perpetuated
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
package ghidra.app.plugin.core.reloc;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.Iterator;

public class RelocationFixupCommand extends BackgroundCommand {
	private RelocationFixupHandler relocationHandler;
	private RelocationFixupHandler genericHandler;
	private Address oldImageBase;
	private Address newImageBase;
	private boolean hasUnhandledRelocations;

	public RelocationFixupCommand(RelocationFixupHandler handler, Address oldImageBase,
			Address newImageBase) {
		super("Relocation Fixup", true, true, true);
		this.relocationHandler = handler;
		this.oldImageBase = oldImageBase;
		this.newImageBase = newImageBase;
		genericHandler = new GenericRefernenceBaseRelocationFixupHandler();
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		Program program = (Program) obj;
		RelocationTable relocationTable = program.getRelocationTable();

		Iterator<Relocation> iterator = relocationTable.getRelocations();
		while (iterator.hasNext()) {
			Relocation relocation = iterator.next();
			try {
				if (!processRelocation(program, relocation)) {
					markAsUnhandled(program, relocation, "Unhandled relocation type");
				}
			}
			catch (MemoryAccessException e) {
				markAsUnhandled(program, relocation, "Memory access Exception");
			}
			catch (CodeUnitInsertionException e) {
				markAsUnhandled(program, relocation, "Error re-creating instruction");
			}

		}
		if (hasUnhandledRelocations) {
			Msg.showError(
				this,
				null,
				"Unhandled Relocation Fixups",
				"One or more relocation fix-ups were not handled for the image rebase.\n"
					+ "Bookmarks were created with the category \"Unhandled Image Base Relocation Fixup\"");
		}

		return true;
	}

	private boolean processRelocation(Program program, Relocation relocation)
			throws MemoryAccessException, CodeUnitInsertionException {
		if (relocationHandler != null &&
			relocationHandler.processRelocation(program, relocation, oldImageBase, newImageBase)) {
			return true;
		}
		return genericHandler.processRelocation(program, relocation, oldImageBase, newImageBase);
	}

	private void markAsUnhandled(Program program, Relocation relocation, String reason) {
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		Address address = relocation.getAddress();
		bookmarkManager.setBookmark(address, BookmarkType.ERROR,
			"Unhandled Image Base Relocation Fixup", "Unhandled Elf relocation fixup (type = " +
				relocation.getType() + ") at address: " + address + ". Reason = " + reason);

		hasUnhandledRelocations = true;
	}
}
