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
package ghidra.trace.database.symbol;

import java.util.ArrayList;
import java.util.Collection;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolType;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.symbol.TraceNamespaceSymbol;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.annot.DBAnnotatedObjectInfo;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceNamespaceSymbol extends AbstractDBTraceSymbol implements TraceNamespaceSymbol {
	protected static final String TABLE_NAME = "Namespaces";
	protected final AddressSet allAddresses;

	public DBTraceNamespaceSymbol(DBTraceSymbolManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(manager, store, record);
		allAddresses = manager.trace.getBaseAddressFactory().getAddressSet();
	}

	@Override
	protected DBTraceNamespaceSymbol checkCircular(DBTraceNamespaceSymbol newParent)
			throws CircularDependencyException {
		DBTraceNamespaceSymbol global = manager.getGlobalNamespace();
		// I cannot be one of my own ancestors
		for (DBTraceNamespaceSymbol p = newParent; p != global; p = p.parent) {
			if (p == this) {
				throw new CircularDependencyException();
			}
		}
		return super.checkCircular(newParent);
	}

	// Internal
	@Override
	public Range<Long> getLifespan() {
		// TODO: Cache this computation and/or keep it as transient fields?
		long min = Long.MAX_VALUE;
		long max = Long.MIN_VALUE;
		Range<Long> range = super.getLifespan();
		if (range != null) {
			min = DBTraceUtils.lowerEndpoint(range);
			max = DBTraceUtils.upperEndpoint(range);
		}
		for (AbstractDBTraceSymbol child : getChildren()) {
			range = child.getLifespan();
			if (range != null) {
				min = Math.min(min, DBTraceUtils.lowerEndpoint(range));
				max = Math.min(max, DBTraceUtils.upperEndpoint(range));
			}
		}
		if (min > max) {
			return null;
		}
		return DBTraceUtils.toRange(min, max);
	}

	@Override
	public AddressSet getAddressSet() {
		if (isGlobal()) {
			return allAddresses;
		}
		AddressSet result = super.getAddressSet();

		/**
		 * TODO: Decide whether I'm tracking the full address set in the parent or relying on
		 * getChildren(). If I use getChildren, I'll need a private getChildren that doesn't
		 * checkIsMine. Otherwise, I cannot recover function bodies upon deletion, which is required
		 * for program-view event translation.
		 */
		//for (AbstractDBTraceSymbol child : getChildren()) {
		//	child.doCollectAddressSet(result);
		//}
		return result;
	}

	@Override
	public SymbolType getSymbolType() {
		if (parentID == -1) {
			return SymbolType.GLOBAL;
		}
		return SymbolType.NAMESPACE;
	}

	@Override
	public AddressSetView getBody() {
		return getAddressSet();
	}

	@Override
	public void setParentNamespace(Namespace parentNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		setNamespace(parentNamespace);
	}

	@Override
	public boolean setPrimary() {
		return false;
	}

	@Override
	public Collection<? extends AbstractDBTraceSymbol> getChildren() {
		return manager.allSymbols.getChildren(this);
	}

	@Override
	public boolean delete() {
		boolean success = true;
		for (AbstractDBTraceSymbol child : getChildren()) {
			success &= child.delete();
		}
		if (success) {
			super.delete();
		}
		return success;
	}

	protected void doGetPath(ArrayList<String> list) {
		if (parent != manager.globalNamespace) {
			parent.doGetPath(list);
		}
		list.add(name);
	}

	@Override
	public boolean isPrimary() {
		return isGlobal();
	}
}
