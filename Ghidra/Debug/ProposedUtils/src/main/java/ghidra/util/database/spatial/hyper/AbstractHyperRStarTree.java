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
package ghidra.util.database.spatial.hyper;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;

import ghidra.util.database.DBCachedObjectStoreFactory;
import ghidra.util.database.spatial.*;
import ghidra.util.exception.VersionException;

public abstract class AbstractHyperRStarTree< //
		P extends HyperPoint, //
		DS extends BoundedShape<NS>, //
		DR extends DBTreeDataRecord<DS, NS, T>, //
		NS extends HyperBox<P, NS>, //
		NR extends DBTreeNodeRecord<NS>, //
		T, //
		Q extends AbstractHyperBoxQuery<P, DS, NS, Q>> //
		extends AbstractRStarConstraintsTree<DS, DR, NS, NR, T, Q> {

	protected static class AsSpatialMap< //
			DS extends BoundedShape<NS>, //
			DR extends DBTreeDataRecord<DS, NS, T>, //
			NS extends HyperBox<?, NS>, T, Q extends AbstractHyperBoxQuery<?, DS, NS, Q>>
			extends AbstractConstraintsTreeSpatialMap<DS, DR, NS, T, Q> {
		public AsSpatialMap(AbstractConstraintsTree<DS, DR, NS, ?, T, Q> tree, Q query) {
			super(tree, query);
		}

		@Override
		public AsSpatialMap<DS, DR, NS, T, Q> reduce(Q andQuery) {
			return new AsSpatialMap<>(this.tree,
				this.query == null ? andQuery : this.query.and(andQuery));
		}
	}

	protected final EuclideanHyperSpace<P, NS> space;
	protected final List<Comparator<NS>> axes;

	protected <V> Comparator<NS> dimComparator(Dimension<V, P, NS> dim) {
		return Comparator.comparing(dim::lower, dim::compare);
	}

	public AbstractHyperRStarTree(DBCachedObjectStoreFactory storeFactory, String tableName,
			EuclideanHyperSpace<P, NS> space, Class<DR> dataType, Class<NR> nodeType,
			boolean upgradeable, int maxChildren) throws VersionException, IOException {
		super(storeFactory, tableName, dataType, nodeType, upgradeable, maxChildren);
		this.space = space;
		this.axes = space.getDimensions().stream().map(this::dimComparator).toList();
	}

	@Override
	protected List<Comparator<NS>> getSplitAxes() {
		return axes;
	}

	@Override
	protected Comparator<NS> getDefaultBoundsComparator() {
		return axes.get(0);
	}

	@Override
	public AbstractConstraintsTreeSpatialMap<DS, DR, NS, T, Q> asSpatialMap() {
		return new AsSpatialMap<>(this, null);
	}
}
