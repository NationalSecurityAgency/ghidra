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
package ghidra.util.database.spatial.rect;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;

import ghidra.util.database.DBCachedObjectStoreFactory;
import ghidra.util.database.spatial.*;
import ghidra.util.exception.VersionException;

public abstract class Abstract2DRStarTree< //
		X, Y, //
		DS extends BoundedShape<NS>, //
		DR extends DBTreeDataRecord<DS, NS, T>, //
		NS extends Rectangle2D<X, Y, NS>, //
		NR extends DBTreeNodeRecord<NS>, //
		T, //
		Q extends AbstractRectangle2DQuery<X, Y, DS, NS, Q>> //
		extends AbstractRStarConstraintsTree<DS, DR, NS, NR, T, Q> {

	protected static class AsSpatialMap< //
			DS extends BoundedShape<NS>, //
			DR extends DBTreeDataRecord<DS, NS, T>, //
			NS extends Rectangle2D<?, ?, NS>, T, Q extends AbstractRectangle2DQuery<?, ?, DS, NS, Q>>
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

	protected final EuclideanSpace2D<X, Y> space;
	protected final List<Comparator<NS>> axes;

	public Abstract2DRStarTree(DBCachedObjectStoreFactory storeFactory, String tableName,
			EuclideanSpace2D<X, Y> space, Class<DR> dataType, Class<NR> nodeType,
			boolean upgradable, int maxChildren) throws VersionException, IOException {
		super(storeFactory, tableName, dataType, nodeType, upgradable, maxChildren);
		this.space = space;

		this.axes = List.of(new Comparator<NS>() {
			@Override
			public int compare(NS o1, NS o2) {
				return space.compareX(o1.getX1(), o2.getX1());
			}
		}, new Comparator<NS>() {
			@Override
			public int compare(NS o1, NS o2) {
				return space.compareY(o1.getY1(), o2.getY1());
			}
		});
	}

	@Override
	protected List<Comparator<NS>> getSplitAxes() {
		return axes;
	}

	@Override
	public AbstractConstraintsTreeSpatialMap<DS, DR, NS, T, Q> asSpatialMap() {
		return new AsSpatialMap<>(this, null);
	}

	public EuclideanSpace2D<X, Y> getShapeSpace() {
		return space;
	}
}
