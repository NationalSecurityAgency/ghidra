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
package ghidra.graph.visualization;

import java.awt.Shape;
import java.awt.geom.PathIterator;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.List;

/**
 * Holds the enum for shape type and the Function to categorize the archetype Shapes into
 * IconShape.Types. Note that the archetype shapes are centered at the origin
 */
public class IconShape {

    public enum Type  {
        TRIANGLE, INVERTED_TRIANGLE, RECTANGLE, DIAMOND, ELLIPSE
    }

    /**
     * Categorize the supplied Shape into one of several simple types.
     *
     */
    static class Function implements java.util.function.Function<Shape, Type> {

        @Override
        public Type apply(Shape shape) {
            List<Point2D> points = getShapePoints(shape);
            if (points.size() == 3) {
                if (isInvertedTriangle(points)) {
                    return Type.INVERTED_TRIANGLE;
                } else {
                    return Type.TRIANGLE;
                }
            }
            // there are 5 points because the final point is the same as the first
            // and closes the shape.
            if (points.size() == 5) {
                if (isDiamond(points)) {
                    return Type.DIAMOND;
                } else {
                    return Type.RECTANGLE;
                }
            }
            // default to ellipse for anything with more that 4 sides
            return Type.ELLIPSE;
        }

        /**
         *
         * Note that for awt drawing, the origin is at the upper left so positive y extends downwards.
         * @param threePoints odd number of points bounding a {@link Shape} centered at the origin
         * @return true it there are fewer points with y below 0
         */
         boolean isInvertedTriangle(List<Point2D> threePoints) {
            if (threePoints.size() != 3) {
                throw new IllegalArgumentException("Shape from " + threePoints + " is not a triangle");
            }
            return threePoints.stream().filter(p -> p.getY() < 0).count() <= threePoints.size() / 2;
        }

        /**
         *
         * @param fivePoints odd number of points bounding a {@link Shape} centered at the origin
         * @return true it there are 2 points with y value 0
         */
         boolean isDiamond(List<Point2D> fivePoints) {
            if (fivePoints.size() != 5) {
                throw new IllegalArgumentException(
                        "Shape from " + fivePoints + " is not a quadrilateral");
            }
            return fivePoints.stream().filter(p -> (int) p.getY() == 0).count() == 2;
        }

         List<Point2D> getShapePoints(Shape shape) {
            float[] seg = new float[6];
            List<Point2D> points = new ArrayList<>();
            for (PathIterator i = shape.getPathIterator(null, 1); !i.isDone(); i.next()) {
                int ret = i.currentSegment(seg);
                if (ret == PathIterator.SEG_MOVETO) {
                    points.add(new Point2D.Float(seg[0], seg[1]));
                }
                else if (ret == PathIterator.SEG_LINETO) {
                    points.add(new Point2D.Float(seg[0], seg[1]));
                }
            }
            return points;
        }
    }
}
