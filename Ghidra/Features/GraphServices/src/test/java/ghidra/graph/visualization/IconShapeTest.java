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

import ghidra.service.graph.AttributedVertex;
import org.junit.Assert;
import org.junit.Test;

import java.awt.geom.Rectangle2D;

public class IconShapeTest {

    private IconShape.Function iconShapeFunction = new IconShape.Function();

    @Test
    public void testShapes() {

        Rectangle2D rectangle = new Rectangle2D.Double(-10, -10, 20, 20);

        Assert.assertEquals(IconShape.Type.RECTANGLE, iconShapeFunction.apply(rectangle));

        AttributedVertex v = new AttributedVertex("id", "name");
        // by vertex type
        v.setAttribute("VertexType", "Entry");
        Assert.assertEquals(IconShape.Type.TRIANGLE,
                iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));

        v.setAttribute("VertexType", "Exit");
        Assert.assertEquals(IconShape.Type.INVERTED_TRIANGLE,
                iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));

        v.setAttribute("VertexType", "Switch");
        Assert.assertEquals(IconShape.Type.DIAMOND, iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));
        v.setAttribute("VertexType", "Body");
        Assert.assertEquals(IconShape.Type.RECTANGLE, iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));
        v.setAttribute("VertexType", "External");
        Assert.assertEquals(IconShape.Type.RECTANGLE, iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));
        v.setAttribute("VertexType", "Foo");
        Assert.assertEquals(IconShape.Type.ELLIPSE, iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));


        // by vertex icon shape name
        v.removeAttribute("VertexType");
        v.setAttribute("Icon", "Square");
        Assert.assertEquals(IconShape.Type.RECTANGLE, iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));
        v.setAttribute("Icon", "TriangleDown");
        Assert.assertEquals(IconShape.Type.TRIANGLE, iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));
        v.setAttribute("Icon", "Triangle");
        Assert.assertEquals(IconShape.Type.INVERTED_TRIANGLE, iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));
        v.setAttribute("Icon", "Diamond");
        Assert.assertEquals(IconShape.Type.DIAMOND, iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));
        v.setAttribute("Icon", "Circle");
        Assert.assertEquals(IconShape.Type.ELLIPSE, iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));
        v.setAttribute("Icon", "Foo");
        Assert.assertEquals(IconShape.Type.RECTANGLE, iconShapeFunction.apply(ProgramGraphFunctions.getVertexShape(v)));
    }
}
