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
package ghidra.app.plugin.core.comments;

import java.awt.event.KeyEvent;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.decompiler.DecompilerLocation;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

public class DecompilerCommentsActionFactory extends CommentsActionFactory {

    @Override
    protected DockingAction doGetEditCommentsAction(CommentsDialog dialog,
            String name) {
        return new DecompilerEditCommentsAction(dialog, name);
    }

    @Override
    protected DockingAction doGetSetCommentsAction(CommentsDialog dialog,
            String name, String actionName, int commentType) {
        return new DecompilerSetCommentsAction(dialog, name, actionName, commentType);
    }

    @Override
    protected boolean doIsCommentSupported(ProgramLocation loc) {
        if (loc == null || loc.getAddress() == null) {
            return false;
        }
        return ((loc instanceof CodeUnitLocation)
                || (loc instanceof DecompilerLocation) || ((loc instanceof FunctionLocation) && !(loc instanceof VariableLocation)));
    }

    private static class DecompilerSetCommentsAction extends DockingAction {
        private final CommentsDialog dialog;
        private final int commentType;

        DecompilerSetCommentsAction(CommentsDialog dialog, String name,
                String actionName, int commentType) {
            super(actionName, name);
            this.dialog = dialog;
            this.commentType = commentType;
            setPopupMenuData(new MenuData(new String[] { "Comments",
                    actionName + "..." }, "comments"));
			setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionComments"));
        }

        protected int getEditCommentType(ActionContext context) {
            return commentType;
        }

        @Override
        public void actionPerformed(ActionContext context) {
            CodeUnit cu = getCodeUnit(context);
            int type = getEditCommentType(context);
            dialog.showDialog(cu, type);
        }

        @Override
        public boolean isEnabledForContext(ActionContext actionContext) {
            ProgramLocation loc = getLocationForContext(actionContext);
            if (!isCommentSupported(loc)) {
                return false;
            }
            return CommentType.isCommentAllowed(getCodeUnit(actionContext), loc);
        }

        @Override
        public boolean isValidContext(ActionContext context) {
            return (context instanceof ListingActionContext)
                    || (context instanceof DecompilerActionContext);
        }

        protected CodeUnit getCodeUnit(ActionContext actionContext) {
            ProgramLocationActionContext context = (ProgramLocationActionContext) actionContext;
            return context.getCodeUnit();
        }

        protected ProgramLocation getLocationForContext(
                ActionContext actionContext) {
            // only allow decompiler to have PRE, PLATE, and Generic Comment actions
            if ((actionContext instanceof DecompilerActionContext)
                    && commentType != CodeUnit.PRE_COMMENT
                    && commentType != CodeUnit.PLATE_COMMENT
                    && commentType != CodeUnit.NO_COMMENT) {
                return null;
            }

            if ( !(actionContext instanceof ProgramLocationActionContext) ) {
                return null;
            }
            
            ProgramLocationActionContext context = (ProgramLocationActionContext) actionContext;
            return context.getLocation();
        }
    }

    private static class DecompilerEditCommentsAction extends
            DecompilerSetCommentsAction {
        // Edit Comments Action info
        private final static String[] EDIT_MENUPATH = new String[] {
                "Comments", "Set..." };

        DecompilerEditCommentsAction(CommentsDialog dialog, String name) {
            super(dialog, name, "Edit Comments", CodeUnit.NO_COMMENT);
            setPopupMenuData(new MenuData(EDIT_MENUPATH, "comments"));
            setKeyBindingData(new KeyBindingData(KeyEvent.VK_SEMICOLON, 0));
        }

        @Override
        protected int getEditCommentType(ActionContext context) {
            if (context instanceof DecompilerActionContext) {
                DecompilerActionContext decompContext = (DecompilerActionContext) context;
                Address addr = decompContext.getAddress();
                if (addr.equals(decompContext.getFunctionEntryPoint())) {
                    return CodeUnit.PLATE_COMMENT;
                }
                return CodeUnit.PRE_COMMENT;
            }
            CodeUnit cu = getCodeUnit(context);
            return CommentType.getCommentType(cu, getLocationForContext(context), CodeUnit.NO_COMMENT);
        }
    }
}
