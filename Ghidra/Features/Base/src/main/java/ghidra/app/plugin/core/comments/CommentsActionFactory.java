/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.context.*;
import ghidra.framework.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.*;

import java.awt.event.*;

import docking.*;
import docking.action.*;

public class CommentsActionFactory {
    static {
        PluggableServiceRegistry.registerPluggableService(CommentsActionFactory.class, new CommentsActionFactory());
    }

    public static DockingAction getSetCommentsAction(CommentsDialog dialog,
            String name, String actionName, int commentType) {
        CommentsActionFactory factory = PluggableServiceRegistry.getPluggableService(CommentsActionFactory.class);
        return factory.doGetSetCommentsAction(dialog, name, actionName, commentType);
    }

    public static DockingAction getEditCommentsAction(CommentsDialog dialog,
            String name) {
        CommentsActionFactory factory = PluggableServiceRegistry.getPluggableService(CommentsActionFactory.class);
        return factory.doGetEditCommentsAction(dialog, name);
    }

    public static boolean isCommentSupported(ProgramLocation loc) {
        CommentsActionFactory factory = PluggableServiceRegistry.getPluggableService(CommentsActionFactory.class);
        return factory.doIsCommentSupported(loc);

    }

    protected DockingAction doGetSetCommentsAction(CommentsDialog dialog,
            String name, String actionName, int commentType) {
        return new SetCommentsAction(dialog, name, actionName, commentType);
    }

    protected DockingAction doGetEditCommentsAction(CommentsDialog dialog,
            String name) {
        return new EditCommentsAction(dialog, name);
    }

    protected boolean doIsCommentSupported(ProgramLocation loc) {
        if (loc == null || loc.getAddress() == null) {
            return false;
        }
        return ((loc instanceof CodeUnitLocation) || ((loc instanceof FunctionLocation) && !(loc instanceof VariableLocation)));
    }

    private static class SetCommentsAction extends DockingAction {
        private final CommentsDialog dialog;
        private final int commentType;

        SetCommentsAction(CommentsDialog dialog, String name,
                String actionName, int commentType) {
            super(actionName, name);
            this.dialog = dialog;
            this.commentType = commentType;
            setPopupMenuData(new MenuData(new String[] { "Comments",
                    actionName + "..." }, "comments"));
            setHelpLocation(new HelpLocation("CommentsPlugin", "Edit_Comments"));
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
            return (context instanceof ListingActionContext);
        }

        protected CodeUnit getCodeUnit(ActionContext actionContext) {
            ProgramLocationActionContext context = (ProgramLocationActionContext) actionContext;
            return context.getCodeUnit();
        }

        protected ProgramLocation getLocationForContext(
                ActionContext actionContext) {
            ProgramLocationActionContext context = (ProgramLocationActionContext) actionContext;
            return context.getLocation();
        }
    }

    private static class EditCommentsAction extends SetCommentsAction {
        // Edit Comments Action info
        private final static String[] EDIT_MENUPATH = new String[] {
                "Comments", "Set..." };

        EditCommentsAction(CommentsDialog dialog, String name) {
            super(dialog, name, "Edit Comments", CodeUnit.NO_COMMENT);
            setPopupMenuData(new MenuData(EDIT_MENUPATH, "comments"));
            setKeyBindingData(new KeyBindingData(KeyEvent.VK_SEMICOLON, 0));
        }

        @Override
        protected int getEditCommentType(ActionContext context) {
            CodeUnit cu = getCodeUnit(context);
            return CommentType.getCommentType(cu, getLocationForContext(context), CodeUnit.NO_COMMENT);
        }
    }
}
