/*
 * Copyright (c) 2013, 2023, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

var moduleSearchIndex;
var packageSearchIndex;
var typeSearchIndex;
var memberSearchIndex;
var tagSearchIndex;

var oddRowColor = "odd-row-color";
var evenRowColor = "even-row-color";
var sortAsc = "sort-asc";
var sortDesc = "sort-desc";
var tableTab = "table-tab";
var activeTableTab = "active-table-tab";

function loadScripts(doc, tag) {
    createElem(doc, tag, 'search.js');

    createElem(doc, tag, 'module-search-index.js');
    createElem(doc, tag, 'package-search-index.js');
    createElem(doc, tag, 'type-search-index.js');
    createElem(doc, tag, 'member-search-index.js');
    createElem(doc, tag, 'tag-search-index.js');
}

function createElem(doc, tag, path) {
    var script = doc.createElement(tag);
    var scriptElement = doc.getElementsByTagName(tag)[0];
    script.src = pathtoroot + path;
    scriptElement.parentNode.insertBefore(script, scriptElement);
}

// Helper for  making content containing release names comparable lexicographically
function makeComparable(s) {
    return s.toLowerCase().replace(/(\d+)/g,
        function(n, m) {
            return ("000" + m).slice(-4);
        });
}

// Switches between two styles depending on a condition
function toggleStyle(classList, condition, trueStyle, falseStyle) {
    if (condition) {
        classList.remove(falseStyle);
        classList.add(trueStyle);
    } else {
        classList.remove(trueStyle);
        classList.add(falseStyle);
    }
}

// Sorts the rows in a table lexicographically by the content of a specific column
function sortTable(header, columnIndex, columns) {
    var container = header.parentElement;
    var descending = header.classList.contains(sortAsc);
    container.querySelectorAll("div.table-header").forEach(
        function(header) {
            header.classList.remove(sortAsc);
            header.classList.remove(sortDesc);
        }
    )
    var cells = container.children;
    var rows = [];
    for (var i = columns; i < cells.length; i += columns) {
        rows.push(Array.prototype.slice.call(cells, i, i + columns));
    }
    var comparator = function(a, b) {
        var ka = makeComparable(a[columnIndex].textContent);
        var kb = makeComparable(b[columnIndex].textContent);
        if (ka < kb)
            return descending ? 1 : -1;
        if (ka > kb)
            return descending ? -1 : 1;
        return 0;
    };
    var sorted = rows.sort(comparator);
    var visible = 0;
    sorted.forEach(function(row) {
        if (row[0].style.display !== 'none') {
            var isEvenRow = visible++ % 2 === 0;
        }
        row.forEach(function(cell) {
            toggleStyle(cell.classList, isEvenRow, evenRowColor, oddRowColor);
            container.appendChild(cell);
        })
    });
    toggleStyle(header.classList, descending, sortDesc, sortAsc);
}

// Toggles the visibility of a table category in all tables in a page
function toggleGlobal(checkbox, selected, columns) {
    var display = checkbox.checked ? '' : 'none';
    document.querySelectorAll("div.table-tabs").forEach(function(t) {
        var id = t.parentElement.getAttribute("id");
        var selectedClass = id + "-tab" + selected;
        // if selected is empty string it selects all uncategorized entries
        var selectUncategorized = !Boolean(selected);
        var visible = 0;
        document.querySelectorAll('div.' + id)
            .forEach(function(elem) {
                if (selectUncategorized) {
                    if (elem.className.indexOf(selectedClass) === -1) {
                        elem.style.display = display;
                    }
                } else if (elem.classList.contains(selectedClass)) {
                    elem.style.display = display;
                }
                if (elem.style.display === '') {
                    var isEvenRow = visible++ % (columns * 2) < columns;
                    toggleStyle(elem.classList, isEvenRow, evenRowColor, oddRowColor);
                }
            });
        var displaySection = visible === 0 ? 'none' : '';
        t.parentElement.style.display = displaySection;
        document.querySelector("li#contents-" + id).style.display = displaySection;
    })
}

// Shows the elements of a table belonging to a specific category
function show(tableId, selected, columns) {
    if (tableId !== selected) {
        document.querySelectorAll('div.' + tableId + ':not(.' + selected + ')')
            .forEach(function(elem) {
                elem.style.display = 'none';
            });
    }
    document.querySelectorAll('div.' + selected)
        .forEach(function(elem, index) {
            elem.style.display = '';
            var isEvenRow = index % (columns * 2) < columns;
            toggleStyle(elem.classList, isEvenRow, evenRowColor, oddRowColor);
        });
    updateTabs(tableId, selected);
}

function updateTabs(tableId, selected) {
    document.getElementById(tableId + '.tabpanel')
        .setAttribute('aria-labelledby', selected);
    document.querySelectorAll('button[id^="' + tableId + '"]')
        .forEach(function(tab, index) {
            if (selected === tab.id || (tableId === selected && index === 0)) {
                tab.className = activeTableTab;
                tab.setAttribute('aria-selected', true);
                tab.setAttribute('tabindex',0);
            } else {
                tab.className = tableTab;
                tab.setAttribute('aria-selected', false);
                tab.setAttribute('tabindex',-1);
            }
        });
}

function switchTab(e) {
    var selected = document.querySelector('[aria-selected=true]');
    if (selected) {
        if ((e.keyCode === 37 || e.keyCode === 38) && selected.previousSibling) {
            // left or up arrow key pressed: move focus to previous tab
            selected.previousSibling.click();
            selected.previousSibling.focus();
            e.preventDefault();
        } else if ((e.keyCode === 39 || e.keyCode === 40) && selected.nextSibling) {
            // right or down arrow key pressed: move focus to next tab
            selected.nextSibling.click();
            selected.nextSibling.focus();
            e.preventDefault();
        }
    }
}

var updateSearchResults = function() {};

function indexFilesLoaded() {
    return moduleSearchIndex
        && packageSearchIndex
        && typeSearchIndex
        && memberSearchIndex
        && tagSearchIndex;
}
// Copy the contents of the local snippet to the clipboard
function copySnippet(button) {
    copyToClipboard(button.nextElementSibling.innerText);
    switchCopyLabel(button, button.firstElementChild);
}
function copyToClipboard(content) {
    var textarea = document.createElement("textarea");
    textarea.style.height = 0;
    document.body.appendChild(textarea);
    textarea.value = content;
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
}
function switchCopyLabel(button, span) {
    var copied = span.getAttribute("data-copied");
    button.classList.add("visible");
    var initialLabel = span.innerHTML;
    span.innerHTML = copied;
    setTimeout(function() {
        button.classList.remove("visible");
        setTimeout(function() {
            if (initialLabel !== copied) {
                span.innerHTML = initialLabel;
            }
        }, 100);
    }, 1900);
}
// Workaround for scroll position not being included in browser history (8249133)
document.addEventListener("DOMContentLoaded", function(e) {
    var contentDiv = document.querySelector("div.flex-content");
    window.addEventListener("popstate", function(e) {
        if (e.state !== null) {
            contentDiv.scrollTop = e.state;
        }
    });
    window.addEventListener("hashchange", function(e) {
        history.replaceState(contentDiv.scrollTop, document.title);
    });
    var timeoutId;
    contentDiv.addEventListener("scroll", function(e) {
        if (timeoutId) {
            clearTimeout(timeoutId);
        }
        timeoutId = setTimeout(function() {
            history.replaceState(contentDiv.scrollTop, document.title);
        }, 100);
    });
    if (!location.hash) {
        history.replaceState(contentDiv.scrollTop, document.title);
    }
});
