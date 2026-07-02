/*
 * Copyright (c) 2022, 2023, Oracle and/or its affiliates. All rights reserved.
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

"use strict";
$(function() {
    var copy = $("#page-search-copy");
    var expand = $("#page-search-expand");
    var searchLink = $("span#page-search-link");
    var redirect = $("input#search-redirect");
    function setSearchUrlTemplate() {
        var href = document.location.href.split(/[#?]/)[0];
        href += "?q=" + "%s";
        if (redirect.is(":checked")) {
            href += "&r=1";
        }
        searchLink.html(href);
        copy[0].onmouseenter();
    }
    function copyLink(e) {
        copyToClipboard(this.previousSibling.innerText);
        switchCopyLabel(this, this.lastElementChild);
    }
    copy.click(copyLink);
    copy[0].onmouseenter = function() {};
    redirect.click(setSearchUrlTemplate);
    setSearchUrlTemplate();
    copy.prop("disabled", false);
    redirect.prop("disabled", false);
    expand.click(function (e) {
        var searchInfo = $("div.page-search-info");
        if(this.parentElement.hasAttribute("open")) {
            searchInfo.attr("style", "border-width: 0;");
        } else {
            searchInfo.attr("style", "border-width: 1px;").height(searchInfo.prop("scrollHeight"));
        }
    });
});
$(window).on("load", function() {
    var input = $("#page-search-input");
    var reset = $("#page-search-reset");
    var notify = $("#page-search-notify");
    var resultSection = $("div#result-section");
    var resultContainer = $("div#result-container");
    var searchTerm = "";
    var activeTab = "";
    var fixedTab = false;
    var visibleTabs = [];
    var feelingLucky = false;
    function renderResults(result) {
        if (!result.length) {
            notify.html(messages.noResult);
        } else if (result.length === 1) {
            notify.html(messages.oneResult);
        } else {
            notify.html(messages.manyResults.replace("{0}", result.length));
        }
        resultContainer.empty();
        var r = {
            "types": [],
            "members": [],
            "packages": [],
            "modules": [],
            "searchTags": []
        };
        for (var i in result) {
            var item = result[i];
            var arr = r[item.category];
            arr.push(item);
        }
        if (!activeTab || r[activeTab].length === 0 || !fixedTab) {
            Object.keys(r).reduce(function(prev, curr) {
                if (r[curr].length > 0 && r[curr][0].score > prev) {
                    activeTab = curr;
                    return r[curr][0].score;
                }
                return prev;
            }, 0);
        }
        if (feelingLucky && activeTab) {
            notify.html(messages.redirecting)
            var firstItem = r[activeTab][0];
            window.location = getURL(firstItem.indexItem, firstItem.category);
            return;
        }
        if (result.length > 20) {
            if (searchTerm[searchTerm.length - 1] === ".") {
                if (activeTab === "types" && r["members"].length > r["types"].length) {
                    activeTab = "members";
                } else if (activeTab === "packages" && r["types"].length > r["packages"].length) {
                    activeTab = "types";
                }
            }
        }
        var categoryCount = Object.keys(r).reduce(function(prev, curr) {
            return prev + (r[curr].length > 0 ? 1 : 0);
        }, 0);
        visibleTabs = [];
        var tabContainer = $("<div class='table-tabs'></div>").appendTo(resultContainer);
        for (var key in r) {
            var id = "#result-tab-" + key.replace("searchTags", "search_tags");
            if (r[key].length) {
                var count = r[key].length >= 1000 ? "999+" : r[key].length;
                if (result.length > 20 && categoryCount > 1) {
                    var button = $("<button id='result-tab-" + key
                        + "' class='page-search-header'><span>" + categories[key] + "</span>"
                        + "<span style='font-weight: normal'> (" + count + ")</span></button>").appendTo(tabContainer);
                    button.click(key, function(e) {
                        fixedTab = true;
                        renderResult(e.data, $(this));
                    });
                    visibleTabs.push(key);
                } else {
                    $("<span class='page-search-header active-table-tab'>" + categories[key]
                        + "<span style='font-weight: normal'> (" + count + ")</span></span>").appendTo(tabContainer);
                    renderTable(key, r[key]).appendTo(resultContainer);
                    tabContainer = $("<div class='table-tabs'></div>").appendTo(resultContainer);

                }
            }
        }
        if (activeTab && result.length > 20 && categoryCount > 1) {
            $("button#result-tab-" + activeTab).addClass("active-table-tab");
            renderTable(activeTab, r[activeTab]).appendTo(resultContainer);
        }
        resultSection.show();
        function renderResult(category, button) {
            activeTab = category;
            setSearchUrl();
            resultContainer.find("div.summary-table").remove();
            renderTable(activeTab, r[activeTab]).appendTo(resultContainer);
            button.siblings().removeClass("active-table-tab");
            button.addClass("active-table-tab");
        }
    }
    function selectTab(category) {
        $("button#result-tab-" + category).click();
    }
    function renderTable(category, items) {
        var table = $("<div class='summary-table'>")
            .addClass(category === "modules"
                ? "one-column-search-results"
                : "two-column-search-results");
        var col1, col2;
        if (category === "modules") {
            col1 = "Module";
        } else if (category === "packages") {
            col1 = "Module";
            col2 = "Package";
        } else if (category === "types") {
            col1 = "Package";
            col2 = "Class"
        } else if (category === "members") {
            col1 = "Class";
            col2 = "Member";
        } else if (category === "searchTags") {
            col1 = "Location";
            col2 = "Name";
        }
        $("<div class='table-header col-plain'>" + col1 + "</div>").appendTo(table);
        if (category !== "modules") {
            $("<div class='table-header col-plain'>" + col2 + "</div>").appendTo(table);
        }
        $.each(items, function(index, item) {
            var rowColor = index % 2 ? "odd-row-color" : "even-row-color";
            renderItem(item, table, rowColor);
        });
        return table;
    }
    function renderItem(item, table, rowColor) {
        var label = getHighlightedText(item.input, item.boundaries, item.prefix.length, item.input.length);
        var link = $("<a/>")
            .attr("href",  getURL(item.indexItem, item.category))
            .attr("tabindex", "0")
            .addClass("search-result-link")
            .html(label);
        var container = getHighlightedText(item.input, item.boundaries, 0, item.prefix.length - 1);
        if (item.category === "searchTags") {
            container = item.indexItem.h || "";
        }
        if (item.category !== "modules") {
            $("<div/>").html(container).addClass("col-plain").addClass(rowColor).appendTo(table);
        }
        $("<div/>").html(link).addClass("col-last").addClass(rowColor).appendTo(table);
    }
    var timeout;
    function schedulePageSearch() {
        if (timeout) {
            clearTimeout(timeout);
        }
        timeout = setTimeout(function () {
            doPageSearch()
        }, 100);
    }
    function doPageSearch() {
        setSearchUrl();
        var term = searchTerm = input.val().trim();
        if (term === "") {
            notify.html(messages.enterTerm);
            activeTab = "";
            fixedTab = false;
            resultContainer.empty();
            resultSection.hide();
        } else {
            notify.html(messages.searching);
            doSearch({ term: term, maxResults: 1200 }, renderResults);
        }
    }
    function setSearchUrl() {
        var query = input.val().trim();
        var url = document.location.pathname;
        if (query) {
            url += "?q=" + encodeURI(query);
            if (activeTab && fixedTab) {
                url += "&c=" + activeTab;
            }
        }
        history.replaceState({query: query}, "", url);
    }
    input.on("input", function(e) {
        feelingLucky = false;
        schedulePageSearch();
    });
    $(document).keydown(function(e) {
        if ((e.ctrlKey || e.metaKey) && (e.key === "ArrowLeft" || e.key === "ArrowRight")) {
            if (activeTab && visibleTabs.length > 1) {
                var idx = visibleTabs.indexOf(activeTab);
                idx += e.key === "ArrowLeft" ? visibleTabs.length - 1 : 1;
                selectTab(visibleTabs[idx % visibleTabs.length]);
                return false;
            }
        }
    });
    reset.click(function() {
        notify.html(messages.enterTerm);
        resultSection.hide();
        activeTab = "";
        fixedTab = false;
        resultContainer.empty();
        input.val('').focus();
        setSearchUrl();
    });
    input.prop("disabled", false);
    reset.prop("disabled", false);

    var urlParams = new URLSearchParams(window.location.search);
    if (urlParams.has("q")) {
        input.val(urlParams.get("q"))
    }
    if (urlParams.has("c")) {
        activeTab = urlParams.get("c");
        fixedTab = true;
    }
    if (urlParams.get("r")) {
        feelingLucky = true;
    }
    if (input.val()) {
        doPageSearch();
    } else {
        notify.html(messages.enterTerm);
    }
    input.select().focus();
});