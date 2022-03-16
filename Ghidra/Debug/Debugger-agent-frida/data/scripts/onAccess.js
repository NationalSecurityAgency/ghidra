onAccess: function(details) {
	console.log(details.from + " " + details.operation + " " + details.address);
	console.log("pages: completed=" + details.pagesCompleted + " total=" + details.pageTotal);
}

