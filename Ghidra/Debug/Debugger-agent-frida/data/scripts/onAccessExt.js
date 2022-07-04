function monitorMemory(base, length, interceptedInstructions = new Set()) {
	const baseAddress = ptr(base.toString());
	MemoryAccessMonitor.enable({ base: baseAddress, size: length }, {
		onAccess: function(details) {
			console.log(details.from + " " + details.operation + " " + details.address);
			let instruction = Instruction.parse(details.from);
			const nextInstr = ptr(instruction.next.toString());
			if (interceptedInstructions.has(nextInstr.toString())) {
				return;
			}
			interceptedInstructions.add(nextInstr.toString());
			Interceptor.attach(nextInstr, function(_) {
				monitorMemory(baseAddress, length, inteceptedInstructions);
			});
		}
	});
}

