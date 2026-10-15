// Smoke test for the Ansible ghidra role: proves the native decompiler runs.
//@category PatchDiff
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class PdSmokeDecompile extends GhidraScript {
	@Override
	public void run() throws Exception {
		DecompInterface decomp = new DecompInterface();
		if (!decomp.openProgram(currentProgram)) {
			println("PD_SMOKE_FAIL " + decomp.getLastMessage());
			return;
		}
		int ok = 0;
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		while (it.hasNext() && ok < 5) {
			Function f = it.next();
			DecompileResults r = decomp.decompileFunction(f, 30, monitor);
			if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
				ok++;
			}
		}
		decomp.dispose();
		println(ok > 0 ? "PD_SMOKE_OK " + ok : "PD_SMOKE_FAIL no function decompiled");
	}
}
