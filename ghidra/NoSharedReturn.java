import ghidra.app.script.GhidraScript;

public class NoSharedReturn extends GhidraScript {
    @Override
    public void run() throws Exception {
        setAnalysisOption(currentProgram, "Shared Return Calls", "false");
    }
}
