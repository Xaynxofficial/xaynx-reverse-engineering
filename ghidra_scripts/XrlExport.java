// Xaynx Reverse Lab - Ghidra headless export script.
//
// Invoked via:  analyzeHeadless ... -postScript XrlExport.java <output.json> <decompile 0|1> <maxDecompiled>
// Exports the functions Ghidra's own analysis found (and optionally Ghidra's decompiler output) as JSON.
// Nothing is invented here: every field is read from Ghidra's program database.
//
// NOTE: this script was written against the public Ghidra API but could not be executed in the
// project's development environment (no Ghidra installation was available). See docs/ghidra.md.
//@category XaynxReverseLab

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

public class XrlExport extends GhidraScript {

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7e) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("XrlExport: missing output path argument");
            return;
        }
        File out = new File(args[0]);
        boolean decompile = args.length > 1 && args[1].equals("1");
        int maxDecompiled = 50;
        if (args.length > 2) {
            try { maxDecompiled = Integer.parseInt(args[2]); } catch (NumberFormatException e) { /* keep default */ }
        }

        DecompInterface ifc = null;
        if (decompile) {
            ifc = new DecompInterface();
            if (!ifc.openProgram(currentProgram)) {
                printerr("XrlExport: decompiler could not open program: " + ifc.getLastMessage());
                ifc = null;
            }
        }

        int total = currentProgram.getFunctionManager().getFunctionCount();
        try (Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8)) {
            w.write("{\n");
            w.write("  \"ghidra_version\": \"" + esc(Application.getApplicationVersion()) + "\",\n");
            w.write("  \"language\": \"" + esc(currentProgram.getLanguageID().toString()) + "\",\n");
            w.write("  \"compiler\": \"" + esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\",\n");
            w.write("  \"image_base\": \"0x" + Long.toHexString(currentProgram.getImageBase().getOffset()) + "\",\n");
            w.write("  \"total_functions\": " + total + ",\n");
            w.write("  \"functions\": [\n");

            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            int decompiledCount = 0;
            boolean first = true;
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (!first) w.write(",\n");
                first = false;
                w.write("    {\"name\": \"" + esc(f.getName()) + "\"");
                w.write(", \"entry\": \"0x" + Long.toHexString(f.getEntryPoint().getOffset()) + "\"");
                w.write(", \"size\": " + f.getBody().getNumAddresses());
                w.write(", \"signature\": \"" + esc(f.getPrototypeString(false, false)) + "\"");
                w.write(", \"external\": " + f.isExternal());
                w.write(", \"thunk\": " + f.isThunk());
                if (ifc != null && decompiledCount < maxDecompiled && !f.isExternal() && !f.isThunk()) {
                    DecompileResults res = ifc.decompileFunction(f, 60, monitor);
                    if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                        w.write(", \"decompiled\": \"" + esc(res.getDecompiledFunction().getC()) + "\"");
                        decompiledCount++;
                    }
                }
                w.write("}");
            }
            w.write("\n  ]\n}\n");
        } finally {
            if (ifc != null) ifc.dispose();
        }
        println("XrlExport: wrote " + out.getAbsolutePath());
    }
}

